// Command gkload drives Check traffic at a running gatekeeper and reports
// throughput and latency percentiles.
//
//	gkload -http http://localhost:8080 -token $TOKEN -c 64 -d 20s
//	gkload -grpc localhost:9090 -token $TOKEN -c 64 -n 100000
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
)

const body = `{"subject":{"id":"u1"},"action":"write","resource":{"type":"doc","id":"d1","attrs":{"owner":"u1"}}}`

type result struct {
	ok, limited, failed atomic.Int64
	mu                  sync.Mutex
	lat                 []time.Duration
	errs                map[string]int
}

func (r *result) add(d time.Duration, err error) {
	switch {
	case err == nil:
		r.ok.Add(1)
	case status.Code(err) == codes.ResourceExhausted:
		r.limited.Add(1)
	default:
		r.failed.Add(1)
	}
	r.mu.Lock()
	r.lat = append(r.lat, d)
	if err != nil && status.Code(err) != codes.ResourceExhausted {
		r.errs[err.Error()]++
	}
	r.mu.Unlock()
}

func main() {
	httpURL := flag.String("http", "", "HTTP base URL, e.g. http://localhost:8080")
	grpcAddr := flag.String("grpc", "", "gRPC address, e.g. localhost:9090 (plaintext)")
	token := flag.String("token", os.Getenv("TOKEN"), "bearer token(s) with policy:check, comma-separated; clients round-robin over them")
	conc := flag.Int("c", 32, "concurrent clients")
	total := flag.Int("n", 0, "total requests; 0 = run for -d")
	dur := flag.Duration("d", 10*time.Second, "duration when -n is 0")
	flag.Parse()
	if (*httpURL == "") == (*grpcAddr == "") || *token == "" {
		fmt.Fprintln(os.Stderr, "need exactly one of -http/-grpc, and -token")
		os.Exit(2)
	}
	tokens := strings.Split(*token, ",")

	var call func(context.Context, string) error
	if *httpURL != "" {
		client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: *conc, MaxConnsPerHost: *conc}}
		call = func(ctx context.Context, tok string) error {
			req, _ := http.NewRequestWithContext(ctx, "POST", *httpURL+"/v1/check", bytes.NewReader([]byte(body)))
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			switch resp.StatusCode {
			case 200:
				return nil
			case 429:
				return status.Error(codes.ResourceExhausted, "429")
			}
			return fmt.Errorf("http %d", resp.StatusCode)
		}
	} else {
		conn, err := grpc.NewClient(*grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer conn.Close()
		gc := pb.NewGatekeeperClient(conn)
		req := &pb.CheckRequest{Subject: &pb.Subject{Id: "u1"}, Action: "write", Resource: &pb.Resource{Type: "doc", Id: "d1"}}
		call = func(ctx context.Context, tok string) error {
			_, err := gc.Check(metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok), req)
			return err
		}
	}

	// Workers stop issuing at the deadline but let their last call finish, so
	// the tail is not polluted with client-side cancellations.
	var stop atomic.Bool
	if *total == 0 {
		time.AfterFunc(*dur, func() { stop.Store(true) })
	}
	ctx := context.Background()
	res := result{errs: map[string]int{}}
	var issued atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok := tokens[i%len(tokens)]
			for !stop.Load() {
				if *total > 0 && issued.Add(1) > int64(*total) {
					return
				}
				t0 := time.Now()
				err := call(ctx, tok)
				res.add(time.Since(t0), err)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	sort.Slice(res.lat, func(i, j int) bool { return res.lat[i] < res.lat[j] })
	pct := func(p float64) time.Duration {
		if len(res.lat) == 0 {
			return 0
		}
		return res.lat[min(len(res.lat)-1, int(float64(len(res.lat))*p))]
	}
	n := int64(len(res.lat))
	fmt.Printf("clients=%d tenants=%d requests=%d ok=%d ratelimited=%d failed=%d elapsed=%s\n",
		*conc, len(tokens), n, res.ok.Load(), res.limited.Load(), res.failed.Load(), elapsed.Round(time.Millisecond))
	fmt.Printf("throughput=%.0f req/s  p50=%s p90=%s p99=%s max=%s\n",
		float64(n)/elapsed.Seconds(), pct(0.5).Round(time.Microsecond), pct(0.9).Round(time.Microsecond),
		pct(0.99).Round(time.Microsecond), pct(1).Round(time.Microsecond))
	for e, n := range res.errs {
		fmt.Printf("  %6d x %s\n", n, e)
	}
}
