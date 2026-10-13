//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

// proc runs a binary under a supervisor that restarts it whenever it exits,
// like a process manager would, and can SIGKILL the current instance.
type proc struct {
	bin        string
	args       []string
	firstExtra []string // fault-injection flags for the first run only

	mu       sync.Mutex
	cmd      *exec.Cmd
	starts   int
	kills    int
	exits    map[int]int // exit code -> count
	onStderr func(string)
}

func (p *proc) supervise(ctx context.Context, t *testing.T, wg *sync.WaitGroup) {
	defer wg.Done()
	for ctx.Err() == nil {
		p.mu.Lock()
		args := p.args
		if p.starts == 0 {
			args = append(append([]string{}, args...), p.firstExtra...)
		}
		cmd := exec.Command(p.bin, args...)
		stderr, _ := cmd.StderrPipe()
		if err := cmd.Start(); err != nil {
			p.mu.Unlock()
			t.Errorf("start %s: %v", p.bin, err)
			return
		}
		p.cmd, p.starts = cmd, p.starts+1
		p.mu.Unlock()
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if p.onStderr != nil {
				p.onStderr(sc.Text())
			}
		}
		err := cmd.Wait()
		p.mu.Lock()
		code := cmd.ProcessState.ExitCode()
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			code = -int(ws.Signal())
		}
		p.exits[code]++
		p.mu.Unlock()
		_ = err
		time.Sleep(50 * time.Millisecond)
	}
}

// kill SIGKILLs the running instance, except the first one, which is left
// to crash at its injected fault point.
func (p *proc) kill() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.ProcessState == nil && p.starts > 1 {
		p.cmd.Process.Signal(syscall.SIGKILL)
		p.kills++
	}
}

func (p *proc) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.ProcessState == nil {
		p.cmd.Process.Signal(syscall.SIGTERM)
	}
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// Transactional outbox under fire. gatekeeper (-outbox) serves Checks for
// four tenants while gkrelay and gkconsumer are SIGKILLed at random and
// restarted; their first runs also crash at the exact duplicate-producing
// points (after the broker ack / after the DB apply). Afterwards:
//   - every audited decision reached the projection exactly once
//     (ledger rows == events, per-tenant counts == audit_events),
//   - the topic holds more records than events, i.e. duplicates really were
//     delivered and the consumer absorbed them,
//   - the outbox drained.
func TestOutboxExactlyOnceUnderKills(t *testing.T) {
	dsn := env("PG_DSN", "postgres://gatekeeper:gatekeeper@localhost:5432/gatekeeper?sslmode=disable")
	brokers := env("KAFKA_BROKERS", "localhost:19092")
	n := 20000
	if os.Getenv("OUTBOX_EVENTS") != "" {
		fmt.Sscan(os.Getenv("OUTBOX_EVENTS"), &n)
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	bin := t.TempDir()
	for _, c := range []string{"gatekeeper", "gkrelay", "gkconsumer"} {
		if out, err := exec.Command("go", "build", "-o", filepath.Join(bin, c), "../cmd/"+c).CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v %s", c, err, out)
		}
	}
	run := time.Now().Format("150405")
	topic, group := "gatekeeper.audit.e2e-"+run, "stats-"+run
	tenants := []string{"t1-" + run, "t2-" + run, "t3-" + run, "t4-" + run}

	httpAddr := freeAddr(t)
	gk := exec.Command(filepath.Join(bin, "gatekeeper"), "-dev-issuer", "-outbox", "-pg-dsn", dsn,
		"-http", httpAddr, "-grpc", freeAddr(t), "-drain", "0s")
	if err := gk.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { gk.Process.Signal(syscall.SIGTERM); gk.Wait() }()
	base := "http://" + httpAddr
	waitHTTP(t, base+"/healthz", 30*time.Second)
	if _, err := pool.Exec(ctx, `DELETE FROM audit_outbox`); err != nil { // start from a drained outbox (test database)
		t.Fatal(err)
	}

	tokens := map[string]string{}
	for _, tn := range tenants {
		tokens[tn] = devToken(t, base, "tenant="+tn+"&scope="+url.QueryEscape("policy:check policy:write"))
		body, _ := json.Marshal(map[string]string{"rego": "package gatekeeper\nallow if input.action == \"read\""})
		if r := do(t, "PUT", base+"/v1/policies", tokens[tn], string(body)); r.code != 200 {
			t.Fatalf("put policy: %d %s", r.code, r.body)
		}
	}

	var skipped atomic.Int64 // lower bound: a batch killed before its log line is not counted
	relay := &proc{bin: filepath.Join(bin, "gkrelay"), exits: map[int]int{},
		args:       []string{"-pg-dsn", dsn, "-brokers", brokers, "-topic", topic},
		firstExtra: []string{"-fault-exit-after-publish", "3"}}
	consumer := &proc{bin: filepath.Join(bin, "gkconsumer"), exits: map[int]int{},
		args:       []string{"-pg-dsn", dsn, "-brokers", brokers, "-topic", topic, "-group", group, "-instance-id", "c1"},
		firstExtra: []string{"-fault-exit-after-apply", "3"},
		onStderr: func(line string) {
			var l struct{ Skipped int64 }
			if json.Unmarshal([]byte(line), &l) == nil {
				skipped.Add(l.Skipped)
			}
		}}
	supCtx, stopSup := context.WithCancel(ctx)
	var sup sync.WaitGroup
	sup.Add(2)
	go relay.supervise(supCtx, t, &sup)
	go consumer.supervise(supCtx, t, &sup)

	// Load: n Checks, half allowed (read) and half denied (write).
	start := time.Now()
	loadDone := make(chan struct{})
	var next atomic.Int64
	var lwg sync.WaitGroup
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
	for range 32 {
		lwg.Add(1)
		go func() {
			defer lwg.Done()
			for i := next.Add(1) - 1; i < int64(n); i = next.Add(1) - 1 {
				tn, action := tenants[i%4], []string{"read", "write"}[(i/4)%2]
				req, _ := http.NewRequest("POST", base+"/v1/check", strings.NewReader(`{"subject":{"id":"u"},"action":"`+action+`","resource":{"type":"doc"}}`))
				req.Header.Set("Authorization", "Bearer "+tokens[tn])
				resp, err := client.Do(req)
				if err != nil {
					t.Errorf("check: %v", err)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					t.Errorf("check: %d", resp.StatusCode)
					return
				}
			}
		}()
	}
	go func() { lwg.Wait(); close(loadDone) }()

	// Chaos while traffic flows.
	for chaos := true; chaos; {
		select {
		case <-loadDone:
			chaos = false
		case <-time.After(time.Duration(150+rand.IntN(350)) * time.Millisecond):
			[]*proc{relay, consumer}[rand.IntN(2)].kill()
		}
	}
	loadTime := time.Since(start)

	// Let the restarted pair drain everything.
	var processed, outboxLeft int
	deadline := time.Now().Add(120 * time.Second)
	for ; time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		pool.QueryRow(ctx, `SELECT count(*) FROM consumer_processed WHERE consumer=$1`, group).Scan(&processed)
		pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox WHERE tenant = ANY($1)`, tenants).Scan(&outboxLeft)
		if processed >= n && outboxLeft == 0 {
			break
		}
	}
	drainTime := time.Since(start)
	stopSup()
	relay.stop()
	consumer.stop()
	sup.Wait()

	// Ground truth is the audit log itself.
	type key struct {
		tenant  string
		allowed bool
	}
	truth, got := map[key]int64{}, map[key]int64{}
	rows, _ := pool.Query(ctx, `SELECT tenant, allowed, count(*) FROM audit_events WHERE tenant = ANY($1) GROUP BY 1, 2`, tenants)
	var audited int64
	for rows.Next() {
		var k key
		var c int64
		rows.Scan(&k.tenant, &k.allowed, &c)
		truth[k], audited = c, audited+c
	}
	rows, _ = pool.Query(ctx, `SELECT tenant, allowed, denied FROM decision_stats WHERE consumer=$1`, group)
	for rows.Next() {
		var tn string
		var a, d int64
		rows.Scan(&tn, &a, &d)
		got[key{tn, true}], got[key{tn, false}] = a, d
	}
	ends, err := kadm.NewClient(mustKafka(t, brokers)).ListEndOffsets(ctx, topic)
	if err != nil {
		t.Fatal(err)
	}
	var delivered int64
	ends.Each(func(o kadm.ListedOffset) { delivered += o.Offset })

	t.Logf("events=%d delivered_to_topic=%d duplicates_delivered=%d consumer_skipped>=%d relay: starts=%d kills=%d exits=%v consumer: starts=%d kills=%d exits=%v load=%s drained=%s",
		audited, delivered, delivered-audited, skipped.Load(), relay.starts, relay.kills, relay.exits,
		consumer.starts, consumer.kills, consumer.exits, loadTime.Round(time.Millisecond), drainTime.Round(time.Millisecond))

	if audited != int64(n) {
		t.Fatalf("audited %d events, want %d", audited, n)
	}
	if processed != n || outboxLeft != 0 {
		t.Fatalf("ledger has %d of %d events, %d left in outbox", processed, n, outboxLeft)
	}
	for k, want := range truth {
		if got[k] != want {
			t.Errorf("tenant %s allowed=%v: projection %d, audit log %d", k.tenant, k.allowed, got[k], want)
		}
	}
	if delivered <= audited || relay.exits[3] == 0 || consumer.exits[3] == 0 {
		t.Fatalf("expected duplicates from the injected crashes: delivered=%d exits relay=%v consumer=%v", delivered, relay.exits, consumer.exits)
	}
	if relay.kills == 0 || consumer.kills == 0 {
		t.Fatalf("chaos did not kill both processes: relay=%d consumer=%d", relay.kills, consumer.kills)
	}
}

func mustKafka(t *testing.T, brokers string) *kgo.Client {
	cl, err := kgo.NewClient(kgo.SeedBrokers(strings.Split(brokers, ",")...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cl.Close)
	return cl
}
