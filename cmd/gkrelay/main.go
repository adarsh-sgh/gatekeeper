// Command gkrelay publishes gatekeeper's audit outbox to Kafka.
//
//	gkrelay -pg-dsn postgres://... -brokers localhost:19092 -topic gatekeeper.audit
//
// Run several for availability: one holds the leader lock, the rest stand by.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/adarsh-sgh/gatekeeper/internal/outbox"
)

func main() {
	dsn := flag.String("pg-dsn", os.Getenv("PG_DSN"), "Postgres DSN of the gatekeeper store")
	brokers := flag.String("brokers", "localhost:19092", "comma-separated Kafka seed brokers")
	topic := flag.String("topic", "gatekeeper.audit", "topic; created with -partitions if missing")
	partitions := flag.Int("partitions", 3, "partitions when creating the topic")
	batch := flag.Int("batch", 500, "max outbox rows per produce")
	poll := flag.Duration("poll", 20*time.Millisecond, "idle poll interval")
	faultAfter := flag.Int("fault-exit-after-publish", 0, "fault injection: exit(3) after the Nth acked batch, before deleting its rows")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Idempotent producer (franz-go default) with acks=all: broker retries
	// within a session do not duplicate; only relay crashes can.
	cl, err := kgo.NewClient(kgo.SeedBrokers(strings.Split(*brokers, ",")...), kgo.RequiredAcks(kgo.AllISRAcks()))
	if err != nil {
		log.Error("kafka", "err", err)
		os.Exit(1)
	}
	defer cl.Close()
	if _, err := kadm.NewClient(cl).CreateTopic(ctx, int32(*partitions), -1, nil, *topic); err != nil && !errors.Is(err, kerr.TopicAlreadyExists) {
		log.Error("create topic", "err", err)
		os.Exit(1)
	}

	published, batches := 0, 0
	r := &outbox.Relay{DSN: *dsn, Kafka: cl, Topic: *topic, Batch: *batch, Poll: *poll, Log: log,
		AfterPublish: func(n int) {
			published, batches = published+n, batches+1
			if *faultAfter > 0 && batches == *faultAfter {
				log.Warn("fault injection: exiting between publish and delete", "batch_rows", n)
				os.Exit(3)
			}
		}}
	r.Run(ctx)
	log.Info("relay stopped", "published", published, "batches", batches)
}
