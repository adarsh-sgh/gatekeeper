// Command gkconsumer applies the audit topic to a Postgres projection
// (per-tenant allow/deny counts), deduplicating by event id.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/adarsh-sgh/gatekeeper/internal/outbox"
)

func main() {
	dsn := flag.String("pg-dsn", os.Getenv("PG_DSN"), "Postgres DSN for the projection and dedup ledger")
	brokers := flag.String("brokers", "localhost:19092", "comma-separated Kafka seed brokers")
	topic := flag.String("topic", "gatekeeper.audit", "topic")
	group := flag.String("group", "audit-stats", "consumer group; also the ledger namespace")
	instance := flag.String("instance-id", "", "static group membership id: a restarted instance reclaims its partitions without waiting out the session timeout")
	faultAfter := flag.Int("fault-exit-after-apply", 0, "fault injection: exit(3) after the Nth applied batch, before committing offsets")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		log.Error("postgres", "err", err)
		os.Exit(1)
	}
	defer pool.Close()
	opts := []kgo.Opt{kgo.SeedBrokers(strings.Split(*brokers, ",")...), kgo.ConsumerGroup(*group),
		kgo.ConsumeTopics(*topic), kgo.DisableAutoCommit(), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.SessionTimeout(6 * time.Second)}
	if *instance != "" {
		opts = append(opts, kgo.InstanceID(*instance))
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		log.Error("kafka", "err", err)
		os.Exit(1)
	}
	defer cl.Close()

	batches := 0
	c := &outbox.Consumer{Pool: pool, Kafka: cl, Name: *group, Log: log, AfterApply: func(applied, skipped int) {
		if batches++; *faultAfter > 0 && batches == *faultAfter {
			log.Warn("fault injection: exiting between apply and offset commit", "applied", applied, "skipped", skipped)
			os.Exit(3)
		}
	}}
	if err := c.Run(ctx); err != nil {
		log.Error("consumer", "err", err)
		os.Exit(1)
	}
}
