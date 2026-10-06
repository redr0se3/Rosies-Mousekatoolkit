// Package pool implements the fixed-size worker pool and the per-host
// rate limiter described in the spec's Architecture section.
//
// Two distinct concerns live here, and the spec is explicit that they
// must not multiply against each other:
//
//  1. Pool: a fixed number of goroutines draining a buffered job channel.
//     This bounds total parallelism so the orchestrator itself can't fork
//     an unbounded number of goroutines when five wordlists and a dozen
//     vhosts are all queued at once.
//  2. HostLimiter: a per-host semaphore sized from the scope file's
//     max_concurrent_requests. Even if the pool has 50 workers free, no
//     more than N of them may have an in-flight request against the same
//     host at once. Tool invocations (feroxbuster, whatweb) are also
//     launched with flags derived from this same number, so the
//     orchestrator's concurrency and the tool's own internal concurrency
//     don't compound into 50x the configured rate.
package pool

import (
	"context"
	"sync"
)

// Pool is a fixed-size worker pool draining a buffered job channel.
type Pool struct {
	jobs    chan func()
	wg      sync.WaitGroup
	workers int
}

// New starts a pool with `workers` goroutines. Buffer size is generous
// (4x workers) so Submit rarely blocks the orchestrator's own goroutine,
// but Submit still blocks rather than growing unbounded — backpressure is
// the point.
func New(workers int) *Pool {
	if workers <= 0 {
		workers = 1
	}
	p := &Pool{
		jobs:    make(chan func(), workers*4),
		workers: workers,
	}
	for i := 0; i < workers; i++ {
		go p.worker()
	}
	return p
}

func (p *Pool) worker() {
	for job := range p.jobs {
		job()
		p.wg.Done()
	}
}

// Submit enqueues a job. Blocks if the buffer is full (backpressure by
// design — see package doc).
func (p *Pool) Submit(job func()) {
	p.wg.Add(1)
	p.jobs <- job
}

// Wait blocks until every submitted job has completed. It does not close
// the pool — callers may continue submitting more jobs afterward (e.g.
// the JS-harvesting feedback loop queuing newly discovered endpoints back
// into directory brute-forcing).
func (p *Pool) Wait() {
	p.wg.Wait()
}

// Close shuts the pool down. Call only after the final Wait().
func (p *Pool) Close() {
	close(p.jobs)
}

// HostLimiter enforces max_concurrent_requests per host, independent of
// how many pool workers are free. Safe for concurrent use; semaphores are
// created lazily per host.
type HostLimiter struct {
	max int

	mu   sync.Mutex
	sems map[string]chan struct{}
}

func NewHostLimiter(maxConcurrentPerHost int) *HostLimiter {
	if maxConcurrentPerHost <= 0 {
		maxConcurrentPerHost = 1
	}
	return &HostLimiter{max: maxConcurrentPerHost, sems: make(map[string]chan struct{})}
}

func (h *HostLimiter) semFor(host string) chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	sem, ok := h.sems[host]
	if !ok {
		sem = make(chan struct{}, h.max)
		h.sems[host] = sem
	}
	return sem
}

// Acquire blocks until a slot for host is free or ctx is cancelled.
func (h *HostLimiter) Acquire(ctx context.Context, host string) error {
	sem := h.semFor(host)
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees a slot for host. Must be paired with a successful Acquire.
func (h *HostLimiter) Release(host string) {
	sem := h.semFor(host)
	select {
	case <-sem:
	default:
	}
}

// MaxPerHost exposes the configured limit, e.g. so a module can pass the
// same number as a concurrency flag to an external tool (feroxbuster
// -t/--threads, etc.) instead of letting the tool default to something
// higher.
func (h *HostLimiter) MaxPerHost() int { return h.max }
