package providers

import (
	"sync"
	"time"
)

type breaker struct {
	mu        sync.Mutex
	failures  int
	threshold int
	openUntil time.Time
	openFor   time.Duration
}

func newBreaker(threshold int, openFor time.Duration) *breaker {
	return &breaker{
		threshold: threshold,
		openFor:   openFor,
	}
}

func (b *breaker) Allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.After(now) {
		return false
	}
	return true
}

func (b *breaker) Success() {
	b.mu.Lock()
	b.failures = 0
	b.mu.Unlock()
}

func (b *breaker) Failure(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	if b.threshold > 0 && b.failures >= b.threshold {
		if b.openFor > 0 {
			b.openUntil = now.Add(b.openFor)
		}
		b.failures = 0
	}
}
