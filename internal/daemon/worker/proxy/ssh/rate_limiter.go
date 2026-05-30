// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"sync"
	"sync/atomic"

	boundaryErrors "github.com/hashicorp/boundary/internal/errors"
)

// SshRateLimitConfig configures rate limiting for SSH sessions.
type SshRateLimitConfig struct {
	// MaxConcurrentSessions is the global cap on concurrent SSH sessions.
	// Zero means unlimited.
	MaxConcurrentSessions int
	// MaxPerTarget is the cap on concurrent SSH sessions per target.
	// Zero means unlimited.
	MaxPerTarget int
}

// rateLimiter implements a global + per-target token-bucket rate limiter for SSH sessions.
type rateLimiter struct {
	maxGlobal int
	maxTarget int

	global atomic.Int32

	// perTarget maps targetId → active session count.
	// Key "_unidentified_" is used when target ID is not yet resolved.
	perTarget sync.Map
}

// newRateLimiter creates a rate limiter from the provided config.
// Returns nil if both limits are zero (rate limiting disabled).
func newRateLimiter(cfg *SshRateLimitConfig) *rateLimiter {
	if cfg == nil {
		return nil
	}
	if cfg.MaxConcurrentSessions == 0 && cfg.MaxPerTarget == 0 {
		return nil
	}
	return &rateLimiter{
		maxGlobal: cfg.MaxConcurrentSessions,
		maxTarget: cfg.MaxPerTarget,
	}
}

// Acquire attempts to reserve a rate limit slot for a session targeting targetId.
// Returns true if the slot was acquired; false if a limit is exceeded.
// The caller must call Release when the session ends.
func (r *rateLimiter) Acquire(ctx context.Context, targetId string) bool {
	// Check global limit.
	if r.maxGlobal > 0 {
		for {
			n := r.global.Load()
			if n >= int32(r.maxGlobal) {
				return false
			}
			if r.global.CompareAndSwap(n, n+1) {
				break
			}
			// CAS failed — another goroutine modified global. Retry.
		}
	}

	// Check per-target limit.
	if r.maxTarget > 0 {
		key := targetId
		if key == "" {
			key = "_unidentified_"
		}

		var targetCount atomic.Int32
		actual, _ := r.perTarget.LoadOrStore(key, &targetCount)

		for {
			n := actual.(*atomic.Int32).Load()
			if n >= int32(r.maxTarget) {
				// Per-target limit exceeded. Decrement global and return false.
				if r.maxGlobal > 0 {
					r.global.Add(-1)
				}
				return false
			}
			if actual.(*atomic.Int32).CompareAndSwap(n, n+1) {
				break
			}
		}
	}

	return true
}

// Release releases the slot acquired by Acquire for the given targetId.
// Safe to call even if Acquire returned false. Safe to call on nil limiter.
func (r *rateLimiter) Release(targetId string) {
	if r == nil {
		return
	}
	if r.maxGlobal > 0 {
		r.global.Add(-1)
	}
	if r.maxTarget > 0 {
		key := targetId
		if key == "" {
			key = "_unidentified_"
		}
		if actual, ok := r.perTarget.Load(key); ok {
			actual.(*atomic.Int32).Add(-1)
		}
	}
}

// Count returns the current global active session count.
// Safe to call on nil limiter.
func (r *rateLimiter) Count() int {
	if r == nil {
		return 0
	}
	return int(r.global.Load())
}

// CheckRateLimit returns an error if the rate limit would be exceeded for the given targetId.
// Unlike Acquire, this does not consume a slot — it is a read-only check.
func (r *rateLimiter) CheckRateLimit(targetId string) error {
	if r == nil {
		return nil
	}
	if r.maxGlobal > 0 && r.global.Load() >= int32(r.maxGlobal) {
		return boundaryErrors.New(context.Background(), boundaryErrors.RetryLimitExceeded, "ssh.checkRateLimit", "global concurrent session limit reached")
	}
	if r.maxTarget > 0 {
		key := targetId
		if key == "" {
			key = "_unidentified_"
		}
		if actual, ok := r.perTarget.Load(key); ok {
			if actual.(*atomic.Int32).Load() >= int32(r.maxTarget) {
				return boundaryErrors.New(context.Background(), boundaryErrors.RetryLimitExceeded, "ssh.checkRateLimit", "per-target concurrent session limit reached")
			}
		}
	}
	return nil
}