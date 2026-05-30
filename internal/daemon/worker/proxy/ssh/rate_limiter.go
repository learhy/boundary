// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SshRateLimitConfig contains rate limiting settings for SSH session recording.
// When both fields are 0, rate limiting is disabled.
type SshRateLimitConfig struct {
	// MaxConcurrentSessions is the maximum number of concurrent SSH sessions
	// allowed globally across all targets. A value of 0 means unlimited.
	MaxConcurrentSessions int
	// MaxPerTarget is the maximum number of concurrent SSH sessions allowed
	// per unique target endpoint host. A value of 0 means unlimited.
	MaxPerTarget int
}

// ErrRateLimited is returned by Acquire when the rate limit has been exceeded.
// Callers should retry with backoff until context deadline or session expiry.
var ErrRateLimited = errors.New("ssh rate limit exceeded")

// tokenBucket implements a simple token-bucket rate limiter with atomic operations.
type tokenBucket struct {
	limit    int32
	tokens   atomic.Int32
	lastTime atomic.Int64 // unix nano
}

// newTokenBucket creates a bucket with the given limit and starts it full.
func newTokenBucket(limit int) *tokenBucket {
	b := &tokenBucket{
		limit: int32(limit),
	}
	b.tokens.Store(int32(limit))
	b.lastTime.Store(time.Now().UnixNano())
	return b
}

// tryAcquire attempts to consume one token from the bucket.
// Returns true if the token was acquired; false if the bucket is empty.
func (b *tokenBucket) tryAcquire() bool {
	// Refill based on elapsed time
	now := time.Now().UnixNano()
	last := b.lastTime.Load()
	elapsed := now - last
	if elapsed > 0 {
		refill := int32(elapsed / int64(time.Second)) // 1 token per second
		if refill > 0 {
			b.lastTime.Store(now)
			newTokens := b.tokens.Add(refill)
			if newTokens > int32(b.limit) {
				b.tokens.Store(int32(b.limit))
			}
		}
	}

	// Try to acquire one token
	for {
		current := b.tokens.Load()
		if current <= 0 {
			return false
		}
		if b.tokens.CompareAndSwap(current, current-1) {
			return true
		}
		// CAS failed, retry
	}
}

// release returns one token to the bucket.
func (b *tokenBucket) release() {
	current := b.tokens.Load()
	if current < int32(b.limit) {
		b.tokens.Add(1)
	}
}

// count returns the current number of tokens in the bucket (approximate).
func (b *tokenBucket) count() int {
	return int(b.tokens.Load())
}

// SshRateLimiter manages token-bucket rate limiting for SSH sessions.
type SshRateLimiter struct {
	cfg    *SshRateLimitConfig
	global atomic.Int32

	// per-target buckets
	targetsMu sync.Mutex
	targets   sync.Map // map[string]*tokenBucket

	// allowZero is true when both limits are 0 (rate limiting disabled)
	allowZero bool
}

// NewSshRateLimiter creates a new rate limiter from the given config.
// If cfg is nil or both limits are 0, the rate limiter operates in pass-through mode.
func NewSshRateLimiter(cfg *SshRateLimitConfig) *SshRateLimiter {
	allowZero := cfg == nil || (cfg.MaxConcurrentSessions == 0 && cfg.MaxPerTarget == 0)
	return &SshRateLimiter{
		cfg:       cfg,
		allowZero: allowZero,
	}
}

// Acquire attempts to acquire one token for the given target endpoint.
// Returns nil on success. Returns ErrRateLimited if the limit has been exceeded.
// The caller should retry on ErrRateLimited with exponential backoff.
func (l *SshRateLimiter) Acquire(ctx context.Context, target string) error {
	if l.allowZero {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	targetHost := extractHost(target)

	// Check global limit
	if l.cfg.MaxConcurrentSessions > 0 {
		newVal := l.global.Add(1)
		if int(newVal) > l.cfg.MaxConcurrentSessions {
			l.global.Add(-1)
			return ErrRateLimited
		}
	} else {
		// Global limit is unlimited; still increment for tracking
		l.global.Add(1)
	}

	// Check per-target limit
	acquired := false
	if l.cfg.MaxPerTarget > 0 {
		b := l.getOrCreateBucket(targetHost)
		if !b.tryAcquire() {
			l.global.Add(-1)
			return ErrRateLimited
		}
		acquired = true
	}

	// Success
	return nil
}

// Release returns one token to the global and per-target buckets.
// Safe to call even if Acquire returned an error.
func (l *SshRateLimiter) Release(target string) {
	if l.allowZero {
		return
	}

	targetHost := extractHost(target)

	// Release from per-target bucket
	if l.cfg.MaxPerTarget > 0 {
		if b, ok := l.targets.Load(targetHost); ok {
			b.(*tokenBucket).release()
		}
	}

	// Release from global
	l.global.Add(-1)
}

// CheckRateLimit returns whether acquiring for the given target is currently allowed,
// along with the current and limit values (approximate). This does not modify state.
func (l *SshRateLimiter) CheckRateLimit(target string) (allowed bool, current int, limit int) {
	if l.allowZero {
		return true, 0, 0
	}

	targetHost := extractHost(target)

	// Global check
	currentGlobal := int(l.global.Load())
	limitGlobal := l.cfg.MaxConcurrentSessions
	if limitGlobal == 0 {
		limitGlobal = -1 // unlimited
	}

	if l.cfg.MaxConcurrentSessions > 0 && currentGlobal >= l.cfg.MaxConcurrentSessions {
		return false, currentGlobal, limitGlobal
	}

	// Per-target check
	if l.cfg.MaxPerTarget > 0 {
		if b, ok := l.targets.Load(targetHost); ok {
			current = b.(*tokenBucket).count()
		} else {
			current = l.cfg.MaxPerTarget // empty bucket = current is at limit (new bucket starts full)
		}
		limit = l.cfg.MaxPerTarget
		if current <= 0 {
			return false, current, limit
		}
	}

	return true, currentGlobal, limitGlobal
}

// getOrCreateBucket returns the token bucket for the given target host,
// creating one if it doesn't exist.
func (l *SshRateLimiter) getOrCreateBucket(targetHost string) *tokenBucket {
	if b, ok := l.targets.Load(targetHost); ok {
		return b.(*tokenBucket)
	}
	l.targetsMu.Lock()
	defer l.targetsMu.Unlock()
	if b, ok := l.targets.Load(targetHost); ok {
		return b.(*tokenBucket)
	}
	b := newTokenBucket(l.cfg.MaxPerTarget)
	l.targets.Store(targetHost, b)
	return b
}

// extractHost extracts the host:port from a target endpoint string.
// Handles ssh://host:port, host:port, and bare host formats.
func extractHost(target string) string {
	// Remove scheme if present
	if idx := strings.Index(target, "://"); idx != -1 {
		target = target[idx+3:]
	}
	// Remove port if present
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	return host
}

// String returns a human-readable description of the rate limiter state.
func (l *SshRateLimiter) String() string {
	if l.allowZero {
		return "rate_limiter(disabled)"
	}
	return fmt.Sprintf("rate_limiter(global=%d/%d, per_target=%d)",
		l.global.Load(), l.cfg.MaxConcurrentSessions, l.cfg.MaxPerTarget)
}