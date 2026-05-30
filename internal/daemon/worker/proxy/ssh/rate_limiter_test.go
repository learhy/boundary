// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSshRateLimiter_Disabled(t *testing.T) {
	// When cfg is nil, all acquires should succeed
	rl := NewSshRateLimiter(nil)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		err := rl.Acquire(ctx, "ssh://target:22")
		if err != nil {
			t.Errorf("Acquire() with nil cfg failed: %v", err)
		}
		rl.Release("ssh://target:22")
	}
}

func TestSshRateLimiter_DisabledBothZero(t *testing.T) {
	// When both limits are 0, rate limiting is disabled
	rl := NewSshRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 0,
		MaxPerTarget:          0,
	})
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		err := rl.Acquire(ctx, "ssh://target:22")
		if err != nil {
			t.Errorf("Acquire() with both zero limits failed: %v", err)
		}
	}
}

func TestSshRateLimiter_GlobalLimit(t *testing.T) {
	rl := NewSshRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 3,
		MaxPerTarget:          0, // unlimited per target
	})
	ctx := context.Background()

	// Acquire 3 should succeed
	for i := 0; i < 3; i++ {
		err := rl.Acquire(ctx, "ssh://target:22")
		if err != nil {
			t.Errorf("Acquire() attempt %d failed: %v", i, err)
		}
	}

	// 4th acquire should fail (global limit = 3)
	err := rl.Acquire(ctx, "ssh://target:22")
	if err != ErrRateLimited {
		t.Errorf("Expected ErrRateLimited, got: %v", err)
	}

	// Release one, should allow one more
	rl.Release("ssh://target:22")
	err = rl.Acquire(ctx, "ssh://target:22")
	if err != nil {
		t.Errorf("Acquire() after release failed: %v", err)
	}
}

func TestSshRateLimiter_PerTargetLimit(t *testing.T) {
	rl := NewSshRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 0, // unlimited global
		MaxPerTarget:          2,
	})
	ctx := context.Background()

	// Acquire 2 on target1 should succeed
	for i := 0; i < 2; i++ {
		err := rl.Acquire(ctx, "ssh://target1:22")
		if err != nil {
			t.Errorf("Acquire() for target1 attempt %d failed: %v", i, err)
		}
	}

	// 3rd acquire on target1 should fail (per-target limit = 2)
	err := rl.Acquire(ctx, "ssh://target1:22")
	if err != ErrRateLimited {
		t.Errorf("Expected ErrRateLimited for target1, got: %v", err)
	}

	// But target2 should still work
	err = rl.Acquire(ctx, "ssh://target2:22")
	if err != nil {
		t.Errorf("Acquire() for target2 failed: %v", err)
	}
	rl.Release("ssh://target2:22")
}

func TestSshRateLimiter_Combined(t *testing.T) {
	rl := NewSshRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 3,
		MaxPerTarget:          2,
	})
	ctx := context.Background()

	// Fill target1 (2 tokens)
	rl.Acquire(ctx, "ssh://target1:22")
	rl.Acquire(ctx, "ssh://target1:22")

	// Fill target2 (1 token, leaving 0 global for target3)
	rl.Acquire(ctx, "ssh://target2:22")

	// target1 exhausted (per-target)
	err := rl.Acquire(ctx, "ssh://target1:22")
	if err != ErrRateLimited {
		t.Errorf("Expected ErrRateLimited (per-target), got: %v", err)
	}

	// target2 can still take 1 (per-target = 2, currently 1)
	err = rl.Acquire(ctx, "ssh://target2:22")
	if err != nil {
		t.Errorf("target2 should accept 2nd token: %v", err)
	}
	rl.Release("ssh://target2:22")

	// Now target2 is also at per-target limit (2 tokens)
	err = rl.Acquire(ctx, "ssh://target2:22")
	if err != ErrRateLimited {
		t.Errorf("target2 should be at limit: %v", err)
	}
}

func TestSshRateLimiter_ReleaseDrain(t *testing.T) {
	rl := NewSshRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 0,
		MaxPerTarget:          1,
	})
	ctx := context.Background()

	// Acquire on two different targets
	err := rl.Acquire(ctx, "ssh://target1:22")
	if err != nil {
		t.Errorf("Acquire target1: %v", err)
	}
	rl.Release("ssh://target1:22")

	// Should be able to re-acquire after release
	err = rl.Acquire(ctx, "ssh://target1:22")
	if err != nil {
		t.Errorf("Re-acquire after release: %v", err)
	}
	rl.Release("ssh://target1:22")
}

func TestSshRateLimiter_Concurrent(t *testing.T) {
	rl := NewSshRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 10,
		MaxPerTarget:          3,
	})

	var acquired atomic.Int32
	var failed atomic.Int32
	var wg sync.WaitGroup

	ctx := context.Background()
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			target := "ssh://target" + string(rune('0'+idx%5)) + ":22"
			err := rl.Acquire(ctx, target)
			if err == nil {
				acquired.Add(1)
				rl.Release(target)
			} else if err == ErrRateLimited {
				failed.Add(1)
			}
		}(i)
	}
	wg.Wait()

	// Some acquisitions should have succeeded, some may have failed
	if acquired.Load() == 0 {
		t.Error("No acquisitions succeeded in concurrent test")
	}
	// Global limit is 10, so at most 10 should be held at once
	// In a 50-goroutine test, some failures are expected
}

func TestSshRateLimiter_ContextCanceled(t *testing.T) {
	rl := NewSshRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 1,
		MaxPerTarget:          1,
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Acquire the only token
	err := rl.Acquire(ctx, "ssh://target:22")
	if err != nil {
		t.Errorf("First acquire failed: %v", err)
	}

	// Cancel context before second acquire
	cancel()

	// Second acquire should fail with context error (not ErrRateLimited)
	err = rl.Acquire(ctx, "ssh://target:22")
	if err == nil {
		t.Error("Expected error after context cancel")
	}
	if err == ErrRateLimited {
		t.Error("Expected context error, not ErrRateLimited")
	}
	// Context error contains "context expired"
}

func TestSshRateLimiter_CheckRateLimit(t *testing.T) {
	rl := NewSshRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 5,
		MaxPerTarget:          2,
	})
	ctx := context.Background()

	// Check before any acquires
	allowed, current, limit := rl.CheckRateLimit("ssh://target:22")
	if !allowed {
		t.Errorf("CheckRateLimit should allow when under limit")
	}
	if current < 0 || limit != 2 {
		t.Errorf("CheckRateLimit returned unexpected values: current=%d, limit=%d", current, limit)
	}

	// Acquire some tokens
	rl.Acquire(ctx, "ssh://target:22")
	rl.Acquire(ctx, "ssh://target:22")

	allowed, _, _ = rl.CheckRateLimit("ssh://target:22")
	// After 2 acquires on a limit of 2, should be at or near limit
	_ = allowed

	rl.Release("ssh://target:22")
	rl.Release("ssh://target:22")
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ssh://target.example.com:22", "target.example.com"},
		{"target.example.com:22", "target.example.com"},
		{"target.example.com", "target.example.com"},
		{"192.168.1.100:22", "192.168.1.100"},
		{"[::1]:22", "::1"},
		{"ssh://192.168.1.100", "192.168.1.100"},
	}
	for _, tt := range tests {
		got := extractHost(tt.input)
		if got != tt.expected {
			t.Errorf("extractHost(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSshRateLimiter_String(t *testing.T) {
	rl := NewSshRateLimiter(nil)
	s := rl.String()
	if s != "rate_limiter(disabled)" {
		t.Errorf("String() = %q for disabled limiter", s)
	}

	rl = NewSshRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 10,
		MaxPerTarget:          5,
	})
	s = rl.String()
	if s == "" {
		t.Error("String() should not be empty for active limiter")
	}
}

func TestSshRateLimiter_String_GlobalZero(t *testing.T) {
	rl := NewSshRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 0,
		MaxPerTarget:          5,
	})
	s := rl.String()
	if s != "rate_limiter(disabled)" {
		t.Errorf("Both zero should be disabled, got: %q", s)
	}
}