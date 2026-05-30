// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"sync"
	"testing"
)

func TestRateLimiter_NilConfigReturnsNil(t *testing.T) {
	rl := newRateLimiter(nil)
	if rl != nil {
		t.Fatal("expected nil rate limiter for nil config")
	}
}

func TestRateLimiter_ZeroLimitsReturnsNil(t *testing.T) {
	rl := newRateLimiter(&SshRateLimitConfig{})
	if rl != nil {
		t.Fatal("expected nil rate limiter when both limits are zero")
	}
}

func TestRateLimiter_GlobalCap(t *testing.T) {
	rl := newRateLimiter(&SshRateLimitConfig{MaxConcurrentSessions: 2})
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}

	if !rl.Acquire(context.Background(), "target1") {
		t.Fatal("first Acquire should succeed")
	}
	if !rl.Acquire(context.Background(), "target2") {
		t.Fatal("second Acquire should succeed")
	}

	if rl.Acquire(context.Background(), "target3") {
		t.Fatal("third Acquire should fail (global cap reached)")
	}

	if rl.Count() != 2 {
		t.Fatalf("expected Count=2, got %d", rl.Count())
	}

	rl.Release("target1")
	if rl.Count() != 1 {
		t.Fatalf("expected Count=1 after release, got %d", rl.Count())
	}

	if !rl.Acquire(context.Background(), "target4") {
		t.Fatal("Acquire after release should succeed")
	}
}

func TestRateLimiter_PerTargetCap(t *testing.T) {
	rl := newRateLimiter(&SshRateLimitConfig{MaxPerTarget: 2})
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}

	if !rl.Acquire(context.Background(), "t1") {
		t.Fatal("first Acquire on target t1 should succeed")
	}
	if !rl.Acquire(context.Background(), "t1") {
		t.Fatal("second Acquire on target t1 should succeed")
	}

	if rl.Acquire(context.Background(), "t1") {
		t.Fatal("third Acquire on target t1 should fail (per-target cap reached)")
	}

	if !rl.Acquire(context.Background(), "t2") {
		t.Fatal("Acquire on different target should succeed")
	}

	rl.Release("t1")
	if !rl.Acquire(context.Background(), "t1") {
		t.Fatal("Acquire on t1 after release should succeed")
	}
}

func TestRateLimiter_CrossTargetIsolation(t *testing.T) {
	rl := newRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 10,
		MaxPerTarget:          1,
	})
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}

	if !rl.Acquire(context.Background(), "targetA") {
		t.Fatal("Acquire on targetA should succeed")
	}
	if !rl.Acquire(context.Background(), "targetB") {
		t.Fatal("Acquire on targetB should succeed (different target)")
	}

	if rl.Acquire(context.Background(), "targetA") {
		t.Fatal("Acquire on targetA again should fail (per-target cap reached)")
	}

	if rl.Count() != 2 {
		t.Fatalf("expected Count=2 (two different targets), got %d", rl.Count())
	}
}

func TestRateLimiter_ConcurrentSafety(t *testing.T) {
	rl := newRateLimiter(&SshRateLimitConfig{MaxConcurrentSessions: 5})
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}

	const goroutines = 20
	var wg sync.WaitGroup
	acquired := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := rl.Acquire(context.Background(), "shared-target")
			acquired <- ok
		}()
	}

	wg.Wait()
	close(acquired)

	successCount := 0
	for ok := range acquired {
		if ok {
			successCount++
		}
	}

	if successCount != 5 {
		t.Fatalf("expected exactly 5 successful acquisitions (global cap), got %d", successCount)
	}

	if rl.Count() != 5 {
		t.Fatalf("expected Count=5 after concurrent acquisitions, got %d", rl.Count())
	}

	for i := 0; i < 5; i++ {
		rl.Release("shared-target")
	}
	if rl.Count() != 0 {
		t.Fatalf("expected Count=0 after releasing all, got %d", rl.Count())
	}
}

func TestRateLimiter_ReleaseSafetyOnNil(t *testing.T) {
	var rl *rateLimiter
	rl.Release("target1")
	rl.Release("")
}

func TestRateLimiter_ReleaseEmptyTarget(t *testing.T) {
	rl := newRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 2,
		MaxPerTarget:          2,
	})
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}

	if !rl.Acquire(context.Background(), "") {
		t.Fatal("Acquire with empty target ID should succeed")
	}
	if !rl.Acquire(context.Background(), "") {
		t.Fatal("second Acquire with empty target ID should succeed")
	}

	rl.Release("")
	rl.Release("")

	if rl.Count() != 0 {
		t.Fatalf("expected Count=0 after releases, got %d", rl.Count())
	}
}

func TestRateLimiter_CheckRateLimit(t *testing.T) {
	rl := newRateLimiter(&SshRateLimitConfig{
		MaxConcurrentSessions: 1,
		MaxPerTarget:          1,
	})
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}

	if err := rl.CheckRateLimit("target1"); err != nil {
		t.Fatalf("CheckRateLimit before acquire should succeed: %v", err)
	}

	if !rl.Acquire(context.Background(), "target1") {
		t.Fatal("Acquire should succeed")
	}

	if err := rl.CheckRateLimit("target1"); err == nil {
		t.Fatal("CheckRateLimit after cap reached should return error")
	}

	if err := rl.CheckRateLimit("target2"); err == nil {
		t.Fatal("CheckRateLimit for different target should return error (global cap reached)")
	}

	rl.Release("target1")

	if err := rl.CheckRateLimit("target1"); err != nil {
		t.Fatalf("CheckRateLimit after release should succeed: %v", err)
	}
}

func TestRateLimiter_NilCheckRateLimit(t *testing.T) {
	var rl *rateLimiter
	if err := rl.CheckRateLimit("target1"); err != nil {
		t.Fatalf("nil CheckRateLimit should return nil: %v", err)
	}
}

func TestRateLimiter_NilCount(t *testing.T) {
	var rl *rateLimiter
	if c := rl.Count(); c != 0 {
		t.Fatalf("nil Count should return 0, got %d", c)
	}
}
