// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package ssh implements the SSH proxy handler for Boundary session recording.
// It provides Bidirectional Session Recording (BSR) for SSH connections,
// intercepting and recording SSH wire messages as BSR chunks while proxying
// the connection between client and target.
//
// # SSH Credential Injection Recording Flow
//
// For SSH targets with credential injection:
//
//  1. Worker receives a client SSH connection
//  2. Worker terminates the SSH handshake with the client using session credentials
//     (injected certificate + private key from the session)
//  3. Worker re-establishes SSH with the target using the same credentials
//  4. Bidirectional data is recorded as BSR DataChunks
//
// The recording uses the BSR SSH protocol to encode SSH wire messages,
// enabling playback of the session later.
package ssh