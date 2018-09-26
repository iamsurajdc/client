// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package kbconst

// RunMode is an enum type for the mode the Keybase app runs in.
type RunMode string

const (
	// DevelRunMode means use devel servers.
	DevelRunMode RunMode = "devel"
	// StagingRunMode means use staging servers.
	StagingRunMode RunMode = "staging"
	// ProductionRunMode means use prod servers (default for
	// released apps).
	ProductionRunMode RunMode = "prod"
	// RunModeError means an error was encountered.
	RunModeError RunMode = "error"
	// NoRunMode is the nil value for RunMode.
	NoRunMode RunMode = ""
)

// KBFSLogFileName is the name of the log file for KBFS.
const KBFSLogFileName = "keybase.kbfs.log"

const defaultMaxFrameLength = 50 * 1024 * 1024

// All the frame length constants are here since multiple places need
// to agree on the same value. For now, set it to a reasonably high
// default value, but depending on the service the max frame length
// can be much smaller.
//
// If you're changing the constants below, you likely want to change
// constants on the server side, too (except for
// MaxServiceFrameLength).

// MaxGregorFrameLength is the maximum frame length that gregor
// accepts.
const MaxGregorFrameLength = defaultMaxFrameLength

// MaxProvisionFrameLength is the maximum frame length that the
// provisioning message router accepts.
const MaxProvisionFrameLength = defaultMaxFrameLength

// MaxServiceFrameLength is the maximum frame length for communicating
// with the local service.
const MaxServiceFrameLength = defaultMaxFrameLength
