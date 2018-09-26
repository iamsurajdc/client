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

// MaxGregorFrameLength is the maximum frame length that gregor
// accepts.
const MaxGregorFrameLength = defaultMaxFrameLength

// MaxProvisionFrameLength is the maximum frame length for
// provisioning.
const MaxProvisionFrameLength = defaultMaxFrameLength

// MaxServiceFrameLength is the maximum frame length for communicating
// with the service.
const MaxServiceFrameLength = defaultMaxFrameLength
