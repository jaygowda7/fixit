package com.fixit.model;

public enum ScannerExecutionOutcome {
	COMPLETED,
    COMPLETED_WITH_FINDINGS,
    PARTIALLY_COMPLETED,
    FAILED,
    TIMED_OUT,
    INTERRUPTED
}
