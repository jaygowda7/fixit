
package com.fixit.model;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ScannerExecutionSummary {

    private ScannerType scanner;
    private ScannerExecutionOutcome outcome;
    private CommandExecutionResult executionResult;
    private List<Finding> findings;
    private int skippedFindingsCount;
    private String message;
}
