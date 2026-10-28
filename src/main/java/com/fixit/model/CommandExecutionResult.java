
package com.fixit.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CommandExecutionResult {

    private ScannerType scanner;
    private ExecutionStatus status;
    private Integer exitCode;
    private String standardOutput;
    private String errorOutput;
    private long durationMillis;
}
