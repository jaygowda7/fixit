
package com.fixit.service;

import java.nio.file.Path;
import java.util.List;

import com.fixit.model.CommandExecutionResult;
import com.fixit.model.ScannerType;
import com.fixit.scanner.ScannerCommandRunner;

public class ScannerExecutionService {

    private final ScannerCommandRunner scannerCommandRunner;

    public ScannerExecutionService(
            ScannerCommandRunner scannerCommandRunner) {

        if (scannerCommandRunner == null) {
            throw new IllegalArgumentException(
                    "Scanner command runner cannot be null"
            );
        }

        this.scannerCommandRunner = scannerCommandRunner;
    }

    public CommandExecutionResult execute(
            ScannerType scanner,
            List<String> command,
            Path workingDirectory,
            long timeoutSeconds) {

        return scannerCommandRunner.run(
                scanner,
                command,
                workingDirectory,
                timeoutSeconds
        );
    }
}
