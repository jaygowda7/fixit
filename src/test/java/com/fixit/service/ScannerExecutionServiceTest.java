
package com.fixit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fixit.model.CommandExecutionResult;
import com.fixit.model.ExecutionStatus;
import com.fixit.model.ScannerType;
import com.fixit.scanner.ScannerCommandRunner;

class ScannerExecutionServiceTest {

    @Test
    void shouldReturnResultFromCommandRunner() {

        CommandExecutionResult expectedResult =
                new CommandExecutionResult();

        expectedResult.setScanner(ScannerType.SNYK);
        expectedResult.setStatus(ExecutionStatus.SUCCESS);
        expectedResult.setExitCode(0);
        expectedResult.setStandardOutput("Snyk report generated");
        expectedResult.setErrorOutput("");
        expectedResult.setDurationMillis(250);

        ScannerCommandRunner fakeRunner = new ScannerCommandRunner() {
            @Override
            public CommandExecutionResult run(
                    ScannerType scanner,
                    List<String> command,
                    Path workingDirectory,
                    long timeoutSeconds) {

                assertEquals(ScannerType.SNYK, scanner);
                assertEquals(List.of("snyk", "test"), command);
                assertEquals(Path.of(".").toAbsolutePath().normalize(),
                        workingDirectory);
                assertEquals(30, timeoutSeconds);

                return expectedResult;
            }
        };

        ScannerExecutionService service =
                new ScannerExecutionService(fakeRunner);

        CommandExecutionResult actualResult = service.execute(
                ScannerType.SNYK,
                List.of("snyk", "test"),
                Path.of(".").toAbsolutePath().normalize(),
                30
        );

        assertSame(expectedResult, actualResult);
        assertEquals(ExecutionStatus.SUCCESS, actualResult.getStatus());
        assertEquals(0, actualResult.getExitCode());
    }
}
