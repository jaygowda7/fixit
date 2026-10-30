
package com.fixit.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fixit.model.CommandExecutionResult;
import com.fixit.model.ExecutionStatus;
import com.fixit.model.ScannerType;

class ScannerCommandRunnerTest {

    private ScannerCommandRunner scannerCommandRunner;
    private Path workingDirectory;

    @BeforeEach
    void setUp() {
        scannerCommandRunner = new ScannerCommandRunner();
        workingDirectory = Path.of(".").toAbsolutePath().normalize();
    }

    @Test
    void shouldCaptureSuccessfulCommandOutput() {

        CommandExecutionResult result = scannerCommandRunner.run(
                ScannerType.SEMGREP,
                List.of("bash", "-c", "echo FIXIT_TEST_SUCCESS"),
                workingDirectory,
                10
        );

        printResult("SUCCESSFUL COMMAND TEST", result);

        assertEquals(ExecutionStatus.SUCCESS, result.getStatus());
        assertEquals(0, result.getExitCode());
        assertTrue(
                result.getStandardOutput().contains("FIXIT_TEST_SUCCESS")
        );
        assertEquals("", result.getErrorOutput());
        assertTrue(result.getDurationMillis() >= 0);
    }

    @Test
    void shouldCaptureFailureWhenCommandReturnsNonZero() {

        CommandExecutionResult result = scannerCommandRunner.run(
                ScannerType.SEMGREP,
                List.of("bash", "-c", "echo FIXIT_TEST_ERROR >&2; exit 2"),
                workingDirectory,
                10
        );

        printResult("FAILED COMMAND TEST", result);

        assertEquals(ExecutionStatus.FAILED, result.getStatus());
        assertEquals(2, result.getExitCode());
        assertEquals("", result.getStandardOutput());
        assertTrue(
                result.getErrorOutput().contains("FIXIT_TEST_ERROR")
        );
        assertTrue(result.getDurationMillis() >= 0);
    }

    @Test
    void shouldMarkCommandAsTimedOut() {

        CommandExecutionResult result = scannerCommandRunner.run(
                ScannerType.SEMGREP,
                List.of("bash", "-c", "sleep 5"),
                workingDirectory,
                1
        );

        printResult("TIMEOUT TEST", result);

        assertEquals(ExecutionStatus.TIMED_OUT, result.getStatus());
        assertEquals(null, result.getExitCode());
        assertTrue(
                result.getErrorOutput().contains("exceeded timeout")
        );
        assertTrue(result.getDurationMillis() >= 1000);
    }

    @Test
    void shouldRejectEmptyCommand() {

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> scannerCommandRunner.run(
                        ScannerType.SEMGREP,
                        List.of(),
                        workingDirectory,
                        10
                )
        );

        System.out.println(
                "Empty command validation: " + exception.getMessage()
        );

        assertEquals(
                "Command cannot be null or empty",
                exception.getMessage()
        );
    }

    private void printResult(
            String testName,
            CommandExecutionResult result) {

        System.out.println("\n========== " + testName + " ==========");
        System.out.println("Scanner: " + result.getScanner());
        System.out.println("Status: " + result.getStatus());
        System.out.println("Exit code: " + result.getExitCode());
        System.out.println("Standard output: "
                + result.getStandardOutput());
        System.out.println("Error output: " + result.getErrorOutput());
        System.out.println("Duration (ms): " + result.getDurationMillis());
        System.out.println("========================================\n");

        assertNotNull(result);
    }
}
