
package com.fixit.scanner.snyk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import com.fixit.model.CommandExecutionResult;
import com.fixit.model.ExecutionStatus;
import com.fixit.model.ScannerExecutionOutcome;
import com.fixit.model.ScannerType;

class SnykExecutionEvaluatorTest {

    private final SnykExecutionEvaluator evaluator =
            new SnykExecutionEvaluator();

    @Test
    void shouldReturnCompletedWhenNoFindingsAreReported() {

        CommandExecutionResult executionResult =
                createExecutionResult(ExecutionStatus.SUCCESS, 0);

        String reportJson = """
                {
                    "ok": true,
                    "dependencyCount": 1,
                    "vulnerabilities": [],
                    "projectName": "test-project",
                    "displayTargetFile": "pom.xml"
                }
                """;

        var summary = evaluator.evaluate(executionResult, reportJson);

        assertEquals(
                ScannerExecutionOutcome.COMPLETED,
                summary.getOutcome()
        );

        assertEquals(
                "Snyk scan completed with no findings",
                summary.getMessage()
        );

        assertNotNull(summary.getFindings());
        assertEquals(0, summary.getFindings().size());
    }

    @Test
    void shouldReturnCompletedWithFindingsWhenVulnerabilitiesAreReported() {

        CommandExecutionResult executionResult =
                createExecutionResult(ExecutionStatus.FAILED, 1);

        String reportJson = """
                {
                    "ok": false,
                    "dependencyCount": 1,
                    "vulnerabilities": [
                        {
                            "id": "SNYK-JAVA-TEST-123",
                            "title": "Test vulnerability",
                            "description": "A test vulnerability",
                            "severity": "high",
                            "packageName": "com.example:test-library",
                            "version": "1.0.0",
                            "fixedIn": ["1.0.1"]
                        }
                    ],
                    "projectName": "test-project",
                    "displayTargetFile": "pom.xml"
                }
                """;

        var summary = evaluator.evaluate(executionResult, reportJson);

        assertEquals(
                ScannerExecutionOutcome.COMPLETED_WITH_FINDINGS,
                summary.getOutcome()
        );

        assertEquals(
                "Snyk scan completed and reported vulnerabilities",
                summary.getMessage()
        );

        assertNotNull(summary.getFindings());
        assertEquals(1, summary.getFindings().size());
    }

    @Test
    void shouldReturnTimedOutWhenExecutionTimesOut() {

        CommandExecutionResult executionResult =
                createExecutionResult(ExecutionStatus.TIMED_OUT, null);

        var summary = evaluator.evaluate(executionResult, null);

        assertEquals(
                ScannerExecutionOutcome.TIMED_OUT,
                summary.getOutcome()
        );

        assertEquals(
                "Snyk execution timed out",
                summary.getMessage()
        );
    }

    @Test
    void shouldReturnInterruptedWhenExecutionWasInterrupted() {

        CommandExecutionResult executionResult =
                createExecutionResult(ExecutionStatus.FAILED, 130);

        var summary = evaluator.evaluate(executionResult, null);

        assertEquals(
                ScannerExecutionOutcome.INTERRUPTED,
                summary.getOutcome()
        );

        assertEquals(
                "Snyk execution was interrupted",
                summary.getMessage()
        );
    }

    @Test
    void shouldReturnFailedWhenReportIsMissing() {

        CommandExecutionResult executionResult =
                createExecutionResult(ExecutionStatus.SUCCESS, 0);

        var summary = evaluator.evaluate(executionResult, null);

        assertEquals(
                ScannerExecutionOutcome.FAILED,
                summary.getOutcome()
        );

        assertEquals(
                "Snyk report is missing or blank",
                summary.getMessage()
        );
    }

    @Test
    void shouldReturnFailedWhenReportIsInvalid() {

        CommandExecutionResult executionResult =
                createExecutionResult(ExecutionStatus.SUCCESS, 0);

        var summary = evaluator.evaluate(
                executionResult,
                "this is not valid JSON"
        );

        assertEquals(
                ScannerExecutionOutcome.FAILED,
                summary.getOutcome()
        );

        assertEquals(
                true,
                summary.getMessage().startsWith(
                        "Failed to validate or parse Snyk report:"
                )
        );
    }

    private CommandExecutionResult createExecutionResult(
            ExecutionStatus status,
            Integer exitCode) {

        CommandExecutionResult result =
                new CommandExecutionResult();

        result.setScanner(ScannerType.SNYK);
        result.setStatus(status);
        result.setExitCode(exitCode);
        result.setStandardOutput("");
        result.setErrorOutput("");
        result.setDurationMillis(100);

        return result;
    }
}
