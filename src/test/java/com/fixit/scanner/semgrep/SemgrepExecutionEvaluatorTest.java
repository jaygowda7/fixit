
package com.fixit.scanner.semgrep;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import com.fixit.model.CommandExecutionResult;
import com.fixit.model.ExecutionStatus;
import com.fixit.model.ScannerExecutionOutcome;
import com.fixit.model.ScannerExecutionSummary;
import com.fixit.model.ScannerType;

class SemgrepExecutionEvaluatorTest {

	private final SemgrepExecutionEvaluator evaluator = new SemgrepExecutionEvaluator();

	@Test
	void shouldReturnCompletedWhenNoFindingsAreReported() {

		CommandExecutionResult executionResult = createExecutionResult(ExecutionStatus.SUCCESS, 0);

		String reportJson = """
				{
				    "version": "1.181.0",
				    "results": [],
				    "errors": []
				}
				""";

		var summary = evaluator.evaluate(executionResult, reportJson);

		assertEquals(ScannerExecutionOutcome.COMPLETED, summary.getOutcome());

		assertEquals("Semgrep scan completed with no findings", summary.getMessage());

		assertNotNull(summary.getFindings());
		assertEquals(0, summary.getFindings().size());
	}

	@Test
	void shouldReturnCompletedWithFindingsWhenVulnerabilitiesAreReported() {

		CommandExecutionResult executionResult = createExecutionResult(ExecutionStatus.SUCCESS, 0);

		String reportJson = """
				{
				    "version": "1.181.0",
				    "results": [
				        {
				            "check_id": "java.lang.security.audit.sql-injection",
				            "path": "src/main/java/VulnerableDemo.java",
				            "start": {
				                "line": 18
				            },
				            "extra": {
				                "message": "Potential SQL injection",
				                "severity": "ERROR",
				                "metadata": {
				                    "vulnerability_class": [
				                        "SQL Injection"
				                    ]
				                }
				            }
				        }
				    ],
				    "errors": []
				}
				""";

		var summary = evaluator.evaluate(executionResult, reportJson);

		assertEquals(ScannerExecutionOutcome.COMPLETED_WITH_FINDINGS, summary.getOutcome());

		assertEquals("Semgrep scan completed with findings", summary.getMessage());

		assertNotNull(summary.getFindings());
		assertEquals(1, summary.getFindings().size());
	}

	@Test
	void shouldReturnTimedOutWhenExecutionTimesOut() {

		CommandExecutionResult executionResult = createExecutionResult(ExecutionStatus.TIMED_OUT, null);

		var summary = evaluator.evaluate(executionResult, null);

		assertEquals(ScannerExecutionOutcome.TIMED_OUT, summary.getOutcome());

		assertEquals("Semgrep execution timed out", summary.getMessage());
	}

	@Test
	void shouldReturnInterruptedWhenExecutionWasInterrupted() {

		CommandExecutionResult executionResult = createExecutionResult(ExecutionStatus.FAILED, 130);

		var summary = evaluator.evaluate(executionResult, null);

		assertEquals(ScannerExecutionOutcome.INTERRUPTED, summary.getOutcome());

		assertEquals("Semgrep execution was interrupted", summary.getMessage());
	}

	@Test
	void shouldReturnFailedWhenReportIsMissing() {

		CommandExecutionResult executionResult = createExecutionResult(ExecutionStatus.SUCCESS, 0);

		var summary = evaluator.evaluate(executionResult, null);

		assertEquals(ScannerExecutionOutcome.FAILED, summary.getOutcome());

		assertEquals("Semgrep report is missing or blank", summary.getMessage());
	}

	@Test
	void shouldReturnFailedWhenReportIsInvalid() {

		CommandExecutionResult executionResult = createExecutionResult(ExecutionStatus.SUCCESS, 0);

		var summary = evaluator.evaluate(executionResult, "this is not valid JSON");

		assertEquals(ScannerExecutionOutcome.FAILED, summary.getOutcome());

		assertTrue(summary.getMessage().startsWith("Failed to validate or parse Semgrep report:"));
	}

	@Test
	void shouldReturnFailedWhenRequiredFieldsAreMissing() {

		CommandExecutionResult executionResult = createExecutionResult(ExecutionStatus.SUCCESS, 0);

		String reportJson = """
				{
				    "version": "1.181.0",
				    "errors": []
				}
				""";

		var summary = evaluator.evaluate(executionResult, reportJson);

		assertEquals(ScannerExecutionOutcome.FAILED, summary.getOutcome());

		assertEquals("Semgrep report is missing required fields", summary.getMessage());
	}

	@Test
	void shouldReturnFailedWhenReportContainsScannerErrors() {

		CommandExecutionResult executionResult = createExecutionResult(ExecutionStatus.SUCCESS, 0);

		String reportJson = """
				{
				    "version": "1.181.0",
				    "results": [],
				    "errors": [
				        {
				            "message": "Failed to parse a source file"
				        }
				    ]
				}
				""";

		var summary = evaluator.evaluate(executionResult, reportJson);

		assertEquals(ScannerExecutionOutcome.FAILED, summary.getOutcome());

		assertEquals("Semgrep report contains scanner errors", summary.getMessage());
	}

	private CommandExecutionResult createExecutionResult(ExecutionStatus status, Integer exitCode) {

		CommandExecutionResult result = new CommandExecutionResult();

		result.setScanner(ScannerType.SEMGREP);
		result.setStatus(status);
		result.setExitCode(exitCode);
		result.setStandardOutput("");
		result.setErrorOutput("");
		result.setDurationMillis(100);

		return result;
	}

	@Test
	void shouldReturnFailedWhenExitCodeIsNonZeroDespiteValidFindings() {

		CommandExecutionResult executionResult = createExecutionResult(ExecutionStatus.FAILED, 1);

		String reportJson = """
				{
				    "version": "1.181.0",
				    "results": [
				        {
				            "check_id": "java.lang.security.audit.sql-injection",
				            "path": "src/main/java/VulnerableDemo.java",
				            "start": {
				                "line": 18
				            },
				            "extra": {
				                "message": "Potential SQL injection",
				                "severity": "ERROR",
				                "metadata": {
				                    "vulnerability_class": ["SQL Injection"]
				                }
				            }
				        }
				    ],
				    "errors": []
				}
				""";

		var summary = evaluator.evaluate(executionResult, reportJson);

		assertEquals(ScannerExecutionOutcome.FAILED, summary.getOutcome());

		assertEquals("Semgrep execution failed with exit code: 1", summary.getMessage());
	}

	@Test
	void shouldReturnFailedWhenExecutionStatusIsFailedDespiteZeroExitCode() {

		CommandExecutionResult executionResult = createExecutionResult(ExecutionStatus.FAILED, 0);

		String reportJson = """
				{
				    "version": "1.181.0",
				    "results": [],
				    "errors": []
				}
				""";

		var summary = evaluator.evaluate(executionResult, reportJson);

		assertEquals(ScannerExecutionOutcome.FAILED, summary.getOutcome());

		assertEquals("Semgrep execution failed with exit code: 0", summary.getMessage());
	}

	@Test
	void shouldThrowExceptionWhenExecutionResultIsNull() {

		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> evaluator.evaluate(null, null));

		assertEquals("Execution result cannot be null", exception.getMessage());
	}

	@Test
	void shouldReturnPartiallyCompletedWhenAllFindingsAreIncomplete() {

		CommandExecutionResult executionResult = createSuccessfulExecutionResult();

		String reportJson = """
				{
				    "version": "1.56.0",
				    "results": [
				        {
				            "check_id": "incomplete-rule",
				            "path": "VulnerableDemo.java",
				            "start": {"line": 10},
				            "extra": {
				                "severity": "ERROR"
				            }
				        }
				    ],
				    "errors": []
				}
				""";

		ScannerExecutionSummary summary = evaluator.evaluate(executionResult, reportJson);

		assertEquals(ScannerExecutionOutcome.PARTIALLY_COMPLETED, summary.getOutcome());

		assertEquals(0, summary.getFindings().size());
		assertEquals(1, summary.getSkippedFindingsCount());

		assertEquals("Semgrep scan partially completed; skipped 1 incomplete findings", summary.getMessage());
	}

	@Test
	void shouldReturnPartiallyCompletedWhenValidAndIncompleteFindingsExist() {

		CommandExecutionResult executionResult = createSuccessfulExecutionResult();

		String reportJson = """
				{
				    "version": "1.56.0",
				    "results": [
				        {
				            "check_id": "incomplete-rule",
				            "path": "VulnerableDemo.java",
				            "start": {"line": 10},
				            "extra": {
				                "severity": "ERROR"
				            }
				        },
				        {
				            "check_id": "valid-rule",
				            "path": "VulnerableDemo.java",
				            "start": {"line": 20},
				            "extra": {
				                "message": "Potential SQL injection",
				                "severity": "ERROR"
				            }
				        }
				    ],
				    "errors": []
				}
				""";

		ScannerExecutionSummary summary = evaluator.evaluate(executionResult, reportJson);

		assertEquals(ScannerExecutionOutcome.PARTIALLY_COMPLETED, summary.getOutcome());

		assertEquals(1, summary.getFindings().size());
		assertEquals(1, summary.getSkippedFindingsCount());

		assertEquals("valid-rule", summary.getFindings().get(0).getVulnerabilityId());
	}

	private CommandExecutionResult createSuccessfulExecutionResult() {

		CommandExecutionResult result = new CommandExecutionResult();

		result.setScanner(ScannerType.SEMGREP);
		result.setStatus(ExecutionStatus.SUCCESS);
		result.setExitCode(0);

		return result;
	}

}
