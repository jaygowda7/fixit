
package com.fixit.scanner.semgrep;

import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fixit.model.CommandExecutionResult;
import com.fixit.model.ExecutionStatus;
import com.fixit.model.Finding;
import com.fixit.model.ScannerExecutionOutcome;
import com.fixit.model.ScannerExecutionSummary;

public class SemgrepExecutionEvaluator {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final SemgrepAdapter semgrepAdapter =
            new SemgrepAdapter();

    public ScannerExecutionSummary evaluate(
            CommandExecutionResult executionResult,
            String reportJson) {

        if (executionResult == null) {
            throw new IllegalArgumentException(
                    "Execution result cannot be null");
        }

        ScannerExecutionSummary summary =
                new ScannerExecutionSummary();

        summary.setScanner(executionResult.getScanner());
        summary.setExecutionResult(executionResult);

        if (executionResult.getStatus() == ExecutionStatus.TIMED_OUT) {
            summary.setOutcome(ScannerExecutionOutcome.TIMED_OUT);
            summary.setMessage("Semgrep execution timed out");
            return summary;
        }

        if (Integer.valueOf(130).equals(executionResult.getExitCode())) {
            summary.setOutcome(ScannerExecutionOutcome.INTERRUPTED);
            summary.setMessage("Semgrep execution was interrupted");
            return summary;
        }

        if (reportJson == null || reportJson.isBlank()) {
            summary.setOutcome(ScannerExecutionOutcome.FAILED);
            summary.setMessage("Semgrep report is missing or blank");
            return summary;
        }

        try {
            JsonNode report = objectMapper.readTree(reportJson);

            if (report == null
                    || !report.isObject()
                    || !report.path("version").isTextual()
                    || !report.path("results").isArray()
                    || !report.path("errors").isArray()) {

                summary.setOutcome(ScannerExecutionOutcome.FAILED);
                summary.setMessage(
                        "Semgrep report is missing required fields");
                return summary;
            }

            JsonNode errors = report.path("errors");

            if (!errors.isEmpty()) {
                summary.setOutcome(ScannerExecutionOutcome.FAILED);
                summary.setMessage(
                        "Semgrep report contains scanner errors");
                return summary;
            }

            SemgrepParseResult parseResult =
                    semgrepAdapter.parseReport(reportJson);

            List<Finding> findings = parseResult.getFindings();

            summary.setFindings(findings);
            summary.setSkippedFindingsCount(
                    parseResult.getSkippedFindingsCount());

            Integer exitCode = executionResult.getExitCode();

            if (executionResult.getStatus() != ExecutionStatus.SUCCESS
                    || !Integer.valueOf(0).equals(exitCode)) {

                summary.setOutcome(ScannerExecutionOutcome.FAILED);
                summary.setMessage(
                        "Semgrep execution failed with exit code: "
                                + exitCode);
                return summary;
            }

            if (summary.getSkippedFindingsCount() > 0) {

                summary.setOutcome(
                        ScannerExecutionOutcome.PARTIALLY_COMPLETED);

                summary.setMessage(
                        "Semgrep scan partially completed; skipped "
                                + summary.getSkippedFindingsCount()
                                + " incomplete findings");

            } else if (findings.isEmpty()) {

                summary.setOutcome(
                        ScannerExecutionOutcome.COMPLETED);

                summary.setMessage(
                        "Semgrep scan completed with no findings");

            } else {

                summary.setOutcome(
                        ScannerExecutionOutcome.COMPLETED_WITH_FINDINGS);

                summary.setMessage(
                        "Semgrep scan completed with findings");
            }

            return summary;

        } catch (Exception e) {

            summary.setOutcome(ScannerExecutionOutcome.FAILED);

            summary.setMessage(
                    "Failed to validate or parse Semgrep report: "
                            + e.getMessage());

            return summary;
        }
    }
}
