
package com.fixit.scanner.snyk;

import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fixit.model.CommandExecutionResult;
import com.fixit.model.ExecutionStatus;
import com.fixit.model.Finding;
import com.fixit.model.ScannerExecutionOutcome;
import com.fixit.model.ScannerExecutionSummary;
import com.fixit.scanner.snyk.model.SnykReport;

public class SnykExecutionEvaluator {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SnykAdapter snykAdapter = new SnykAdapter();

    public ScannerExecutionSummary evaluate(
            CommandExecutionResult executionResult,
            String reportJson) {

        if (executionResult == null) {
            throw new IllegalArgumentException(
                    "Execution result cannot be null"
            );
        }

        ScannerExecutionSummary summary =
                new ScannerExecutionSummary();

        summary.setScanner(executionResult.getScanner());
        summary.setExecutionResult(executionResult);

        if (executionResult.getStatus() == ExecutionStatus.TIMED_OUT) {
            summary.setOutcome(ScannerExecutionOutcome.TIMED_OUT);
            summary.setMessage("Snyk execution timed out");
            return summary;
        }

        if (Integer.valueOf(130).equals(executionResult.getExitCode())) {
            summary.setOutcome(ScannerExecutionOutcome.INTERRUPTED);
            summary.setMessage("Snyk execution was interrupted");
            return summary;
        }

        if (reportJson == null || reportJson.isBlank()) {
            summary.setOutcome(ScannerExecutionOutcome.FAILED);
            summary.setMessage("Snyk report is missing or blank");
            return summary;
        }

        try {
            SnykReport report =
                    objectMapper.readValue(reportJson, SnykReport.class);

            if (report.getOk() == null
                    || report.getVulnerabilities() == null) {

                summary.setOutcome(ScannerExecutionOutcome.FAILED);
                summary.setMessage("Snyk report is missing required fields");
                return summary;
            }

            List<Finding> findings =
                    snykAdapter.parseFindings(reportJson);

            summary.setFindings(findings);

            Integer exitCode = executionResult.getExitCode();

            if (Integer.valueOf(0).equals(exitCode)) {

                summary.setOutcome(
                        findings.isEmpty()
                                ? ScannerExecutionOutcome.COMPLETED
                                : ScannerExecutionOutcome.COMPLETED_WITH_FINDINGS
                );

                summary.setMessage(
                        findings.isEmpty()
                                ? "Snyk scan completed with no findings"
                                : "Snyk scan completed with findings"
                );

                return summary;
            }

            if (Integer.valueOf(1).equals(exitCode)
                    && !findings.isEmpty()) {

                summary.setOutcome(
                        ScannerExecutionOutcome.COMPLETED_WITH_FINDINGS
                );

                summary.setMessage(
                        "Snyk scan completed and reported vulnerabilities"
                );

                return summary;
            }

            summary.setOutcome(ScannerExecutionOutcome.FAILED);
            summary.setMessage(
                    "Snyk execution failed with exit code: " + exitCode
            );

            return summary;

        } catch (Exception e) {
            summary.setOutcome(ScannerExecutionOutcome.FAILED);
            summary.setMessage(
                    "Failed to validate or parse Snyk report: "
                            + e.getMessage()
            );

            return summary;
        }
    }
}
