
package com.fixit.scanner.semgrep;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fixit.model.Finding;
import com.fixit.model.ScannerType;
import com.fixit.model.Severity;
import com.fixit.scanner.ScannerAdapter;

public class SemgrepAdapter implements ScannerAdapter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public List<Finding> parseFindings(String scannerOutput) {
        return parseReport(scannerOutput).getFindings();
    }

    public SemgrepParseResult parseReport(String scannerOutput) {

        System.out.println("[SEMGREP] Starting to parse report...");

        try {
            JsonNode report = objectMapper.readTree(scannerOutput);
            JsonNode results = report.get("results");

            List<Finding> findings = new ArrayList<>();
            int skippedFindingsCount = 0;

            if (results == null || !results.isArray()) {
                System.out.println(
                        "[SEMGREP] Report contains no valid results list.");

                SemgrepParseResult parseResult = new SemgrepParseResult();
                parseResult.setFindings(findings);
                parseResult.setSkippedFindingsCount(0);

                return parseResult;
            }

            for (JsonNode result : results) {

                JsonNode extra = result.path("extra");
                JsonNode metadata = extra.path("metadata");

                String ruleId = result.path("check_id").asText(null);
                String component = result.path("path").asText(null);
                int line = result.path("start").path("line").asInt(0);
                String message = extra.path("message").asText(null);
                String scannerSeverity =
                        extra.path("severity").asText(null);

                // Fall back to result-level severity if extra severity is missing.
                if (scannerSeverity == null) {
                    scannerSeverity =
                            result.path("severity").asText(null);
                }

                // Skip findings that do not contain essential information.
                if (ruleId == null || ruleId.isBlank()
                        || component == null || component.isBlank()
                        || line <= 0
                        || message == null || message.isBlank()
                        || scannerSeverity == null
                        || scannerSeverity.isBlank()) {

                    skippedFindingsCount++;

                    System.out.println(
                            "[SEMGREP] Skipping incomplete finding: " + ruleId);

                    continue;
                }

                Finding finding = new Finding();

                finding.setId(
                        ruleId + ":" + component + ":" + line);
                finding.setScanner(ScannerType.SEMGREP);
                finding.setVulnerabilityId(ruleId);

                JsonNode vulnerabilityClasses =
                        metadata.path("vulnerability_class");

                String title = vulnerabilityClasses.isArray()
                        && !vulnerabilityClasses.isEmpty()
                        ? vulnerabilityClasses.get(0).asText()
                        : ruleId;

                finding.setTitle(title);
                finding.setDescription(message);
                finding.setSeverity(mapSeverity(scannerSeverity));
                finding.setComponent(component);
                finding.setLocation(component + ":" + line);

                finding.setCurrentVersion(null);
                finding.setFixedVersion(null);
                finding.setRemediationAvailable(false);
                finding.setVulnerableVersionRanges(new ArrayList<>());
                finding.setAvailableFixedVersions(new ArrayList<>());

                findings.add(finding);
            }

            System.out.println(
                    "[SEMGREP] Total findings parsed: " + findings.size());

            System.out.println(
                    "[SEMGREP] Total findings skipped: "
                            + skippedFindingsCount);

            SemgrepParseResult parseResult = new SemgrepParseResult();
            parseResult.setFindings(findings);
            parseResult.setSkippedFindingsCount(skippedFindingsCount);

            return parseResult;

        } catch (Exception e) {
            System.out.println(
                    "[SEMGREP] Failed to parse report: " + e.getMessage());

            throw new IllegalArgumentException(
                    "Failed to parse Semgrep output", e);
        }
    }

    private Severity mapSeverity(String severity) {

        if (severity == null) {
            return null;
        }

        return switch (severity.toUpperCase()) {
            case "ERROR" -> Severity.HIGH;
            case "WARNING" -> Severity.MEDIUM;
            case "INFO" -> Severity.LOW;
            default -> throw new IllegalArgumentException(
                    "Unsupported Semgrep severity: " + severity);
        };
    }
}
