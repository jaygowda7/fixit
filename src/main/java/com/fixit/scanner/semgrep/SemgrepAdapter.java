
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

        System.out.println("[SEMGREP] Starting to parse report...");

        try {
            JsonNode report = objectMapper.readTree(scannerOutput);
            JsonNode results = report.get("results");

            List<Finding> findings = new ArrayList<>();

            if (results == null || !results.isArray()) {
                System.out.println(
                        "[SEMGREP] Report contains no valid results list.");
                return findings;
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

                // Semgrep's severity is normally stored inside extra.
                // Fall back to the result-level field if necessary.
                if (scannerSeverity == null) {
                    scannerSeverity =
                            result.path("severity").asText(null);
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

                finding.setLocation(
                        component == null
                                ? null
                                : line > 0
                                        ? component + ":" + line
                                        : component);

                finding.setCurrentVersion(null);
                finding.setFixedVersion(null);
                finding.setRemediationAvailable(false);
                finding.setVulnerableVersionRanges(new ArrayList<>());
                finding.setAvailableFixedVersions(new ArrayList<>());

                findings.add(finding);
            }

            System.out.println(
                    "[SEMGREP] Total findings parsed: " + findings.size());

            return findings;

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
