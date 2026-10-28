
package com.fixit.scanner.sonarqube;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fixit.model.Finding;
import com.fixit.model.ScannerType;
import com.fixit.model.Severity;
import com.fixit.scanner.ScannerAdapter;
import com.fixit.scanner.sonarqube.model.SonarQubeIssue;
import com.fixit.scanner.sonarqube.model.SonarQubeIssuesResponse;

public class SonarQubeAdapter implements ScannerAdapter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public List<Finding> parseFindings(String scannerOutput) {

        System.out.println("[SONARQUBE] Starting to parse report...");

        try {
            SonarQubeIssuesResponse report = objectMapper.readValue(
                    scannerOutput, SonarQubeIssuesResponse.class);

            List<Finding> findings = new ArrayList<>();

            if (report.getIssues() == null) {
                System.out.println(
                        "[SONARQUBE] Report contains no issue list.");
                return findings;
            }

            for (SonarQubeIssue issue : report.getIssues()) {

                Finding finding = new Finding();

                finding.setId(issue.getKey());
                finding.setScanner(ScannerType.SONARQUBE);
                finding.setVulnerabilityId(issue.getRule());
                finding.setTitle(issue.getMessage());
                finding.setDescription(
                        "Type: " + issue.getType()
                                + "; Status: " + issue.getStatus());
                finding.setSeverity(mapSeverity(issue.getSeverity()));

                String component = issue.getComponent();

                if (component != null && component.startsWith("fixit:")) {
                    component = component.substring("fixit:".length());
                }

                finding.setComponent(component);

                finding.setLocation(
                        component == null
                                ? null
                                : issue.getLine() == null
                                        ? component
                                        : component + ":" + issue.getLine());

                finding.setCurrentVersion(null);
                finding.setFixedVersion(null);
                finding.setRemediationAvailable(false);
                finding.setVulnerableVersionRanges(new ArrayList<>());
                finding.setAvailableFixedVersions(new ArrayList<>());

                findings.add(finding);
            }

            System.out.println(
                    "[SONARQUBE] Total findings parsed: " + findings.size());

            return findings;

        } catch (Exception e) {
            System.out.println(
                    "[SONARQUBE] Failed to parse report: " + e.getMessage());

            throw new IllegalArgumentException(
                    "Failed to parse SonarQube output", e);
        }
    }

    private Severity mapSeverity(String severity) {

        if (severity == null) {
            return null;
        }

        return switch (severity.toUpperCase()) {
            case "BLOCKER", "CRITICAL" -> Severity.CRITICAL;
            case "MAJOR" -> Severity.HIGH;
            case "MINOR" -> Severity.LOW;
            case "INFO" -> Severity.LOW;
            default -> throw new IllegalArgumentException(
                    "Unsupported SonarQube severity: " + severity);
        };
    }
}
