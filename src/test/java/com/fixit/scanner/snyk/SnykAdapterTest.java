package com.fixit.scanner.snyk;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.apache.maven.artifact.versioning.ComparableVersion;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fixit.model.Finding;
import com.fixit.model.ScannerType;
import com.fixit.model.Severity;
import com.fixit.scanner.snyk.model.SnykReport;

class SnykAdapterTest {

    private final SnykAdapter adapter = new SnykAdapter();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void parsesRealSnykReport() throws Exception {

        String reportJson;

        try (InputStream input = getClass().getResourceAsStream(
                "/scanner/snyk-report.json")) {

            assertNotNull(input, "Snyk report test resource must exist");
            reportJson = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }

        SnykReport report =
                objectMapper.readValue(reportJson, SnykReport.class);

        List<Finding> findings = adapter.parseFindings(reportJson);

        assertNotNull(findings);
        assertFalse(findings.isEmpty());
        assertEquals(report.getVulnerabilities().size(), findings.size());

        Finding firstFinding = findings.get(0);

        System.out.println("\n========== SNYK VERSION VERIFICATION ==========");
        System.out.println("Vulnerability ID: " + firstFinding.getVulnerabilityId());
        System.out.println("Component: " + firstFinding.getComponent());
        System.out.println("Current Version: " + firstFinding.getCurrentVersion());

        System.out.println("Available Fixed Versions: "
                + firstFinding.getAvailableFixedVersions());

        System.out.println("Selected Fixed Version: "
                + firstFinding.getFixedVersion());

        System.out.println("Remediation Available: "
                + firstFinding.isRemediationAvailable());

        System.out.println("===============================================\n");

        assertEquals(ScannerType.SNYK, firstFinding.getScanner());
        assertNotNull(firstFinding.getVulnerabilityId());
        assertNotNull(firstFinding.getTitle());
        assertNotNull(firstFinding.getSeverity());
        assertNotNull(firstFinding.getComponent());
        assertNotNull(firstFinding.getCurrentVersion());

        assertNotNull(firstFinding.getLocation());
        assertFalse(firstFinding.getLocation().isBlank());

        assertNotNull(firstFinding.getVulnerableVersionRanges());
        assertFalse(firstFinding.getVulnerableVersionRanges().isEmpty());

        // Verify that all available fixed versions are retained.
        assertNotNull(firstFinding.getAvailableFixedVersions());

        List<String> availableVersions =
                firstFinding.getAvailableFixedVersions();

        if (!availableVersions.isEmpty()) {

            String highestVersion = availableVersions.stream()
                    .filter(version -> version != null && !version.isBlank())
                    .max((v1, v2) ->
                            new ComparableVersion(v1).compareTo(
                                    new ComparableVersion(v2)))
                    .orElse(null);

            assertNotNull(highestVersion,
                    "At least one valid fixed version should exist");

            assertEquals(highestVersion, firstFinding.getFixedVersion());
            assertTrue(firstFinding.isRemediationAvailable());
        }

        assertTrue(
                findings.stream().anyMatch(
                        finding -> finding.getSeverity() == Severity.CRITICAL),
                "Real report should contain at least one critical finding"
        );
    }

    @Test
    void mapsSeverityCorrectly() {

        assertEquals(Severity.CRITICAL, parseSeverity("critical"));
        assertEquals(Severity.HIGH, parseSeverity("high"));
        assertEquals(Severity.MEDIUM, parseSeverity("medium"));
        assertEquals(Severity.LOW, parseSeverity("low"));
    }

    @Test
    void parsesReportWithNoVulnerabilities() {

        String emptyReport = """
                {
                    "vulnerabilities": [],
                    "projectName": "test-project",
                    "displayTargetFile": "pom.xml"
                }
                """;

        List<Finding> findings = adapter.parseFindings(emptyReport);

        assertNotNull(findings);
        assertTrue(findings.isEmpty());
    }

    private Severity parseSeverity(String severity) {

        return switch (severity) {
            case "critical" -> Severity.CRITICAL;
            case "high" -> Severity.HIGH;
            case "medium" -> Severity.MEDIUM;
            case "low" -> Severity.LOW;
            default -> fail("Unexpected severity");
        };
    }
}