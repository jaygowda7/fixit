
package com.fixit.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fixit.model.Finding;
import com.fixit.model.ScannerType;
import com.fixit.model.Severity;
import com.fixit.scanner.semgrep.SemgrepAdapter;

class SemgrepAdapterTest {

    private SemgrepAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new SemgrepAdapter();
    }

    @Test
    void shouldParseRealSemgrepReport() throws IOException {

        String report = readFixture("/scanner/semgrep-report.json");

        List<Finding> findings = adapter.parseFindings(report);

        System.out.println("\n========== SEMGREP TEST RESULTS ==========");
        System.out.println("Total findings: " + findings.size());

        for (Finding finding : findings) {
            System.out.println("------------------------------------------");
            System.out.println("ID: " + finding.getId());
            System.out.println("Scanner: " + finding.getScanner());
            System.out.println(
                    "Vulnerability ID: " + finding.getVulnerabilityId());
            System.out.println("Title: " + finding.getTitle());
            System.out.println("Description: " + finding.getDescription());
            System.out.println("Severity: " + finding.getSeverity());
            System.out.println("Component: " + finding.getComponent());
            System.out.println("Location: " + finding.getLocation());
            System.out.println(
                    "Remediation Available: "
                            + finding.isRemediationAvailable());
            System.out.println(
                    "Current Version: " + finding.getCurrentVersion());
            System.out.println(
                    "Fixed Version: " + finding.getFixedVersion());
        }

        System.out.println("==========================================\n");

        assertEquals(1, findings.size());

        Finding finding = findings.get(0);

        assertEquals(ScannerType.SEMGREP, finding.getScanner());
        assertEquals(
                "java.lang.security.audit.formatted-sql-string.formatted-sql-string",
                finding.getVulnerabilityId());
        assertEquals("SQL Injection", finding.getTitle());
        assertTrue(
                finding.getDescription().contains("SQL injection"));
        assertEquals(Severity.HIGH, finding.getSeverity());
        assertEquals(
                "src/main/java/VulnerableDemo.java",
                finding.getComponent());
        assertEquals(
                "src/main/java/VulnerableDemo.java:18",
                finding.getLocation());

        assertFalse(finding.isRemediationAvailable());
        assertNotNull(finding.getAvailableFixedVersions());
        assertTrue(finding.getAvailableFixedVersions().isEmpty());
    }

    @Test
    void shouldReturnEmptyListWhenResultsAreEmpty() {

        String report = """
                {
                    "version": "1.181.0",
                    "results": [],
                    "errors": []
                }
                """;

        List<Finding> findings = adapter.parseFindings(report);

        assertNotNull(findings);
        assertTrue(findings.isEmpty());
    }

    @Test
    void shouldReturnEmptyListWhenResultsAreMissing() {

        String report = """
                {
                    "version": "1.181.0",
                    "errors": []
                }
                """;

        List<Finding> findings = adapter.parseFindings(report);

        assertNotNull(findings);
        assertTrue(findings.isEmpty());
    }

    @Test
    void shouldRejectMalformedJson() {

        assertThrows(
                IllegalArgumentException.class,
                () -> adapter.parseFindings("{invalid json"));
    }

    @Test
    void shouldMapSemgrepSeveritiesCorrectly() {

        assertEquals(Severity.HIGH, parseSeverity("ERROR"));
        assertEquals(Severity.MEDIUM, parseSeverity("WARNING"));
        assertEquals(Severity.LOW, parseSeverity("INFO"));
    }

    private Severity parseSeverity(String severity) {

        String report = """
                {
                    "results": [
                        {
                            "check_id": "test.rule",
                            "path": "src/Test.java",
                            "start": {
                                "line": 5,
                                "col": 1
                            },
                            "extra": {
                                "message": "Test finding",
                                "severity": "%s",
                                "metadata": {
                                    "vulnerability_class": ["Test"]
                                }
                            }
                        }
                    ],
                    "errors": []
                }
                """.formatted(severity);

        return adapter.parseFindings(report).get(0).getSeverity();
    }

    private String readFixture(String path) throws IOException {

        try (InputStream inputStream =
                     getClass().getResourceAsStream(path)) {

            if (inputStream == null) {
                throw new IOException(
                        "Test fixture not found: " + path);
            }

            return new String(
                    inputStream.readAllBytes(),
                    StandardCharsets.UTF_8);
        }
    }
}
