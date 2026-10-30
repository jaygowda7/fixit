
package com.fixit.scanner.semgrep;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.fixit.model.Finding;
import com.fixit.model.ScannerType;
import com.fixit.model.Severity;

class SemgrepAdapterTest {

    private final SemgrepAdapter adapter = new SemgrepAdapter();

    @Test
    void shouldParseValidFinding() {

        String reportJson = """
                {
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
                    ]
                }
                """;

        List<Finding> findings = adapter.parseFindings(reportJson);

        assertEquals(1, findings.size());

        Finding finding = findings.get(0);

        assertEquals(ScannerType.SEMGREP, finding.getScanner());
        assertEquals("java.lang.security.audit.sql-injection",
                finding.getVulnerabilityId());
        assertEquals("SQL Injection", finding.getTitle());
        assertEquals("Potential SQL injection", finding.getDescription());
        assertEquals(Severity.HIGH, finding.getSeverity());
        assertEquals("src/main/java/VulnerableDemo.java",
                finding.getComponent());
        assertEquals("src/main/java/VulnerableDemo.java:18",
                finding.getLocation());
    }

    @Test
    void shouldSkipFindingWhenRuleIdIsMissing() {

        String reportJson = """
                {
                    "results": [
                        {
                            "path": "VulnerableDemo.java",
                            "start": {"line": 18},
                            "extra": {
                                "message": "Potential SQL injection",
                                "severity": "ERROR"
                            }
                        }
                    ]
                }
                """;

        assertEquals(0, adapter.parseFindings(reportJson).size());
    }

    @Test
    void shouldSkipFindingWhenFilePathIsMissing() {

        String reportJson = """
                {
                    "results": [
                        {
                            "check_id": "sql-injection",
                            "start": {"line": 18},
                            "extra": {
                                "message": "Potential SQL injection",
                                "severity": "ERROR"
                            }
                        }
                    ]
                }
                """;

        assertEquals(0, adapter.parseFindings(reportJson).size());
    }

    @Test
    void shouldSkipFindingWhenLineNumberIsMissing() {

        String reportJson = """
                {
                    "results": [
                        {
                            "check_id": "sql-injection",
                            "path": "VulnerableDemo.java",
                            "start": {},
                            "extra": {
                                "message": "Potential SQL injection",
                                "severity": "ERROR"
                            }
                        }
                    ]
                }
                """;

        assertEquals(0, adapter.parseFindings(reportJson).size());
    }

    @Test
    void shouldSkipIncompleteFindingsAndRetainValidFindings() {

        String reportJson = """
                {
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
                    ]
                }
                """;

        List<Finding> findings = adapter.parseFindings(reportJson);

        assertEquals(1, findings.size());
        assertEquals("valid-rule", findings.get(0).getVulnerabilityId());
    }

    @Test
    void shouldThrowExceptionForUnsupportedSeverity() {

        String reportJson = """
                {
                    "results": [
                        {
                            "check_id": "test-rule",
                            "path": "Test.java",
                            "start": {"line": 10},
                            "extra": {
                                "message": "Test finding",
                                "severity": "CRITICAL"
                            }
                        }
                    ]
                }
                """;

        assertThrows(
                IllegalArgumentException.class,
                () -> adapter.parseFindings(reportJson)
        );
    }
    
    @Test
    void shouldReturnSkippedFindingsCount() {

        String reportJson = """
                {
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
                    ]
                }
                """;

        SemgrepParseResult result = adapter.parseReport(reportJson);

        assertEquals(1, result.getFindings().size());
        assertEquals(1, result.getSkippedFindingsCount());

        assertEquals(
                "valid-rule",
                result.getFindings().get(0).getVulnerabilityId());
    }
}
