
package com.fixit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fixit.model.Finding;
import com.fixit.model.ScannerType;
import com.fixit.model.Severity;
import com.fixit.scanner.ScannerAdapter;

class ScannerReportCollectionServiceTest {

    private ScannerReportCollectionService scannerReportCollectionService;
    private Map<ScannerType, ScannerAdapter> scannerAdapters;

    @BeforeEach
    void setUp() {

        scannerAdapters = new HashMap<>();

        scannerAdapters.put(
                ScannerType.SNYK,
                createAdapter(ScannerType.SNYK, "SNYK-001")
        );

        scannerAdapters.put(
                ScannerType.SEMGREP,
                createAdapter(ScannerType.SEMGREP, "SEMGREP-001")
        );

        scannerAdapters.put(
                ScannerType.SONARQUBE,
                createAdapter(ScannerType.SONARQUBE, "SONAR-001")
        );

        scannerAdapters.put(
                ScannerType.OWASP_DEPENDENCY_CHECK,
                createAdapter(
                        ScannerType.OWASP_DEPENDENCY_CHECK,
                        "CVE-2024-0001"
                )
        );

        FindingAggregator findingAggregator = new FindingAggregator();

        FindingCollectionService findingCollectionService =
                new FindingCollectionService(findingAggregator);

        scannerReportCollectionService =
                new ScannerReportCollectionService(
                        scannerAdapters,
                        findingCollectionService
                );
    }

    @Test
    void shouldCollectFindingsFromAllFourScanners() {

        Map<ScannerType, String> scannerReports = new HashMap<>();

        scannerReports.put(ScannerType.SNYK, "SNYK_REPORT");
        scannerReports.put(ScannerType.SEMGREP, "SEMGREP_REPORT");
        scannerReports.put(ScannerType.SONARQUBE, "SONAR_REPORT");
        scannerReports.put(
                ScannerType.OWASP_DEPENDENCY_CHECK,
                "OWASP_REPORT"
        );

        List<Finding> findings =
                scannerReportCollectionService.collect(scannerReports);

        printFindings("ALL FOUR SCANNERS TEST", findings);

        assertEquals(4, findings.size());

        assertTrue(findings.stream().anyMatch(
                finding -> finding.getScanner() == ScannerType.SNYK
        ));

        assertTrue(findings.stream().anyMatch(
                finding -> finding.getScanner() == ScannerType.SEMGREP
        ));

        assertTrue(findings.stream().anyMatch(
                finding -> finding.getScanner() == ScannerType.SONARQUBE
        ));

        assertTrue(findings.stream().anyMatch(
                finding -> finding.getScanner()
                        == ScannerType.OWASP_DEPENDENCY_CHECK
        ));
    }

    @Test
    void shouldReturnEmptyListWhenNoReportsAreProvided() {

        List<Finding> findings =
                scannerReportCollectionService.collect(Map.of());

        printFindings("EMPTY REPORT COLLECTION TEST", findings);

        assertTrue(findings.isEmpty());
    }

    @Test
    void shouldThrowExceptionWhenScannerAdapterIsMissing() {

        Map<ScannerType, String> scannerReports = Map.of(
                ScannerType.SNYK, "SNYK_REPORT",
                ScannerType.SEMGREP, "SEMGREP_REPORT"
        );

        Map<ScannerType, ScannerAdapter> incompleteAdapters = Map.of(
                ScannerType.SNYK,
                createAdapter(ScannerType.SNYK, "SNYK-001")
        );

        ScannerReportCollectionService service =
                new ScannerReportCollectionService(
                        incompleteAdapters,
                        new FindingCollectionService(new FindingAggregator())
                );

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> service.collect(scannerReports)
        );

        System.out.println(
                "Missing adapter error: " + exception.getMessage()
        );

        assertTrue(
                exception.getMessage().contains("No adapter configured")
        );
    }

    @Test
    void shouldThrowExceptionWhenReportIsBlank() {

        Map<ScannerType, String> scannerReports = Map.of(
                ScannerType.SNYK, "   "
        );

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> scannerReportCollectionService.collect(scannerReports)
        );

        System.out.println(
                "Blank report error: " + exception.getMessage()
        );

        assertTrue(
                exception.getMessage().contains("cannot be null or blank")
        );
    }

    @Test
    void shouldThrowExceptionWhenAdapterReturnsNull() {

        Map<ScannerType, ScannerAdapter> adapters = Map.of(
                ScannerType.SNYK,
                scannerOutput -> null
        );

        ScannerReportCollectionService service =
                new ScannerReportCollectionService(
                        adapters,
                        new FindingCollectionService(new FindingAggregator())
                );

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> service.collect(
                        Map.of(ScannerType.SNYK, "SNYK_REPORT")
                )
        );

        System.out.println(
                "Null findings error: " + exception.getMessage()
        );

        assertTrue(
                exception.getMessage().contains("returned null findings")
        );
    }

    private ScannerAdapter createAdapter(
            ScannerType scannerType,
            String vulnerabilityId) {

        return scannerOutput -> {

            Finding finding = new Finding();

            finding.setScanner(scannerType);
            finding.setVulnerabilityId(vulnerabilityId);
            finding.setTitle("Test finding from " + scannerType);
            finding.setSeverity(Severity.HIGH);

            System.out.println(
                    "[TEST ADAPTER] Parsed report for " + scannerType
                            + ": " + scannerOutput
            );

            return List.of(finding);
        };
    }

    private void printFindings(
            String testName,
            List<Finding> findings) {

        System.out.println(
                "\n========== " + testName + " =========="
        );

        System.out.println("Total findings: " + findings.size());

        for (Finding finding : findings) {
            System.out.println("------------------------------------------");
            System.out.println("Scanner: " + finding.getScanner());
            System.out.println(
                    "Vulnerability ID: " + finding.getVulnerabilityId()
            );
            System.out.println("Title: " + finding.getTitle());
            System.out.println("Severity: " + finding.getSeverity());
        }

        System.out.println("==========================================\n");
    }
}
