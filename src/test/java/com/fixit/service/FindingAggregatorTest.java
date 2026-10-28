package com.fixit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fixit.model.Finding;
import com.fixit.model.ScannerType;
import com.fixit.model.Severity;

class FindingAggregatorTest {

    private FindingAggregator findingAggregator;

    @BeforeEach
    void setUp() {
        findingAggregator = new FindingAggregator();
    }

    @Test
    void shouldAggregateFindingsFromMultipleScanners() {

        Finding snykFinding = createFinding(
                ScannerType.SNYK,
                "CVE-2024-0001"
        );

        Finding semgrepFinding = createFinding(
                ScannerType.SEMGREP,
                "SQL_INJECTION"
        );

        List<Finding> snykFindings = List.of(snykFinding);
        List<Finding> semgrepFindings = List.of(semgrepFinding);

        List<Finding> consolidatedFindings =
                findingAggregator.aggregate(
                        List.of(snykFindings, semgrepFindings)
                );

        printFindings("AGGREGATION TEST", consolidatedFindings);

        assertEquals(2, consolidatedFindings.size());
        assertTrue(consolidatedFindings.contains(snykFinding));
        assertTrue(consolidatedFindings.contains(semgrepFinding));
    }

    @Test
    void shouldReturnEmptyListWhenNoScannerFindings() {

        List<Finding> consolidatedFindings =
                findingAggregator.aggregate(List.of());

        printFindings("EMPTY SCANNER COLLECTION TEST", consolidatedFindings);

        assertTrue(consolidatedFindings.isEmpty());
    }

    @Test
    void shouldHandleNullScannerFindings() {

        List<Finding> consolidatedFindings =
                findingAggregator.aggregate(null);

        printFindings("NULL SCANNER COLLECTION TEST", consolidatedFindings);

        assertTrue(consolidatedFindings.isEmpty());
    }

    @Test
    void shouldIgnoreEmptyScannerResults() {

        Finding snykFinding = createFinding(
                ScannerType.SNYK,
                "CVE-2024-0001"
        );

        List<Finding> consolidatedFindings =
                findingAggregator.aggregate(
                        List.of(
                                new ArrayList<>(),
                                List.of(snykFinding),
                                new ArrayList<>()
                        )
                );

        printFindings("EMPTY SCANNER RESULTS TEST", consolidatedFindings);

        assertEquals(1, consolidatedFindings.size());
        assertTrue(consolidatedFindings.contains(snykFinding));
    }

    @Test
    void shouldRetainDuplicateFindingsFromDifferentScanners() {

        Finding snykFinding = createFinding(
                ScannerType.SNYK,
                "CVE-2024-0001"
        );

        Finding owaspFinding = createFinding(
                ScannerType.OWASP_DEPENDENCY_CHECK,
                "CVE-2024-0001"
        );

        List<Finding> consolidatedFindings =
                findingAggregator.aggregate(
                        List.of(
                                List.of(snykFinding),
                                List.of(owaspFinding)
                        )
                );

        printFindings("DUPLICATE FINDINGS TEST", consolidatedFindings);

        assertEquals(2, consolidatedFindings.size());

        assertTrue(consolidatedFindings.contains(snykFinding));
        assertTrue(consolidatedFindings.contains(owaspFinding));

        System.out.println(
                "Duplicate vulnerability ID retained: "
                        + snykFinding.getVulnerabilityId()
        );
    }

    private Finding createFinding(
            ScannerType scanner,
            String vulnerabilityId) {

        Finding finding = new Finding();

        finding.setScanner(scanner);
        finding.setVulnerabilityId(vulnerabilityId);
        finding.setSeverity(Severity.HIGH);
        finding.setTitle("Test vulnerability");
        finding.setComponent("test-component");
        finding.setCurrentVersion("1.0.0");
        finding.setFixedVersion("1.0.1");
        finding.setRemediationAvailable(true);

        return finding;
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
            System.out.println("Component: " + finding.getComponent());
            System.out.println(
                    "Current Version: " + finding.getCurrentVersion()
            );
            System.out.println(
                    "Fixed Version: " + finding.getFixedVersion()
            );
            System.out.println(
                    "Remediation Available: "
                            + finding.isRemediationAvailable()
            );
        }

        System.out.println("==========================================\n");
    }
}
