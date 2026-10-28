
package com.fixit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fixit.model.Finding;
import com.fixit.model.ScannerType;

class FindingCollectionServiceTest {

    private FindingCollectionService findingCollectionService;

    @BeforeEach
    void setUp() {
        findingCollectionService =
                new FindingCollectionService(new FindingAggregator());
    }

    @Test
    void shouldCollectFindingsFromMultipleScanners() {

        Finding snykFinding = createFinding(
                ScannerType.SNYK,
                "SNYK-TEST-001",
                "Dependency vulnerability"
        );

        Finding semgrepFinding = createFinding(
                ScannerType.SEMGREP,
                "SEMGREP-TEST-001",
                "SQL Injection"
        );

        Finding sonarFinding = createFinding(
                ScannerType.SONARQUBE,
                "SONAR-TEST-001",
                "Security issue"
        );

        Finding owaspFinding = createFinding(
                ScannerType.OWASP_DEPENDENCY_CHECK,
                "CVE-2024-0001",
                "Known dependency vulnerability"
        );

        List<Finding> consolidatedFindings =
                findingCollectionService.collect(
                        List.of(
                                List.of(snykFinding),
                                List.of(semgrepFinding),
                                List.of(sonarFinding),
                                List.of(owaspFinding)
                        )
                );

        System.out.println(
                "\n========== CONSOLIDATED FINDINGS =========="
        );

        System.out.println(
                "Total findings: " + consolidatedFindings.size()
        );

        for (Finding finding : consolidatedFindings) {
            System.out.println("------------------------------------------");
            System.out.println("Scanner: " + finding.getScanner());
            System.out.println("Finding ID: " + finding.getId());
            System.out.println(
                    "Vulnerability ID: " + finding.getVulnerabilityId()
            );
            System.out.println("Title: " + finding.getTitle());
            System.out.println("Severity: " + finding.getSeverity());
        }

        System.out.println(
                "==========================================\n"
        );

        assertEquals(4, consolidatedFindings.size());

        assertTrue(consolidatedFindings.contains(snykFinding));
        assertTrue(consolidatedFindings.contains(semgrepFinding));
        assertTrue(consolidatedFindings.contains(sonarFinding));
        assertTrue(consolidatedFindings.contains(owaspFinding));
    }

    @Test
    void shouldReturnEmptyCollectionWhenNoFindingsExist() {

        List<Finding> consolidatedFindings =
                findingCollectionService.collect(List.of());

        System.out.println(
                "\n========== EMPTY COLLECTION TEST =========="
        );
        System.out.println(
                "Total findings: " + consolidatedFindings.size()
        );
        System.out.println(
                "Collection is empty: " + consolidatedFindings.isEmpty()
        );
        System.out.println(
                "===========================================\n"
        );

        assertTrue(consolidatedFindings.isEmpty());
    }

    private Finding createFinding(
            ScannerType scanner,
            String vulnerabilityId,
            String title) {

        Finding finding = new Finding();

        finding.setScanner(scanner);
        finding.setVulnerabilityId(vulnerabilityId);
        finding.setTitle(title);

        return finding;
    }
}
