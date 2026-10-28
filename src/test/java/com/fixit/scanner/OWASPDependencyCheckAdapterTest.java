package com.fixit.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fixit.model.Finding;
import com.fixit.model.ScannerType;
import com.fixit.model.Severity;
import com.fixit.model.VulnerableVersionRange;
import com.fixit.scanner.owasp.OWASPDependencyCheckAdapter;

class OWASPDependencyCheckAdapterTest {

    @Test
    void shouldParseDependencyCheckFinding() throws Exception {

        String scannerOutput = Files.readString(
                Path.of("src/test/resources/scanner/dependency-check-sample.json"));

        ScannerAdapter adapter = new OWASPDependencyCheckAdapter();

        List<Finding> findings = adapter.parseFindings(scannerOutput);

        assertNotNull(findings);
        assertEquals(1, findings.size());

        Finding finding = findings.get(0);

        assertEquals(ScannerType.OWASP_DEPENDENCY_CHECK, finding.getScanner());
        assertEquals("CVE-2026-12345", finding.getVulnerabilityId());
        assertEquals(Severity.HIGH, finding.getSeverity());
        assertEquals("jackson-databind-2.15.0.jar", finding.getComponent());
    }
    
    @Test
    void shouldParseRealDependencyCheckReport() throws Exception {

        String scannerOutput = Files.readString(
                Path.of("src/test/resources/scanner/dependency-check-report.json"));

        ScannerAdapter adapter = new OWASPDependencyCheckAdapter();

        List<Finding> findings = adapter.parseFindings(scannerOutput);

        assertNotNull(findings);
        assertEquals(5, findings.size());

        for (Finding finding : findings) {

            System.out.println("----- Finding -----");
            System.out.println("Scanner: " + finding.getScanner());
            System.out.println("Vulnerability: " + finding.getVulnerabilityId());
            System.out.println("Severity: " + finding.getSeverity());
            System.out.println("Component: " + finding.getComponent());
            System.out.println("Current Version: " + finding.getCurrentVersion());
            System.out.println("Vulnerable Ranges:");

            for (VulnerableVersionRange range : finding.getVulnerableVersionRanges()) {
            	System.out.println(
            	"  " + (range.isStartInclusive() ? "[" : "(")
            	+ (range.getStartVersion() == null ? "" : range.getStartVersion())
            	+ ", "
            	+ (range.getEndVersion() == null ? "" : range.getEndVersion())
            	+ (range.isEndInclusive() ? "]" : ")")
            	);
            }

            assertEquals(
                    ScannerType.OWASP_DEPENDENCY_CHECK,
                    finding.getScanner()
            );

            assertEquals(
                    "com.fasterxml.jackson.core:jackson-databind",
                    finding.getComponent()
            );

            assertEquals(
                    "2.15.0",
                    finding.getCurrentVersion()
            );
        }
    }
}