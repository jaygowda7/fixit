
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
import com.fixit.scanner.sonarqube.SonarQubeAdapter;

class SonarQubeAdapterTest {

	private SonarQubeAdapter adapter;

	@BeforeEach
	void setUp() {
		adapter = new SonarQubeAdapter();
	}

	@Test
	void shouldParseRealSonarQubeReport() throws IOException {

		String report = readFixture("/scanner/sonarqube-issues.json");

		List<Finding> findings = adapter.parseFindings(report);

		assertEquals(19, findings.size());

		Finding finding = findings.get(0);

		assertEquals(ScannerType.SONARQUBE, finding.getScanner());
		assertEquals("e8f719d2-e3d2-4e9f-9f09-0c66f533e9fc", finding.getId());
		assertEquals("java:S3776", finding.getVulnerabilityId());
		assertEquals("Refactor this method to reduce its Cognitive Complexity from 45 to the 15 allowed.",
				finding.getTitle());
		assertEquals(Severity.CRITICAL, finding.getSeverity());
		assertEquals("src/main/java/com/fixit/scanner/owasp/OWASPDependencyCheckAdapter.java", finding.getComponent());
		assertEquals("src/main/java/com/fixit/scanner/owasp/OWASPDependencyCheckAdapter.java:23",
				finding.getLocation());

		assertFalse(finding.isRemediationAvailable());
		assertNotNull(finding.getAvailableFixedVersions());
		assertTrue(finding.getAvailableFixedVersions().isEmpty());
	}

	@Test
	void shouldReturnEmptyListWhenIssuesAreEmpty() {

		String report = """
				{
				    "total": 0,
				    "issues": []
				}
				""";

		List<Finding> findings = adapter.parseFindings(report);

		assertNotNull(findings);
		assertTrue(findings.isEmpty());
	}

	@Test
	void shouldReturnEmptyListWhenIssueListIsMissing() {

		String report = """
				{
				    "total": 0
				}
				""";

		List<Finding> findings = adapter.parseFindings(report);

		assertNotNull(findings);
		assertTrue(findings.isEmpty());
	}

	@Test
	void shouldRejectMalformedJson() {

		assertThrows(IllegalArgumentException.class, () -> adapter.parseFindings("{invalid json"));
	}

	@Test
	void shouldMapSonarQubeSeveritiesCorrectly() {

		assertEquals(Severity.CRITICAL, parseSeverity("BLOCKER"));
		assertEquals(Severity.CRITICAL, parseSeverity("CRITICAL"));
		assertEquals(Severity.HIGH, parseSeverity("MAJOR"));
		assertEquals(Severity.LOW, parseSeverity("MINOR"));
		assertEquals(Severity.LOW, parseSeverity("INFO"));
	}

	private Severity parseSeverity(String severity) {

		String report = """
				{
				    "total": 1,
				    "issues": [
				        {
				            "key": "test-issue",
				            "rule": "java:S1234",
				            "severity": "%s",
				            "component": "fixit:src/main/java/Test.java",
				            "line": 1,
				            "message": "Test issue",
				            "type": "CODE_SMELL",
				            "status": "OPEN"
				        }
				    ]
				}
				""".formatted(severity);

		return adapter.parseFindings(report).get(0).getSeverity();
	}

	private String readFixture(String path) throws IOException {

		try (InputStream inputStream = getClass().getResourceAsStream(path)) {

			if (inputStream == null) {
				throw new IOException("Test fixture not found: " + path);
			}

			return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
		}
	}
}
