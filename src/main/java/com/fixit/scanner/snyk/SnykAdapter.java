package com.fixit.scanner.snyk;

import java.util.ArrayList;
import java.util.List;

import org.apache.maven.artifact.versioning.ComparableVersion;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fixit.model.Finding;
import com.fixit.model.ScannerType;
import com.fixit.model.Severity;
import com.fixit.model.VulnerableVersionRange;
import com.fixit.scanner.ScannerAdapter;
import com.fixit.scanner.snyk.model.SnykReport;
import com.fixit.scanner.snyk.model.SnykVulnerability;

public class SnykAdapter implements ScannerAdapter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public List<Finding> parseFindings(String scannerOutput) {

        System.out.println("[SNYK] Starting to parse report...");

        try {
            SnykReport report =
                    objectMapper.readValue(scannerOutput, SnykReport.class);

            System.out.println("[SNYK] Report parsed successfully.");

            List<Finding> findings = new ArrayList<>();

            if (report.getVulnerabilities() == null) {
                System.out.println("[SNYK] Report contains no vulnerability list.");
                return findings;
            }

            for (SnykVulnerability vulnerability : report.getVulnerabilities()) {

                Finding finding = new Finding();

                finding.setScanner(ScannerType.SNYK);
                finding.setVulnerabilityId(vulnerability.getId());
                finding.setTitle(vulnerability.getTitle());
                finding.setDescription(vulnerability.getDescription());
                finding.setSeverity(mapSeverity(vulnerability.getSeverity()));

                String component = vulnerability.getPackageName();

                if (component == null) {
                    component = vulnerability.getName();
                }

                finding.setComponent(component);
                finding.setCurrentVersion(vulnerability.getVersion());

                List<String> fixedVersions = vulnerability.getFixedIn();

                if (fixedVersions != null && !fixedVersions.isEmpty()) {

                finding.setAvailableFixedVersions(new ArrayList<>(fixedVersions));

                String highestVersion = fixedVersions.stream()
                        .filter(version -> version != null && !version.isBlank())
                        .max((version1, version2) ->
                                new ComparableVersion(version1)
                                        .compareTo(new ComparableVersion(version2)))
                        .orElse(null);

                finding.setFixedVersion(highestVersion);
                finding.setRemediationAvailable(highestVersion != null);

                } else {
                finding.setAvailableFixedVersions(new ArrayList<>());
                finding.setFixedVersion(null);
                finding.setRemediationAvailable(false);
                }

                finding.setLocation(
                        vulnerability.getFrom() == null
                                ? null
                                : String.join(" -> ", vulnerability.getFrom())
                );

                finding.setVulnerableVersionRanges(
                        mapVulnerableRanges(vulnerability)
                );

                findings.add(finding);
            }

            System.out.println("[SNYK] Total findings parsed: " + findings.size());

            return findings;

        } catch (Exception e) {
            System.out.println("[SNYK] Failed to parse report: " + e.getMessage());

            throw new IllegalArgumentException(
                    "Failed to parse Snyk output", e);
        }
    }

    private Severity mapSeverity(String severity) {

        if (severity == null) {
            return null;
        }

        return switch (severity.toLowerCase()) {
            case "critical" -> Severity.CRITICAL;
            case "high" -> Severity.HIGH;
            case "medium" -> Severity.MEDIUM;
            case "low" -> Severity.LOW;
            default -> throw new IllegalArgumentException(
                    "Unsupported Snyk severity: " + severity);
        };
    }

    private List<VulnerableVersionRange> mapVulnerableRanges(
            SnykVulnerability vulnerability) {

        List<VulnerableVersionRange> ranges = new ArrayList<>();

        if (vulnerability.getSemver() == null
                || vulnerability.getSemver().getVulnerable() == null) {
            return ranges;
        }

        for (String vulnerableRange : vulnerability.getSemver().getVulnerable()) {

            if (vulnerableRange == null || vulnerableRange.length() < 3) {
                continue;
            }

            int commaIndex = vulnerableRange.indexOf(',');

            if (commaIndex < 0) {
                continue;
            }

            char startBoundary = vulnerableRange.charAt(0);
            char endBoundary = vulnerableRange.charAt(vulnerableRange.length() - 1);

            String start = vulnerableRange.substring(1, commaIndex).trim();
            String end = vulnerableRange.substring(
                    commaIndex + 1, vulnerableRange.length() - 1).trim();

            VulnerableVersionRange range = new VulnerableVersionRange();

            if (!start.isEmpty()) {
                range.setStartVersion(start);
                range.setStartInclusive(startBoundary == '[');
            }

            if (!end.isEmpty()) {
                range.setEndVersion(end);
                range.setEndInclusive(endBoundary == ']');
            }

            ranges.add(range);
        }

        return ranges;
    }
}