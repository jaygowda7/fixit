package com.fixit.scanner;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fixit.model.Finding;
import com.fixit.model.ScannerType;
import com.fixit.model.Severity;
import com.fixit.model.VulnerableVersionRange;

public class OWASPDependencyCheckAdapter implements ScannerAdapter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public List<Finding> parseFindings(String scannerOutput) {

        List<Finding> findings = new ArrayList<>();

        try {
            DependencyCheckReport report =
                    objectMapper.readValue(scannerOutput, DependencyCheckReport.class);

            for (DependencyCheckDependency dependency : report.getDependencies()) {
            	
            	if (dependency.getVulnerabilities() == null) {
            	    continue;
            	}

            	for (DependencyCheckVulnerability vulnerability : dependency.getVulnerabilities()) {

            	    Finding finding = new Finding();

            	    finding.setScanner(ScannerType.OWASP_DEPENDENCY_CHECK);
            	    finding.setVulnerabilityId(vulnerability.getName());

            	    finding.setSeverity(
            	            Severity.valueOf(vulnerability.getSeverity().toUpperCase())
            	    );

            	    finding.setDescription(vulnerability.getDescription());
            	    
            	    String packageId = null;

            	    if (dependency.getPackages() != null && !dependency.getPackages().isEmpty()) {
            	        packageId = dependency.getPackages().get(0).getId();
            	    }

            	    if (packageId != null) {
            	        finding.setComponent(extractComponent(packageId));
            	        finding.setCurrentVersion(extractVersion(packageId));
            	    } else {
            	        finding.setComponent(dependency.getFileName());
            	    }
            	    
            	    finding.setRemediationAvailable(false);

            	    List<VulnerableVersionRange> ranges = new ArrayList<>();

            	    if (vulnerability.getVulnerableSoftware() != null) {

            	        for (DependencyCheckVulnerableSoftware vulnerableSoftware
            	                : vulnerability.getVulnerableSoftware()) {

            	            DependencyCheckSoftware software =
            	                    vulnerableSoftware.getSoftware();

            	            if (software != null) {

            	                VulnerableVersionRange range =
            	                        new VulnerableVersionRange();

            	                range.setStartIncluding(
            	                        software.getVersionStartIncluding()
            	                );

            	                range.setEndExcluding(
            	                        software.getVersionEndExcluding()
            	                );

            	                if (range.getStartIncluding() != null
            	                        || range.getEndExcluding() != null) {

            	                    ranges.add(range);
            	                }
            	            }
            	        }
            	    }

            	    finding.setVulnerableVersionRanges(ranges);

            	    findings.add(finding);
            	}
            }

            return findings;

        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Failed to parse OWASP Dependency-Check output", e);
        }
    }
    
    private String extractComponent(String packageId) {

        if (packageId == null || !packageId.startsWith("pkg:maven/")) {
            return null;
        }

        String purl = packageId.substring("pkg:maven/".length());

        String[] parts = purl.split("@", 2);

        String coordinates = parts[0];

        String[] coordinateParts = coordinates.split("/", 2);

        if (coordinateParts.length != 2) {
            return null;
        }

        return coordinateParts[0] + ":" + coordinateParts[1];
    }
    
    private String extractVersion(String packageId) {

        if (packageId == null) {
            return null;
        }

        String[] parts = packageId.split("@", 2);

        return parts.length == 2 ? parts[1] : null;
    }
    
    
}