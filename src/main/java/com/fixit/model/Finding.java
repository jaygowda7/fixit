package com.fixit.model;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Finding {
	
	private String id;
	private ScannerType scanner;
	private String vulnerabilityId;
	private String title;
	private String description;
	private Severity severity;
	private String component;
	private String currentVersion;
	private String fixedVersion;
	private String location;
	private boolean remediationAvailable;
	private List<VulnerableVersionRange> vulnerableVersionRanges;

}
