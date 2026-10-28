package com.fixit.scanner.snyk.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class SnykReport {

    private List<SnykVulnerability> vulnerabilities;
    private String displayTargetFile;
    private String projectName;
}