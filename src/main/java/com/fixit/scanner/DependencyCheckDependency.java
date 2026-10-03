package com.fixit.scanner;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Getter;
import lombok.Setter;

@JsonIgnoreProperties(ignoreUnknown = true)
@Getter
@Setter
public class DependencyCheckDependency {

    private String fileName;

    private List<DependencyCheckPackage> packages;

    private List<DependencyCheckVulnerability> vulnerabilities;
}
