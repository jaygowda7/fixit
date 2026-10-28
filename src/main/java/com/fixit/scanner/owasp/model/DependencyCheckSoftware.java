package com.fixit.scanner.owasp.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Getter;
import lombok.Setter;

@JsonIgnoreProperties(ignoreUnknown = true)
@Getter
@Setter
public class DependencyCheckSoftware {

    private String id;
    private String versionStartIncluding;
    private String versionEndExcluding;
}
