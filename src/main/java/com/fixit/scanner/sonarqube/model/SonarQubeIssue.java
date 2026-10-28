package com.fixit.scanner.sonarqube.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class SonarQubeIssue {

    private String key;
    private String rule;
    private String severity;
    private String component;
    private Integer line;
    private String message;
    private String type;
    private String status;
}