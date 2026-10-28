package com.fixit.scanner.sonarqube.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class SonarQubeIssuesResponse {

    private int total;
    private List<SonarQubeIssue> issues;
}