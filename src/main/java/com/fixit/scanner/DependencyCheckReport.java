package com.fixit.scanner;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Getter;
import lombok.Setter;

@JsonIgnoreProperties(ignoreUnknown = true)
@Getter
@Setter
public class DependencyCheckReport {

    private List<DependencyCheckDependency> dependencies;

}
