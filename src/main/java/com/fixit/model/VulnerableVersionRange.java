package com.fixit.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VulnerableVersionRange {

    private String startVersion;
    private boolean startInclusive;

    private String endVersion;
    private boolean endInclusive;
}