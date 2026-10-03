package com.fixit.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VulnerableVersionRange {

    private String startIncluding;
    private String endExcluding;
}