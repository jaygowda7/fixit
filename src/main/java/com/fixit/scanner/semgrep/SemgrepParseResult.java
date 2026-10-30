
package com.fixit.scanner.semgrep;

import java.util.List;

import com.fixit.model.Finding;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SemgrepParseResult {

    private List<Finding> findings;
    private int skippedFindingsCount;
}
