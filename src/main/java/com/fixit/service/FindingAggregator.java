
package com.fixit.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.fixit.model.Finding;

public class FindingAggregator {

    public List<Finding> aggregate(
            Collection<List<Finding>> scannerFindings) {

        List<Finding> consolidatedFindings = new ArrayList<>();

        if (scannerFindings == null) {
            return consolidatedFindings;
        }

        for (List<Finding> findings : scannerFindings) {

            if (findings == null || findings.isEmpty()) {
                continue;
            }

            consolidatedFindings.addAll(findings);
        }

        return consolidatedFindings;
    }
}
