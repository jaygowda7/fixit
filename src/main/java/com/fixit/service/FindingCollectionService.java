
package com.fixit.service;

import java.util.Collection;
import java.util.List;

import com.fixit.model.Finding;

public class FindingCollectionService {

    private final FindingAggregator findingAggregator;

    public FindingCollectionService(FindingAggregator findingAggregator) {
        this.findingAggregator = findingAggregator;
    }

    public List<Finding> collect(
            Collection<List<Finding>> scannerFindings) {

        return findingAggregator.aggregate(scannerFindings);
    }
}
