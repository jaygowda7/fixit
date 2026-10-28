
package com.fixit.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fixit.model.Finding;
import com.fixit.model.ScannerType;
import com.fixit.scanner.ScannerAdapter;

public class ScannerReportCollectionService {

    private final Map<ScannerType, ScannerAdapter> scannerAdapters;
    private final FindingCollectionService findingCollectionService;

    public ScannerReportCollectionService(
            Map<ScannerType, ScannerAdapter> scannerAdapters,
            FindingCollectionService findingCollectionService) {

        if (scannerAdapters == null) {
            throw new IllegalArgumentException(
                    "Scanner adapters cannot be null"
            );
        }

        if (findingCollectionService == null) {
            throw new IllegalArgumentException(
                    "Finding collection service cannot be null"
            );
        }

        this.scannerAdapters = Map.copyOf(scannerAdapters);
        this.findingCollectionService = findingCollectionService;
    }

    public List<Finding> collect(
            Map<ScannerType, String> scannerReports) {

        if (scannerReports == null || scannerReports.isEmpty()) {
            return findingCollectionService.collect(List.of());
        }

        List<List<Finding>> findingsByScanner = new ArrayList<>();

        for (Map.Entry<ScannerType, String> entry
                : scannerReports.entrySet()) {

            ScannerType scannerType = entry.getKey();
            String scannerOutput = entry.getValue();

            if (scannerType == null) {
                throw new IllegalArgumentException(
                        "Scanner type cannot be null"
                );
            }

            if (scannerOutput == null || scannerOutput.isBlank()) {
                throw new IllegalArgumentException(
                        "Scanner report cannot be null or blank: "
                                + scannerType
                );
            }

            ScannerAdapter adapter = scannerAdapters.get(scannerType);

            if (adapter == null) {
                throw new IllegalArgumentException(
                        "No adapter configured for scanner: "
                                + scannerType
                );
            }

            System.out.println(
                    "[FIXIT] Processing report from: " + scannerType
            );

            List<Finding> findings =
                    adapter.parseFindings(scannerOutput);

            if (findings == null) {
                throw new IllegalStateException(
                        "Scanner adapter returned null findings: "
                                + scannerType
                );
            }

            System.out.println(
                    "[FIXIT] Findings parsed from "
                            + scannerType + ": " + findings.size()
            );

            findingsByScanner.add(findings);
        }

        List<Finding> consolidatedFindings =
                findingCollectionService.collect(findingsByScanner);

        System.out.println(
                "[FIXIT] Total consolidated findings: "
                        + consolidatedFindings.size()
        );

        return consolidatedFindings;
    }
}
