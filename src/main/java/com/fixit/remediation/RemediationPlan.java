package com.fixit.remediation;

import java.util.List;

import com.fixit.compatibility.CompatibilityAnalysis;
import com.fixit.model.Finding;

public class RemediationPlan {
	
	private Finding finding;

	private RemediationType type;

	private RemediationStatus status;

	private List<RemediationChange> changes;
	
	private CompatibilityAnalysis compatibilityAnalysis;

}
