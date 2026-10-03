package com.fixit.scanner;

import java.util.List;

import com.fixit.model.Finding;

public interface ScannerAdapter {
	
	List<Finding> parseFindings(String scannerOutput);

}
