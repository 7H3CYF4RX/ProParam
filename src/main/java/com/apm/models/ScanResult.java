package com.apm.models;

import burp.IHttpRequestResponse;
import java.util.*;

/**
 * Represents the result of a scan
 */
public class ScanResult {

    private final String scanId;
    private final IHttpRequestResponse baseRequest;
    private final long startTime;
    private long endTime;

    private final List<ParameterInfo> parameters;
    private final List<CachePoisonVulnerability> vulnerabilities;
    private CacheAnalysisResult cacheAnalysis;

    public ScanResult(String scanId, IHttpRequestResponse baseRequest) {
        this.scanId = scanId;
        this.baseRequest = baseRequest;
        this.startTime = System.currentTimeMillis();
        this.parameters = new ArrayList<>();
        this.vulnerabilities = new ArrayList<>();
    }

    public void addParameter(ParameterInfo param) {
        parameters.add(param);
    }

    public void addParameters(List<ParameterInfo> params) {
        parameters.addAll(params);
    }

    public void addVulnerability(CachePoisonVulnerability vuln) {
        vulnerabilities.add(vuln);
    }

    public void addVulnerabilities(List<CachePoisonVulnerability> vulns) {
        vulnerabilities.addAll(vulns);
    }

    public void setCacheAnalysis(CacheAnalysisResult analysis) {
        this.cacheAnalysis = analysis;
    }

    public void complete() {
        this.endTime = System.currentTimeMillis();
    }

    // Getters
    public String getScanId() {
        return scanId;
    }

    public IHttpRequestResponse getBaseRequest() {
        return baseRequest;
    }

    public long getStartTime() {
        return startTime;
    }

    public long getEndTime() {
        return endTime;
    }

    public long getDuration() {
        return endTime - startTime;
    }

    public List<ParameterInfo> getParameters() {
        return new ArrayList<>(parameters);
    }

    public List<CachePoisonVulnerability> getVulnerabilities() {
        return new ArrayList<>(vulnerabilities);
    }

    public CacheAnalysisResult getCacheAnalysis() {
        return cacheAnalysis;
    }

    public boolean hasFindings() {
        return !parameters.isEmpty() || !vulnerabilities.isEmpty();
    }

    public int getFindingsCount() {
        return parameters.size() + vulnerabilities.size();
    }
}
