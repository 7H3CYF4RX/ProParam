package com.apm.models;

import com.apm.core.ConfigManager.Severity;

/**
 * Represents a discovered parameter or header
 */
public class ParameterInfo {

    private final String name;
    private final ParameterType type;
    private final String evidence;
    private final Severity severity;
    private final boolean cached;
    private final boolean unkeyed;
    private final String testValue;
    private final String responseSnippet;

    public ParameterInfo(String name, ParameterType type, String evidence, Severity severity) {
        this(name, type, evidence, severity, false, false, "", "");
    }

    public ParameterInfo(String name, ParameterType type, String evidence, Severity severity,
            boolean cached, boolean unkeyed, String testValue, String responseSnippet) {
        this.name = name;
        this.type = type;
        this.evidence = evidence;
        this.severity = severity;
        this.cached = cached;
        this.unkeyed = unkeyed;
        this.testValue = testValue;
        this.responseSnippet = responseSnippet;
    }

    public String getName() {
        return name;
    }

    public ParameterType getType() {
        return type;
    }

    public String getEvidence() {
        return evidence;
    }

    public Severity getSeverity() {
        return severity;
    }

    public boolean isCached() {
        return cached;
    }

    public boolean isUnkeyed() {
        return unkeyed;
    }

    public String getTestValue() {
        return testValue;
    }

    public String getResponseSnippet() {
        return responseSnippet;
    }

    @Override
    public String toString() {
        return String.format("%s (%s) - %s", name, type, evidence);
    }

    public enum ParameterType {
        QUERY("Query Parameter"),
        POST_BODY("POST Body Parameter"),
        JSON("JSON Parameter"),
        XML("XML Parameter"),
        COOKIE("Cookie"),
        HEADER("HTTP Header"),
        PATH("URL Path Segment");

        public final String displayName;

        ParameterType(String displayName) {
            this.displayName = displayName;
        }
    }
}
