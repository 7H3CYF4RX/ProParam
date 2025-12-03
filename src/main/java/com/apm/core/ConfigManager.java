package com.apm.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.*;
import java.util.*;

/**
 * Configuration Manager for the extension
 */
public class ConfigManager {

    private final BurpExtender extender;
    private final Gson gson;
    private ScanConfig config;

    public ConfigManager(BurpExtender extender) {
        this.extender = extender;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
    }

    public void loadDefaultConfig() {
        config = new ScanConfig();

        // Default scan settings
        config.threadCount = 10;
        config.requestDelay = 100;
        config.followRedirects = true;
        config.inScopeOnly = true;

        // Discovery settings
        config.wordlistTier = WordlistTier.NORMAL;
        config.includeHeaders = true;
        config.includeCookies = true;
        config.includeJsonParams = true;
        config.includeXmlParams = true;
        config.maxParametersToTest = 1000;

        // Cache poisoning settings
        config.enableCacheAnalysis = true;
        config.autoVerifyFindings = true;
        config.cacheStabilityTests = 3;
        config.detectUnkeyedHeaders = true;
        config.detectParameterCloaking = true;
        config.detectFatGET = true;
        config.detectCacheDeception = true;

        // Reporting settings
        config.autoGeneratePoCs = true;
        config.createBurpIssues = true;
        config.minSeverityToReport = Severity.LOW;

        extender.getStdout().println("✓ Default configuration loaded");
    }

    public void saveConfig(File file) {
        try (FileWriter writer = new FileWriter(file)) {
            gson.toJson(config, writer);
            extender.getStdout().println("Configuration saved to: " + file.getAbsolutePath());
        } catch (IOException e) {
            extender.getStderr().println("Error saving configuration: " + e.getMessage());
        }
    }

    public void loadConfig(File file) {
        try (FileReader reader = new FileReader(file)) {
            config = gson.fromJson(reader, ScanConfig.class);
            extender.getStdout().println("Configuration loaded from: " + file.getAbsolutePath());
        } catch (IOException e) {
            extender.getStderr().println("Error loading configuration: " + e.getMessage());
            loadDefaultConfig();
        }
    }

    public ScanConfig getConfig() {
        return config;
    }

    public void setConfig(ScanConfig config) {
        this.config = config;
    }

    // Configuration class
    public static class ScanConfig {
        // Scan settings
        public int threadCount;
        public int requestDelay;
        public boolean followRedirects;
        public boolean inScopeOnly;

        // Discovery settings
        public WordlistTier wordlistTier;
        public boolean includeHeaders;
        public boolean includeCookies;
        public boolean includeJsonParams;
        public boolean includeXmlParams;
        public int maxParametersToTest;

        // Cache poisoning settings
        public boolean enableCacheAnalysis;
        public boolean autoVerifyFindings;
        public int cacheStabilityTests;
        public boolean detectUnkeyedHeaders;
        public boolean detectParameterCloaking;
        public boolean detectFatGET;
        public boolean detectCacheDeception;

        // Reporting settings
        public boolean autoGeneratePoCs;
        public boolean createBurpIssues;
        public Severity minSeverityToReport;
    }

    public enum WordlistTier {
        FAST(100),
        NORMAL(500),
        DEEP(2000),
        EXHAUSTIVE(5000);

        public final int size;

        WordlistTier(int size) {
            this.size = size;
        }
    }

    public enum Severity {
        INFO(0),
        LOW(1),
        MEDIUM(2),
        HIGH(3),
        CRITICAL(4);

        public final int level;

        Severity(int level) {
            this.level = level;
        }
    }
}
