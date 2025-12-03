package com.apm.models;

import java.util.*;

/**
 * Result of cache behavior analysis
 */
public class CacheAnalysisResult {

    private final String url;
    private final CacheSystem cacheSystem;
    private final boolean isCached;
    private final int ttl;
    private final Map<String, String> cacheHeaders;
    private final List<String> keyedComponents;
    private final List<String> unkeyedComponents;
    private final String notes;

    public CacheAnalysisResult(String url, CacheSystem cacheSystem, boolean isCached,
            int ttl, Map<String, String> cacheHeaders,
            List<String> keyedComponents, List<String> unkeyedComponents,
            String notes) {
        this.url = url;
        this.cacheSystem = cacheSystem;
        this.isCached = isCached;
        this.ttl = ttl;
        this.cacheHeaders = cacheHeaders;
        this.keyedComponents = keyedComponents;
        this.unkeyedComponents = unkeyedComponents;
        this.notes = notes;
    }

    public String getUrl() {
        return url;
    }

    public CacheSystem getCacheSystem() {
        return cacheSystem;
    }

    public boolean isCached() {
        return isCached;
    }

    public int getTtl() {
        return ttl;
    }

    public Map<String, String> getCacheHeaders() {
        return cacheHeaders;
    }

    public List<String> getKeyedComponents() {
        return keyedComponents;
    }

    public List<String> getUnkeyedComponents() {
        return unkeyedComponents;
    }

    public String getNotes() {
        return notes;
    }

    public enum CacheSystem {
        CLOUDFLARE("Cloudflare"),
        AKAMAI("Akamai"),
        FASTLY("Fastly"),
        VARNISH("Varnish"),
        NGINX("Nginx"),
        APACHE_TRAFFIC_SERVER("Apache Traffic Server"),
        CLOUDFRONT("CloudFront"),
        CUSTOM("Custom"),
        UNKNOWN("Unknown");

        public final String displayName;

        CacheSystem(String displayName) {
            this.displayName = displayName;
        }
    }
}
