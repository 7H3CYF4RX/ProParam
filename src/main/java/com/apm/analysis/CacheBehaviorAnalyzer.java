package com.apm.analysis;

import burp.*;
import com.apm.core.BurpExtender;
import com.apm.models.CacheAnalysisResult;
import com.apm.models.CacheAnalysisResult.CacheSystem;
import java.util.*;

/**
 * Analyzes cache behavior and fingerprints cache systems
 */
public class CacheBehaviorAnalyzer {

    private final BurpExtender extender;

    public CacheBehaviorAnalyzer(BurpExtender extender) {
        this.extender = extender;
    }

    public CacheAnalysisResult analyze(IHttpRequestResponse baseRequest) {
        IRequestInfo requestInfo = extender.getHelpers().analyzeRequest(baseRequest);
        String url = requestInfo.getUrl().toString();

        // Make request and analyze response
        IHttpRequestResponse response = extender.getCallbacks().makeHttpRequest(
                baseRequest.getHttpService(),
                baseRequest.getRequest());

        IResponseInfo responseInfo = extender.getHelpers().analyzeResponse(response.getResponse());
        Map<String, String> headers = extractHeaders(responseInfo.getHeaders());

        // Detect cache system
        CacheSystem cacheSystem = identifyCacheSystem(headers);

        // Check if cached
        boolean isCached = detectCached(headers);

        // Get TTL
        int ttl = extractTTL(headers);

        // Analyze cache key components
        List<String> keyedComponents = new ArrayList<>();
        List<String> unkeyedComponents = new ArrayList<>();
        analyzeCacheKeyComponents(baseRequest, keyedComponents, unkeyedComponents);

        // Build notes
        String notes = buildNotes(cacheSystem, isCached, ttl);

        return new CacheAnalysisResult(
                url,
                cacheSystem,
                isCached,
                ttl,
                headers,
                keyedComponents,
                unkeyedComponents,
                notes);
    }

    private CacheSystem identifyCacheSystem(Map<String, String> headers) {
        // Check for Cloudflare
        if (headers.containsKey("cf-cache-status") || headers.containsKey("cf-ray")) {
            return CacheSystem.CLOUDFLARE;
        }

        // Check for Akamai
        if (headers.containsKey("x-akamai-request-id") || headers.containsKey("x-akamai-session-info")) {
            return CacheSystem.AKAMAI;
        }

        // Check for Fastly
        if (headers.containsKey("x-served-by") && headers.get("x-served-by").contains("fastly")) {
            return CacheSystem.FASTLY;
        }
        if (headers.containsKey("fastly-io-info")) {
            return CacheSystem.FASTLY;
        }

        // Check for Varnish
        if (headers.containsKey("x-varnish") || headers.containsKey("via") &&
                headers.get("via").toLowerCase().contains("varnish")) {
            return CacheSystem.VARNISH;
        }

        // Check for Nginx
        if (headers.containsKey("x-nginx-cache-status") || headers.containsKey("x-microcache")) {
            return CacheSystem.NGINX;
        }

        // Check for CloudFront
        if (headers.containsKey("x-amz-cf-id") || headers.containsKey("x-amz-cf-pop")) {
            return CacheSystem.CLOUDFRONT;
        }

        // Check for Apache Traffic Server
        if (headers.containsKey("x-ats-cache-status")) {
            return CacheSystem.APACHE_TRAFFIC_SERVER;
        }

        // Check for generic cache headers
        if (headers.containsKey("x-cache") || headers.containsKey("age")) {
            return CacheSystem.CUSTOM;
        }

        return CacheSystem.UNKNOWN;
    }

    private boolean detectCached(Map<String, String> headers) {
        // Check X-Cache header
        String xCache = headers.get("x-cache");
        if (xCache != null && (xCache.toLowerCase().contains("hit") ||
                xCache.toLowerCase().contains("cached"))) {
            return true;
        }

        // Check CF-Cache-Status
        String cfCache = headers.get("cf-cache-status");
        if (cfCache != null && cfCache.equalsIgnoreCase("hit")) {
            return true;
        }

        // Check X-Cache-Hits
        String cacheHits = headers.get("x-cache-hits");
        if (cacheHits != null && !cacheHits.equals("0")) {
            return true;
        }

        // Check Age header (> 0 means cached)
        String age = headers.get("age");
        if (age != null) {
            try {
                return Integer.parseInt(age) > 0;
            } catch (NumberFormatException e) {
                // Ignore
            }
        }

        return false;
    }

    private int extractTTL(Map<String, String> headers) {
        // Try Cache-Control max-age
        String cacheControl = headers.get("cache-control");
        if (cacheControl != null && cacheControl.contains("max-age=")) {
            try {
                String maxAge = cacheControl.substring(cacheControl.indexOf("max-age=") + 8);
                maxAge = maxAge.split("[,;]")[0].trim();
                return Integer.parseInt(maxAge);
            } catch (Exception e) {
                // Continue to next method
            }
        }

        // Try Expires header
        String expires = headers.get("expires");
        if (expires != null) {
            // Simplified - would need proper date parsing
            return 3600; // Default 1 hour
        }

        return 0; // No TTL found
    }

    private void analyzeCacheKeyComponents(IHttpRequestResponse request,
            List<String> keyed,
            List<String> unkeyed) {
        // Default cache key components (most caches)
        keyed.add("URL Path");
        keyed.add("Query String");
        keyed.add("Host Header");

        // Typically not in cache key
        unkeyed.add("User-Agent");
        unkeyed.add("Accept-Language");
        unkeyed.add("Accept-Encoding");
        unkeyed.add("Cookie");
        unkeyed.add("Authorization");
        unkeyed.add("X-Forwarded-For");
        unkeyed.add("X-Forwarded-Host");
        unkeyed.add("Referer");
    }

    private Map<String, String> extractHeaders(List<String> headersList) {
        Map<String, String> headers = new HashMap<>();

        for (String header : headersList) {
            if (header.contains(":")) {
                String[] parts = header.split(":", 2);
                headers.put(parts[0].trim().toLowerCase(), parts[1].trim());
            }
        }

        return headers;
    }

    private String buildNotes(CacheSystem system, boolean cached, int ttl) {
        StringBuilder notes = new StringBuilder();

        notes.append("Cache System: ").append(system.displayName).append("\n");
        notes.append("Cached: ").append(cached ? "Yes" : "No").append("\n");

        if (ttl > 0) {
            notes.append("TTL: ").append(ttl).append(" seconds (")
                    .append(ttl / 60).append(" minutes)\n");
        }

        if (system == CacheSystem.CLOUDFLARE) {
            notes.append("\nCloudflare-specific considerations:\n");
            notes.append("- Respect Cache-Control headers\n");
            notes.append("- Custom cache rules may apply\n");
        } else if (system == CacheSystem.VARNISH) {
            notes.append("\nVarnish-specific considerations:\n");
            notes.append("- VCL rules may customize behavior\n");
            notes.append("- Check for custom cache key logic\n");
        }

        return notes.toString();
    }
}
