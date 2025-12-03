package com.apm.analysis;

import burp.*;
import java.util.*;
import java.util.regex.*;

/**
 * Response Fingerprint for comparison
 */
public class ResponseFingerprint {

    private final IHttpRequestResponse response;
    private final IExtensionHelpers helpers;

    private int statusCode;
    private Map<String, String> headers;
    private String bodyHash;
    private String normalizedBody;
    private int bodyLength;
    private Set<String> reflections;
    private boolean cached;
    private boolean unkeyed;
    private long responseTime;

    public ResponseFingerprint(IHttpRequestResponse response, IExtensionHelpers helpers) {
        this.response = response;
        this.helpers = helpers;
        analyze();
    }

    private void analyze() {
        IResponseInfo responseInfo = helpers.analyzeResponse(response.getResponse());

        this.statusCode = responseInfo.getStatusCode();
        this.headers = extractHeaders(responseInfo.getHeaders());
        this.bodyLength = response.getResponse().length - responseInfo.getBodyOffset();
        this.normalizedBody = extractAndNormalizeBody();
        this.bodyHash = calculateHash(normalizedBody);
        this.reflections = findReflections();
        this.cached = detectCached();
        this.unkeyed = false; // Set by detection logic
    }

    private Map<String, String> extractHeaders(List<String> headersList) {
        Map<String, String> headerMap = new HashMap<>();

        for (String header : headersList) {
            if (header.contains(":")) {
                String[] parts = header.split(":", 2);
                headerMap.put(parts[0].trim().toLowerCase(), parts[1].trim());
            }
        }

        return headerMap;
    }

    private String extractAndNormalizeBody() {
        byte[] response = this.response.getResponse();
        IResponseInfo responseInfo = helpers.analyzeResponse(response);

        byte[] bodyBytes = Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length);
        String body = new String(bodyBytes);

        // Normalize: remove dynamic content
        body = removeDynamicContent(body);

        return body;
    }

    private String removeDynamicContent(String body) {
        // Remove common dynamic patterns

        // Timestamps
        body = body.replaceAll("\\d{10,13}", "TIMESTAMP");

        // UUIDs
        body = body.replaceAll("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "UUID");

        // CSRF tokens (common patterns)
        body = body.replaceAll("csrf[_-]?token[\"']?\\s*[:=]\\s*[\"']?[a-zA-Z0-9]{20,}", "CSRF_TOKEN");

        // Nonces
        body = body.replaceAll("nonce[\"']?\\s*[:=]\\s*[\"']?[a-zA-Z0-9]{10,}", "NONCE");

        // Session IDs
        body = body.replaceAll("session[_-]?id[\"']?\\s*[:=]\\s*[\"']?[a-zA-Z0-9]{20,}", "SESSION_ID");

        // Random strings (base64-like)
        body = body.replaceAll("[a-zA-Z0-9+/]{40,}={0,2}", "RANDOM_STRING");

        return body;
    }

    private String calculateHash(String content) {
        return String.valueOf(content.hashCode());
    }

    private Set<String> findReflections() {
        Set<String> reflections = new HashSet<>();

        // Extract test values from request
        IRequestInfo requestInfo = helpers.analyzeRequest(response.getRequest());

        // Check URL parameters
        for (IParameter param : requestInfo.getParameters()) {
            String value = param.getValue();
            if (value != null && !value.isEmpty() && normalizedBody.contains(value)) {
                reflections.add(param.getName() + "=" + value);
            }
        }

        // Check headers
        for (String header : requestInfo.getHeaders()) {
            if (header.toLowerCase().startsWith("x-") && header.contains(":")) {
                String[] parts = header.split(":", 2);
                if (parts.length == 2 && normalizedBody.contains(parts[1].trim())) {
                    reflections.add(parts[0].trim());
                }
            }
        }

        return reflections;
    }

    private boolean detectCached() {
        // Check cache indicators in headers
        for (Map.Entry<String, String> header : headers.entrySet()) {
            String key = header.getKey().toLowerCase();
            String value = header.getValue().toLowerCase();

            // Common cache headers
            if (key.equals("x-cache") && (value.contains("hit") || value.contains("cached"))) {
                return true;
            }
            if (key.equals("cf-cache-status") && value.equals("hit")) {
                return true;
            }
            if (key.equals("x-cache-hits") && !value.equals("0")) {
                return true;
            }
            if (key.equals("age") && Integer.parseInt(value.replaceAll("[^0-9]", "0")) > 0) {
                return true;
            }
        }

        return false;
    }

    // Comparison methods
    public boolean isDifferentFrom(ResponseFingerprint other) {
        // Status code difference
        if (this.statusCode != other.statusCode) {
            return true;
        }

        // Body hash difference
        if (!this.bodyHash.equals(other.bodyHash)) {
            return true;
        }

        // Significant header differences
        for (String key : Arrays.asList("content-length", "content-type", "location")) {
            String thisValue = this.headers.get(key);
            String otherValue = other.headers.get(key);

            if (thisValue != null && otherValue != null && !thisValue.equals(otherValue)) {
                return true;
            }
        }

        return false;
    }

    public boolean isSimilarTo(ResponseFingerprint other) {
        // Same status and similar body
        if (this.statusCode != other.statusCode) {
            return false;
        }

        double similarity = calculateSimilarity(this.normalizedBody, other.normalizedBody);
        return similarity > 0.95; // 95% similar
    }

    private double calculateSimilarity(String s1, String s2) {
        if (s1.equals(s2))
            return 1.0;
        if (s1.isEmpty() || s2.isEmpty())
            return 0.0;

        int maxLen = Math.max(s1.length(), s2.length());
        int distance = levenshteinDistance(s1, s2);

        return 1.0 - ((double) distance / maxLen);
    }

    private int levenshteinDistance(String s1, String s2) {
        // Simple approximation for performance
        if (s1.length() > 1000 || s2.length() > 1000) {
            // For large strings, use simple comparison
            return s1.equals(s2) ? 0 : Math.max(s1.length(), s2.length());
        }

        int[][] dp = new int[s1.length() + 1][s2.length() + 1];

        for (int i = 0; i <= s1.length(); i++) {
            dp[i][0] = i;
        }
        for (int j = 0; j <= s2.length(); j++) {
            dp[0][j] = j;
        }

        for (int i = 1; i <= s1.length(); i++) {
            for (int j = 1; j <= s2.length(); j++) {
                int cost = s1.charAt(i - 1) == s2.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1), dp[i - 1][j - 1] + cost);
            }
        }

        return dp[s1.length()][s2.length()];
    }

    public boolean reflectsValue(String value) {
        return normalizedBody.contains(value);
    }

    public boolean hasErrorMessage() {
        String lowerBody = normalizedBody.toLowerCase();
        return lowerBody.contains("error") ||
                lowerBody.contains("exception") ||
                lowerBody.contains("warning") ||
                statusCode >= 400;
    }

    public boolean hasSignificantChange() {
        return bodyLength > 100 && !reflections.isEmpty();
    }

    public boolean hasSignificantContent() {
        return bodyLength > 500;
    }

    public boolean hasReflection() {
        return !reflections.isEmpty();
    }

    // Getters
    public int getStatusCode() {
        return statusCode;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getBodyHash() {
        return bodyHash;
    }

    public String getNormalizedBody() {
        return normalizedBody;
    }

    public int getBodyLength() {
        return bodyLength;
    }

    public Set<String> getReflections() {
        return reflections;
    }

    public boolean isCached() {
        return cached;
    }

    public boolean isUnkeyed() {
        return unkeyed;
    }

    public void setUnkeyed(boolean unkeyed) {
        this.unkeyed = unkeyed;
    }

    public long getResponseTime() {
        return responseTime;
    }

    public String getReflectionSnippet() {
        if (reflections.isEmpty())
            return "";
        return reflections.iterator().next();
    }
}
