package com.apm.utils;

import burp.*;
import com.apm.core.*;
import com.apm.models.*;
import java.io.*;
import java.util.*;

/**
 * Generates payloads and wordlists for testing
 */
public class PayloadGenerator {

    private final BurpExtender extender;
    private List<String> cachedWordlist;

    // Tier 1: Common parameters (always included)
    private static final String[] COMMON_PARAMS = {
            "id", "page", "sort", "filter", "limit", "offset", "order", "search",
            "callback", "redirect", "url", "next", "return", "redirect_uri",
            "debug", "test", "admin", "key", "token", "api_key",
            "username", "user", "email", "password", "pass",
            "q", "query", "s", "keyword", "term",
            "category", "cat", "type", "action", "method",
            "file", "path", "dir", "folder",
            "from", "to", "start", "end", "date",
            "status", "state", "mode", "format", "output",
            "lang", "language", "locale", "country",
            "ref", "referer", "source", "utm_source", "utm_campaign"
    };

    // Tier 2: Framework-specific parameters
    private static final String[] FRAMEWORK_PARAMS = {
            // PHP
            "PHPSESSID", "php_session", "__PHP_Incomplete_Class_Name",
            // Java/Spring
            "jsessionid", "spring_session", "SPRING_SECURITY_REMEMBER_ME_COOKIE",
            // .NET
            "aspxerrorpath", "aspxauth", "__VIEWSTATE", "__EVENTVALIDATION",
            // Rails
            "_rails_session", "authenticity_token",
            // Django
            "csrfmiddlewaretoken", "sessionid",
            // Node.js/Express
            "connect.sid", "express_session"
    };

    // Tier 3: API-specific parameters
    private static final String[] API_PARAMS = {
            "api_key", "apikey", "api_token", "access_token", "auth_token",
            "api_version", "v", "version", "format", "response_type",
            "client_id", "client_secret", "grant_type", "scope",
            "oauth_token", "bearer_token"
    };

    // Custom headers for header discovery
    private static final String[] CUSTOM_HEADERS = {
            "X-Api-Key", "X-Auth-Token", "X-Session-Id", "X-Request-Id",
            "X-Correlation-Id", "X-Trace-Id", "X-Custom-Header"
    };

    public PayloadGenerator(BurpExtender extender) {
        this.extender = extender;
    }

    public List<String> generateWordlist(IHttpRequestResponse request) {
        ConfigManager.WordlistTier tier = extender.getConfigManager().getConfig().wordlistTier;

        List<String> wordlist = new ArrayList<>();

        // Tier 1: Always include common params
        wordlist.addAll(Arrays.asList(COMMON_PARAMS));

        if (tier == ConfigManager.WordlistTier.NORMAL ||
                tier == ConfigManager.WordlistTier.DEEP ||
                tier == ConfigManager.WordlistTier.EXHAUSTIVE) {

            // Tier 2: Add framework-specific
            wordlist.addAll(Arrays.asList(FRAMEWORK_PARAMS));
            wordlist.addAll(Arrays.asList(API_PARAMS));

            // Add variations of existing parameters
            wordlist.addAll(generateVariations(request));
        }

        if (tier == ConfigManager.WordlistTier.DEEP ||
                tier == ConfigManager.WordlistTier.EXHAUSTIVE) {

            // Tier 3: Add from external wordlist
            wordlist.addAll(loadExternalWordlist());
        }

        if (tier == ConfigManager.WordlistTier.EXHAUSTIVE) {
            // Tier 4: Add comprehensive wordlist
            wordlist.addAll(loadComprehensiveWordlist());
        }

        // Remove duplicates
        return new ArrayList<>(new LinkedHashSet<>(wordlist));
    }

    private List<String> generateVariations(IHttpRequestResponse request) {
        List<String> variations = new ArrayList<>();

        IRequestInfo requestInfo = extender.getHelpers().analyzeRequest(request);

        // Get existing parameters
        for (IParameter param : requestInfo.getParameters()) {
            String name = param.getName();

            // Add variations
            variations.add(name + "_id");
            variations.add(name + "_key");
            variations.add(name + "_token");
            variations.add("new_" + name);
            variations.add("old_" + name);
            variations.add(name + "2");
            variations.add(name + "_backup");

            // Camel case variations
            if (name.contains("_")) {
                variations.add(toCamelCase(name));
            } else {
                variations.add(toSnakeCase(name));
            }
        }

        return variations;
    }

    private String toCamelCase(String snakeCase) {
        StringBuilder result = new StringBuilder();
        boolean capitalizeNext = false;

        for (char c : snakeCase.toCharArray()) {
            if (c == '_') {
                capitalizeNext = true;
            } else {
                if (capitalizeNext) {
                    result.append(Character.toUpperCase(c));
                    capitalizeNext = false;
                } else {
                    result.append(c);
                }
            }
        }

        return result.toString();
    }

    private String toSnakeCase(String camelCase) {
        return camelCase.replaceAll("([a-z])([A-Z])", "$1_$2").toLowerCase();
    }

    private List<String> loadExternalWordlist() {
        if (cachedWordlist != null) {
            return cachedWordlist;
        }

        List<String> wordlist = new ArrayList<>();

        try {
            InputStream is = getClass().getResourceAsStream("/wordlists/params.txt");
            if (is != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(is));
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        wordlist.add(line);
                    }
                }
                reader.close();
            }
        } catch (Exception e) {
            extender.getStderr().println("Error loading wordlist: " + e.getMessage());
        }

        cachedWordlist = wordlist;
        return wordlist;
    }

    private List<String> loadComprehensiveWordlist() {
        // Load comprehensive wordlist (would be a separate file)
        // For now, return extended list
        return loadExternalWordlist();
    }

    public List<String> getCustomHeaders() {
        return Arrays.asList(CUSTOM_HEADERS);
    }

    public String generateRandomValue() {
        return "apm_" + UUID.randomUUID().toString().substring(0, 8);
    }
}
