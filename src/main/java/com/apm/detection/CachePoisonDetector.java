package com.apm.detection;

import burp.*;
import com.apm.core.*;
import com.apm.models.*;
import com.apm.models.CachePoisonVulnerability.VulnerabilityType;
import com.apm.analysis.*;
import java.util.*;

/**
 * Cache Poisoning Detection Module
 */
public class CachePoisonDetector {

    private final BurpExtender extender;
    private final CacheBehaviorAnalyzer cacheAnalyzer;

    // Potentially unkeyed headers to test
    private static final String[] UNKEYED_HEADER_CANDIDATES = {
            "X-Forwarded-Host", "X-Forwarded-For", "X-Original-URL", "X-Rewrite-URL",
            "X-Forwarded-Server", "X-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
            "X-HTTP-Host-Override", "X-Custom-IP-Authorization", "Forwarded",
            "CF-Connecting-IP", "True-Client-IP", "X-Real-IP", "X-Client-IP"
    };

    public CachePoisonDetector(BurpExtender extender) {
        this.extender = extender;
        this.cacheAnalyzer = new CacheBehaviorAnalyzer(extender);
    }

    public List<CachePoisonVulnerability> detect(IHttpRequestResponse baseRequest) {
        List<CachePoisonVulnerability> vulnerabilities = new ArrayList<>();

        ConfigManager.ScanConfig config = extender.getConfigManager().getConfig();

        // First analyze cache behavior
        CacheAnalysisResult cacheAnalysis = cacheAnalyzer.analyze(baseRequest);

        if (!cacheAnalysis.isCached()) {
            extender.getStdout().println("    Response not cached, skipping cache poisoning tests");
            return vulnerabilities;
        }

        extender.getStdout().println("    Cache system detected: " + cacheAnalysis.getCacheSystem().displayName);

        // Test for unkeyed header poisoning
        if (config.detectUnkeyedHeaders) {
            vulnerabilities.addAll(detectUnkeyedHeaders(baseRequest, cacheAnalysis));
        }

        // Test for parameter cloaking
        if (config.detectParameterCloaking) {
            vulnerabilities.addAll(detectParameterCloaking(baseRequest));
        }

        // Test for Fat GET
        if (config.detectFatGET) {
            CachePoisonVulnerability fatGET = detectFatGET(baseRequest);
            if (fatGET != null) {
                vulnerabilities.add(fatGET);
            }
        }

        // Test for cache deception
        if (config.detectCacheDeception) {
            vulnerabilities.addAll(detectCacheDeception(baseRequest));
        }

        return vulnerabilities;
    }

    private List<CachePoisonVulnerability> detectUnkeyedHeaders(IHttpRequestResponse baseRequest,
            CacheAnalysisResult cacheAnalysis) {
        List<CachePoisonVulnerability> vulnerabilities = new ArrayList<>();

        extender.getStdout().println("      Testing for unkeyed headers...");

        for (String header : UNKEYED_HEADER_CANDIDATES) {
            try {
                if (testUnkeyedHeader(baseRequest, header)) {
                    String poc = generateUnkeyedHeaderPoC(baseRequest, header);
                    String evidence = "Header '" + header + "' affects response but is not part of cache key";

                    CachePoisonVulnerability vuln = new CachePoisonVulnerability(
                            VulnerabilityType.UNKEYED_HEADER,
                            "Unkeyed Header: " + header,
                            "The " + header + " header affects the application's response but is not included " +
                                    "in the cache key. This allows an attacker to poison the cache with malicious responses.",
                            ConfigManager.Severity.HIGH,
                            header,
                            evidence,
                            poc,
                            "Include " + header + " in the cache key or remove its influence on the response.",
                            true);

                    vulnerabilities.add(vuln);
                    extender.getStdout().println("        ⚠ Found unkeyed header: " + header);
                }

                Thread.sleep(extender.getConfigManager().getConfig().requestDelay);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                // Continue testing
            }
        }

        return vulnerabilities;
    }

    private boolean testUnkeyedHeader(IHttpRequestResponse baseRequest, String headerName) {
        try {
            // Step 1: Get baseline cached response
            IHttpRequestResponse baseline = sendRequest(baseRequest);
            ResponseFingerprint baselineFingerprint = new ResponseFingerprint(baseline, extender.getHelpers());

            // Wait for cache
            Thread.sleep(500);

            // Step 2: Send request with poisoned header
            String poisonValue = "evil.com";
            IHttpRequestResponse poisoned = addHeader(baseRequest, headerName, poisonValue);
            ResponseFingerprint poisonedFingerprint = new ResponseFingerprint(poisoned, extender.getHelpers());

            // Check if header affects response
            if (!poisonedFingerprint.isDifferentFrom(baselineFingerprint)) {
                return false; // Header doesn't affect response
            }

            // Step 3: Send baseline request again
            Thread.sleep(500);
            IHttpRequestResponse verification = sendRequest(baseRequest);
            ResponseFingerprint verificationFingerprint = new ResponseFingerprint(verification, extender.getHelpers());

            // Step 4: Check if cached response contains poison
            // If verification matches poisoned response, cache poisoning confirmed
            boolean isPoisoned = verificationFingerprint.isSimilarTo(poisonedFingerprint);

            // Step 5: Stability test
            if (isPoisoned) {
                // Clear cache and verify again
                Thread.sleep(2000);
                return verifyStability(baseRequest, headerName, poisonValue);
            }

            return false;

        } catch (Exception e) {
            return false;
        }
    }

    private boolean verifyStability(IHttpRequestResponse baseRequest, String headerName, String value) {
        int stabilityTests = extender.getConfigManager().getConfig().cacheStabilityTests;
        int successCount = 0;

        for (int i = 0; i < stabilityTests; i++) {
            try {
                if (testUnkeyedHeader(baseRequest, headerName)) {
                    successCount++;
                }
                Thread.sleep(1000);
            } catch (Exception e) {
                // Continue
            }
        }

        // Require at least 66% success rate
        return successCount >= (stabilityTests * 2 / 3);
    }

    private List<CachePoisonVulnerability> detectParameterCloaking(IHttpRequestResponse baseRequest) {
        List<CachePoisonVulnerability> vulnerabilities = new ArrayList<>();

        extender.getStdout().println("      Testing for parameter cloaking...");

        String[] testParams = { "utm_content", "callback", "redirect", "url" };

        for (String param : testParams) {
            try {
                if (testParameterCloaking(baseRequest, param)) {
                    String poc = generateCloakingPoC(baseRequest, param);

                    CachePoisonVulnerability vuln = new CachePoisonVulnerability(
                            VulnerabilityType.PARAMETER_CLOAKING,
                            "Parameter Cloaking: " + param,
                            "The parameter '" + param + "' is included in the cache key based on parameter name " +
                                    "but not value. This allows cache poisoning through parameter cloaking.",
                            ConfigManager.Severity.MEDIUM,
                            param,
                            "Parameter name affects cache key but value does not",
                            poc,
                            "Include parameter value in cache key or exclude parameter entirely.",
                            true);

                    vulnerabilities.add(vuln);
                    extender.getStdout().println("        ⚠ Found parameter cloaking: " + param);
                }

                Thread.sleep(extender.getConfigManager().getConfig().requestDelay);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                // Continue
            }
        }

        return vulnerabilities;
    }

    private boolean testParameterCloaking(IHttpRequestResponse baseRequest, String param) {
        try {
            // Test if param=value1 and param=value2 are cached as same
            IHttpRequestResponse test1 = addQueryParameter(baseRequest, param, "value1");
            Thread.sleep(500);

            IHttpRequestResponse test2 = addQueryParameter(baseRequest, param, "value2");
            Thread.sleep(500);

            ResponseFingerprint fp1 = new ResponseFingerprint(test1, extender.getHelpers());
            ResponseFingerprint fp2 = new ResponseFingerprint(test2, extender.getHelpers());

            // If both cached and same response, cloaking exists
            return fp1.isCached() && fp2.isCached() && fp1.isSimilarTo(fp2) && fp1.isDifferentFrom(fp2);

        } catch (Exception e) {
            return false;
        }
    }

    private CachePoisonVulnerability detectFatGET(IHttpRequestResponse baseRequest) {
        extender.getStdout().println("      Testing for Fat GET...");

        try {
            // Create GET request with body
            byte[] getWithBody = createGETWithBody(baseRequest, "{\"admin\":true}");
            IHttpRequestResponse test = extender.getCallbacks().makeHttpRequest(
                    baseRequest.getHttpService(),
                    getWithBody);

            ResponseFingerprint testFp = new ResponseFingerprint(test, extender.getHelpers());

            // Check if body affects response and is cached
            if (testFp.isCached() && testFp.hasSignificantChange()) {
                String poc = generateFatGETPoC(baseRequest);

                return new CachePoisonVulnerability(
                        VulnerabilityType.FAT_GET,
                        "Fat GET Cache Poisoning",
                        "GET request body affects the response and is cached. This allows cache poisoning " +
                                "through GET requests with a body payload.",
                        ConfigManager.Severity.HIGH,
                        "GET body",
                        "GET request with body is processed and cached",
                        poc,
                        "Reject GET requests with body or include body in cache key.",
                        true);
            }

        } catch (Exception e) {
            // Not vulnerable
        }

        return null;
    }

    private List<CachePoisonVulnerability> detectCacheDeception(IHttpRequestResponse baseRequest) {
        List<CachePoisonVulnerability> vulnerabilities = new ArrayList<>();

        extender.getStdout().println("      Testing for cache deception...");

        String[] pathSuffixes = {
                "/style.css", "/.css", ";.css", "?.css", "%0a.css", "%23.css", "/..%2fstatic.css"
        };

        for (String suffix : pathSuffixes) {
            try {
                if (testCacheDeception(baseRequest, suffix)) {
                    String poc = generateCacheDeceptionPoC(baseRequest, suffix);

                    CachePoisonVulnerability vuln = new CachePoisonVulnerability(
                            VulnerabilityType.CACHE_DECEPTION,
                            "Web Cache Deception via " + suffix,
                            "Dynamic content is cached when accessed with path suffix '" + suffix + "'. " +
                                    "This allows attackers to cache sensitive user data.",
                            ConfigManager.Severity.HIGH,
                            "Path: " + suffix,
                            "Dynamic content cached with static file suffix",
                            poc,
                            "Only cache requests with proper static file extensions.",
                            true);

                    vulnerabilities.add(vuln);
                    extender.getStdout().println("        ⚠ Found cache deception: " + suffix);
                }

                Thread.sleep(extender.getConfigManager().getConfig().requestDelay);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                // Continue
            }
        }

        return vulnerabilities;
    }

    private boolean testCacheDeception(IHttpRequestResponse baseRequest, String pathSuffix) {
        try {
            byte[] modifiedRequest = modifyPath(baseRequest, pathSuffix);
            IHttpRequestResponse test = extender.getCallbacks().makeHttpRequest(
                    baseRequest.getHttpService(),
                    modifiedRequest);

            ResponseFingerprint fp = new ResponseFingerprint(test, extender.getHelpers());

            // Check if response is cached and contains sensitive data
            return fp.isCached() && fp.hasSignificantContent();

        } catch (Exception e) {
            return false;
        }
    }

    // Helper methods
    private IHttpRequestResponse sendRequest(IHttpRequestResponse request) {
        return extender.getCallbacks().makeHttpRequest(
                request.getHttpService(),
                request.getRequest());
    }

    private IHttpRequestResponse addHeader(IHttpRequestResponse baseRequest, String name, String value) {
        byte[] request = baseRequest.getRequest();
        IRequestInfo requestInfo = extender.getHelpers().analyzeRequest(request);

        List<String> headers = new ArrayList<>(requestInfo.getHeaders());
        headers.add(name + ": " + value);

        byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
        byte[] newRequest = extender.getHelpers().buildHttpMessage(headers, body);

        return extender.getCallbacks().makeHttpRequest(baseRequest.getHttpService(), newRequest);
    }

    private IHttpRequestResponse addQueryParameter(IHttpRequestResponse baseRequest, String name, String value) {
        byte[] request = baseRequest.getRequest();
        IParameter param = extender.getHelpers().buildParameter(name, value, IParameter.PARAM_URL);
        byte[] newRequest = extender.getHelpers().addParameter(request, param);
        return extender.getCallbacks().makeHttpRequest(baseRequest.getHttpService(), newRequest);
    }

    private byte[] createGETWithBody(IHttpRequestResponse baseRequest, String body) {
        byte[] request = baseRequest.getRequest();
        IRequestInfo requestInfo = extender.getHelpers().analyzeRequest(request);

        List<String> headers = new ArrayList<>(requestInfo.getHeaders());
        // Ensure it's GET
        headers.set(0, headers.get(0).replaceFirst("POST", "GET"));

        return extender.getHelpers().buildHttpMessage(headers, body.getBytes());
    }

    private byte[] modifyPath(IHttpRequestResponse baseRequest, String suffix) {
        byte[] request = baseRequest.getRequest();
        IRequestInfo requestInfo = extender.getHelpers().analyzeRequest(request);

        List<String> headers = new ArrayList<>(requestInfo.getHeaders());
        String firstLine = headers.get(0);
        String modifiedLine = firstLine.replace(" HTTP/", suffix + " HTTP/");
        headers.set(0, modifiedLine);

        byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
        return extender.getHelpers().buildHttpMessage(headers, body);
    }

    // PoC Generators
    private String generateUnkeyedHeaderPoC(IHttpRequestResponse baseRequest, String header) {
        IRequestInfo info = extender.getHelpers().analyzeRequest(baseRequest);
        String url = info.getUrl().toString();

        return String.format(
                "# Unkeyed Header Cache Poisoning PoC\n\n" +
                        "## Steps:\n" +
                        "1. Send request with poisoned header:\n" +
                        "   %s: evil.com\n" +
                        "   GET %s\n\n" +
                        "2. Send normal request:\n" +
                        "   GET %s\n\n" +
                        "3. Observe that the poisoned response is cached and served to other users.\n\n" +
                        "## Impact:\n" +
                        "This can lead to XSS, phishing, or redirecting users to malicious sites.",
                header, url, url);
    }

    private String generateCloakingPoC(IHttpRequestResponse baseRequest, String param) {
        return String.format(
                "# Parameter Cloaking PoC\n\n" +
                        "Parameter '%s' exhibits cloaking behavior.\n" +
                        "Both %s=value1 and %s=value2 result in the same cached response.",
                param, param, param);
    }

    private String generateFatGETPoC(IHttpRequestResponse baseRequest) {
        return "# Fat GET PoC\n\nSend GET request with body payload to poison cache.";
    }

    private String generateCacheDeceptionPoC(IHttpRequestResponse baseRequest, String suffix) {
        IRequestInfo info = extender.getHelpers().analyzeRequest(baseRequest);
        return String.format(
                "# Cache Deception PoC\n\nAccess: %s%s\n" +
                        "Dynamic content will be cached as if it were static.",
                info.getUrl().toString(), suffix);
    }
}
