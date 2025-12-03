package com.apm.detection;

import burp.*;
import com.apm.core.*;
import com.apm.models.*;
import com.apm.utils.*;
import com.apm.analysis.*;
import java.util.*;

/**
 * Header Discovery Module
 */
public class HeaderDiscovery {

    private final BurpExtender extender;
    private final PayloadGenerator payloadGenerator;
    private final DifferenceDetector differenceDetector;

    // Common headers to test
    private static final String[] COMMON_HEADERS = {
            "X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL",
            "X-Custom-IP-Authorization", "X-Originating-IP", "X-Remote-IP", "X-Client-IP",
            "X-Real-IP", "X-Host", "X-Forwarded-Server", "X-Forwarded-Proto",
            "Forwarded", "CF-Connecting-IP", "True-Client-IP", "X-ProxyUser-Ip",
            "X-Original-Host", "X-HTTP-Host-Override", "X-Forwarded-Scheme",
            "X-Frame-Options", "X-Debug", "X-Debug-Mode", "X-Test", "X-Development",
            "Accept-Language", "Accept-Encoding", "User-Agent", "Referer",
            "Cookie", "Authorization", "X-Api-Version", "X-Requested-With"
    };

    public HeaderDiscovery(BurpExtender extender) {
        this.extender = extender;
        this.payloadGenerator = new PayloadGenerator(extender);
        this.differenceDetector = new DifferenceDetector(extender);
    }

    public List<ParameterInfo> discover(IHttpRequestResponse baseRequest) {
        List<ParameterInfo> discovered = new ArrayList<>();

        try {
            // Get baseline
            ResponseFingerprint baseline = getBaseline(baseRequest);

            // Get headers to test
            List<String> headersToTest = getHeadersToTest();

            // Test each header
            for (String header : headersToTest) {
                ParameterInfo result = testHeader(baseRequest, header, baseline);
                if (result != null) {
                    discovered.add(result);
                    extender.getStdout().println("    ✓ Found header: " + header);
                }

                // Rate limiting
                Thread.sleep(extender.getConfigManager().getConfig().requestDelay);
            }

        } catch (Exception e) {
            extender.getStderr().println("Error in header discovery: " + e.getMessage());
        }

        return discovered;
    }

    private ParameterInfo testHeader(IHttpRequestResponse baseRequest, String headerName,
            ResponseFingerprint baseline) {
        try {
            String testValue = generateTestValue(headerName);
            IHttpRequestResponse testRequest = addHeader(baseRequest, headerName, testValue);

            if (testRequest == null)
                return null;

            ResponseFingerprint testResponse = getResponse(testRequest);

            // Check for meaningful difference
            if (differenceDetector.hasMeaningfulDifference(baseline, testResponse)) {
                // Validate with second test
                if (validateHeader(baseRequest, headerName, baseline)) {
                    String evidence = differenceDetector.getEvidenceDescription(baseline, testResponse);
                    ConfigManager.Severity severity = determineHeaderSeverity(headerName, testResponse);

                    return new ParameterInfo(
                            headerName,
                            ParameterInfo.ParameterType.HEADER,
                            evidence,
                            severity,
                            testResponse.isCached(),
                            testResponse.isUnkeyed(),
                            testValue,
                            testResponse.getReflectionSnippet());
                }
            }

        } catch (Exception e) {
            // Continue testing other headers
        }

        return null;
    }

    private boolean validateHeader(IHttpRequestResponse baseRequest, String headerName,
            ResponseFingerprint baseline) {
        try {
            // Test with two different values
            String value1 = generateTestValue(headerName) + "_1";
            String value2 = generateTestValue(headerName) + "_2";

            IHttpRequestResponse test1 = addHeader(baseRequest, headerName, value1);
            IHttpRequestResponse test2 = addHeader(baseRequest, headerName, value2);

            if (test1 == null || test2 == null)
                return false;

            ResponseFingerprint resp1 = getResponse(test1);
            ResponseFingerprint resp2 = getResponse(test2);

            // Should show consistent behavior
            return resp1.isDifferentFrom(baseline) && resp2.isDifferentFrom(baseline);

        } catch (Exception e) {
            return false;
        }
    }

    private List<String> getHeadersToTest() {
        List<String> headers = new ArrayList<>();

        // Add common headers
        headers.addAll(Arrays.asList(COMMON_HEADERS));

        // Add custom headers from wordlist if in deep mode
        ConfigManager.WordlistTier tier = extender.getConfigManager().getConfig().wordlistTier;
        if (tier == ConfigManager.WordlistTier.DEEP || tier == ConfigManager.WordlistTier.EXHAUSTIVE) {
            headers.addAll(payloadGenerator.getCustomHeaders());
        }

        return headers;
    }

    private IHttpRequestResponse addHeader(IHttpRequestResponse baseRequest, String name, String value) {
        try {
            byte[] request = baseRequest.getRequest();
            IRequestInfo requestInfo = extender.getHelpers().analyzeRequest(request);

            List<String> headers = new ArrayList<>(requestInfo.getHeaders());

            // Remove existing header with same name
            headers.removeIf(h -> h.toLowerCase().startsWith(name.toLowerCase() + ":"));

            // Add new header
            headers.add(name + ": " + value);

            // Rebuild request
            byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
            byte[] newRequest = extender.getHelpers().buildHttpMessage(headers, body);

            return extender.getCallbacks().makeHttpRequest(baseRequest.getHttpService(), newRequest);

        } catch (Exception e) {
            return null;
        }
    }

    private ResponseFingerprint getBaseline(IHttpRequestResponse request) {
        IHttpRequestResponse response = extender.getCallbacks().makeHttpRequest(
                request.getHttpService(),
                request.getRequest());
        return new ResponseFingerprint(response, extender.getHelpers());
    }

    private ResponseFingerprint getResponse(IHttpRequestResponse request) {
        IHttpRequestResponse response = extender.getCallbacks().makeHttpRequest(
                request.getHttpService(),
                request.getRequest());
        return new ResponseFingerprint(response, extender.getHelpers());
    }

    private String generateTestValue(String headerName) {
        if (headerName.toLowerCase().contains("ip") || headerName.toLowerCase().contains("forwarded")) {
            return "127.0.0.1";
        } else if (headerName.toLowerCase().contains("host")) {
            return "evil.com";
        } else if (headerName.toLowerCase().contains("url")) {
            return "/admin";
        } else if (headerName.toLowerCase().contains("user-agent")) {
            return "APM-Scanner/1.0";
        } else {
            return "apm_test_" + UUID.randomUUID().toString().substring(0, 8);
        }
    }

    private ConfigManager.Severity determineHeaderSeverity(String headerName, ResponseFingerprint response) {
        // High severity for security-critical headers
        if (headerName.toLowerCase().contains("host") ||
                headerName.toLowerCase().contains("url") ||
                headerName.toLowerCase().contains("origin")) {
            return ConfigManager.Severity.HIGH;
        }

        // Medium for headers that could affect behavior
        if (headerName.toLowerCase().contains("forwarded") ||
                headerName.toLowerCase().contains("debug") ||
                headerName.toLowerCase().contains("api")) {
            return ConfigManager.Severity.MEDIUM;
        }

        // Check if reflected
        if (response.hasReflection()) {
            return ConfigManager.Severity.MEDIUM;
        }

        return ConfigManager.Severity.LOW;
    }
}
