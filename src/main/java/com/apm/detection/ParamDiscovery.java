package com.apm.detection;

import burp.*;
import com.apm.core.*;
import com.apm.models.*;
import com.apm.utils.*;
import com.apm.analysis.*;
import java.util.*;

/**
 * Parameter Discovery Module
 */
public class ParamDiscovery {

    private final BurpExtender extender;
    private final PayloadGenerator payloadGenerator;
    private final DifferenceDetector differenceDetector;

    public ParamDiscovery(BurpExtender extender) {
        this.extender = extender;
        this.payloadGenerator = new PayloadGenerator(extender);
        this.differenceDetector = new DifferenceDetector(extender);
    }

    public List<ParameterInfo> discover(IHttpRequestResponse baseRequest) {
        List<ParameterInfo> discovered = new ArrayList<>();

        try {
            // Get baseline response
            ResponseFingerprint baseline = getBaseline(baseRequest);

            // Generate wordlist based on mode
            List<String> wordlist = payloadGenerator.generateWordlist(baseRequest);

            // Test query parameters
            discovered.addAll(discoverQueryParameters(baseRequest, baseline, wordlist));

            // Test POST body parameters
            if (isPOSTRequest(baseRequest)) {
                discovered.addAll(discoverPostParameters(baseRequest, baseline, wordlist));
            }

            // Test JSON parameters if applicable
            if (extender.getConfigManager().getConfig().includeJsonParams && hasJsonContent(baseRequest)) {
                discovered.addAll(discoverJsonParameters(baseRequest, baseline, wordlist));
            }

        } catch (Exception e) {
            extender.getStderr().println("Error in parameter discovery: " + e.getMessage());
        }

        return discovered;
    }

    private List<ParameterInfo> discoverQueryParameters(IHttpRequestResponse baseRequest,
            ResponseFingerprint baseline,
            List<String> wordlist) {
        List<ParameterInfo> found = new ArrayList<>();

        for (String param : wordlist) {
            try {
                // Test parameter with random value
                String testValue = generateRandomValue();
                IHttpRequestResponse testRequest = addQueryParameter(baseRequest, param, testValue);

                if (testRequest == null)
                    continue;

                ResponseFingerprint testResponse = getResponse(testRequest);

                // Check for differences
                if (differenceDetector.hasMeaningfulDifference(baseline, testResponse)) {
                    // Validate with second test
                    if (validateParameter(baseRequest, param, ParameterInfo.ParameterType.QUERY)) {
                        String evidence = differenceDetector.getEvidenceDescription(baseline, testResponse);
                        ConfigManager.Severity severity = determineSeverity(testResponse, param);

                        ParameterInfo paramInfo = new ParameterInfo(
                                param,
                                ParameterInfo.ParameterType.QUERY,
                                evidence,
                                severity,
                                testResponse.isCached(),
                                testResponse.isUnkeyed(),
                                testValue,
                                testResponse.getReflectionSnippet());

                        found.add(paramInfo);
                        extender.getStdout().println("    ✓ Found query param: " + param);
                    }
                }

                // Rate limiting
                Thread.sleep(extender.getConfigManager().getConfig().requestDelay);

            } catch (Exception e) {
                // Continue with next parameter
            }
        }

        return found;
    }

    private List<ParameterInfo> discoverPostParameters(IHttpRequestResponse baseRequest,
            ResponseFingerprint baseline,
            List<String> wordlist) {
        List<ParameterInfo> found = new ArrayList<>();

        for (String param : wordlist) {
            try {
                String testValue = generateRandomValue();
                IHttpRequestResponse testRequest = addPostParameter(baseRequest, param, testValue);

                if (testRequest == null)
                    continue;

                ResponseFingerprint testResponse = getResponse(testRequest);

                if (differenceDetector.hasMeaningfulDifference(baseline, testResponse)) {
                    if (validateParameter(baseRequest, param, ParameterInfo.ParameterType.POST_BODY)) {
                        String evidence = differenceDetector.getEvidenceDescription(baseline, testResponse);
                        ConfigManager.Severity severity = determineSeverity(testResponse, param);

                        ParameterInfo paramInfo = new ParameterInfo(
                                param,
                                ParameterInfo.ParameterType.POST_BODY,
                                evidence,
                                severity,
                                testResponse.isCached(),
                                testResponse.isUnkeyed(),
                                testValue,
                                testResponse.getReflectionSnippet());

                        found.add(paramInfo);
                        extender.getStdout().println("    ✓ Found POST param: " + param);
                    }
                }

                Thread.sleep(extender.getConfigManager().getConfig().requestDelay);

            } catch (Exception e) {
                // Continue
            }
        }

        return found;
    }

    private List<ParameterInfo> discoverJsonParameters(IHttpRequestResponse baseRequest,
            ResponseFingerprint baseline,
            List<String> wordlist) {
        List<ParameterInfo> found = new ArrayList<>();

        for (String param : wordlist) {
            try {
                String testValue = generateRandomValue();
                IHttpRequestResponse testRequest = addJsonParameter(baseRequest, param, testValue);

                if (testRequest == null)
                    continue;

                ResponseFingerprint testResponse = getResponse(testRequest);

                if (differenceDetector.hasMeaningfulDifference(baseline, testResponse)) {
                    if (validateParameter(baseRequest, param, ParameterInfo.ParameterType.JSON)) {
                        String evidence = differenceDetector.getEvidenceDescription(baseline, testResponse);
                        ConfigManager.Severity severity = determineSeverity(testResponse, param);

                        ParameterInfo paramInfo = new ParameterInfo(
                                param,
                                ParameterInfo.ParameterType.JSON,
                                evidence,
                                severity);

                        found.add(paramInfo);
                        extender.getStdout().println("    ✓ Found JSON param: " + param);
                    }
                }

                Thread.sleep(extender.getConfigManager().getConfig().requestDelay);

            } catch (Exception e) {
                // Continue
            }
        }

        return found;
    }

    private boolean validateParameter(IHttpRequestResponse baseRequest, String param,
            ParameterInfo.ParameterType type) {
        // Test with different values to ensure stability
        try {
            String value1 = generateRandomValue();
            String value2 = generateRandomValue();

            IHttpRequestResponse test1 = addParameter(baseRequest, param, value1, type);
            IHttpRequestResponse test2 = addParameter(baseRequest, param, value2, type);

            if (test1 == null || test2 == null)
                return false;

            ResponseFingerprint resp1 = getResponse(test1);
            ResponseFingerprint resp2 = getResponse(test2);

            // Both should show differences from baseline
            return resp1.isDifferentFrom(resp2) || resp1.reflectsValue(value1);

        } catch (Exception e) {
            return false;
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

    private IHttpRequestResponse addQueryParameter(IHttpRequestResponse baseRequest, String name, String value) {
        byte[] request = baseRequest.getRequest();
        IParameter param = extender.getHelpers().buildParameter(name, value, IParameter.PARAM_URL);
        byte[] newRequest = extender.getHelpers().addParameter(request, param);
        return extender.getCallbacks().makeHttpRequest(baseRequest.getHttpService(), newRequest);
    }

    private IHttpRequestResponse addPostParameter(IHttpRequestResponse baseRequest, String name, String value) {
        byte[] request = baseRequest.getRequest();
        IParameter param = extender.getHelpers().buildParameter(name, value, IParameter.PARAM_BODY);
        byte[] newRequest = extender.getHelpers().addParameter(request, param);
        return extender.getCallbacks().makeHttpRequest(baseRequest.getHttpService(), newRequest);
    }

    private IHttpRequestResponse addJsonParameter(IHttpRequestResponse baseRequest, String name, String value) {
        byte[] request = baseRequest.getRequest();
        IParameter param = extender.getHelpers().buildParameter(name, value, IParameter.PARAM_JSON);
        byte[] newRequest = extender.getHelpers().addParameter(request, param);
        return extender.getCallbacks().makeHttpRequest(baseRequest.getHttpService(), newRequest);
    }

    private IHttpRequestResponse addParameter(IHttpRequestResponse baseRequest, String name,
            String value, ParameterInfo.ParameterType type) {
        switch (type) {
            case QUERY:
                return addQueryParameter(baseRequest, name, value);
            case POST_BODY:
                return addPostParameter(baseRequest, name, value);
            case JSON:
                return addJsonParameter(baseRequest, name, value);
            default:
                return null;
        }
    }

    private boolean isPOSTRequest(IHttpRequestResponse request) {
        IRequestInfo info = extender.getHelpers().analyzeRequest(request);
        return "POST".equals(info.getMethod());
    }

    private boolean hasJsonContent(IHttpRequestResponse request) {
        IRequestInfo info = extender.getHelpers().analyzeRequest(request);
        for (String header : info.getHeaders()) {
            if (header.toLowerCase().contains("content-type") &&
                    header.toLowerCase().contains("application/json")) {
                return true;
            }
        }
        return false;
    }

    private String generateRandomValue() {
        return "apm_" + UUID.randomUUID().toString().substring(0, 8);
    }

    private ConfigManager.Severity determineSeverity(ResponseFingerprint response, String paramName) {
        if (response.hasErrorMessage()) {
            return ConfigManager.Severity.LOW;
        }
        if (response.reflectsValue(paramName)) {
            return ConfigManager.Severity.MEDIUM;
        }
        if (response.hasSignificantChange()) {
            return ConfigManager.Severity.MEDIUM;
        }
        return ConfigManager.Severity.INFO;
    }
}
