package com.apm.analysis;

import com.apm.core.BurpExtender;
import java.util.*;

/**
 * Detects meaningful differences between responses
 */
public class DifferenceDetector {

    private final BurpExtender extender;

    // Thresholds for determining meaningful differences
    private static final double SIMILARITY_THRESHOLD = 0.85;
    private static final int MIN_LENGTH_DIFF = 50;

    public DifferenceDetector(BurpExtender extender) {
        this.extender = extender;
    }

    public boolean hasMeaningfulDifference(ResponseFingerprint baseline, ResponseFingerprint test) {
        // Status code change is always meaningful
        if (baseline.getStatusCode() != test.getStatusCode()) {
            return true;
        }

        // Significant body length difference
        int lengthDiff = Math.abs(baseline.getBodyLength() - test.getBodyLength());
        if (lengthDiff > MIN_LENGTH_DIFF) {
            return true;
        }

        // Body hash difference (normalized)
        if (!baseline.getBodyHash().equals(test.getBodyHash())) {
            // Check if it's a meaningful difference (not just dynamic content)
            if (lengthDiff > 10) {
                return true;
            }
        }

        // New reflections
        if (!test.getReflections().isEmpty() && baseline.getReflections().isEmpty()) {
            return true;
        }

        // Error in test but not baseline
        if (test.hasErrorMessage() && !baseline.hasErrorMessage()) {
            return true;
        }

        // Header differences
        if (hasSignificantHeaderDifference(baseline, test)) {
            return true;
        }

        return false;
    }

    private boolean hasSignificantHeaderDifference(ResponseFingerprint baseline, ResponseFingerprint test) {
        Map<String, String> baseHeaders = baseline.getHeaders();
        Map<String, String> testHeaders = test.getHeaders();

        // Check important headers
        String[] importantHeaders = {
                "location", "set-cookie", "content-type", "content-length",
                "x-frame-options", "content-security-policy"
        };

        for (String header : importantHeaders) {
            String baseValue = baseHeaders.get(header);
            String testValue = testHeaders.get(header);

            if (baseValue == null && testValue != null)
                return true;
            if (baseValue != null && testValue == null)
                return true;
            if (baseValue != null && testValue != null && !baseValue.equals(testValue))
                return true;
        }

        return false;
    }

    public String getEvidenceDescription(ResponseFingerprint baseline, ResponseFingerprint test) {
        StringBuilder evidence = new StringBuilder();

        // Status code difference
        if (baseline.getStatusCode() != test.getStatusCode()) {
            evidence.append(String.format("Status code changed: %d → %d. ",
                    baseline.getStatusCode(), test.getStatusCode()));
        }

        // Body length difference
        int lengthDiff = test.getBodyLength() - baseline.getBodyLength();
        if (Math.abs(lengthDiff) > MIN_LENGTH_DIFF) {
            evidence.append(String.format("Body length changed by %d bytes. ", lengthDiff));
        }

        // Reflections
        if (!test.getReflections().isEmpty()) {
            evidence.append("Parameter reflected in response. ");
        }

        // Errors
        if (test.hasErrorMessage()) {
            evidence.append("Error message in response. ");
        }

        // Header differences
        Map<String, String> baseHeaders = baseline.getHeaders();
        Map<String, String> testHeaders = test.getHeaders();

        for (String header : testHeaders.keySet()) {
            if (!baseHeaders.containsKey(header)) {
                evidence.append(String.format("New header: %s. ", header));
            }
        }

        if (evidence.length() == 0) {
            evidence.append("Response differs from baseline.");
        }

        return evidence.toString().trim();
    }

    public DiffResult getDetailedDiff(ResponseFingerprint baseline, ResponseFingerprint test) {
        DiffResult result = new DiffResult();

        result.statusCodeChanged = baseline.getStatusCode() != test.getStatusCode();
        result.statusCodeDiff = String.format("%d → %d",
                baseline.getStatusCode(), test.getStatusCode());

        result.bodyLengthDiff = test.getBodyLength() - baseline.getBodyLength();
        result.hasReflection = !test.getReflections().isEmpty();
        result.reflections = new ArrayList<>(test.getReflections());

        result.newHeaders = new ArrayList<>();
        for (String header : test.getHeaders().keySet()) {
            if (!baseline.getHeaders().containsKey(header)) {
                result.newHeaders.add(header);
            }
        }

        result.modifiedHeaders = new HashMap<>();
        for (Map.Entry<String, String> entry : test.getHeaders().entrySet()) {
            String header = entry.getKey();
            String testValue = entry.getValue();
            String baseValue = baseline.getHeaders().get(header);

            if (baseValue != null && !baseValue.equals(testValue)) {
                result.modifiedHeaders.put(header, baseValue + " → " + testValue);
            }
        }

        return result;
    }

    public static class DiffResult {
        public boolean statusCodeChanged;
        public String statusCodeDiff;
        public int bodyLengthDiff;
        public boolean hasReflection;
        public List<String> reflections;
        public List<String> newHeaders;
        public Map<String, String> modifiedHeaders;

        public DiffResult() {
            this.reflections = new ArrayList<>();
            this.newHeaders = new ArrayList<>();
            this.modifiedHeaders = new HashMap<>();
        }
    }
}
