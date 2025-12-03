package com.apm.utils;

import burp.*;
import com.apm.models.CachePoisonVulnerability;
import java.net.URL;

/**
 * Custom Scan Issue for Burp Suite integration
 */
public class CustomScanIssue implements IScanIssue {

    private final IHttpRequestResponse baseRequestResponse;
    private final CachePoisonVulnerability vulnerability;
    private final IExtensionHelpers helpers;

    public CustomScanIssue(IHttpRequestResponse baseRequestResponse,
            CachePoisonVulnerability vulnerability,
            IExtensionHelpers helpers) {
        this.baseRequestResponse = baseRequestResponse;
        this.vulnerability = vulnerability;
        this.helpers = helpers;
    }

    @Override
    public URL getUrl() {
        return helpers.analyzeRequest(baseRequestResponse).getUrl();
    }

    @Override
    public String getIssueName() {
        return "ProParam: " + vulnerability.getTitle();
    }

    @Override
    public int getIssueType() {
        // Custom issue type
        return 0x08000000; // Custom extension issue
    }

    @Override
    public String getSeverity() {
        switch (vulnerability.getSeverity()) {
            case CRITICAL:
                return "High"; // Burp doesn't have Critical
            case HIGH:
                return "High";
            case MEDIUM:
                return "Medium";
            case LOW:
                return "Low";
            case INFO:
            default:
                return "Information";
        }
    }

    @Override
    public String getConfidence() {
        return vulnerability.isVerified() ? "Certain" : "Firm";
    }

    @Override
    public String getIssueBackground() {
        return "<p>This issue was identified by the ProParam extension.</p>" +
                "<p><b>Vulnerability Type:</b> " + vulnerability.getType().displayName + "</p>" +
                "<p>" + vulnerability.getDescription() + "</p>";
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        StringBuilder detail = new StringBuilder();

        detail.append("<p><b>Affected Parameter/Header:</b> ")
                .append(vulnerability.getAffectedParameter())
                .append("</p>");

        detail.append("<p><b>Evidence:</b><br>")
                .append(vulnerability.getEvidence())
                .append("</p>");

        if (vulnerability.getProofOfConcept() != null && !vulnerability.getProofOfConcept().isEmpty()) {
            detail.append("<p><b>Proof of Concept:</b></p>")
                    .append("<pre>")
                    .append(htmlEncode(vulnerability.getProofOfConcept()))
                    .append("</pre>");
        }

        return detail.toString();
    }

    @Override
    public String getRemediationDetail() {
        if (vulnerability.getRemediation() != null && !vulnerability.getRemediation().isEmpty()) {
            return "<p>" + vulnerability.getRemediation() + "</p>";
        }
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return new IHttpRequestResponse[] { baseRequestResponse };
    }

    @Override
    public IHttpService getHttpService() {
        return baseRequestResponse.getHttpService();
    }

    private String htmlEncode(String text) {
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
