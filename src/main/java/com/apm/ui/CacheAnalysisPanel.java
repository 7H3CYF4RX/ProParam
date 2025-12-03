package com.apm.ui;

import com.apm.core.*;
import com.apm.models.*;
import javax.swing.*;
import java.awt.*;
import java.util.*;

/**
 * Cache Analysis Panel for displaying cache behavior
 */
public class CacheAnalysisPanel extends JPanel {

    private final BurpExtender extender;

    private JLabel cacheSystemLabel;
    private JLabel cacheStatusLabel;
    private JLabel ttlLabel;
    private JTextArea cacheHeadersArea;
    private JList<String> keyedComponentsList;
    private JList<String> unkeyedComponentsList;
    private JTextArea notesArea;

    public CacheAnalysisPanel(BurpExtender extender) {
        this.extender = extender;
        initializeUI();
    }

    private void initializeUI() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Main panel
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Cache System Info
        JPanel infoPanel = new JPanel(new GridLayout(3, 2, 10, 5));
        infoPanel.setBorder(BorderFactory.createTitledBorder("Cache Information"));

        infoPanel.add(new JLabel("Cache System:"));
        cacheSystemLabel = new JLabel("Unknown");
        cacheSystemLabel.setFont(new Font("Arial", Font.BOLD, 12));
        infoPanel.add(cacheSystemLabel);

        infoPanel.add(new JLabel("Cache Status:"));
        cacheStatusLabel = new JLabel("Not Analyzed");
        infoPanel.add(cacheStatusLabel);

        infoPanel.add(new JLabel("TTL:"));
        ttlLabel = new JLabel("Unknown");
        infoPanel.add(ttlLabel);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 0.2;
        mainPanel.add(infoPanel, gbc);

        // Cache Headers
        JPanel headersPanel = new JPanel(new BorderLayout());
        headersPanel.setBorder(BorderFactory.createTitledBorder("Cache Headers"));
        cacheHeadersArea = new JTextArea(5, 40);
        cacheHeadersArea.setEditable(false);
        cacheHeadersArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        headersPanel.add(new JScrollPane(cacheHeadersArea), BorderLayout.CENTER);

        gbc.gridy = 1;
        gbc.weighty = 0.2;
        mainPanel.add(headersPanel, gbc);

        // Cache Key Components
        JPanel componentsPanel = new JPanel(new GridLayout(1, 2, 10, 5));

        // Keyed Components
        JPanel keyedPanel = new JPanel(new BorderLayout());
        keyedPanel.setBorder(BorderFactory.createTitledBorder("Keyed Components (Included in Cache Key)"));
        keyedComponentsList = new JList<>();
        keyedComponentsList.setFont(new Font("Arial", Font.PLAIN, 11));
        keyedPanel.add(new JScrollPane(keyedComponentsList), BorderLayout.CENTER);

        // Unkeyed Components
        JPanel unkeyedPanel = new JPanel(new BorderLayout());
        unkeyedPanel.setBorder(BorderFactory.createTitledBorder("Unkeyed Components (NOT in Cache Key)"));
        unkeyedComponentsList = new JList<>();
        unkeyedComponentsList.setFont(new Font("Arial", Font.PLAIN, 11));
        unkeyedPanel.add(new JScrollPane(unkeyedComponentsList), BorderLayout.CENTER);

        componentsPanel.add(keyedPanel);
        componentsPanel.add(unkeyedPanel);

        gbc.gridy = 2;
        gbc.weighty = 0.3;
        mainPanel.add(componentsPanel, gbc);

        // Notes
        JPanel notesPanel = new JPanel(new BorderLayout());
        notesPanel.setBorder(BorderFactory.createTitledBorder("Analysis Notes"));
        notesArea = new JTextArea(8, 40);
        notesArea.setEditable(false);
        notesArea.setFont(new Font("Arial", Font.PLAIN, 11));
        notesArea.setLineWrap(true);
        notesArea.setWrapStyleWord(true);
        notesPanel.add(new JScrollPane(notesArea), BorderLayout.CENTER);

        gbc.gridy = 3;
        gbc.weighty = 0.3;
        mainPanel.add(notesPanel, gbc);

        add(mainPanel, BorderLayout.CENTER);

        // Default message
        displayDefaultMessage();
    }

    private void displayDefaultMessage() {
        notesArea.setText("No cache analysis performed yet.\n\n" +
                "To analyze cache behavior:\n" +
                "1. Right-click on a request in Burp\n" +
                "2. Select 'Analyze Cache Behavior'\n\n" +
                "The extension will:\n" +
                "- Identify the cache system\n" +
                "- Determine cache key components\n" +
                "- Detect potential cache poisoning vectors");
    }

    public void displayAnalysis(CacheAnalysisResult analysis) {
        // Update cache system
        cacheSystemLabel.setText(analysis.getCacheSystem().displayName);

        // Set color based on system
        if (analysis.getCacheSystem() != CacheAnalysisResult.CacheSystem.UNKNOWN) {
            cacheSystemLabel.setForeground(new Color(0, 128, 0)); // Green
        } else {
            cacheSystemLabel.setForeground(Color.GRAY);
        }

        // Update cache status
        if (analysis.isCached()) {
            cacheStatusLabel.setText("✓ Cached");
            cacheStatusLabel.setForeground(new Color(0, 128, 0));
        } else {
            cacheStatusLabel.setText("✗ Not Cached");
            cacheStatusLabel.setForeground(Color.RED);
        }

        // Update TTL
        if (analysis.getTtl() > 0) {
            int seconds = analysis.getTtl();
            int minutes = seconds / 60;
            int hours = minutes / 60;

            if (hours > 0) {
                ttlLabel.setText(String.format("%d hours (%d seconds)", hours, seconds));
            } else if (minutes > 0) {
                ttlLabel.setText(String.format("%d minutes (%d seconds)", minutes, seconds));
            } else {
                ttlLabel.setText(seconds + " seconds");
            }
        } else {
            ttlLabel.setText("Not specified");
        }

        // Update headers
        StringBuilder headersText = new StringBuilder();
        for (Map.Entry<String, String> entry : analysis.getCacheHeaders().entrySet()) {
            if (entry.getKey().contains("cache") || entry.getKey().contains("age") ||
                    entry.getKey().contains("expires") || entry.getKey().contains("etag")) {
                headersText.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
            }
        }
        cacheHeadersArea.setText(headersText.toString());

        // Update keyed components
        DefaultListModel<String> keyedModel = new DefaultListModel<>();
        for (String component : analysis.getKeyedComponents()) {
            keyedModel.addElement("✓ " + component);
        }
        keyedComponentsList.setModel(keyedModel);

        // Update unkeyed components
        DefaultListModel<String> unkeyedModel = new DefaultListModel<>();
        for (String component : analysis.getUnkeyedComponents()) {
            unkeyedModel.addElement("✗ " + component);
        }
        unkeyedComponentsList.setModel(unkeyedModel);

        // Update notes
        notesArea.setText(analysis.getNotes());

        // Add warning if there are unkeyed components
        if (!analysis.getUnkeyedComponents().isEmpty()) {
            notesArea.append("\n\n⚠ WARNING: Unkeyed components detected!\n");
            notesArea.append("These inputs affect the response but are not part of the cache key.\n");
            notesArea.append("This could lead to cache poisoning vulnerabilities.");
        }
    }
}
