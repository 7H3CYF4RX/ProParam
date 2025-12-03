package com.apm.ui;

import com.apm.core.*;
import com.apm.models.*;
import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

/**
 * Main UI Panel for the extension
 */
public class MainPanel extends JPanel {

    private final BurpExtender extender;

    private JTabbedPane tabbedPane;
    private ResultsTable resultsTable;
    private CacheAnalysisPanel cacheAnalysisPanel;
    private ConfigPanel configPanel;
    private JTextArea logArea;

    public MainPanel(BurpExtender extender) {
        this.extender = extender;
        initializeUI();
    }

    private void initializeUI() {
        setLayout(new BorderLayout());

        // Create tabbed pane
        tabbedPane = new JTabbedPane();

        // Dashboard tab
        tabbedPane.addTab("Dashboard", createDashboardPanel());

        // Results tab
        resultsTable = new ResultsTable(extender);
        tabbedPane.addTab("Scan Results", new JScrollPane(resultsTable));

        // Cache Analysis tab
        cacheAnalysisPanel = new CacheAnalysisPanel(extender);
        tabbedPane.addTab("Cache Analysis", cacheAnalysisPanel);

        // Configuration tab
        configPanel = new ConfigPanel(extender);
        tabbedPane.addTab("Configuration", configPanel);

        // Logs tab
        tabbedPane.addTab("Logs", createLogsPanel());

        add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createDashboardPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Header
        JPanel headerPanel = new JPanel(new GridLayout(2, 1));
        JLabel titleLabel = new JLabel("ProParam");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 24));
        JLabel versionLabel = new JLabel(
                "Version " + BurpExtender.VERSION + " - Cache Poisoning Detection & Parameter Discovery");
        versionLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        versionLabel.setForeground(Color.GRAY);
        headerPanel.add(titleLabel);
        headerPanel.add(versionLabel);
        panel.add(headerPanel, BorderLayout.NORTH);

        // Stats panel
        JPanel statsPanel = new JPanel(new GridLayout(2, 3, 10, 10));
        statsPanel.setBorder(BorderFactory.createTitledBorder("Statistics"));

        JLabel totalScansLabel = new JLabel("Total Scans: 0");
        JLabel activeScansLabel = new JLabel("Active Scans: 0");
        JLabel paramsFoundLabel = new JLabel("Parameters Found: 0");
        JLabel vulnsFoundLabel = new JLabel("Cache Issues Found: 0");
        JLabel highSeverityLabel = new JLabel("High Severity: 0");
        JLabel mediumSeverityLabel = new JLabel("Medium Severity: 0");

        statsPanel.add(totalScansLabel);
        statsPanel.add(activeScansLabel);
        statsPanel.add(paramsFoundLabel);
        statsPanel.add(vulnsFoundLabel);
        statsPanel.add(highSeverityLabel);
        statsPanel.add(mediumSeverityLabel);

        panel.add(statsPanel, BorderLayout.CENTER);

        // Quick actions panel
        JPanel actionsPanel = new JPanel(new GridLayout(3, 2, 10, 10));
        actionsPanel.setBorder(BorderFactory.createTitledBorder("Quick Actions"));

        JButton viewResultsBtn = new JButton("View Scan Results");
        viewResultsBtn.addActionListener(e -> tabbedPane.setSelectedIndex(1));

        JButton viewCacheBtn = new JButton("View Cache Analysis");
        viewCacheBtn.addActionListener(e -> tabbedPane.setSelectedIndex(2));

        JButton configBtn = new JButton("Open Configuration");
        configBtn.addActionListener(e -> tabbedPane.setSelectedIndex(3));

        JButton exportBtn = new JButton("Export Results");
        exportBtn.addActionListener(e -> exportResults());

        JButton clearBtn = new JButton("Clear Results");
        clearBtn.addActionListener(e -> clearResults());

        JButton helpBtn = new JButton("Help & Documentation");
        helpBtn.addActionListener(e -> showHelp());

        actionsPanel.add(viewResultsBtn);
        actionsPanel.add(viewCacheBtn);
        actionsPanel.add(configBtn);
        actionsPanel.add(exportBtn);
        actionsPanel.add(clearBtn);
        actionsPanel.add(helpBtn);

        panel.add(actionsPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createLogsPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JScrollPane scrollPane = new JScrollPane(logArea);
        panel.add(scrollPane, BorderLayout.CENTER);

        // Clear button
        JButton clearBtn = new JButton("Clear Logs");
        clearBtn.addActionListener(e -> logArea.setText(""));
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(clearBtn);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    public void addScanResult(ScanResult result) {
        SwingUtilities.invokeLater(() -> {
            resultsTable.addResult(result);
            logMessage("Scan completed: " + result.getFindingsCount() + " findings");
        });
    }

    public void displayCacheAnalysis(CacheAnalysisResult result) {
        SwingUtilities.invokeLater(() -> {
            cacheAnalysisPanel.displayAnalysis(result);
            tabbedPane.setSelectedComponent(cacheAnalysisPanel);
        });
    }

    public void logMessage(String message) {
        SwingUtilities.invokeLater(() -> {
            if (logArea != null) {
                logArea.append("[" + new java.util.Date() + "] " + message + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            }
        });
    }

    private void exportResults() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Results");

        int result = fileChooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            // TODO: Implement export logic
            JOptionPane.showMessageDialog(this,
                    "Export functionality will be implemented in future version",
                    "Export", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void clearResults() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to clear all results?",
                "Clear Results", JOptionPane.YES_NO_OPTION);

        if (confirm == JOptionPane.YES_OPTION) {
            resultsTable.clearResults();
            logMessage("Results cleared");
        }
    }

    private void showHelp() {
        String help = "ProParam - Help\n\n" +
                "Usage:\n" +
                "1. Right-click on any request in Burp\n" +
                "2. Select 'Scan with ProParam'\n" +
                "3. View results in the Scan Results tab\n\n" +
                "Features:\n" +
                "- Parameter Discovery (Query, POST, JSON)\n" +
                "- Header Discovery\n" +
                "- Cache Poisoning Detection\n" +
                "- Automatic PoC Generation\n\n" +
                "For more information, visit the documentation.";

        JOptionPane.showMessageDialog(this, help, "Help", JOptionPane.INFORMATION_MESSAGE);
    }
}
