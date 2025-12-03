package com.apm.ui;

import com.apm.core.*;
import com.apm.core.ConfigManager.*;
import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * Configuration Panel for settings
 */
public class ConfigPanel extends JPanel {

    private final BurpExtender extender;

    // Scan settings
    private JSpinner threadCountSpinner;
    private JSpinner requestDelaySpinner;
    private JCheckBox followRedirectsCheckbox;
    private JCheckBox inScopeOnlyCheckbox;

    // Discovery settings
    private JComboBox<WordlistTier> wordlistTierCombo;
    private JCheckBox includeHeadersCheckbox;
    private JCheckBox includeCookiesCheckbox;
    private JCheckBox includeJsonParamsCheckbox;

    // Cache poisoning settings
    private JCheckBox enableCacheAnalysisCheckbox;
    private JCheckBox autoVerifyCheckbox;
    private JSpinner stabilityTestsSpinner;
    private JCheckBox detectUnkeyedHeadersCheckbox;
    private JCheckBox detectParameterCloakingCheckbox;
    private JCheckBox detectFatGETCheckbox;
    private JCheckBox detectCacheDeceptionCheckbox;

    // Reporting settings
    private JCheckBox autoGeneratePoCsCheckbox;
    private JCheckBox createBurpIssuesCheckbox;
    private JComboBox<Severity> minSeverityCombo;

    public ConfigPanel(BurpExtender extender) {
        this.extender = extender;
        initializeUI();
        loadCurrentConfig();
    }

    private void initializeUI() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // Scan Settings
        mainPanel.add(createScanSettingsPanel());

        // Discovery Settings
        mainPanel.add(createDiscoverySettingsPanel());

        // Cache Poisoning Settings
        mainPanel.add(createCachePoisoningSettingsPanel());

        // Reporting Settings
        mainPanel.add(createReportingSettingsPanel());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        add(scrollPane, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        JButton saveBtn = new JButton("Save Configuration");
        saveBtn.addActionListener(e -> saveConfiguration());
        buttonPanel.add(saveBtn);

        JButton loadBtn = new JButton("Load Configuration");
        loadBtn.addActionListener(e -> loadConfiguration());
        buttonPanel.add(loadBtn);

        JButton resetBtn = new JButton("Reset to Defaults");
        resetBtn.addActionListener(e -> resetToDefaults());
        buttonPanel.add(resetBtn);

        add(buttonPanel, BorderLayout.SOUTH);
    }

    private JPanel createScanSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Scan Settings"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Thread Count:"), gbc);
        gbc.gridx = 1;
        threadCountSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 50, 1));
        panel.add(threadCountSpinner, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        panel.add(new JLabel("Request Delay (ms):"), gbc);
        gbc.gridx = 1;
        requestDelaySpinner = new JSpinner(new SpinnerNumberModel(100, 0, 5000, 50));
        panel.add(requestDelaySpinner, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        followRedirectsCheckbox = new JCheckBox("Follow Redirects");
        panel.add(followRedirectsCheckbox, gbc);

        gbc.gridx = 1;
        inScopeOnlyCheckbox = new JCheckBox("In-Scope Only");
        panel.add(inScopeOnlyCheckbox, gbc);

        return panel;
    }

    private JPanel createDiscoverySettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Discovery Settings"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Wordlist Tier:"), gbc);
        gbc.gridx = 1;
        wordlistTierCombo = new JComboBox<>(WordlistTier.values());
        panel.add(wordlistTierCombo, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        includeHeadersCheckbox = new JCheckBox("Include Headers");
        panel.add(includeHeadersCheckbox, gbc);

        gbc.gridx = 1;
        includeCookiesCheckbox = new JCheckBox("Include Cookies");
        panel.add(includeCookiesCheckbox, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        includeJsonParamsCheckbox = new JCheckBox("Include JSON Parameters");
        panel.add(includeJsonParamsCheckbox, gbc);

        return panel;
    }

    private JPanel createCachePoisoningSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Cache Poisoning Detection"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        enableCacheAnalysisCheckbox = new JCheckBox("Enable Cache Analysis");
        panel.add(enableCacheAnalysisCheckbox, gbc);

        gbc.gridy = 1;
        autoVerifyCheckbox = new JCheckBox("Auto-Verify Findings");
        panel.add(autoVerifyCheckbox, gbc);

        gbc.gridy = 2;
        gbc.gridwidth = 1;
        panel.add(new JLabel("Cache Stability Tests:"), gbc);
        gbc.gridx = 1;
        stabilityTestsSpinner = new JSpinner(new SpinnerNumberModel(3, 1, 10, 1));
        panel.add(stabilityTestsSpinner, gbc);

        gbc.gridx = 0;
        gbc.gridy = 3;
        detectUnkeyedHeadersCheckbox = new JCheckBox("Detect Unkeyed Headers");
        panel.add(detectUnkeyedHeadersCheckbox, gbc);

        gbc.gridx = 1;
        detectParameterCloakingCheckbox = new JCheckBox("Detect Parameter Cloaking");
        panel.add(detectParameterCloakingCheckbox, gbc);

        gbc.gridx = 0;
        gbc.gridy = 4;
        detectFatGETCheckbox = new JCheckBox("Detect Fat GET");
        panel.add(detectFatGETCheckbox, gbc);

        gbc.gridx = 1;
        detectCacheDeceptionCheckbox = new JCheckBox("Detect Cache Deception");
        panel.add(detectCacheDeceptionCheckbox, gbc);

        return panel;
    }

    private JPanel createReportingSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Reporting"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        gbc.gridx = 0;
        gbc.gridy = 0;
        autoGeneratePoCsCheckbox = new JCheckBox("Auto-Generate PoCs");
        panel.add(autoGeneratePoCsCheckbox, gbc);

        gbc.gridx = 1;
        createBurpIssuesCheckbox = new JCheckBox("Create Burp Issues");
        panel.add(createBurpIssuesCheckbox, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        panel.add(new JLabel("Min Severity to Report:"), gbc);
        gbc.gridx = 1;
        minSeverityCombo = new JComboBox<>(Severity.values());
        panel.add(minSeverityCombo, gbc);

        return panel;
    }

    private void loadCurrentConfig() {
        ScanConfig config = extender.getConfigManager().getConfig();

        threadCountSpinner.setValue(config.threadCount);
        requestDelaySpinner.setValue(config.requestDelay);
        followRedirectsCheckbox.setSelected(config.followRedirects);
        inScopeOnlyCheckbox.setSelected(config.inScopeOnly);

        wordlistTierCombo.setSelectedItem(config.wordlistTier);
        includeHeadersCheckbox.setSelected(config.includeHeaders);
        includeCookiesCheckbox.setSelected(config.includeCookies);
        includeJsonParamsCheckbox.setSelected(config.includeJsonParams);

        enableCacheAnalysisCheckbox.setSelected(config.enableCacheAnalysis);
        autoVerifyCheckbox.setSelected(config.autoVerifyFindings);
        stabilityTestsSpinner.setValue(config.cacheStabilityTests);
        detectUnkeyedHeadersCheckbox.setSelected(config.detectUnkeyedHeaders);
        detectParameterCloakingCheckbox.setSelected(config.detectParameterCloaking);
        detectFatGETCheckbox.setSelected(config.detectFatGET);
        detectCacheDeceptionCheckbox.setSelected(config.detectCacheDeception);

        autoGeneratePoCsCheckbox.setSelected(config.autoGeneratePoCs);
        createBurpIssuesCheckbox.setSelected(config.createBurpIssues);
        minSeverityCombo.setSelectedItem(config.minSeverityToReport);
    }

    private void saveConfiguration() {
        ScanConfig config = new ScanConfig();

        config.threadCount = (int) threadCountSpinner.getValue();
        config.requestDelay = (int) requestDelaySpinner.getValue();
        config.followRedirects = followRedirectsCheckbox.isSelected();
        config.inScopeOnly = inScopeOnlyCheckbox.isSelected();

        config.wordlistTier = (WordlistTier) wordlistTierCombo.getSelectedItem();
        config.includeHeaders = includeHeadersCheckbox.isSelected();
        config.includeCookies = includeCookiesCheckbox.isSelected();
        config.includeJsonParams = includeJsonParamsCheckbox.isSelected();

        config.enableCacheAnalysis = enableCacheAnalysisCheckbox.isSelected();
        config.autoVerifyFindings = autoVerifyCheckbox.isSelected();
        config.cacheStabilityTests = (int) stabilityTestsSpinner.getValue();
        config.detectUnkeyedHeaders = detectUnkeyedHeadersCheckbox.isSelected();
        config.detectParameterCloaking = detectParameterCloakingCheckbox.isSelected();
        config.detectFatGET = detectFatGETCheckbox.isSelected();
        config.detectCacheDeception = detectCacheDeceptionCheckbox.isSelected();

        config.autoGeneratePoCs = autoGeneratePoCsCheckbox.isSelected();
        config.createBurpIssues = createBurpIssuesCheckbox.isSelected();
        config.minSeverityToReport = (Severity) minSeverityCombo.getSelectedItem();

        extender.getConfigManager().setConfig(config);

        JOptionPane.showMessageDialog(this, "Configuration saved successfully!",
                "Success", JOptionPane.INFORMATION_MESSAGE);
    }

    private void loadConfiguration() {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            extender.getConfigManager().loadConfig(file);
            loadCurrentConfig();
            JOptionPane.showMessageDialog(this, "Configuration loaded successfully!",
                    "Success", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void resetToDefaults() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to reset to default settings?",
                "Reset Configuration", JOptionPane.YES_NO_OPTION);

        if (confirm == JOptionPane.YES_OPTION) {
            extender.getConfigManager().loadDefaultConfig();
            loadCurrentConfig();
            JOptionPane.showMessageDialog(this, "Configuration reset to defaults!",
                    "Success", JOptionPane.INFORMATION_MESSAGE);
        }
    }
}
