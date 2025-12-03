package com.apm.core;

import burp.*;
import com.apm.ui.MainPanel;
import javax.swing.*;
import java.io.PrintWriter;

/**
 * ProParam - Burp Suite Extension
 * Professional Parameter Mining & Cache Poisoning Detection
 * 
 * @author Muhammed Farhan (7H3CYF4RX)
 * @version 1.0.0
 */
public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private MainPanel mainPanel;
    private ScanEngine scanEngine;
    private ConfigManager configManager;

    public static final String EXTENSION_NAME = "ProParam";
    public static final String VERSION = "1.0.0";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // Set extension name
        callbacks.setExtensionName(EXTENSION_NAME);

        stdout.println("========================================");
        stdout.println(EXTENSION_NAME + " v" + VERSION);
        stdout.println("========================================");
        stdout.println("Initializing extension...");

        try {
            // Initialize components
            initializeComponents();

            // Register UI tab
            SwingUtilities.invokeLater(() -> {
                mainPanel = new MainPanel(this);
                callbacks.addSuiteTab(BurpExtender.this);
            });

            // Register context menu
            callbacks.registerContextMenuFactory(this);

            stdout.println("✓ Extension loaded successfully!");
            stdout.println("✓ UI tab added: " + EXTENSION_NAME);
            stdout.println("✓ Context menu registered");
            stdout.println("========================================");

        } catch (Exception e) {
            stderr.println("Error initializing extension:");
            e.printStackTrace(stderr);
        }
    }

    private void initializeComponents() {
        stdout.println("Loading configuration...");
        configManager = new ConfigManager(this);
        configManager.loadDefaultConfig();
        stdout.println("✓ Configuration loaded");

        stdout.println("Initializing scan engine...");
        scanEngine = new ScanEngine(this);
        stdout.println("✓ Scan engine ready");
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public java.awt.Component getUiComponent() {
        return mainPanel;
    }

    @Override
    public java.util.List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        java.util.List<JMenuItem> menuItems = new java.util.ArrayList<>();

        // Only show menu for requests
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
                invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST ||
                invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_PROXY_HISTORY ||
                invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE) {

            JMenuItem scanItem = new JMenuItem("Scan with ProParam");
            scanItem.addActionListener(e -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) {
                    for (IHttpRequestResponse message : messages) {
                        scanEngine.startScan(message);
                    }
                    stdout.println("Started scan for " + messages.length + " request(s)");
                }
            });
            menuItems.add(scanItem);

            JMenuItem quickScanItem = new JMenuItem("Quick Scan (Fast mode)");
            quickScanItem.addActionListener(e -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) {
                    for (IHttpRequestResponse message : messages) {
                        scanEngine.startQuickScan(message);
                    }
                    stdout.println("Started quick scan for " + messages.length + " request(s)");
                }
            });
            menuItems.add(quickScanItem);

            JMenuItem cacheScanItem = new JMenuItem("Analyze Cache Behavior");
            cacheScanItem.addActionListener(e -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) {
                    scanEngine.analyzeCacheBehavior(messages[0]);
                    stdout.println("Started cache analysis");
                }
            });
            menuItems.add(cacheScanItem);
        }

        return menuItems;
    }

    // Getters for other components
    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public IExtensionHelpers getHelpers() {
        return helpers;
    }

    public PrintWriter getStdout() {
        return stdout;
    }

    public PrintWriter getStderr() {
        return stderr;
    }

    public ScanEngine getScanEngine() {
        return scanEngine;
    }

    public ConfigManager getConfigManager() {
        return configManager;
    }

    public MainPanel getMainPanel() {
        return mainPanel;
    }
}
