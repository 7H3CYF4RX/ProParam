package com.apm.ui;

import com.apm.core.*;
import com.apm.models.*;
import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.*;

/**
 * Results Table for displaying scan findings
 */
public class ResultsTable extends JTable {

    private final BurpExtender extender;
    private final ResultsTableModel tableModel;

    public ResultsTable(BurpExtender extender) {
        this.extender = extender;
        this.tableModel = new ResultsTableModel();

        setModel(tableModel);
        setupTable();
        setupContextMenu();
    }

    private void setupTable() {
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setAutoCreateRowSorter(true);

        // Set column widths
        getColumnModel().getColumn(0).setPreferredWidth(150); // Name
        getColumnModel().getColumn(1).setPreferredWidth(100); // Type
        getColumnModel().getColumn(2).setPreferredWidth(300); // Evidence
        getColumnModel().getColumn(3).setPreferredWidth(80); // Severity
        getColumnModel().getColumn(4).setPreferredWidth(80); // Cached

        // Custom renderer for severity
        getColumnModel().getColumn(3).setCellRenderer(new SeverityRenderer());
    }

    private void setupContextMenu() {
        JPopupMenu contextMenu = new JPopupMenu();

        JMenuItem viewDetailsItem = new JMenuItem("View Details");
        viewDetailsItem.addActionListener(e -> viewDetails());
        contextMenu.add(viewDetailsItem);

        JMenuItem generatePoCItem = new JMenuItem("Generate PoC");
        generatePoCItem.addActionListener(e -> generatePoC());
        contextMenu.add(generatePoCItem);

        contextMenu.addSeparator();

        JMenuItem sendToRepeaterItem = new JMenuItem("Send to Repeater");
        sendToRepeaterItem.addActionListener(e -> sendToRepeater());
        contextMenu.add(sendToRepeaterItem);

        JMenuItem deleteItem = new JMenuItem("Delete");
        deleteItem.addActionListener(e -> deleteSelected());
        contextMenu.add(deleteItem);

        setComponentPopupMenu(contextMenu);
    }

    public void addResult(ScanResult result) {
        // Add parameters
        for (ParameterInfo param : result.getParameters()) {
            tableModel.addFinding(new Finding(param, result));
        }

        // Add vulnerabilities
        for (CachePoisonVulnerability vuln : result.getVulnerabilities()) {
            tableModel.addFinding(new Finding(vuln, result));
        }
    }

    public void clearResults() {
        tableModel.clearFindings();
    }

    private void viewDetails() {
        int row = getSelectedRow();
        if (row >= 0) {
            row = convertRowIndexToModel(row);
            Finding finding = tableModel.getFinding(row);
            showDetailsDialog(finding);
        }
    }

    private void showDetailsDialog(Finding finding) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Finding Details", true);
        dialog.setLayout(new BorderLayout());

        JTextArea detailsArea = new JTextArea(20, 60);
        detailsArea.setEditable(false);
        detailsArea.setText(finding.getDetailedDescription());

        dialog.add(new JScrollPane(detailsArea), BorderLayout.CENTER);

        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dialog.dispose());
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(closeBtn);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        dialog.pack();
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }

    private void generatePoC() {
        int row = getSelectedRow();
        if (row >= 0) {
            row = convertRowIndexToModel(row);
            Finding finding = tableModel.getFinding(row);
            String poc = finding.getProofOfConcept();

            JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Proof of Concept", true);
            dialog.setLayout(new BorderLayout());

            JTextArea pocArea = new JTextArea(20, 60);
            pocArea.setEditable(false);
            pocArea.setText(poc);

            dialog.add(new JScrollPane(pocArea), BorderLayout.CENTER);

            JPanel buttonPanel = new JPanel();
            JButton copyBtn = new JButton("Copy to Clipboard");
            copyBtn.addActionListener(e -> {
                java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(poc);
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
                JOptionPane.showMessageDialog(dialog, "Copied to clipboard!");
            });
            JButton closeBtn = new JButton("Close");
            closeBtn.addActionListener(e -> dialog.dispose());
            buttonPanel.add(copyBtn);
            buttonPanel.add(closeBtn);
            dialog.add(buttonPanel, BorderLayout.SOUTH);

            dialog.pack();
            dialog.setLocationRelativeTo(this);
            dialog.setVisible(true);
        }
    }

    private void sendToRepeater() {
        int row = getSelectedRow();
        if (row >= 0) {
            row = convertRowIndexToModel(row);
            Finding finding = tableModel.getFinding(row);

            extender.getCallbacks().sendToRepeater(
                    finding.getRequest().getHttpService().getHost(),
                    finding.getRequest().getHttpService().getPort(),
                    finding.getRequest().getHttpService().getProtocol().equals("https"),
                    finding.getRequest().getRequest(),
                    finding.getName());

            extender.getStdout().println("Sent to Repeater: " + finding.getName());
        }
    }

    private void deleteSelected() {
        int row = getSelectedRow();
        if (row >= 0) {
            row = convertRowIndexToModel(row);
            tableModel.removeFinding(row);
        }
    }

    // Inner classes
    private static class ResultsTableModel extends AbstractTableModel {
        private final String[] columnNames = { "Name", "Type", "Evidence", "Severity", "Cached" };
        private final List<Finding> findings = new ArrayList<>();

        @Override
        public int getRowCount() {
            return findings.size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public Object getValueAt(int row, int column) {
            Finding finding = findings.get(row);

            switch (column) {
                case 0:
                    return finding.getName();
                case 1:
                    return finding.getType();
                case 2:
                    return finding.getEvidence();
                case 3:
                    return finding.getSeverity();
                case 4:
                    return finding.isCached() ? "Yes" : "No";
                default:
                    return "";
            }
        }

        public void addFinding(Finding finding) {
            findings.add(finding);
            fireTableRowsInserted(findings.size() - 1, findings.size() - 1);
        }

        public void removeFinding(int row) {
            findings.remove(row);
            fireTableRowsDeleted(row, row);
        }

        public void clearFindings() {
            findings.clear();
            fireTableDataChanged();
        }

        public Finding getFinding(int row) {
            return findings.get(row);
        }
    }

    private static class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus,
                int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (value instanceof ConfigManager.Severity) {
                ConfigManager.Severity severity = (ConfigManager.Severity) value;

                switch (severity) {
                    case CRITICAL:
                    case HIGH:
                        c.setForeground(Color.RED);
                        break;
                    case MEDIUM:
                        c.setForeground(Color.ORANGE);
                        break;
                    case LOW:
                        c.setForeground(Color.BLUE);
                        break;
                    case INFO:
                        c.setForeground(Color.GRAY);
                        break;
                }
            }

            return c;
        }
    }

    private static class Finding {
        private ParameterInfo paramInfo;
        private CachePoisonVulnerability vulnerability;
        private ScanResult scanResult;

        public Finding(ParameterInfo paramInfo, ScanResult scanResult) {
            this.paramInfo = paramInfo;
            this.scanResult = scanResult;
        }

        public Finding(CachePoisonVulnerability vulnerability, ScanResult scanResult) {
            this.vulnerability = vulnerability;
            this.scanResult = scanResult;
        }

        public String getName() {
            return paramInfo != null ? paramInfo.getName() : vulnerability.getAffectedParameter();
        }

        public String getType() {
            return paramInfo != null ? paramInfo.getType().displayName : vulnerability.getType().displayName;
        }

        public String getEvidence() {
            return paramInfo != null ? paramInfo.getEvidence() : vulnerability.getEvidence();
        }

        public ConfigManager.Severity getSeverity() {
            return paramInfo != null ? paramInfo.getSeverity() : vulnerability.getSeverity();
        }

        public boolean isCached() {
            return paramInfo != null ? paramInfo.isCached() : true;
        }

        public burp.IHttpRequestResponse getRequest() {
            return scanResult.getBaseRequest();
        }

        public String getDetailedDescription() {
            if (paramInfo != null) {
                return String.format(
                        "Parameter: %s\n" +
                                "Type: %s\n" +
                                "Evidence: %s\n" +
                                "Severity: %s\n" +
                                "Cached: %s\n" +
                                "Unkeyed: %s\n" +
                                "Test Value: %s\n" +
                                "Response Snippet: %s\n",
                        paramInfo.getName(),
                        paramInfo.getType().displayName,
                        paramInfo.getEvidence(),
                        paramInfo.getSeverity(),
                        paramInfo.isCached(),
                        paramInfo.isUnkeyed(),
                        paramInfo.getTestValue(),
                        paramInfo.getResponseSnippet());
            } else {
                return String.format(
                        "Vulnerability: %s\n" +
                                "Type: %s\n" +
                                "Affected: %s\n" +
                                "Severity: %s\n" +
                                "Verified: %s\n\n" +
                                "Description:\n%s\n\n" +
                                "Evidence:\n%s\n\n" +
                                "Remediation:\n%s\n",
                        vulnerability.getTitle(),
                        vulnerability.getType().displayName,
                        vulnerability.getAffectedParameter(),
                        vulnerability.getSeverity(),
                        vulnerability.isVerified(),
                        vulnerability.getDescription(),
                        vulnerability.getEvidence(),
                        vulnerability.getRemediation());
            }
        }

        public String getProofOfConcept() {
            if (vulnerability != null && vulnerability.getProofOfConcept() != null) {
                return vulnerability.getProofOfConcept();
            }

            return "# Proof of Concept\n\n" +
                    "Parameter: " + getName() + "\n" +
                    "Type: " + getType() + "\n\n" +
                    "Test the parameter with different values to verify its behavior.";
        }
    }
}
