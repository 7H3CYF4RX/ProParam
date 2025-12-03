package com.apm.core;

import burp.*;
import com.apm.detection.*;
import com.apm.models.*;
import com.apm.analysis.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * Core scan orchestration engine
 */
public class ScanEngine {

    private final BurpExtender extender;
    private final ExecutorService executorService;
    private final Map<String, ScanTask> activeScanTasks;
    private final List<ScanResult> allResults;

    public ScanEngine(BurpExtender extender) {
        this.extender = extender;
        this.activeScanTasks = new ConcurrentHashMap<>();
        this.allResults = new CopyOnWriteArrayList<>();

        int threadCount = extender.getConfigManager().getConfig().threadCount;
        this.executorService = Executors.newFixedThreadPool(threadCount);
    }

    public void startScan(IHttpRequestResponse baseRequest) {
        String taskId = UUID.randomUUID().toString();

        ScanTask task = new ScanTask(taskId, baseRequest, ScanMode.FULL);
        activeScanTasks.put(taskId, task);

        executorService.submit(() -> {
            try {
                executeScan(task);
            } catch (Exception e) {
                extender.getStderr().println("Scan error: " + e.getMessage());
                e.printStackTrace(extender.getStderr());
            } finally {
                activeScanTasks.remove(taskId);
            }
        });

        extender.getStdout().println("Started scan " + taskId);
    }

    public void startQuickScan(IHttpRequestResponse baseRequest) {
        String taskId = UUID.randomUUID().toString();

        ScanTask task = new ScanTask(taskId, baseRequest, ScanMode.QUICK);
        activeScanTasks.put(taskId, task);

        executorService.submit(() -> {
            try {
                executeScan(task);
            } catch (Exception e) {
                extender.getStderr().println("Quick scan error: " + e.getMessage());
                e.printStackTrace(extender.getStderr());
            } finally {
                activeScanTasks.remove(taskId);
            }
        });
    }

    public void analyzeCacheBehavior(IHttpRequestResponse baseRequest) {
        executorService.submit(() -> {
            try {
                CacheBehaviorAnalyzer analyzer = new CacheBehaviorAnalyzer(extender);
                CacheAnalysisResult result = analyzer.analyze(baseRequest);

                // Update UI with results
                if (extender.getMainPanel() != null) {
                    extender.getMainPanel().displayCacheAnalysis(result);
                }
            } catch (Exception e) {
                extender.getStderr().println("Cache analysis error: " + e.getMessage());
            }
        });
    }

    private void executeScan(ScanTask task) {
        task.setStatus(ScanStatus.RUNNING);
        ScanResult result = new ScanResult(task.getTaskId(), task.getBaseRequest());

        extender.getStdout().println("Executing scan: " + task.getTaskId());

        ConfigManager.ScanConfig config = extender.getConfigManager().getConfig();

        // 1. Parameter Discovery
        if (task.getMode() == ScanMode.FULL || task.getMode() == ScanMode.QUICK) {
            extender.getStdout().println("  > Running parameter discovery...");
            ParamDiscovery paramDiscovery = new ParamDiscovery(extender);
            List<ParameterInfo> params = paramDiscovery.discover(task.getBaseRequest());
            result.addParameters(params);
            extender.getStdout().println("    Found " + params.size() + " parameters");
        }

        // 2. Header Discovery
        if (config.includeHeaders && task.getMode() == ScanMode.FULL) {
            extender.getStdout().println("  > Running header discovery...");
            HeaderDiscovery headerDiscovery = new HeaderDiscovery(extender);
            List<ParameterInfo> headers = headerDiscovery.discover(task.getBaseRequest());
            result.addParameters(headers);
            extender.getStdout().println("    Found " + headers.size() + " headers");
        }

        // 3. Cache Poisoning Detection
        if (config.enableCacheAnalysis) {
            extender.getStdout().println("  > Analyzing cache behavior...");
            CachePoisonDetector cacheDetector = new CachePoisonDetector(extender);
            List<CachePoisonVulnerability> vulns = cacheDetector.detect(task.getBaseRequest());
            result.addVulnerabilities(vulns);
            extender.getStdout().println("    Found " + vulns.size() + " cache poisoning issues");
        }

        task.setStatus(ScanStatus.COMPLETED);
        task.setProgress(100);
        allResults.add(result);

        // Update UI
        if (extender.getMainPanel() != null) {
            extender.getMainPanel().addScanResult(result);
        }

        // Create Burp issues
        if (config.createBurpIssues) {
            createBurpIssues(result);
        }

        extender.getStdout().println("Scan completed: " + task.getTaskId());
    }

    private void createBurpIssues(ScanResult result) {
        for (CachePoisonVulnerability vuln : result.getVulnerabilities()) {
            if (vuln.getSeverity().level >= extender.getConfigManager().getConfig().minSeverityToReport.level) {
                // Create custom issue
                CustomScanIssue issue = new CustomScanIssue(
                        result.getBaseRequest(),
                        vuln,
                        extender.getHelpers());
                extender.getCallbacks().addScanIssue(issue);
            }
        }
    }

    public List<ScanTask> getActiveTasks() {
        return new ArrayList<>(activeScanTasks.values());
    }

    public List<ScanResult> getAllResults() {
        return new ArrayList<>(allResults);
    }

    public void stopScan(String taskId) {
        ScanTask task = activeScanTasks.get(taskId);
        if (task != null) {
            task.setStatus(ScanStatus.STOPPED);
            activeScanTasks.remove(taskId);
        }
    }

    public void shutdown() {
        executorService.shutdownNow();
    }

    // Inner classes
    public static class ScanTask {
        private final String taskId;
        private final IHttpRequestResponse baseRequest;
        private final ScanMode mode;
        private ScanStatus status;
        private int progress;

        public ScanTask(String taskId, IHttpRequestResponse baseRequest, ScanMode mode) {
            this.taskId = taskId;
            this.baseRequest = baseRequest;
            this.mode = mode;
            this.status = ScanStatus.PENDING;
            this.progress = 0;
        }

        public String getTaskId() {
            return taskId;
        }

        public IHttpRequestResponse getBaseRequest() {
            return baseRequest;
        }

        public ScanMode getMode() {
            return mode;
        }

        public ScanStatus getStatus() {
            return status;
        }

        public void setStatus(ScanStatus status) {
            this.status = status;
        }

        public int getProgress() {
            return progress;
        }

        public void setProgress(int progress) {
            this.progress = progress;
        }
    }

    public enum ScanMode {
        QUICK,
        FULL,
        CACHE_ONLY
    }

    public enum ScanStatus {
        PENDING,
        RUNNING,
        COMPLETED,
        STOPPED,
        ERROR
    }
}
