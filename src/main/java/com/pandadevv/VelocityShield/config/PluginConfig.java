package com.pandadevv.VelocityShield.config;

import com.pandadevv.VelocityShield.VelocityShield;
import com.pandadevv.VelocityShield.util.LogHelper;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class PluginConfig {
    private final Path configPath;
    private final Path whitelistPath;
    private final Path logPath;
    private String proxycheckApiKey;
    private String vpnapiApiKey;
    private String iphubApiKey;
    private String ipapiIsApiKey;
    private String kickMessageTitle;
    private String kickMessageBody;
    private boolean useProxycheckAsPrimary;
    private boolean enableFallbackService;
    private boolean allowJoinOnApiFailure;
    private boolean enableCache;
    private boolean enableDebug;
    private Set<String> whitelistedIps;
    private long cacheDuration;
    private String cacheTimeUnit;
    private int apiConnectionTimeout;
    private int apiReadTimeout;

    // Multi-provider consensus
    private List<String> enabledProviderNames = new ArrayList<>();
    private Map<String, Double> providerWeights = new HashMap<>();
    private int minVpnVotes;
    private double minConsensusScore;
    private boolean trustMobileNetworks;
    private int mobileMinVpnVotes;
    private boolean alwaysBlockTor;

    // Reporting to an external support/ticket system
    private boolean reportingEnabled;
    private String reportingUrl;
    private String reportingApiKey;
    private String reportingApiKeyHeader;
    private String reportingServerName;
    private boolean reportOnlyBlocked;
    private String reportingMode;

    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public PluginConfig(Path dataDirectory) {
        this.configPath = dataDirectory.resolve("config.yml");
        this.whitelistPath = dataDirectory.resolve("whitelist.txt");
        this.logPath = dataDirectory.resolve("log.txt");
        try {
            Files.createDirectories(dataDirectory);
        } catch (IOException e) {
            LogHelper.logConfigError(VelocityShield.getInstance().getLogger(), "Failed to create plugin directory", e);
        }
        loadConfig();
        loadWhitelist();
    }

    private void loadConfig() {
        try {
            String defaultConfigContent;
            try (InputStream in = getClass().getResourceAsStream("/config.yml")) {
                if (in == null) {
                    VelocityShield.getInstance().getLogger().error("Could not find default config.yml in resources");
                    return;
                }
                defaultConfigContent = new String(in.readAllBytes());
            }

            if (!Files.exists(configPath)) {
                Files.writeString(configPath, defaultConfigContent);
                VelocityShield.getInstance().getLogger().info("Created default configuration file");
            }

            String currentConfigContent = Files.readString(configPath);
            Map<String, Object> currentConfig;
            try {
                Yaml yaml = new Yaml();
                currentConfig = yaml.load(currentConfigContent);
            } catch (Exception e) {
                LogHelper.logConfigError(VelocityShield.getInstance().getLogger(), "Failed to parse config", e);
                return;
            }

            loadValuesFromConfig(currentConfig);
        } catch (IOException e) {
            LogHelper.logConfigError(VelocityShield.getInstance().getLogger(), "Failed to load config", e);
        }
    }

    @SuppressWarnings("unchecked")
    private void loadValuesFromConfig(Map<String, Object> config) {
        this.proxycheckApiKey = (String) config.getOrDefault("proxycheck-api-key", "YOUR_PROXYCHECK_API_KEY");
        this.vpnapiApiKey = (String) config.getOrDefault("vpnapi-api-key", "");
        this.iphubApiKey = (String) config.getOrDefault("iphub-api-key", "");
        this.ipapiIsApiKey = (String) config.getOrDefault("ipapi-is-api-key", "");

        Map<String, Object> kickMessage = (Map<String, Object>) config.getOrDefault("kick-message", Map.of());
        this.kickMessageTitle = (String) kickMessage.getOrDefault("title", "<red><bold>VPN Detected!</bold></red>");
        this.kickMessageBody = (String) kickMessage.getOrDefault("message", 
            "<white>Please join without a VPN.</white>\n<white>If this is a false positive, please open a ticket.</white>");
        
        this.useProxycheckAsPrimary = (Boolean) config.getOrDefault("use-proxycheck-as-primary", true);
        this.enableFallbackService = (Boolean) config.getOrDefault("enable-fallback-service", true);
        this.allowJoinOnApiFailure = (Boolean) config.getOrDefault("allow-join-on-api-failure", true);
        this.enableCache = (Boolean) config.getOrDefault("enable-cache", true);
        this.enableDebug = (Boolean) config.getOrDefault("enable-debug", false);
        this.cacheDuration = ((Number) config.getOrDefault("cache-duration", 24)).longValue();
        this.cacheTimeUnit = (String) config.getOrDefault("cache-time-unit", "HOURS");
        this.apiConnectionTimeout = ((Number) config.getOrDefault("api-connection-timeout", 5000)).intValue();
        this.apiReadTimeout = ((Number) config.getOrDefault("api-read-timeout", 5000)).intValue();

        loadProviders(config);
        loadConsensus(config);
        loadReporting(config);

        if (this.proxycheckApiKey.equals("YOUR_PROXYCHECK_API_KEY")
                && this.enabledProviderNames.contains("proxycheck")) {
            VelocityShield.getInstance().getLogger().warn("===============================================");
            VelocityShield.getInstance().getLogger().warn("No proxycheck.io API key is set in config.yml.");
            VelocityShield.getInstance().getLogger().warn("Other providers will still be used.");
            VelocityShield.getInstance().getLogger().warn("Get a free key at: https://proxycheck.io/");
            VelocityShield.getInstance().getLogger().warn("===============================================");
        }
    }

    @SuppressWarnings("unchecked")
    private void loadProviders(Map<String, Object> config) {
        this.enabledProviderNames = new ArrayList<>();
        this.providerWeights = new HashMap<>();

        Map<String, Object> providers = (Map<String, Object>) config.get("providers");

        // Config from 1.1 and earlier has no providers block. Keep those servers working by
        // turning on the two services that need no key, plus proxycheck if a key is present.
        if (providers == null || providers.isEmpty()) {
            enabledProviderNames.add("proxycheck");
            enabledProviderNames.add("ip-api");
            providerWeights.put("proxycheck", 1.0);
            providerWeights.put("ip-api", 1.0);
            return;
        }

        for (Map.Entry<String, Object> entry : providers.entrySet()) {
            String name = entry.getKey().toLowerCase();
            Object value = entry.getValue();
            boolean enabled;
            double weight = 1.0;

            if (value instanceof Boolean flag) {
                enabled = flag;
            } else if (value instanceof Map<?, ?> settings) {
                Map<String, Object> map = (Map<String, Object>) settings;
                enabled = Boolean.TRUE.equals(map.getOrDefault("enabled", Boolean.TRUE));
                Object rawWeight = map.get("weight");
                if (rawWeight instanceof Number number) weight = number.doubleValue();
                Object key = map.get("api-key");
                if (key instanceof String keyString && !keyString.isBlank()) {
                    switch (name) {
                        case "proxycheck" -> this.proxycheckApiKey = keyString;
                        case "vpnapi", "vpnapi.io" -> this.vpnapiApiKey = keyString;
                        case "iphub" -> this.iphubApiKey = keyString;
                        case "ipapi.is", "ipapiis" -> this.ipapiIsApiKey = keyString;
                        default -> { }
                    }
                }
            } else {
                continue;
            }

            if (enabled) {
                enabledProviderNames.add(name);
                providerWeights.put(name, weight <= 0 ? 1.0 : weight);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void loadConsensus(Map<String, Object> config) {
        Map<String, Object> consensus = (Map<String, Object>) config.getOrDefault("consensus", Map.of());
        this.minVpnVotes = ((Number) consensus.getOrDefault("min-vpn-votes", 2)).intValue();
        this.minConsensusScore = ((Number) consensus.getOrDefault("min-score", 0.5)).doubleValue();
        this.trustMobileNetworks = (Boolean) consensus.getOrDefault("trust-mobile-networks", true);
        this.mobileMinVpnVotes = ((Number) consensus.getOrDefault("mobile-min-vpn-votes", 3)).intValue();
        this.alwaysBlockTor = (Boolean) consensus.getOrDefault("always-block-tor", true);
    }

    @SuppressWarnings("unchecked")
    private void loadReporting(Map<String, Object> config) {
        Map<String, Object> reporting = (Map<String, Object>) config.getOrDefault("reporting", Map.of());
        this.reportingEnabled = (Boolean) reporting.getOrDefault("enabled", false);
        this.reportingUrl = (String) reporting.getOrDefault("url", "");
        this.reportingApiKey = (String) reporting.getOrDefault("api-key", "");
        this.reportingApiKeyHeader = (String) reporting.getOrDefault("api-key-header", "x-api-key");
        this.reportingServerName = (String) reporting.getOrDefault("server-name", "proxy");
        this.reportOnlyBlocked = (Boolean) reporting.getOrDefault("only-blocked", true);
        // mode wins when set; only-blocked is kept so existing configs keep working.
        this.reportingMode = ((String) reporting.getOrDefault("mode",
            this.reportOnlyBlocked ? "blocked" : "all")).toLowerCase();
    }

    public void loadWhitelist() {
        this.whitelistedIps = new HashSet<>();
        if (!Files.exists(whitelistPath)) {
            try {
                Files.createFile(whitelistPath);
            } catch (IOException e) {
                VelocityShield.getInstance().getLogger().error("Failed to create whitelist file", e);
            }
        } else {
            try (BufferedReader reader = Files.newBufferedReader(whitelistPath)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        whitelistedIps.add(line);
                    }
                }
            } catch (IOException e) {
                VelocityShield.getInstance().getLogger().error("Failed to load whitelist", e);
            }
        }
    }

    /**
     * Log a detection along with which providers flagged it, so a "false positive"
     * complaint can be checked afterwards instead of taken on trust.
     */
    public void logVPNDetection(String username, String ip, com.pandadevv.VelocityShield.util.VPNResult result) {
        StringBuilder breakdown = new StringBuilder();
        for (com.pandadevv.VelocityShield.util.provider.ProviderResult provider : result.getProviders()) {
            if (breakdown.length() > 0) breakdown.append(", ");
            breakdown.append(provider.getProvider()).append('=')
                .append(provider.getVerdict().name().toLowerCase());
        }
        logVPNDetection(username, ip, String.format("%s | %s | %s | %s",
            result.getVoteSummary(), result.getConnectionType(), result.getReason(), breakdown));
    }

    public void logVPNDetection(String username, String ip) {
        logVPNDetection(username, ip, (String) null);
    }

    public void logVPNDetection(String username, String ip, String extra) {
        try {
            String timestamp = LocalDateTime.now().format(DATE_FORMAT);
            String logEntry = extra == null
                ? String.format("[%s] VPN detected - Username: %s, IP: %s%n", timestamp, username, ip)
                : String.format("[%s] VPN detected - Username: %s, IP: %s - %s%n", timestamp, username, ip, extra);
            
            Files.write(logPath, logEntry.getBytes(), Files.exists(logPath) ? 
                java.nio.file.StandardOpenOption.APPEND : 
                java.nio.file.StandardOpenOption.CREATE);
        } catch (IOException e) {
            VelocityShield.getInstance().getLogger().error("Failed to write to log file", e);
        }
    }

    public String getProxycheckApiKey() {
        return proxycheckApiKey;
    }

    public String getVpnapiApiKey() {
        return vpnapiApiKey;
    }

    public String getIphubApiKey() {
        return iphubApiKey;
    }

    public String getIpapiIsApiKey() {
        return ipapiIsApiKey;
    }

    public List<String> getEnabledProviderNames() {
        return new ArrayList<>(enabledProviderNames);
    }

    public double getProviderWeight(String provider) {
        return providerWeights.getOrDefault(provider.toLowerCase(), 1.0);
    }

    public int getMinVpnVotes() {
        return Math.max(1, minVpnVotes);
    }

    public double getMinConsensusScore() {
        return minConsensusScore;
    }

    public boolean isTrustMobileNetworks() {
        return trustMobileNetworks;
    }

    public int getMobileMinVpnVotes() {
        return mobileMinVpnVotes;
    }

    public boolean isAlwaysBlockTor() {
        return alwaysBlockTor;
    }

    public boolean isReportingEnabled() {
        return reportingEnabled;
    }

    public String getReportingUrl() {
        return reportingUrl;
    }

    public String getReportingApiKey() {
        return reportingApiKey;
    }

    public String getReportingApiKeyHeader() {
        return reportingApiKeyHeader == null || reportingApiKeyHeader.isBlank()
            ? "x-api-key" : reportingApiKeyHeader;
    }

    public String getReportingServerName() {
        return reportingServerName;
    }

    public boolean isReportOnlyBlocked() {
        return reportOnlyBlocked;
    }

    /** "blocked" = kicks only, "flagged" = kicks plus anyone at least one provider flagged, "all" = every check. */
    public String getReportingMode() {
        return reportingMode == null ? "blocked" : reportingMode;
    }

    public String getKickMessageTitle() {
        return kickMessageTitle;
    }

    public String getKickMessageBody() {
        return kickMessageBody;
    }

    public boolean isUseProxycheckAsPrimary() {
        return useProxycheckAsPrimary;
    }

    public boolean isEnableFallbackService() {
        return enableFallbackService;
    }

    public boolean isAllowJoinOnApiFailure() {
        return allowJoinOnApiFailure;
    }

    public boolean isEnableCache() {
        return enableCache;
    }

    public boolean isEnableDebug() {
        return enableDebug;
    }

    public boolean isIPWhitelisted(String ip) {
        return whitelistedIps.contains(ip);
    }

    public void reloadWhitelist() {
        loadWhitelist();
    }

    public long getCacheDuration() {
        return cacheDuration;
    }

    public String getCacheTimeUnit() {
        return cacheTimeUnit;
    }

    public void addToWhitelist(String ip) {
        if (whitelistedIps.add(ip)) {
            try {
                Files.write(whitelistPath, (ip + "\n").getBytes(), 
                    Files.exists(whitelistPath) ? 
                        java.nio.file.StandardOpenOption.APPEND : 
                        java.nio.file.StandardOpenOption.CREATE);
            } catch (IOException e) {
                VelocityShield.getInstance().getLogger().error("Failed to add IP to whitelist: " + ip, e);
            }
        }
    }

    public void removeFromWhitelist(String ip) {
        if (whitelistedIps.remove(ip)) {
            try {
                Set<String> lines = new HashSet<>(Files.readAllLines(whitelistPath));
                lines.remove(ip);
                Files.write(whitelistPath, lines);
            } catch (IOException e) {
                VelocityShield.getInstance().getLogger().error("Failed to remove IP from whitelist: " + ip, e);
            }
        }
    }

    public void reload() {
        loadConfig();
        loadWhitelist();
    }

    public int getApiConnectionTimeout() {
        return apiConnectionTimeout;
    }

    public int getApiReadTimeout() {
        return apiReadTimeout;
    }

    public Set<String> getWhitelistedIps() {
        return new HashSet<>(whitelistedIps);
    }
} 