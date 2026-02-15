package com.pandadevv.VelocityShield.config;

import com.pandadevv.VelocityShield.VelocityShield;
import com.pandadevv.VelocityShield.util.LogHelper;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class PluginConfig {
    private final Path configPath;
    private final Path whitelistPath;
    private final Path logPath;
    private String proxycheckApiKey;
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
        
        if (this.proxycheckApiKey.equals("YOUR_PROXYCHECK_API_KEY") && this.useProxycheckAsPrimary) {
            VelocityShield.getInstance().getLogger().warn("===============================================");
            VelocityShield.getInstance().getLogger().warn("VelocityShield is not configured!");
            VelocityShield.getInstance().getLogger().warn("Please set your proxycheck.io API key in config.yml");
            VelocityShield.getInstance().getLogger().warn("Get your API key at: https://proxycheck.io/");
            VelocityShield.getInstance().getLogger().warn("===============================================");
        }
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

    public void logVPNDetection(String username, String ip) {
        try {
            String timestamp = LocalDateTime.now().format(DATE_FORMAT);
            String logEntry = String.format("[%s] VPN detected - Username: %s, IP: %s%n", timestamp, username, ip);
            
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