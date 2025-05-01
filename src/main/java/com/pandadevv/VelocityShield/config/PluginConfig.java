package com.pandadevv.VelocityShield.config;

import com.pandadevv.VelocityShield.VelocityShield;
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
    private String kickMessage;
    private boolean proxycheckIoAsMainCheck;
    private boolean fallbackToNonMain;
    private boolean allowJoinOnFailure;
    private boolean enableCache;
    private boolean debug;
    private Set<String> whitelistedIps;
    private long cacheDuration;
    private String cacheTimeUnit;
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final double CURRENT_CONFIG_VERSION = 1.1;

    public PluginConfig(Path dataDirectory) {
        this.configPath = dataDirectory.resolve("config.yml");
        this.whitelistPath = dataDirectory.resolve("whitelist.txt");
        this.logPath = dataDirectory.resolve("log.txt");
        try {
            Files.createDirectories(dataDirectory);
        } catch (IOException e) {
            VelocityShield.getInstance().getLogger().error("Failed to create plugin directory", e);
        }
        loadConfig();
        loadWhitelist();
    }

    private void loadConfig() {
        try {
            // Load the default config from resources
            String defaultConfigContent;
            try (InputStream in = getClass().getResourceAsStream("/config.yml")) {
                if (in == null) {
                    VelocityShield.getInstance().getLogger().error("Could not find default config.yml in resources");
                    return;
                }
                defaultConfigContent = new String(in.readAllBytes());
            }

            // If config doesn't exist, copy it from resources and return
            if (!Files.exists(configPath)) {
                Files.writeString(configPath, defaultConfigContent);
                // Load values from default config
                Yaml yaml = new Yaml();
                Map<String, Object> defaultConfig = yaml.load(defaultConfigContent);
                loadValuesFromConfig(defaultConfig);
                return;
            }

            // Load the current config
            String currentConfigContent = Files.readString(configPath);
            Map<String, Object> currentConfig;
            try {
                Yaml yaml = new Yaml();
                currentConfig = yaml.load(currentConfigContent);
            } catch (Exception e) {
                VelocityShield.getInstance().getLogger().error("Failed to parse current config, using default", e);
                currentConfig = new java.util.LinkedHashMap<>();
            }

            // Get current config version
            double configVersion = ((Number) currentConfig.getOrDefault("config-version", 0)).doubleValue();
            
            // If config version is lower than current, update it
            if (configVersion < CURRENT_CONFIG_VERSION) {
                VelocityShield.getInstance().getLogger().info("Updating config from version " + configVersion + " to " + CURRENT_CONFIG_VERSION);
                
                // Parse the default config to get its structure
                Yaml yaml = new Yaml();
                Map<String, Object> defaultConfig = yaml.load(defaultConfigContent);
                
                // Process the current config content to preserve formatting
                String[] lines = currentConfigContent.split("\n");
                StringBuilder updatedConfig = new StringBuilder();
                
                // Process each line
                for (String line : lines) {
                    if (line.trim().startsWith("#")) {
                        // Keep comments as is
                        updatedConfig.append(line).append("\n");
                    } else if (line.contains(":")) {
                        String key = line.substring(0, line.indexOf(":")).trim();
                        if (key.equals("config-version")) {
                            // Update config version
                            updatedConfig.append("config-version: ").append(CURRENT_CONFIG_VERSION).append("\n");
                        } else if (defaultConfig.containsKey(key) && !currentConfig.containsKey(key)) {
                            // Add new option
                            Object value = defaultConfig.get(key);
                            if (value instanceof String && ((String) value).contains("\n")) {
                                updatedConfig.append(key).append(": |\n");
                                for (String valueLine : ((String) value).split("\n")) {
                                    updatedConfig.append("  ").append(valueLine).append("\n");
                                }
                            } else {
                                updatedConfig.append(key).append(": ").append(value).append("\n");
                            }
                        } else {
                            // Keep existing line
                            updatedConfig.append(line).append("\n");
                        }
                    } else {
                        // Keep other lines as is
                        updatedConfig.append(line).append("\n");
                    }
                }
                
                // Write the updated config
                Files.writeString(configPath, updatedConfig.toString());
            }
            
            // Load values from current config
            loadValuesFromConfig(currentConfig);
        } catch (IOException e) {
            VelocityShield.getInstance().getLogger().error("Failed to load config", e);
        }
    }

    private void loadValuesFromConfig(Map<String, Object> config) {
        this.proxycheckApiKey = (String) config.getOrDefault("proxycheck-api-key", "YOUR_PROXYCHECK_API_KEY");
        this.kickMessage = (String) config.getOrDefault("kick-message", "§c§lVPN Detected!\n\n§fPlease join without a VPN.\n§fIf this is a false positive, please open a ticket.");
        this.proxycheckIoAsMainCheck = (Boolean) config.getOrDefault("proxycheck-io-as-main-check", true);
        this.fallbackToNonMain = (Boolean) config.getOrDefault("fallback-to-non-main", true);
        this.allowJoinOnFailure = (Boolean) config.getOrDefault("allow-join-on-failure", true);
        this.enableCache = (Boolean) config.getOrDefault("enable-cache", true);
        this.debug = (Boolean) config.getOrDefault("debug", false);
        this.cacheDuration = ((Number) config.getOrDefault("cache-duration", 24)).longValue();
        this.cacheTimeUnit = (String) config.getOrDefault("cache-time-unit", "HOURS");
        
        // Check if API key is configured
        if (this.proxycheckApiKey.equals("YOUR_PROXYCHECK_API_KEY")) {
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

    public String getKickMessage() {
        return kickMessage;
    }

    public boolean isProxycheckIoAsMainCheck() {
        return proxycheckIoAsMainCheck;
    }

    public boolean isFallbackToNonMain() {
        return fallbackToNonMain;
    }

    public boolean isAllowJoinOnFailure() {
        return allowJoinOnFailure;
    }

    public boolean isDebug() {
        return debug;
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

    public boolean isEnableCache() {
        return enableCache;
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
                // Read all lines
                Set<String> lines = new HashSet<>(Files.readAllLines(whitelistPath));
                // Remove the IP
                lines.remove(ip);
                // Write back all lines
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
} 