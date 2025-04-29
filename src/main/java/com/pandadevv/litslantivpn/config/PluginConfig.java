package com.pandadevv.litslantivpn.config;

import com.pandadevv.litslantivpn.VelocityShield;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.DumperOptions;

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
        if (!Files.exists(configPath)) {
            // Default configuration
            this.proxycheckApiKey = "YOUR_PROXYCHECK_API_KEY";
            this.kickMessage = "§c§lVPN Detected!\n\n§fPlease join without a VPN.\n§fIf this is a false positive, please open a ticket.";
            this.proxycheckIoAsMainCheck = true;
            this.fallbackToNonMain = true;
            this.allowJoinOnFailure = true;
            this.enableCache = true;
            this.debug = false;
            this.cacheDuration = 24;
            this.cacheTimeUnit = "HOURS";
            saveConfig();
        } else {
            try (Reader reader = Files.newBufferedReader(configPath)) {
                Yaml yaml = new Yaml();
                Map<String, Object> config = yaml.load(reader);
                
                // Get current config version
                double configVersion = ((Number) config.getOrDefault("config-version", 0)).doubleValue();
                
                // Load existing values
                this.proxycheckApiKey = (String) config.getOrDefault("proxycheck-api-key", "YOUR_PROXYCHECK_API_KEY");
                this.kickMessage = (String) config.getOrDefault("kick-message", "§c§lVPN Detected!\n\n§fPlease join without a VPN.\n§fIf this is a false positive, please open a ticket.");
                this.proxycheckIoAsMainCheck = (Boolean) config.getOrDefault("proxycheck-io-as-main-check", true);
                this.fallbackToNonMain = (Boolean) config.getOrDefault("fallback-to-non-main", true);
                this.allowJoinOnFailure = (Boolean) config.getOrDefault("allow-join-on-failure", true);
                this.enableCache = (Boolean) config.getOrDefault("enable-cache", true);
                this.debug = (Boolean) config.getOrDefault("debug", false);
                this.cacheDuration = ((Number) config.getOrDefault("cache-duration", 24)).longValue();
                this.cacheTimeUnit = (String) config.getOrDefault("cache-time-unit", "HOURS");
                
                // If config version is lower than current, update it
                if (configVersion < CURRENT_CONFIG_VERSION) {
                    VelocityShield.getInstance().getLogger().info("Updating config from version " + configVersion + " to " + CURRENT_CONFIG_VERSION);
                    saveConfig();
                }
            } catch (IOException e) {
                VelocityShield.getInstance().getLogger().error("Failed to load config", e);
            }
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

    public void saveConfig() {
        try {
            // Create a map with the desired order
            Map<String, Object> config = new java.util.LinkedHashMap<>();
            
            // Add values in the desired order with comments
            config.put("proxycheck-api-key", proxycheckApiKey);
            config.put("kick-message", kickMessage);
            config.put("proxycheck-io-as-main-check", proxycheckIoAsMainCheck);
            config.put("fallback-to-non-main", fallbackToNonMain);
            config.put("allow-join-on-failure", allowJoinOnFailure);
            config.put("enable-cache", enableCache);
            config.put("cache-duration", cacheDuration);
            config.put("cache-time-unit", cacheTimeUnit);
            config.put("debug", debug);
            config.put("config-version", CURRENT_CONFIG_VERSION);

            // Configure YAML options
            DumperOptions options = new DumperOptions();
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            options.setPrettyFlow(true);
            options.setIndent(2);
            options.setWidth(120);
            options.setDefaultScalarStyle(DumperOptions.ScalarStyle.LITERAL);

            // Create YAML with comments
            StringBuilder yamlContent = new StringBuilder();
            yamlContent.append("# VelocityShield Configuration\n");
            yamlContent.append("# Utilizes proxycheck.io and ip-api.com to check for VPNs\n");
            yamlContent.append("# https://proxycheck.io/\n");
            yamlContent.append("proxycheck-api-key: \"").append(proxycheckApiKey).append("\"\n\n");
            yamlContent.append("kick-message: |\n");
            yamlContent.append("  ").append(kickMessage.replace("\n", "\n  ")).append("\n\n");
            yamlContent.append("# Use proxycheck.io as the main check (recommended)\n");
            yamlContent.append("proxycheck-io-as-main-check: ").append(proxycheckIoAsMainCheck).append("\n");
            yamlContent.append("# Fallback to either ip-api.com or proxycheck.io if the main check fails\n");
            yamlContent.append("# (recommended if you use the free tier of proxycheck.io)\n");
            yamlContent.append("fallback-to-non-main: ").append(fallbackToNonMain).append("\n\n");
            yamlContent.append("# Do you want to allow players to join even if the VPN check fails (eg. you run out of requests)?\n");
            yamlContent.append("allow-join-on-failure: ").append(allowJoinOnFailure).append("\n\n");
            yamlContent.append("# Cache settings\n");
            yamlContent.append("# Enable caching to reduce API requests (recommended)\n");
            yamlContent.append("enable-cache: ").append(enableCache).append("\n");
            yamlContent.append("cache-duration: ").append(cacheDuration).append("\n");
            yamlContent.append("cache-time-unit: \"").append(cacheTimeUnit).append("\" # Options: SECONDS, MINUTES, HOURS, DAYS \n\n");
            yamlContent.append("# Enable debug mode for detailed logging\n");
            yamlContent.append("debug: ").append(debug).append("\n\n");
            yamlContent.append("config-version: ").append(CURRENT_CONFIG_VERSION).append("\n");

            // Write to file
            try (Writer writer = Files.newBufferedWriter(configPath)) {
                writer.write(yamlContent.toString());
            }
        } catch (IOException e) {
            VelocityShield.getInstance().getLogger().error("Failed to save config", e);
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