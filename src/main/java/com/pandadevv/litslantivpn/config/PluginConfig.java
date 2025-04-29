package com.pandadevv.litslantivpn.config;

import com.pandadevv.litslantivpn.LitslAntiVPN;
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
    private boolean useIpApiAsFallback;
    private boolean debug;
    private Set<String> whitelistedIps;
    private long cacheDuration;
    private String cacheTimeUnit;
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public PluginConfig(Path dataDirectory) {
        this.configPath = dataDirectory.resolve("config.yml");
        this.whitelistPath = dataDirectory.resolve("whitelist.txt");
        this.logPath = dataDirectory.resolve("log.txt");
        try {
            Files.createDirectories(dataDirectory);
        } catch (IOException e) {
            LitslAntiVPN.getInstance().getLogger().error("Failed to create plugin directory", e);
        }
        loadConfig();
        loadWhitelist();
    }

    private void loadConfig() {
        if (!Files.exists(configPath)) {
            // Default configuration
            this.proxycheckApiKey = "YOUR_PROXYCHECK_API_KEY";
            this.kickMessage = "§c§lVPN Detected!\n\n§fPlease join without a VPN.\n§fIf this is a false positive, please open a ticket.";
            this.useIpApiAsFallback = true;
            this.debug = false;
            this.cacheDuration = 24;
            this.cacheTimeUnit = "HOURS";
            saveConfig();
        } else {
            try (Reader reader = Files.newBufferedReader(configPath)) {
                Yaml yaml = new Yaml();
                Map<String, Object> config = yaml.load(reader);
                
                this.proxycheckApiKey = (String) config.getOrDefault("proxycheck-api-key", "YOUR_PROXYCHECK_API_KEY");
                this.kickMessage = (String) config.getOrDefault("kick-message", "§c§lVPN Detected!\n\n§fPlease join without a VPN.\n§fIf this is a false positive, please open a ticket.");
                this.useIpApiAsFallback = (Boolean) config.getOrDefault("use-ip-api-fallback", true);
                this.debug = (Boolean) config.getOrDefault("debug", false);
                this.cacheDuration = ((Number) config.getOrDefault("cache-duration", 24)).longValue();
                this.cacheTimeUnit = (String) config.getOrDefault("cache-time-unit", "HOURS");
            } catch (IOException e) {
                LitslAntiVPN.getInstance().getLogger().error("Failed to load config", e);
            }
        }
    }

    public void loadWhitelist() {
        this.whitelistedIps = new HashSet<>();
        if (!Files.exists(whitelistPath)) {
            try {
                Files.createFile(whitelistPath);
            } catch (IOException e) {
                LitslAntiVPN.getInstance().getLogger().error("Failed to create whitelist file", e);
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
                LitslAntiVPN.getInstance().getLogger().error("Failed to load whitelist", e);
            }
        }
    }

    public void saveConfig() {
        try {
            Map<String, Object> config = new java.util.HashMap<>();
            config.put("proxycheck-api-key", proxycheckApiKey);
            config.put("kick-message", kickMessage);
            config.put("use-ip-api-fallback", useIpApiAsFallback);
            config.put("debug", debug);
            config.put("cache-duration", cacheDuration);
            config.put("cache-time-unit", cacheTimeUnit);

            Yaml yaml = new Yaml();
            try (Writer writer = Files.newBufferedWriter(configPath)) {
                yaml.dump(config, writer);
            }
        } catch (IOException e) {
            LitslAntiVPN.getInstance().getLogger().error("Failed to save config", e);
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
            LitslAntiVPN.getInstance().getLogger().error("Failed to write to log file", e);
        }
    }

    public String getProxycheckApiKey() {
        return proxycheckApiKey;
    }

    public String getKickMessage() {
        return kickMessage;
    }

    public boolean isUseIpApiAsFallback() {
        return useIpApiAsFallback;
    }

    public boolean isDebug() {
        return debug;
    }

    public boolean isIpWhitelisted(String ip) {
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
} 