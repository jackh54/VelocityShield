package com.pandadevv.litslantivpn.util;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.pandadevv.litslantivpn.LitslAntiVPN;
import com.pandadevv.litslantivpn.config.PluginConfig;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class VPNChecker {
    private final PluginConfig config;
    private final IPCache ipCache;
    private static final String PROXYCHECK_URL = "http://proxycheck.io/v2/%s?key=%s&vpn=1";

    public VPNChecker(PluginConfig config, Path dataDirectory) {
        this.config = config;
        this.ipCache = new IPCache(config.getCacheDuration(), TimeUnit.valueOf(config.getCacheTimeUnit()), dataDirectory);
    }

    public CompletableFuture<Boolean> isVPN(String ip) {
        return CompletableFuture.supplyAsync(() -> {
            // Check cache first
            Boolean cachedResult = ipCache.getCachedResult(ip);
            if (cachedResult != null) {
                if (config.isDebug()) {
                    LitslAntiVPN.getInstance().getLogger().info("Using cached result for IP: " + ip + " - VPN: " + cachedResult);
                }
                return cachedResult;
            }

            try {
                URL url = new URL(String.format(PROXYCHECK_URL, ip, config.getProxycheckApiKey()));
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }

                    JsonObject jsonResponse = JsonParser.parseString(response.toString()).getAsJsonObject();
                    if (jsonResponse.has("status") && jsonResponse.get("status").getAsString().equals("ok")) {
                        JsonObject ipData = jsonResponse.getAsJsonObject(ip);
                        if (ipData != null && ipData.has("proxy")) {
                            boolean isVPN = ipData.get("proxy").getAsString().equals("yes");
                            // Cache the result
                            ipCache.cacheResult(ip, isVPN);
                            return isVPN;
                        }
                    }
                }
            } catch (Exception e) {
                if (config.isDebug()) {
                    LitslAntiVPN.getInstance().getLogger().error("Error checking VPN status for IP: " + ip + " - Allowing connection", e);
                }
            }
            // If any error occurs or the response is invalid, allow the connection
            return false;
        });
    }
} 