package com.pandadevv.VelocityShield.util;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.pandadevv.VelocityShield.VelocityShield;
import com.pandadevv.VelocityShield.config.PluginConfig;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Path;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class VPNChecker {
    private final PluginConfig config;
    private final IPCache ipCache;
    private static final String PROXYCHECK_URL = "http://proxycheck.io/v2/%s?key=%s&vpn=1";
    private static final String IP_API_URL = "http://ip-api.com/json/%s?fields=status,isp,org,proxy,query";
    private static final int CONNECTION_TIMEOUT = 3000;
    private static final int READ_TIMEOUT = 3000;
    private static final int MAX_REQUESTS_PER_SECOND = 10;
    private final AtomicInteger requestCount = new AtomicInteger(0);
    private final AtomicLong lastResetTime = new AtomicLong(System.currentTimeMillis());
    private final ExecutorService executorService;
    private static final JsonParser jsonParser = new JsonParser();

    public VPNChecker(PluginConfig config, Path dataDirectory) {
        this.config = config;
        this.ipCache = new IPCache(config.getCacheDuration(), TimeUnit.valueOf(config.getCacheTimeUnit()), dataDirectory);
        this.executorService = new ThreadPoolExecutor(
            2,
            4,
            60L,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(100),
            new ThreadPoolExecutor.CallerRunsPolicy()
        );
    }

    public CompletableFuture<Boolean> isVPN(String ip) {
        return CompletableFuture.supplyAsync(() -> {
            if (config.isEnableCache()) {
                Boolean cachedResult = ipCache.getCachedResult(ip);
                if (cachedResult != null) {
                    if (config.isDebug()) {
                        VelocityShield.getInstance().getLogger().info("Using cached result for IP: " + ip + " - VPN: " + cachedResult);
                    }
                    return cachedResult;
                }
            }

            try {
                waitForRateLimit();
                Boolean mainCheckResult = checkWithMainService(ip);
                if (mainCheckResult != null) {
                    if (config.isEnableCache()) {
                        ipCache.cacheResult(ip, mainCheckResult);
                    }
                    return mainCheckResult;
                }
                if (config.isFallbackToNonMain()) {
                    waitForRateLimit();
                    Boolean fallbackResult = checkWithFallbackService(ip);
                    if (fallbackResult != null) {
                        if (config.isEnableCache()) {
                            ipCache.cacheResult(ip, fallbackResult);
                        }
                        return fallbackResult;
                    }
                }
                if (config.isAllowJoinOnFailure()) {
                    if (config.isDebug()) {
                        VelocityShield.getInstance().getLogger().warn("Both VPN checks failed for IP: " + ip + " - Allowing connection due to allow-join-on-failure setting");
                    }
                    return false;
                } else {
                    if (config.isDebug()) {
                        VelocityShield.getInstance().getLogger().warn("Both VPN checks failed for IP: " + ip + " - Blocking connection due to allow-join-on-failure setting");
                    }
                    return true;
                }
            } catch (Exception e) {
                VelocityShield.getInstance().getLogger().error("Error checking VPN status for IP: " + ip, e);
                return config.isAllowJoinOnFailure() ? false : true;
            }
        }, executorService);
    }

    private void waitForRateLimit() {
        long currentTime = System.currentTimeMillis();
        long lastReset = lastResetTime.get();
        if (currentTime - lastReset >= 1000) {
            requestCount.set(0);
            lastResetTime.set(currentTime);
        }
        while (requestCount.get() >= MAX_REQUESTS_PER_SECOND) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        requestCount.incrementAndGet();
    }

    private Boolean checkWithMainService(String ip) {
        try {
            String url = config.isProxycheckIoAsMainCheck() ? 
                String.format(PROXYCHECK_URL, ip, config.getProxycheckApiKey()) :
                String.format(IP_API_URL, ip);

            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(CONNECTION_TIMEOUT);
            conn.setReadTimeout(READ_TIMEOUT);
            conn.setRequestProperty("User-Agent", "VelocityShield/1.0");

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                StringBuilder response = new StringBuilder();
                char[] buffer = new char[1024];
                int read;
                while ((read = reader.read(buffer)) != -1) {
                    response.append(buffer, 0, read);
                }

                JsonObject jsonResponse = jsonParser.parse(response.toString()).getAsJsonObject();
                
                if (config.isProxycheckIoAsMainCheck()) {
                    if (jsonResponse.has("status") && jsonResponse.get("status").getAsString().equals("ok")) {
                        JsonObject ipData = jsonResponse.getAsJsonObject(ip);
                        if (ipData != null && ipData.has("proxy")) {
                            return ipData.get("proxy").getAsString().equals("yes");
                        }
                    }
                } else {
                    if (jsonResponse.has("status") && jsonResponse.get("status").getAsString().equals("success")) {
                        return jsonResponse.has("proxy") && jsonResponse.get("proxy").getAsBoolean();
                    }
                }
            }
        } catch (Exception e) {
            if (config.isDebug()) {
                VelocityShield.getInstance().getLogger().error("Error with main VPN check for IP: " + ip, e);
            }
        }
        return null;
    }

    private Boolean checkWithFallbackService(String ip) {
        try {
            String url = !config.isProxycheckIoAsMainCheck() ? 
                String.format(PROXYCHECK_URL, ip, config.getProxycheckApiKey()) :
                String.format(IP_API_URL, ip);

            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(CONNECTION_TIMEOUT);
            conn.setReadTimeout(READ_TIMEOUT);
            conn.setRequestProperty("User-Agent", "VelocityShield/1.0");

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                StringBuilder response = new StringBuilder();
                char[] buffer = new char[1024];
                int read;
                while ((read = reader.read(buffer)) != -1) {
                    response.append(buffer, 0, read);
                }

                JsonObject jsonResponse = jsonParser.parse(response.toString()).getAsJsonObject();
                
                if (!config.isProxycheckIoAsMainCheck()) {
                    if (jsonResponse.has("status") && jsonResponse.get("status").getAsString().equals("ok")) {
                        JsonObject ipData = jsonResponse.getAsJsonObject(ip);
                        if (ipData != null && ipData.has("proxy")) {
                            return ipData.get("proxy").getAsString().equals("yes");
                        }
                    }
                } else {
                    if (jsonResponse.has("status") && jsonResponse.get("status").getAsString().equals("success")) {
                        return jsonResponse.has("proxy") && jsonResponse.get("proxy").getAsBoolean();
                    }
                }
            }
        } catch (Exception e) {
            if (config.isDebug()) {
                VelocityShield.getInstance().getLogger().error("Error with fallback VPN check for IP: " + ip, e);
            }
        }
        return null;
    }

    public void shutdown() {
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
} 