package com.pandadevv.VelocityShield.util;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.pandadevv.VelocityShield.VelocityShield;
import com.pandadevv.VelocityShield.config.PluginConfig;
import com.pandadevv.VelocityShield.util.provider.ProviderResult;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;

/**
 * Optionally posts the per-provider breakdown of a check to an external endpoint.
 *
 * <p>This exists so a support system can tell a player exactly which services flagged
 * them when they open a "false positive" ticket, instead of staff guessing. Sending is
 * fire-and-forget on a background thread: the endpoint being down must never slow down
 * or block a login.
 */
public class ShieldReporter {

    private final PluginConfig config;
    private final ExecutorService executor;

    public ShieldReporter(PluginConfig config) {
        this.config = config;
        this.executor = new ThreadPoolExecutor(
            0, 2, 30L, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(100),
            r -> {
                Thread t = new Thread(r, "VelocityShield-Reporter");
                t.setDaemon(true);
                return t;
            },
            new ThreadPoolExecutor.DiscardOldestPolicy()
        );
    }

    public void report(String username, String uuid, VPNResult result, boolean kicked) {
        if (!config.isReportingEnabled()) return;
        if (config.getReportingUrl() == null || config.getReportingUrl().isBlank()) return;
        // "flagged" keeps the near-misses: somebody let through who a provider still
        // disliked is exactly who turns up in a support ticket saying they cannot join.
        switch (config.getReportingMode()) {
            case "all" -> { }
            case "flagged" -> { if (!kicked && result.getVpnVotes() == 0) return; }
            default -> { if (!kicked) return; }
        }

        executor.execute(() -> {
            try {
                send(buildPayload(username, uuid, result, kicked));
            } catch (Exception e) {
                if (config.isEnableDebug()) {
                    VelocityShield.getInstance().getLogger()
                        .warn("Could not report VPN check for {}: {}", username, e.getMessage());
                }
            }
        });
    }

    private JsonObject buildPayload(String username, String uuid, VPNResult result, boolean kicked) {
        JsonObject payload = new JsonObject();
        payload.addProperty("player", username);
        if (uuid != null) payload.addProperty("uuid", uuid);
        payload.addProperty("ip", result.getIp());
        payload.addProperty("blocked", kicked);
        payload.addProperty("score", round(result.getScore()));
        payload.addProperty("votes_vpn", result.getVpnVotes());
        payload.addProperty("votes_total", result.getAnsweredCount());
        payload.addProperty("reason", result.getReason());
        payload.addProperty("connection_type", result.getConnectionType());
        payload.addProperty("checked_at", result.getCheckedAt());
        payload.addProperty("source", "velocityshield");
        payload.addProperty("server", config.getReportingServerName());
        if (result.getIsp() != null) payload.addProperty("isp", result.getIsp());
        if (result.getAsn() != null) payload.addProperty("asn", result.getAsn());
        if (result.getCountry() != null) payload.addProperty("country", result.getCountry());

        JsonArray providers = new JsonArray();
        for (ProviderResult provider : result.getProviders()) {
            JsonObject entry = new JsonObject();
            entry.addProperty("name", provider.getProvider());
            entry.addProperty("verdict", provider.getVerdict().name().toLowerCase());
            entry.addProperty("detail", provider.getDetail());
            entry.addProperty("latency_ms", provider.getLatencyMs());
            providers.add(entry);
        }
        payload.add("providers", providers);
        return payload;
    }

    private void send(JsonObject payload) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(config.getReportingUrl()).openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(config.getApiConnectionTimeout());
            conn.setReadTimeout(config.getApiReadTimeout());
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("User-Agent", "VelocityShield/1.2.0");
            if (config.getReportingApiKey() != null && !config.getReportingApiKey().isBlank()) {
                conn.setRequestProperty(config.getReportingApiKeyHeader(), config.getReportingApiKey());
            }

            byte[] body = payload.toString().getBytes(StandardCharsets.UTF_8);
            try (OutputStream out = conn.getOutputStream()) {
                out.write(body);
            }

            int status = conn.getResponseCode();
            if (status >= 400) {
                throw new IllegalStateException("endpoint returned HTTP " + status);
            }
        } finally {
            conn.disconnect();
        }
    }

    private static double round(double value) {
        return Math.round(value * 100.0) / 100.0;
    }

    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(3, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
