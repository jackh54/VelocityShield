package com.pandadevv.VelocityShield.util.provider;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * A single VPN/proxy reputation service.
 *
 * <p>Implementations must never throw out of {@link #check}: return an ERROR result
 * instead, so one broken service cannot decide whether a player gets in.
 */
public abstract class VPNProvider {

    /** Config key and display name, e.g. "proxycheck". */
    public abstract String name();

    /** False when the service needs an API key that has not been set. */
    public boolean isConfigured() {
        return true;
    }

    /** Where to get a key, shown in logs when a keyed provider is enabled without one. */
    public String signupUrl() {
        return null;
    }

    protected abstract ProviderResult doCheck(String ip, int connectTimeout, int readTimeout) throws Exception;

    public ProviderResult check(String ip, int connectTimeout, int readTimeout) {
        long started = System.currentTimeMillis();
        try {
            ProviderResult result = doCheck(ip, connectTimeout, readTimeout);
            return result == null
                ? ProviderResult.error(name(), "empty response", System.currentTimeMillis() - started)
                : result;
        } catch (Exception e) {
            String message = e.getClass().getSimpleName()
                + (e.getMessage() == null ? "" : ": " + e.getMessage());
            return ProviderResult.error(name(), message, System.currentTimeMillis() - started);
        }
    }

    // ── HTTP helpers ────────────────────────────────────────────────────────

    protected JsonObject getJson(String url, int connectTimeout, int readTimeout) throws Exception {
        return getJson(url, connectTimeout, readTimeout, Map.of());
    }

    protected JsonObject getJson(String url, int connectTimeout, int readTimeout, Map<String, String> headers)
            throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);
            conn.setRequestProperty("User-Agent", "VelocityShield/1.2.0 (+https://github.com/jackh54/VelocityShield)");
            conn.setRequestProperty("Accept", "application/json");
            headers.forEach(conn::setRequestProperty);

            int status = conn.getResponseCode();
            InputStream stream = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
            if (stream == null) {
                throw new IllegalStateException("HTTP " + status + " with no body");
            }

            StringBuilder body = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                char[] buffer = new char[1024];
                int read;
                while ((read = reader.read(buffer)) != -1) {
                    body.append(buffer, 0, read);
                }
            }

            if (status == 429) {
                throw new IllegalStateException("rate limited (HTTP 429)");
            }
            if (status >= 400) {
                throw new IllegalStateException("HTTP " + status);
            }

            return JsonParser.parseString(body.toString()).getAsJsonObject();
        } finally {
            conn.disconnect();
        }
    }

    // ── JSON helpers that tolerate missing or oddly-typed fields ────────────

    protected static boolean bool(JsonObject obj, String key) {
        try {
            if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) return false;
            String raw = obj.get(key).getAsString();
            return "true".equalsIgnoreCase(raw) || "yes".equalsIgnoreCase(raw) || "1".equals(raw);
        } catch (Exception e) {
            return false;
        }
    }

    protected static String str(JsonObject obj, String key) {
        try {
            if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) return null;
            return obj.get(key).getAsString();
        } catch (Exception e) {
            return null;
        }
    }

    protected static JsonObject obj(JsonObject parent, String key) {
        try {
            if (parent == null || !parent.has(key) || !parent.get(key).isJsonObject()) return null;
            return parent.getAsJsonObject(key);
        } catch (Exception e) {
            return null;
        }
    }
}
