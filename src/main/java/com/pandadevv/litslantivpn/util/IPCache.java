package com.pandadevv.litslantivpn.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.pandadevv.litslantivpn.LitslAntiVPN;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class IPCache {
    private final Map<String, CacheEntry> cache;
    private final long cacheDuration;
    private final TimeUnit cacheTimeUnit;
    private final Path cacheFile;
    private final Gson gson;

    public IPCache(long cacheDuration, TimeUnit cacheTimeUnit, Path dataDirectory) {
        this.cache = new ConcurrentHashMap<>();
        this.cacheDuration = cacheDuration;
        this.cacheTimeUnit = cacheTimeUnit;
        this.cacheFile = dataDirectory.resolve("ip_cache.json");
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        loadCache();
    }

    public void cacheResult(String ip, boolean isVPN) {
        cache.put(ip, new CacheEntry(isVPN, System.currentTimeMillis()));
        saveCache();
    }

    public Boolean getCachedResult(String ip) {
        CacheEntry entry = cache.get(ip);
        if (entry == null) {
            return null;
        }

        long currentTime = System.currentTimeMillis();
        long entryTime = entry.getTimestamp();
        long durationMillis = cacheTimeUnit.toMillis(cacheDuration);

        if (currentTime - entryTime > durationMillis) {
            cache.remove(ip);
            saveCache();
            return null;
        }

        return entry.isVPN();
    }

    public void clearCache() {
        cache.clear();
        saveCache();
    }

    private void loadCache() {
        if (!Files.exists(cacheFile)) {
            return;
        }

        try (Reader reader = Files.newBufferedReader(cacheFile)) {
            Map<String, CacheEntry> loadedCache = gson.fromJson(reader, new TypeToken<Map<String, CacheEntry>>(){}.getType());
            if (loadedCache != null) {
                cache.putAll(loadedCache);
                // Clean expired entries on load
                cleanExpiredEntries();
            }
        } catch (IOException e) {
            LitslAntiVPN.getInstance().getLogger().error("Failed to load IP cache", e);
        }
    }

    private void saveCache() {
        try {
            // Clean expired entries before saving
            cleanExpiredEntries();
            
            try (Writer writer = Files.newBufferedWriter(cacheFile)) {
                gson.toJson(cache, writer);
            }
        } catch (IOException e) {
            LitslAntiVPN.getInstance().getLogger().error("Failed to save IP cache", e);
        }
    }

    private void cleanExpiredEntries() {
        long currentTime = System.currentTimeMillis();
        long durationMillis = cacheTimeUnit.toMillis(cacheDuration);
        
        cache.entrySet().removeIf(entry -> 
            currentTime - entry.getValue().getTimestamp() > durationMillis
        );
    }

    private static class CacheEntry {
        private final boolean isVPN;
        private final long timestamp;

        public CacheEntry(boolean isVPN, long timestamp) {
            this.isVPN = isVPN;
            this.timestamp = timestamp;
        }

        public boolean isVPN() {
            return isVPN;
        }

        public long getTimestamp() {
            return timestamp;
        }
    }
} 