package com.pandadevv.litslantivpn.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.pandadevv.litslantivpn.VelocityShield;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class IPCache {
    private final Map<String, CacheEntry> cache;
    private final long cacheDuration;
    private final TimeUnit cacheTimeUnit;
    private final Path cacheFile;
    private final Gson gson;
    
    // Cache size limits
    private static final int MAX_CACHE_SIZE = 10000;
    private final AtomicInteger currentCacheSize = new AtomicInteger(0);
    
    // Scheduled cleanup
    private final ScheduledExecutorService cleanupExecutor;
    private static final long CLEANUP_INTERVAL = 1; // 1 hour

    public IPCache(long cacheDuration, TimeUnit cacheTimeUnit, Path dataDirectory) {
        this.cache = new ConcurrentHashMap<>();
        this.cacheDuration = cacheDuration;
        this.cacheTimeUnit = cacheTimeUnit;
        this.cacheFile = dataDirectory.resolve("ip_cache.json");
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        
        // Initialize cleanup scheduler
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "IPCache-Cleanup");
            t.setDaemon(true);
            return t;
        });
        
        // Schedule periodic cleanup
        this.cleanupExecutor.scheduleAtFixedRate(
            this::cleanExpiredEntries,
            CLEANUP_INTERVAL,
            CLEANUP_INTERVAL,
            TimeUnit.HOURS
        );
        
        loadCache();
    }

    public void cacheResult(String ip, boolean isVPN) {
        // Check if we need to remove old entries to make space
        if (currentCacheSize.get() >= MAX_CACHE_SIZE) {
            removeOldestEntries(MAX_CACHE_SIZE / 10); // Remove 10% of entries
        }
        
        cache.put(ip, new CacheEntry(isVPN, System.currentTimeMillis()));
        currentCacheSize.incrementAndGet();
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
            currentCacheSize.decrementAndGet();
            saveCache();
            return null;
        }

        return entry.isVPN();
    }

    public void clearCache() {
        cache.clear();
        currentCacheSize.set(0);
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
                currentCacheSize.set(cache.size());
                // Clean expired entries on load
                cleanExpiredEntries();
            }
        } catch (IOException e) {
            VelocityShield.getInstance().getLogger().error("Failed to load IP cache", e);
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
            VelocityShield.getInstance().getLogger().error("Failed to save IP cache", e);
        }
    }

    private void cleanExpiredEntries() {
        long currentTime = System.currentTimeMillis();
        long durationMillis = cacheTimeUnit.toMillis(cacheDuration);
        
        cache.entrySet().removeIf(entry -> {
            boolean expired = currentTime - entry.getValue().getTimestamp() > durationMillis;
            if (expired) {
                currentCacheSize.decrementAndGet();
            }
            return expired;
        });
    }

    private void removeOldestEntries(int count) {
        cache.entrySet().stream()
            .sorted((e1, e2) -> Long.compare(e1.getValue().getTimestamp(), e2.getValue().getTimestamp()))
            .limit(count)
            .forEach(entry -> {
                cache.remove(entry.getKey());
                currentCacheSize.decrementAndGet();
            });
    }

    public void shutdown() {
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
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