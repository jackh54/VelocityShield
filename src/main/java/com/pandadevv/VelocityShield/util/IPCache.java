package com.pandadevv.VelocityShield.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.pandadevv.VelocityShield.VelocityShield;
import com.pandadevv.VelocityShield.util.provider.ProviderResult;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * On-disk cache of check results.
 *
 * <p>Stores the whole per-provider breakdown, not just a boolean, so a cached hit can
 * still explain itself in a ticket or to staff. Entries written by older versions
 * (which only had isVPN) are still readable and are treated as a bare verdict.
 */
public class IPCache {
    private final Map<String, CacheEntry> cache;
    private final long cacheDuration;
    private final TimeUnit cacheTimeUnit;
    private final Path cacheFile;
    private final Gson gson;

    private static final int MAX_CACHE_SIZE = 10000;
    private final AtomicInteger currentCacheSize = new AtomicInteger(0);

    private final ScheduledExecutorService cleanupExecutor;
    private static final long CLEANUP_INTERVAL = 5;
    private static final TimeUnit CLEANUP_TIME_UNIT = TimeUnit.MINUTES;

    public IPCache(long cacheDuration, TimeUnit cacheTimeUnit, Path dataDirectory) {
        this.cache = new ConcurrentHashMap<>();
        this.cacheDuration = cacheDuration;
        this.cacheTimeUnit = cacheTimeUnit;
        this.cacheFile = dataDirectory.resolve("ip_cache.json");
        this.gson = new GsonBuilder().setPrettyPrinting().create();

        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "IPCache-Cleanup");
            t.setDaemon(true);
            return t;
        });

        this.cleanupExecutor.scheduleAtFixedRate(
            this::cleanExpiredEntries, CLEANUP_INTERVAL, CLEANUP_INTERVAL, CLEANUP_TIME_UNIT);

        loadCache();
    }

    public void cacheResult(String ip, VPNResult result) {
        if (currentCacheSize.get() >= MAX_CACHE_SIZE) {
            removeOldestEntries(MAX_CACHE_SIZE / 10);
        }

        CacheEntry entry = new CacheEntry();
        entry.isVPN = result.isBlocked();
        entry.timestamp = System.currentTimeMillis();
        entry.score = result.getScore();
        entry.vpnVotes = result.getVpnVotes();
        entry.answered = result.getAnsweredCount();
        entry.reason = result.getReason();
        entry.providers = new ArrayList<>();
        for (ProviderResult provider : result.getProviders()) {
            CachedProvider cached = new CachedProvider();
            cached.name = provider.getProvider();
            cached.verdict = provider.getVerdict().name();
            cached.detail = provider.getDetail();
            cached.tor = provider.isTor();
            cached.hosting = provider.isHosting();
            cached.mobile = provider.isMobile();
            cached.isp = provider.getIsp();
            cached.asn = provider.getAsn();
            cached.country = provider.getCountry();
            entry.providers.add(cached);
        }

        cache.put(ip, entry);
        currentCacheSize.set(cache.size());
        saveCache();
    }

    public VPNResult getCachedResult(String ip) {
        CacheEntry entry = cache.get(ip);
        if (entry == null) return null;

        long durationMillis = cacheTimeUnit.toMillis(cacheDuration);
        if (System.currentTimeMillis() - entry.timestamp > durationMillis) {
            cache.remove(ip);
            currentCacheSize.set(cache.size());
            saveCache();
            return null;
        }

        List<ProviderResult> providers = new ArrayList<>();
        if (entry.providers != null) {
            for (CachedProvider cached : entry.providers) {
                ProviderResult.Verdict verdict;
                try {
                    verdict = ProviderResult.Verdict.valueOf(cached.verdict);
                } catch (Exception e) {
                    verdict = ProviderResult.Verdict.ERROR;
                }
                providers.add(ProviderResult.builder(cached.name)
                    .verdict(verdict)
                    .detail(cached.detail)
                    .tor(cached.tor)
                    .hosting(cached.hosting)
                    .mobile(cached.mobile)
                    .isp(cached.isp)
                    .asn(cached.asn)
                    .country(cached.country)
                    .build());
            }
        }

        String reason = entry.reason == null ? "Cached result" : entry.reason;
        return new VPNResult(ip, entry.isVPN, entry.score, entry.vpnVotes, entry.answered,
            reason, providers, entry.timestamp, true);
    }

    public void clearCache() {
        cache.clear();
        currentCacheSize.set(0);
        saveCache();
    }

    public int size() {
        return cache.size();
    }

    private void loadCache() {
        if (!Files.exists(cacheFile)) return;

        try (Reader reader = Files.newBufferedReader(cacheFile)) {
            Map<String, CacheEntry> loaded =
                gson.fromJson(reader, new TypeToken<Map<String, CacheEntry>>() {}.getType());
            if (loaded != null) {
                cache.putAll(loaded);
                currentCacheSize.set(cache.size());
                cleanExpiredEntries();
            }
        } catch (Exception e) {
            // A cache we cannot read is not worth crashing over - start empty.
            VelocityShield.getInstance().getLogger()
                .warn("Could not read ip_cache.json ({}), starting with an empty cache", e.getMessage());
        }
    }

    private void saveCache() {
        try (Writer writer = Files.newBufferedWriter(cacheFile)) {
            gson.toJson(cache, writer);
        } catch (IOException e) {
            VelocityShield.getInstance().getLogger().error("Failed to save IP cache", e);
        }
    }

    private void cleanExpiredEntries() {
        long currentTime = System.currentTimeMillis();
        long durationMillis = cacheTimeUnit.toMillis(cacheDuration);
        final AtomicInteger removed = new AtomicInteger(0);

        cache.entrySet().removeIf(entry -> {
            boolean expired = currentTime - entry.getValue().timestamp > durationMillis;
            if (expired) removed.incrementAndGet();
            return expired;
        });

        if (removed.get() > 0) {
            currentCacheSize.set(cache.size());
            saveCache();
        }
    }

    private void removeOldestEntries(int count) {
        cache.entrySet().stream()
            .sorted((a, b) -> Long.compare(a.getValue().timestamp, b.getValue().timestamp))
            .limit(count)
            .map(Map.Entry::getKey)
            .forEach(cache::remove);
        currentCacheSize.set(cache.size());
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
        boolean isVPN;
        long timestamp;
        double score;
        int vpnVotes;
        int answered;
        String reason;
        List<CachedProvider> providers;
    }

    private static class CachedProvider {
        String name;
        String verdict;
        String detail;
        boolean tor;
        boolean hosting;
        boolean mobile;
        String isp;
        String asn;
        String country;
    }
}
