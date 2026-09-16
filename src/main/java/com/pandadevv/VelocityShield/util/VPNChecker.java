package com.pandadevv.VelocityShield.util;

import com.pandadevv.VelocityShield.VelocityShield;
import com.pandadevv.VelocityShield.config.PluginConfig;
import com.pandadevv.VelocityShield.util.provider.*;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

/**
 * Asks every enabled provider about an address at the same time and decides from the
 * answers as a group.
 *
 * <p>The old behaviour was "ask one service, believe it". That is where the false
 * positives came from: a single reputation service calling a mobile carrier a proxy got
 * the player kicked with no second opinion. Now a player is only blocked when enough
 * independent services agree, and a mobile/carrier connection needs a stronger majority
 * before it counts, because those are the ones that get mislabelled most often.
 */
public class VPNChecker {

    private final PluginConfig config;
    private final IPCache ipCache;
    private final ExecutorService executorService;
    private final List<VPNProvider> providers = new ArrayList<>();

    public VPNChecker(PluginConfig config, Path dataDirectory) {
        this.config = config;
        this.ipCache = new IPCache(config.getCacheDuration(),
            TimeUnit.valueOf(config.getCacheTimeUnit().toUpperCase()), dataDirectory);

        this.executorService = new ThreadPoolExecutor(
            2, Math.max(4, config.getEnabledProviderNames().size() * 2),
            60L, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(200),
            r -> {
                Thread t = new Thread(r, "VelocityShield-Check");
                t.setDaemon(true);
                return t;
            },
            new ThreadPoolExecutor.CallerRunsPolicy()
        );

        buildProviders();
    }

    private void buildProviders() {
        providers.clear();
        for (String name : config.getEnabledProviderNames()) {
            VPNProvider provider = switch (name.toLowerCase()) {
                case "proxycheck" -> new ProxyCheckProvider(config.getProxycheckApiKey());
                case "ip-api", "ipapi" -> new IpApiProvider();
                case "ipapi.is", "ipapiis" -> new IpApiIsProvider(config.getIpapiIsApiKey());
                case "vpnapi", "vpnapi.io" -> new VpnApiProvider(config.getVpnapiApiKey());
                case "iphub" -> new IpHubProvider(config.getIphubApiKey());
                default -> null;
            };

            if (provider == null) {
                VelocityShield.getInstance().getLogger()
                    .warn("Unknown VPN provider '{}' in config - skipping", name);
                continue;
            }
            if (!provider.isConfigured()) {
                VelocityShield.getInstance().getLogger().warn(
                    "Provider '{}' is enabled but has no API key - skipping it. Get one at {}",
                    provider.name(), provider.signupUrl());
                continue;
            }
            providers.add(provider);
        }

        if (providers.isEmpty()) {
            VelocityShield.getInstance().getLogger()
                .error("No usable VPN providers are configured! Every player will be treated as {}.",
                    config.isAllowJoinOnApiFailure() ? "allowed" : "blocked");
        } else if (providers.size() < config.getMinVpnVotes()) {
            VelocityShield.getInstance().getLogger().warn(
                "Only {} provider(s) available but consensus.min-vpn-votes is {} - nobody can ever be blocked. "
                    + "Enable more providers or lower min-vpn-votes.",
                providers.size(), config.getMinVpnVotes());
        }
    }

    /** Re-read providers after a config reload. */
    public void reload() {
        buildProviders();
    }

    public List<VPNProvider> getProviders() {
        return List.copyOf(providers);
    }

    /** Kept for backwards compatibility - prefer {@link #check(String)}. */
    public CompletableFuture<Boolean> isVPN(String ip) {
        return check(ip).thenApply(VPNResult::isBlocked);
    }

    public CompletableFuture<VPNResult> check(String ip) {
        if (config.isEnableCache()) {
            VPNResult cached = ipCache.getCachedResult(ip);
            if (cached != null) {
                LogHelper.logCacheHit(VelocityShield.getInstance().getLogger(), ip, cached.isBlocked(),
                    config.isEnableDebug());
                return CompletableFuture.completedFuture(cached.asCached());
            }
            LogHelper.logCacheMiss(VelocityShield.getInstance().getLogger(), ip, config.isEnableDebug());
        }

        List<CompletableFuture<ProviderResult>> futures = new ArrayList<>();
        for (VPNProvider provider : providers) {
            futures.add(CompletableFuture
                .supplyAsync(() -> provider.check(ip, config.getApiConnectionTimeout(), config.getApiReadTimeout()),
                    executorService)
                .completeOnTimeout(
                    ProviderResult.error(provider.name(), "timed out", config.getApiReadTimeout()),
                    config.getApiConnectionTimeout() + config.getApiReadTimeout() + 500L,
                    TimeUnit.MILLISECONDS)
                .exceptionally(t -> ProviderResult.error(provider.name(), String.valueOf(t.getMessage()), 0)));
        }

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
            .thenApply(ignored -> {
                List<ProviderResult> results = new ArrayList<>();
                for (CompletableFuture<ProviderResult> future : futures) {
                    results.add(future.join());
                }
                VPNResult verdict = decide(ip, results);

                if (config.isEnableCache() && verdict.getAnsweredCount() > 0) {
                    ipCache.cacheResult(ip, verdict);
                }
                return verdict;
            });
    }

    /**
     * Turn the individual answers into one allow/block decision.
     */
    private VPNResult decide(String ip, List<ProviderResult> results) {
        double weightedVpn = 0;
        double weightedTotal = 0;
        int vpnVotes = 0;
        int answered = 0;
        boolean tor = false;
        boolean mobile = false;
        boolean hosting = false;
        String hostingSource = null;

        for (ProviderResult result : results) {
            if (!result.answered()) continue;
            answered++;
            double weight = config.getProviderWeight(result.getProvider());
            weightedTotal += weight;
            if (result.flaggedVpn()) {
                vpnVotes++;
                weightedVpn += weight;
            }
            if (result.isTor()) tor = true;
            if (result.isMobile()) mobile = true;
            if (result.isHosting()) {
                hosting = true;
                if (hostingSource == null) hostingSource = result.getProvider();
            }
        }

        long now = System.currentTimeMillis();
        double score = weightedTotal == 0 ? 0 : weightedVpn / weightedTotal;

        // Nobody answered - fall back to the configured behaviour rather than guessing.
        if (answered == 0) {
            boolean blocked = !config.isAllowJoinOnApiFailure();
            return new VPNResult(ip, blocked, 0, 0, 0,
                "No provider answered; " + (blocked ? "blocking" : "allowing") + " per allow-join-on-api-failure",
                results, now, false);
        }

        // Tor exit nodes are never a false positive worth protecting.
        if (tor && config.isAlwaysBlockTor()) {
            return new VPNResult(ip, true, 1.0, vpnVotes, answered, "Tor exit node", results, now, false);
        }

        // A datacenter range is a much harder fact than a generic "proxy" label: real
        // players do not log in from hosting providers. Treat it as decisive on its own,
        // so detection still works when only one provider is answering (quota, outage).
        // Mobile carriers are never hosting, so this cannot catch the phone players that
        // the vote threshold exists to protect.
        if (hosting && config.isDatacenterDecisive() && !mobile) {
            return new VPNResult(ip, true, Math.max(score, 1.0 / Math.max(answered, 1)), vpnVotes, answered,
                "Datacenter/hosting range (reported by " + hostingSource + ")", results, now, false);
        }

        int required = config.getMinVpnVotes();

        // Mobile carriers (and consoles behind carrier NAT) are the biggest source of bad
        // flags, so they need a bigger majority before we believe it.
        if (mobile && config.isTrustMobileNetworks()) {
            required = Math.max(required, config.getMobileMinVpnVotes());
            if (vpnVotes < required) {
                return new VPNResult(ip, false, score, vpnVotes, answered,
                    "Mobile carrier connection with only " + vpnVotes + "/" + answered
                        + " flagged (needs " + required + ")",
                    results, now, false);
            }
        }

        if (vpnVotes < required) {
            return new VPNResult(ip, false, score, vpnVotes, answered,
                "Only " + vpnVotes + "/" + answered + " providers flagged it (needs " + required + ")",
                results, now, false);
        }

        if (score < config.getMinConsensusScore()) {
            return new VPNResult(ip, false, score, vpnVotes, answered,
                String.format("Weighted score %.2f below threshold %.2f", score, config.getMinConsensusScore()),
                results, now, false);
        }

        return new VPNResult(ip, true, score, vpnVotes, answered,
            vpnVotes + " of " + answered + " providers flagged it", results, now, false);
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
        if (ipCache != null) {
            ipCache.shutdown();
        }
    }

    public void clearCache() {
        if (ipCache != null) {
            ipCache.clearCache();
        }
    }
}
