package com.pandadevv.VelocityShield;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandManager;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import com.pandadevv.VelocityShield.commands.MainCommand;
import com.pandadevv.VelocityShield.config.PluginConfig;
import com.pandadevv.VelocityShield.config.UpdateChecker;
import com.pandadevv.VelocityShield.util.LogHelper;
import com.pandadevv.VelocityShield.util.VPNChecker;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;

import org.bstats.velocity.Metrics;
import org.bstats.charts.SingleLineChart;
import org.slf4j.Logger;
import net.kyori.adventure.text.minimessage.MiniMessage;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

@Plugin(
        id = "velocityshield",
        name = "VelocityShield",
        version = "1.1.0",
        description = "A VPN detection plugin for Velocity",
        authors = {"PandaDevv"}
)
public class VelocityShield {
    private static VelocityShield instance;
    private final ProxyServer server;
    private final Logger logger;
    private final Metrics.Factory metricsFactory;
    private final Path dataDirectory;
    private PluginConfig config;
    private VPNChecker vpnChecker;
    private MiniMessage miniMessage;
    private UpdateChecker updateChecker;
    private final AtomicInteger vpnMitigations = new AtomicInteger(0);
    private final AtomicInteger vpnMitigationsSinceLastReport = new AtomicInteger(0);
    private long startTime;

    @Inject
    public VelocityShield(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory, Metrics.Factory metricsFactory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
        this.metricsFactory = metricsFactory;
        instance = this;
        this.miniMessage = MiniMessage.miniMessage();
    }

    @Subscribe
    public void onProxyInitialization(ProxyInitializeEvent event) {
        this.startTime = System.currentTimeMillis();
        
        int pluginId = 25843;
        Metrics metrics = metricsFactory.make(this, pluginId);
        
        // Reset counter after each report to prevent wave pattern
        metrics.addCustomChart(new SingleLineChart("vpn_mitigations", () -> {
            return vpnMitigationsSinceLastReport.getAndSet(0);
        }));
        
        this.config = new PluginConfig(dataDirectory);
        this.vpnChecker = new VPNChecker(config, dataDirectory);
        this.updateChecker = new UpdateChecker(this);
        this.updateChecker.checkForUpdates();
        
        CommandManager commandManager = server.getCommandManager();
        
        CommandMeta mainMeta = commandManager.metaBuilder("velocityshield")
                .aliases("vshield", "vs")
                .build();
        commandManager.register(mainMeta, new MainCommand(this));
        
        // Legacy command for backwards compatibility
        CommandMeta whitelistMeta = commandManager.metaBuilder("vshieldwhitelist")
                .aliases("vshieldwl")
                .build();
        
        SimpleCommand whitelistCommand = invocation -> {
            if (!invocation.source().hasPermission("velocityshield.whitelist")) {
                invocation.source().sendMessage(Component.text("You don't have permission to use this command!")
                    .color(NamedTextColor.RED));
                return;
            }
            
            String[] args = invocation.arguments();
            if (args.length < 2) {
                invocation.source().sendMessage(Component.text("Usage: /vshieldwhitelist <add|remove> <ip>")
                    .color(NamedTextColor.RED));
                return;
            }
            
            String action = args[0].toLowerCase();
            String ip = args[1];
            
            switch (action) {
                case "add":
                    config.addToWhitelist(ip);
                    invocation.source().sendMessage(Component.text("IP " + ip + " added to whitelist!")
                        .color(NamedTextColor.GREEN));
                    break;
                case "remove":
                    config.removeFromWhitelist(ip);
                    invocation.source().sendMessage(Component.text("IP " + ip + " removed from whitelist!")
                        .color(NamedTextColor.GREEN));
                    break;
                default:
                    invocation.source().sendMessage(Component.text("Invalid action! Use 'add' or 'remove'.")
                        .color(NamedTextColor.RED));
            }
        };
        
        commandManager.register(whitelistMeta, whitelistCommand);
        
        logger.info("VelocityShield has been enabled!");
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        if (vpnChecker != null) {
            vpnChecker.shutdown();
        }
        logger.info("VelocityShield has been disabled!");
    }

    @Subscribe
    public void onPlayerLogin(LoginEvent event) {
        String ip = event.getPlayer().getRemoteAddress().getAddress().getHostAddress();
        String username = event.getPlayer().getUsername();
        
        if (event.getPlayer().hasPermission("velocityshield.bypass")) {
            LogHelper.logPermissionBypass(logger, username, config.isEnableDebug());
            return;
        }
        
        if (config.isIPWhitelisted(ip)) {
            LogHelper.logWhitelistBypass(logger, username, ip, config.isEnableDebug());
            return;
        }

        if (config.isEnableDebug()) {
            logger.info("Checking player {} from IP: {}", username, ip);
        }
        
        boolean isVPN = vpnChecker.isVPN(ip).join();
        if (isVPN) {
            LogHelper.logVpnCheck(logger, username, ip, true, config.isEnableDebug());
            config.logVPNDetection(username, ip);
            vpnMitigations.incrementAndGet();
            vpnMitigationsSinceLastReport.incrementAndGet();
            
            Component kickMessage = Component.text()
                .append(miniMessage.deserialize(config.getKickMessageTitle()))
                .append(Component.newline())
                .append(Component.newline())
                .append(miniMessage.deserialize(config.getKickMessageBody()))
                .build();
            
            event.setResult(LoginEvent.ComponentResult.denied(kickMessage));
        } else {
            LogHelper.logVpnCheck(logger, username, ip, false, config.isEnableDebug());
        }
    }

    public static VelocityShield getInstance() {
        return instance;
    }

    public ProxyServer getServer() {
        return server;
    }

    public Logger getLogger() {
        return logger;
    }

    public Path getDataDirectory() {
        return dataDirectory;
    }

    public PluginConfig getConfig() {
        return config;
    }

    public VPNChecker getVpnChecker() {
        return vpnChecker;
    }

    public long getStartTime() {
        return startTime;
    }

    public int getVpnMitigations() {
        return vpnMitigations.get();
    }
} 