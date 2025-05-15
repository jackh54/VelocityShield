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
import com.pandadevv.VelocityShield.config.PluginConfig;
import com.pandadevv.VelocityShield.config.UpdateChecker;
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
        version = "1.0.0",
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
        // bstats
        int pluginId = 25843;
        Metrics metrics = metricsFactory.make(this, pluginId);
        
        // Add VPN mitigations chart
        metrics.addCustomChart(new SingleLineChart("vpn_mitigations", () -> vpnMitigations.get()));
        // end bstats
        
        this.config = new PluginConfig(dataDirectory);
        this.vpnChecker = new VPNChecker(config, dataDirectory);
        this.updateChecker = new UpdateChecker(this);
        this.updateChecker.checkForUpdates();
        
        CommandManager commandManager = server.getCommandManager();
        
        CommandMeta reloadMeta = commandManager.metaBuilder("velocityshield")
                .aliases("vshield")
                .build();
        
        SimpleCommand reloadCommand = invocation -> {
            if (!invocation.source().hasPermission("velocityshield.reload")) {
                invocation.source().sendMessage(Component.text("You don't have permission to use this command!")
                    .color(NamedTextColor.RED));
                return;
            }
            
            config.reload();
            invocation.source().sendMessage(Component.text("Configuration reloaded!")
                .color(NamedTextColor.GREEN));
        };
        
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
        
        commandManager.register(reloadMeta, reloadCommand);
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
        
        if (event.getPlayer().hasPermission("velocityshield.bypass")) {
            if (config.isEnableDebug()) {
                logger.info("Player {} has bypass permission, skipping VPN check", event.getPlayer().getUsername());
            }
            return;
        }
        
        if (config.isIPWhitelisted(ip)) {
            if (config.isEnableDebug()) {
                logger.info("IP {} is whitelisted, skipping VPN check", ip);
            }
            return;
        }

        if (config.isEnableDebug()) {
            logger.info("Player {} connecting from IP: {}", event.getPlayer().getUsername(), ip);
        }
        
        boolean isVPN = vpnChecker.isVPN(ip).join();
        if (isVPN) {
            if (config.isEnableDebug()) {
                logger.info("VPN detected for player {} (IP: {})", event.getPlayer().getUsername(), ip);
            }
            config.logVPNDetection(event.getPlayer().getUsername(), ip);
            vpnMitigations.incrementAndGet();
            
            Component kickMessage = Component.text()
                .append(miniMessage.deserialize(config.getKickMessageTitle()))
                .append(Component.newline())
                .append(Component.newline())
                .append(miniMessage.deserialize(config.getKickMessageBody()))
                .build();
            
            event.setResult(LoginEvent.ComponentResult.denied(kickMessage));
        } else if (config.isEnableDebug()) {
            logger.info("No VPN detected for player {} (IP: {})", event.getPlayer().getUsername(), ip);
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
} 