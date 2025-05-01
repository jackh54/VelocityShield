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
import com.pandadevv.VelocityShield.util.VPNChecker;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.slf4j.Logger;

import java.nio.file.Path;

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
    private final Path dataDirectory;
    private PluginConfig config;
    private VPNChecker vpnChecker;

    @Inject
    public VelocityShield(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
        instance = this;
    }

    @Subscribe
    public void onProxyInitialization(ProxyInitializeEvent event) {
        this.config = new PluginConfig(dataDirectory);
        this.vpnChecker = new VPNChecker(config, dataDirectory);
        
        // Register commands
        CommandManager commandManager = server.getCommandManager();
        
        // Reload command
        CommandMeta reloadMeta = commandManager.metaBuilder("velocityshield")
                .aliases("vshield")
                .build();
        
        SimpleCommand reloadCommand = invocation -> {
            if (!invocation.source().hasPermission("velocityshield.reload")) {
                invocation.source().sendMessage(Component.text("You don't have permission to use this command!"));
                return;
            }
            
            config.reload();
            invocation.source().sendMessage(Component.text("Configuration reloaded!"));
        };
        
        // Whitelist command
        CommandMeta whitelistMeta = commandManager.metaBuilder("vshieldwhitelist")
                .aliases("vshieldwl")
                .build();
        
        SimpleCommand whitelistCommand = invocation -> {
            if (!invocation.source().hasPermission("velocityshield.whitelist")) {
                invocation.source().sendMessage(Component.text("You don't have permission to use this command!"));
                return;
            }
            
            String[] args = invocation.arguments();
            if (args.length < 2) {
                invocation.source().sendMessage(Component.text("Usage: /vshieldwhitelist <add|remove> <ip>"));
                return;
            }
            
            String action = args[0].toLowerCase();
            String ip = args[1];
            
            if (action.equals("add")) {
                config.addToWhitelist(ip);
                invocation.source().sendMessage(Component.text("IP " + ip + " added to whitelist!"));
            } else if (action.equals("remove")) {
                config.removeFromWhitelist(ip);
                invocation.source().sendMessage(Component.text("IP " + ip + " removed from whitelist!"));
            } else {
                invocation.source().sendMessage(Component.text("Invalid action! Use 'add' or 'remove'."));
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
        
        // Check for bypass permission
        if (event.getPlayer().hasPermission("velocityshield.bypass")) {
            if (config.isDebug()) {
                logger.info("Player {} has bypass permission, skipping VPN check", event.getPlayer().getUsername());
            }
            return;
        }

        // Check whitelist
        if (config.isIPWhitelisted(ip)) {
            if (config.isDebug()) {
                logger.info("IP {} is whitelisted, skipping VPN check", ip);
            }
            return;
        }

        if (config.isDebug()) {
            logger.info("Player {} connecting from IP: {}", event.getPlayer().getUsername(), ip);
        }
        
        boolean isVPN = vpnChecker.isVPN(ip).join();
        if (isVPN) {
            if (config.isDebug()) {
                logger.info("VPN detected for player {} (IP: {})", event.getPlayer().getUsername(), ip);
            }
            // Log the VPN detection
            config.logVPNDetection(event.getPlayer().getUsername(), ip);
            Component kickMessage = LegacyComponentSerializer.legacyAmpersand().deserialize(config.getKickMessage());
            event.setResult(LoginEvent.ComponentResult.denied(kickMessage));
        } else if (config.isDebug()) {
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