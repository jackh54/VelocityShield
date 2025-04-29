package com.pandadevv.litslantivpn;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandManager;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import com.pandadevv.litslantivpn.config.PluginConfig;
import com.pandadevv.litslantivpn.util.VPNChecker;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.slf4j.Logger;

import java.nio.file.Path;

@Plugin(
        id = "litslantivpn",
        name = "LitslAntiVPN",
        version = "1.0-SNAPSHOT",
        authors = {"pandadevv"}
)
public class LitslAntiVPN {
    private static LitslAntiVPN instance;
    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;
    private PluginConfig config;
    private VPNChecker vpnChecker;

    @Inject
    public LitslAntiVPN(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        instance = this;
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInitialization(ProxyInitializeEvent event) {
        this.config = new PluginConfig(dataDirectory);
        this.vpnChecker = new VPNChecker(config, dataDirectory);
        
        // Register reload command
        CommandManager commandManager = server.getCommandManager();
        CommandMeta reloadMeta = commandManager.metaBuilder("litslantivpn")
                .aliases("lantivpn")
                .build();
        
        SimpleCommand reloadCommand = invocation -> {
            if (!invocation.source().hasPermission("litslantivpn.reload")) {
                invocation.source().sendMessage(Component.text("You don't have permission to use this command.", NamedTextColor.RED));
                return;
            }
            
            config.reloadWhitelist();
            invocation.source().sendMessage(Component.text("Whitelist reloaded successfully!", NamedTextColor.GREEN));
        };
        
        commandManager.register(reloadMeta, reloadCommand);
        
        logger.info("LitslAntiVPN has been enabled!");
    }

    @Subscribe
    public void onPlayerLogin(LoginEvent event) {
        String ip = event.getPlayer().getRemoteAddress().getAddress().getHostAddress();
        
        // Check for bypass permission
        if (event.getPlayer().hasPermission("litslantivpn.bypass")) {
            if (config.isDebug()) {
                logger.info("Player {} has bypass permission, skipping VPN check", event.getPlayer().getUsername());
            }
            return;
        }

        // Check whitelist
        if (config.isIpWhitelisted(ip)) {
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

    public static LitslAntiVPN getInstance() {
        return instance;
    }

    public Logger getLogger() {
        return logger;
    }
} 