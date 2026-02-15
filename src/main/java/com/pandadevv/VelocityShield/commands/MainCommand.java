package com.pandadevv.VelocityShield.commands;

import com.pandadevv.VelocityShield.VelocityShield;
import com.velocitypowered.api.command.SimpleCommand;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public class MainCommand implements SimpleCommand {
    private final VelocityShield plugin;

    public MainCommand(VelocityShield plugin) {
        this.plugin = plugin;
    }

    @Override
    public void execute(Invocation invocation) {
        if (!invocation.source().hasPermission("velocityshield.admin")) {
            invocation.source().sendMessage(Component.text("You don't have permission to use this command!")
                .color(NamedTextColor.RED));
            return;
        }

        String[] args = invocation.arguments();
        
        if (args.length == 0) {
            showHelp(invocation);
            return;
        }

        String subCommand = args[0].toLowerCase();
        
        switch (subCommand) {
            case "reload":
                plugin.getConfig().reload();
                invocation.source().sendMessage(Component.text("Configuration reloaded!")
                    .color(NamedTextColor.GREEN));
                break;
            case "stats":
                showStats(invocation);
                break;
            case "lookup":
                if (args.length < 2) {
                    invocation.source().sendMessage(Component.text("Usage: /vshield lookup <ip>")
                        .color(NamedTextColor.RED));
                    return;
                }
                lookupIP(invocation, args[1]);
                break;
            case "cache":
                if (args.length < 2) {
                    invocation.source().sendMessage(Component.text("Usage: /vshield cache <clear>")
                        .color(NamedTextColor.RED));
                    return;
                }
                if (args[1].equalsIgnoreCase("clear")) {
                    clearCache(invocation);
                }
                break;
            case "whitelist":
                handleWhitelist(invocation, args);
                break;
            case "help":
            default:
                showHelp(invocation);
                break;
        }
    }

    private void showHelp(Invocation invocation) {
        invocation.source().sendMessage(Component.text()
            .append(Component.text("=== VelocityShield Commands ===", NamedTextColor.GOLD))
            .append(Component.newline())
            .append(Component.text("/vshield reload", NamedTextColor.YELLOW))
            .append(Component.text(" - Reload configuration", NamedTextColor.GRAY))
            .append(Component.newline())
            .append(Component.text("/vshield stats", NamedTextColor.YELLOW))
            .append(Component.text(" - View plugin statistics", NamedTextColor.GRAY))
            .append(Component.newline())
            .append(Component.text("/vshield lookup <ip>", NamedTextColor.YELLOW))
            .append(Component.text(" - Check if an IP is a VPN", NamedTextColor.GRAY))
            .append(Component.newline())
            .append(Component.text("/vshield cache clear", NamedTextColor.YELLOW))
            .append(Component.text(" - Clear the IP cache", NamedTextColor.GRAY))
            .append(Component.newline())
            .append(Component.text("/vshield whitelist <add|remove|list> [ip]", NamedTextColor.YELLOW))
            .append(Component.text(" - Manage IP whitelist", NamedTextColor.GRAY))
            .build());
    }

    private void showStats(Invocation invocation) {
        long uptime = (System.currentTimeMillis() - plugin.getStartTime()) / 1000;
        long hours = uptime / 3600;
        long minutes = (uptime % 3600) / 60;
        long seconds = uptime % 60;
        
        invocation.source().sendMessage(Component.text()
            .append(Component.text("=== VelocityShield Statistics ===", NamedTextColor.GOLD))
            .append(Component.newline())
            .append(Component.text("Version: ", NamedTextColor.GRAY))
            .append(Component.text("1.1.0", NamedTextColor.GREEN))
            .append(Component.newline())
            .append(Component.text("Uptime: ", NamedTextColor.GRAY))
            .append(Component.text(String.format("%dh %dm %ds", hours, minutes, seconds), NamedTextColor.GREEN))
            .append(Component.newline())
            .append(Component.text("VPN Blocks: ", NamedTextColor.GRAY))
            .append(Component.text(String.valueOf(plugin.getVpnMitigations()), NamedTextColor.RED))
            .append(Component.newline())
            .append(Component.text("Cache Enabled: ", NamedTextColor.GRAY))
            .append(Component.text(plugin.getConfig().isEnableCache() ? "Yes" : "No", 
                plugin.getConfig().isEnableCache() ? NamedTextColor.GREEN : NamedTextColor.RED))
            .build());
    }

    private void lookupIP(Invocation invocation, String ip) {
        invocation.source().sendMessage(Component.text("Checking IP: " + ip + "...", NamedTextColor.YELLOW));
        
        plugin.getVpnChecker().isVPN(ip).thenAccept(isVPN -> {
            invocation.source().sendMessage(Component.text()
                .append(Component.text("IP: ", NamedTextColor.GRAY))
                .append(Component.text(ip, NamedTextColor.YELLOW))
                .append(Component.text(" - Status: ", NamedTextColor.GRAY))
                .append(Component.text(isVPN ? "VPN DETECTED" : "Clean", 
                    isVPN ? NamedTextColor.RED : NamedTextColor.GREEN))
                .build());
        }).exceptionally(throwable -> {
            invocation.source().sendMessage(Component.text("Error: " + throwable.getMessage())
                .color(NamedTextColor.RED));
            return null;
        });
    }

    private void clearCache(Invocation invocation) {
        plugin.getVpnChecker().clearCache();
        invocation.source().sendMessage(Component.text("Cache cleared successfully!")
            .color(NamedTextColor.GREEN));
    }

    private void handleWhitelist(Invocation invocation, String[] args) {
        if (args.length < 2) {
            invocation.source().sendMessage(Component.text("Usage: /vshield whitelist <add|remove|list> [ip]")
                .color(NamedTextColor.RED));
            return;
        }

        String action = args[1].toLowerCase();
        
        switch (action) {
            case "add":
                if (args.length < 3) {
                    invocation.source().sendMessage(Component.text("Usage: /vshield whitelist add <ip>")
                        .color(NamedTextColor.RED));
                    return;
                }
                plugin.getConfig().addToWhitelist(args[2]);
                invocation.source().sendMessage(Component.text("IP " + args[2] + " added to whitelist!")
                    .color(NamedTextColor.GREEN));
                break;
            case "remove":
                if (args.length < 3) {
                    invocation.source().sendMessage(Component.text("Usage: /vshield whitelist remove <ip>")
                        .color(NamedTextColor.RED));
                    return;
                }
                plugin.getConfig().removeFromWhitelist(args[2]);
                invocation.source().sendMessage(Component.text("IP " + args[2] + " removed from whitelist!")
                    .color(NamedTextColor.GREEN));
                break;
            case "list":
                int count = plugin.getConfig().getWhitelistedIps().size();
                invocation.source().sendMessage(Component.text("Whitelisted IPs: " + count, NamedTextColor.GREEN));
                break;
            default:
                invocation.source().sendMessage(Component.text("Invalid action! Use: add, remove, or list")
                    .color(NamedTextColor.RED));
                break;
        }
    }

    @Override
    public List<String> suggest(Invocation invocation) {
        String[] args = invocation.arguments();
        List<String> suggestions = new ArrayList<>();

        if (args.length == 0 || args.length == 1) {
            List<String> subCommands = List.of("reload", "stats", "lookup", "cache", "whitelist", "help");
            String input = args.length == 0 ? "" : args[0].toLowerCase();
            for (String cmd : subCommands) {
                if (cmd.startsWith(input)) {
                    suggestions.add(cmd);
                }
            }
        } else if (args.length == 2) {
            String subCommand = args[0].toLowerCase();
            String input = args[1].toLowerCase();
            
            if (subCommand.equals("cache")) {
                if ("clear".startsWith(input)) {
                    suggestions.add("clear");
                }
            } else if (subCommand.equals("whitelist")) {
                List<String> whitelistActions = List.of("add", "remove", "list");
                for (String action : whitelistActions) {
                    if (action.startsWith(input)) {
                        suggestions.add(action);
                    }
                }
            }
        }

        return suggestions;
    }

    @Override
    public CompletableFuture<List<String>> suggestAsync(Invocation invocation) {
        return CompletableFuture.completedFuture(suggest(invocation));
    }

    @Override
    public boolean hasPermission(Invocation invocation) {
        return invocation.source().hasPermission("velocityshield.admin");
    }
}
