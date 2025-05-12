package com.pandadevv.VelocityShield.config;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.pandadevv.VelocityShield.VelocityShield;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class UpdateChecker {
    private static final String CURRENT_VERSION = "1.0";
    private boolean updateAvailable = false;
    private String latestVersion = "";
    private final VelocityShield plugin;

    public UpdateChecker(VelocityShield plugin) {
        this.plugin = plugin;
    }

    public void checkForUpdates() {
        plugin.getLogger().info("Checking for VelocityShield updates...");
        
        plugin.getServer().getScheduler().buildTask(plugin, () -> {
            try {
                URL url = new URL("https://api.pandadevv.dev/checkupdate/velocityshield/" + CURRENT_VERSION);
                
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                connection.setConnectTimeout(5000);
                connection.setReadTimeout(5000);
                
                int responseCode = connection.getResponseCode();
                
                if (responseCode != 200) {
                    plugin.getLogger().warn("Failed to check for updates. Response code: " + responseCode);
                    return;
                }
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                
                JsonObject jsonResponse = JsonParser.parseString(response.toString()).getAsJsonObject();
                updateAvailable = jsonResponse.get("update").getAsBoolean();
                latestVersion = jsonResponse.get("currentVersion").getAsString();
                
                if (updateAvailable) {
                    plugin.getLogger().warn("==========================================");
                    plugin.getLogger().warn("VelocityShield Update Available!");
                    plugin.getLogger().warn("Current Version: " + CURRENT_VERSION);
                    plugin.getLogger().warn("Latest Version: " + latestVersion);
                    plugin.getLogger().warn("Download at: https://builtbybit.com/resources/velocityshield.66897/");
                    plugin.getLogger().warn("==========================================");
                    
                    plugin.getServer().getAllPlayers().stream()
                        .filter(player -> player.hasPermission("velocityshield.admin"))
                        .forEach(this::sendUpdateMessage);
                } else {
                    plugin.getLogger().info("VelocityShield is up to date! (Version: " + CURRENT_VERSION + ")");
                }
            } catch (Exception e) {
                //plugin.getLogger().warn("Failed to check for updates: " + e.getMessage());
            }
        }).schedule();
    }

    private void sendUpdateMessage(com.velocitypowered.api.proxy.Player player) {
        Component message = Component.text()
            .append(Component.text("[VelocityShield] ", NamedTextColor.GOLD))
            .append(Component.text("An update is available! Current version: ", NamedTextColor.YELLOW))
            .append(Component.text(CURRENT_VERSION, NamedTextColor.RED))
            .append(Component.text(" Latest version: ", NamedTextColor.YELLOW))
            .append(Component.text(latestVersion, NamedTextColor.GREEN))
            .build();
        
        player.sendMessage(message);
    }

    public boolean isUpdateAvailable() {
        return updateAvailable;
    }

    public String getLatestVersion() {
        return latestVersion;
    }
} 