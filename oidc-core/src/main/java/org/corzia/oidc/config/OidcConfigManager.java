package org.corzia.oidc.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Properties;
import org.corzia.oidc.OidcClient;
import org.corzia.oidc.OidcClientFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcConfigManager {
    private static final Logger log = LoggerFactory.getLogger(OidcConfigManager.class);
    private static final Map<String, Properties> providerConfigs = new java.util.concurrent.ConcurrentHashMap<>();
    private static final Map<String, Properties> securityConfigs = new java.util.concurrent.ConcurrentHashMap<>();

    static {
        loadInitialConfig();
    }

    private static void loadInitialConfig() {
        try (InputStream is = OidcConfigManager.class.getResourceAsStream("/oidc-providers.properties")) {
            if (is != null) {
                Properties p = new Properties();
                p.load(is);
                log.info("Loaded initial OIDC configuration from oidc-providers.properties");

                // Group properties
                p.stringPropertyNames().forEach(key -> {
                    int dot = key.indexOf('.');
                    if (dot > 0) {
                        String category = key.substring(0, dot).toLowerCase();
                        String subKey = key.substring(dot + 1);

                        if ("security".equals(category)) {
                            securityConfigs.computeIfAbsent(category, k -> new Properties())
                                    .setProperty(subKey, p.getProperty(key));
                        } else {
                            providerConfigs.computeIfAbsent(category, k -> new Properties())
                                    .setProperty(subKey, p.getProperty(key));
                        }
                    }
                });
            }
        } catch (IOException e) {
            log.warn("Could not load oidc-providers.properties", e);
        }
    }

    /**
     * Updates or adds configuration for a specific provider.
     * If the client is already active, it will be reconfigured immediately.
     */
    public static void updateProvider(String providerName, Properties properties) {
        log.info("Updating OIDC configuration for provider: {}", providerName);
        if (properties == null) {
            providerConfigs.remove(providerName.toLowerCase());
        } else {
            providerConfigs.put(providerName.toLowerCase(), properties);
        }

        // Notify client if it exists
        OidcClient client = OidcClientFactory.getInstance().getClient(providerName);
        if (client != null) {
            client.configure(getProviderConfig(providerName));
        }
    }

    public static Properties getProviderConfig(String providerName) {
        Properties p = providerConfigs.get(providerName.toLowerCase());
        Properties result = new Properties();

        if (p != null) {
            result.putAll(p);
        }

        // Apply environment variable overrides
        // Pattern: OIDC_{PROVIDER}_{KEY} (e.g. OIDC_GOOGLE_CLIENT_ID)
        String prefix = "OIDC_" + providerName.toUpperCase() + "_";

        // We check for common keys defined in OidcRealm
        String[] keys = {
                "CLIENT_ID", "CLIENT_SECRET", "TENANT_ID", "REDIRECT_URI",
                "SCOPES", "TOKEN_ENDPOINT", "AUTHORIZATION_ENDPOINT",
                "JWKS_URI", "ISSUER", "AUTHORITY", "IMAGE_URL"
        };

        for (String key : keys) {
            String envVar = prefix + key;
            String envVal = System.getenv(envVar);
            if (envVal != null && !envVal.isEmpty()) {
                log.info("Overriding OIDC property {} for provider {} from environment variable {}", key, providerName,
                        envVar);
                result.setProperty(key, envVal);
            }
        }

        return result;
    }

    /**
     * Legacy method for full configuration updates.
     */
    public static void update(Map<String, String> properties) {
        if (properties == null) {
            providerConfigs.clear();
            loadInitialConfig();
            OidcClientFactory.getInstance().reconfigureAll();
            return;
        }

        log.info("Batch updating OIDC configuration");
        properties.forEach((key, value) -> {
            int dot = key.indexOf('.');
            if (dot > 0) {
                String provider = key.substring(0, dot).toLowerCase();
                String subKey = key.substring(dot + 1);
                providerConfigs.computeIfAbsent(provider, k -> new Properties())
                        .setProperty(subKey, value);
            }
        });
        OidcClientFactory.getInstance().reconfigureAll();
    }

    public static Map<String, Properties> getAllProviderConfigs() {
        return new java.util.HashMap<>(providerConfigs);
    }

    /**
     * Retrieves global security configuration (e.g. key starting with 'security.').
     * Category is usually 'security'.
     */
    public static Properties getSecurityConfig(String category) {
        Properties p = securityConfigs.get(category.toLowerCase());
        Properties result = new Properties();
        if (p != null) {
            result.putAll(p);
        }
        return result;
    }
}
