package org.corzia.oidc.osgi;

import java.util.Dictionary;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.corzia.oidc.config.OidcConfigManager;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedService;

/**
 * Bridges OSGi ConfigAdmin to the core OidcConfigManager.
 */
public class ConfigAdminManagedService implements ManagedService {

    @Override
    public void updated(Dictionary<String, ?> properties) throws ConfigurationException {
        String pid = properties != null ? (String) properties.get("service.pid") : null;
        String provider = identifyProvider(pid);

        if (properties == null) {
            if (provider != null) {
                OidcConfigManager.updateProvider(provider, null);
            } else {
                OidcConfigManager.update(null);
            }
            return;
        }

        Properties props = new Properties();
        Enumeration<String> keys = properties.keys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            Object value = properties.get(key);
            if (value != null && !key.startsWith("service.")) {
                props.setProperty(key, value.toString());
            }
        }

        if (provider != null) {
            OidcConfigManager.updateProvider(provider, props);
        } else {
            // Fallback for generic config maps
            Map<String, String> map = new HashMap<>();
            props.forEach((k, v) -> map.put((String) k, (String) v));
            OidcConfigManager.update(map);
        }
    }

    private String identifyProvider(String pid) {
        if (pid == null)
            return null;
        String s = pid.toLowerCase();
        // Typically PIDs are like org.corzia.oidc.google
        if (s.contains("google"))
            return "google";
        if (s.contains("entra"))
            return "entra";
        if (s.contains("okta"))
            return "okta";
        if (s.contains("mock"))
            return "mock";
        return null;
    }
}
