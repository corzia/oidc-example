/**************************************************************************
 * Copyright 2025 Corzia AB, Sweden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **************************************************************************/
package org.corzia.oidc.internal.osgi;

import java.util.Dictionary;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.corzia.oidc.internal.config.OidcConfigManager;
import org.osgi.framework.Constants;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedService;

/**
 * Bridges OSGi ConfigAdmin to the core OidcConfigManager.
 */
public class ConfigAdminManagedService implements ManagedService {

    @Override
    public void updated(Dictionary<String, ?> properties) throws ConfigurationException {
        String pid = properties != null ? (String) properties.get(Constants.SERVICE_PID) : null;
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
