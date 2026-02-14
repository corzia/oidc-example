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
package org.corzia.oidc;

import java.util.Collection;
import java.util.Map;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.corzia.oidc.internal.config.OidcConfigManager;

/**
 * Simple registry / factory for {@link OidcClient} instances.
 */
public class OidcClientFactory {

    private static final Logger log = LoggerFactory.getLogger(OidcClientFactory.class); // Added logger

    private static final OidcClientFactory INSTANCE = new OidcClientFactory();

    private final Map<String, OidcClient> clients = new ConcurrentHashMap<>();

    private OidcClientFactory() {
        // Load clients from ServiceLoader for non-OSGi environments
        try {
            ServiceLoader<OidcClient> loader = ServiceLoader.load(OidcClient.class, OidcClient.class.getClassLoader());
            for (OidcClient client : loader) {
                log.info("Loaded OIDC client via ServiceLoader: {}", client.getName());
                // Fetch configuration from the default source
                client.configure(OidcConfigManager.getProviderConfig(client.getName()));
                clients.put(client.getName().toLowerCase(), client); // Changed to lowercase and direct put
            }
        } catch (Throwable e) {
            log.warn(
                    "Failed to load OIDC clients via ServiceLoader (often happens in OSGi due to classloader isolation): {}",
                    e.getMessage());
        }
    }

    /**
     * Returns the singleton instance of the factory.
     */
    public static OidcClientFactory getInstance() {
        return INSTANCE;
    }

    /**
     * Registers a client implementation for its {@link OidcClient#getName()}.
     */
    public void register(OidcClient client) {
        if (client != null) {
            clients.put(client.getName(), client);
        }
    }

    /**
     * Unregisters a client implementation.
     */
    public void unregister(OidcClient client) {
        if (client != null) {
            clients.remove(client.getName(), client);
        }
    }

    /**
     * Reconfigures all registered clients using the latest settings from
     * OidcConfigManager.
     */
    public void reconfigureAll() {
        for (OidcClient client : clients.values()) {
            Properties p = OidcConfigManager.getProviderConfig(client.getName());
            if (p != null && !p.isEmpty()) {
                client.configure(p);
            }
        }
    }

    /**
     * Returns the {@link OidcClient} for the requested provider name.
     */
    public OidcClient getClient(String name) {
        OidcClient client = clients.get(name);
        if (client == null) {
            throw new IllegalArgumentException("No OIDC client registered for: " + name);
        }
        return client;
    }

    /**
     * @return a collection of all registered OIDC clients.
     */
    public Collection<OidcClient> getAllClients() {
        return clients.values();
    }

    /**
     * Manually configures a specific client. Use this to override
     * default settings or provide configuration in standalone environments.
     */
    public void configure(String name, Properties props) {
        getClient(name).configure(props);
    }

}
