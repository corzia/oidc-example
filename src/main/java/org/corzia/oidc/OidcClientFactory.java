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

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.ServiceLoader;

/**
 * Simple registry / factory for {@link OidcClient} instances.
 */
public class OidcClientFactory {

    private static final OidcClientFactory INSTANCE = new OidcClientFactory();

    private final Map<String, OidcClient> clients = new HashMap<>();

    private OidcClientFactory() {
        ServiceLoader<OidcClient> loader = ServiceLoader.load(OidcClient.class);
        for (OidcClient client : loader) {
            // Fetch configuration from the default source (Realm)
            client.configure(OidcRealm.getOidcProviderConfig(client.getName()));
            register(client);
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
        clients.put(client.getName(), client);
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
    public java.util.Collection<OidcClient> getAllClients() {
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
