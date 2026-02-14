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

import java.util.Hashtable;
import java.util.Properties;
import org.corzia.oidc.OidcClient;
import org.corzia.oidc.OidcClientFactory;
import org.corzia.oidc.internal.config.OidcConfigManager;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceReference;
import org.osgi.service.cm.ManagedService;
import org.osgi.util.tracker.ServiceTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcActivator implements BundleActivator {
    private static final Logger log = LoggerFactory.getLogger(OidcActivator.class);
    private static final String SERVICE_PID = "org.corzia.oidc.providers";

    private ServiceTracker<OidcClient, OidcClient> clientTracker;

    @Override
    public void start(BundleContext context) throws Exception {
        log.info("Starting OIDC Core Bundle");

        Hashtable<String, Object> props = new Hashtable<>();
        props.put(Constants.SERVICE_PID, SERVICE_PID);

        context.registerService(ManagedService.class.getName(), new ConfigAdminManagedService(), props);
        log.info("Registered OIDC Config Bridge as ManagedService with PID: {}", SERVICE_PID);

        // Set up Whiteboard pattern for OidcClient
        clientTracker = new ServiceTracker<OidcClient, OidcClient>(context, OidcClient.class, null) {
            @Override
            public OidcClient addingService(ServiceReference<OidcClient> reference) {
                OidcClient client = context.getService(reference);
                if (client != null) {
                    log.info("Adding OIDC Client via Whiteboard: {}", client.getName());
                    // Only push configuration if we have something for it
                    Properties p = OidcConfigManager.getProviderConfig(client.getName());
                    if (p != null && !p.isEmpty()) {
                        log.info("Configuring OIDC client '{}' from central settings", client.getName());
                        client.configure(p);
                    } else {
                        log.debug(
                                "No central configuration for OIDC client '{}', assuming it's pre-configured or waiting for ConfigAdmin",
                                client.getName());
                    }
                    OidcClientFactory.getInstance().register(client);
                }
                return client;
            }

            @Override
            public void removedService(ServiceReference<OidcClient> reference, OidcClient client) {
                log.info("Removing OIDC Client: {}", client.getName());
                OidcClientFactory.getInstance().unregister(client);
                context.ungetService(reference);
            }
        };
        clientTracker.open();
    }

    @Override
    public void stop(BundleContext context) throws Exception {
        log.info("Stopping OIDC Core Bundle");
        if (clientTracker != null) {
            clientTracker.close();
        }
    }
}
