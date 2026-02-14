/**************************************************************************
 * Copyright 2025 Corzia AB, Sweden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **************************************************************************/
module org.corzia.oidc {
    // Export public API packages
    exports org.corzia.oidc;
    exports org.corzia.oidc.shiro;
    exports org.corzia.oidc.servlet;

    // Dependencies
    requires transitive jakarta.servlet;
    requires org.apache.shiro.core;
    requires org.apache.shiro.web;
    requires org.json;

    // Implementation dependencies
    requires org.slf4j;
    requires com.nimbusds.jose.jwt;
    requires io.github.bucket4j.core;
    requires osgi.core;
    requires org.osgi.service.cm;

    // JPMS Service Discovery
    uses org.corzia.oidc.OidcClient;

    provides org.corzia.oidc.OidcClient with
            org.corzia.oidc.internal.provider.GoogleOidcClient,
            org.corzia.oidc.internal.provider.EntraOidcClient,
            org.corzia.oidc.internal.provider.OktaOidcClient,
            org.corzia.oidc.internal.provider.MockOidcClient;
}
