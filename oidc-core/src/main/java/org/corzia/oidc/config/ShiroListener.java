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
package org.corzia.oidc.config;

import jakarta.servlet.ServletContext;
import jakarta.servlet.annotation.WebListener;
import org.apache.shiro.web.env.DefaultWebEnvironment;
import org.apache.shiro.web.env.EnvironmentLoaderListener;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@WebListener
public class ShiroListener extends EnvironmentLoaderListener {

        private static final Logger log = LoggerFactory.getLogger(ShiroListener.class);

        @Override
        protected WebEnvironment createEnvironment(ServletContext sc) {
                log.info("Initializing Shiro WebEnvironment programmatically");

                // 1. Create the Environment
                DefaultWebEnvironment environment = new DefaultWebEnvironment();
                environment.setServletContext(sc);

                // 2a. Create OIDC Realm
                org.corzia.oidc.OidcRealm oidcRealm = new org.corzia.oidc.OidcRealm();

                // 2b. Create Simple Realm (Local Testing)
                org.apache.shiro.realm.SimpleAccountRealm simpleRealm = new org.apache.shiro.realm.SimpleAccountRealm();
                simpleRealm.addAccount("test", "test");

                // Pre-populate test user profile
                org.corzia.oidc.OidcUserDirectory.put(new org.corzia.oidc.UserInfo(
                                "test",
                                "test@example.com",
                                "Test User",
                                "Test",
                                "User",
                                null,
                                "en-US",
                                true,
                                java.util.Set.of("USERS", "TESTERS")));

                // 2c. Create API Token Realm
                org.corzia.oidc.api.ApiTokenRealm apiRealm = new org.corzia.oidc.api.ApiTokenRealm();

                // 3. Create SessionManager (Hybrid)
                HybridWebSessionManager sessionManager = new HybridWebSessionManager();

                // Configure SessionDAO
                org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO sessionDAO = new org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO();
                sessionDAO.setSessionIdGenerator(new PreserveIdSessionIdGenerator());
                sessionManager.setSessionDAO(sessionDAO);

                // 4. Create SecurityManager
                DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
                securityManager.setRealms(java.util.Arrays.asList(oidcRealm, simpleRealm, apiRealm));
                securityManager.setSessionManager(sessionManager);

                // 5. Configure Filter Chains
                org.apache.shiro.web.filter.mgt.DefaultFilterChainManager filterChainManager = new org.apache.shiro.web.filter.mgt.DefaultFilterChainManager();
                // Add default filters (anon, authc, etc. are automatic in some configs, but
                // safe to add if needed or rely on default constructor?)
                // DefaultFilterChainManager constructor adds default filters.

                // Add our custom filters
                filterChainManager.addFilter("headers", new org.corzia.oidc.config.SecurityHeaderFilter());
                filterChainManager.addFilter("tabIdMaster", new org.corzia.oidc.config.TabIdEnforcementFilter());
                filterChainManager.addFilter("contentType", new org.corzia.oidc.config.ContentTypeFilter());
                filterChainManager.addFilter("csrf", new org.corzia.oidc.config.CsrfFilter());
                filterChainManager.addFilter("bearer", new org.corzia.oidc.api.BearerAuthFilter());

                // Rate limiting: 5 requests per minute for login/auth
                filterChainManager.addFilter("rateLimitAuth",
                                new org.corzia.oidc.config.RateLimitFilter(5, java.time.Duration.ofMinutes(1)));
                // Rate limiting: 100 requests per minute for general API
                filterChainManager.addFilter("rateLimitApi",
                                new org.corzia.oidc.config.RateLimitFilter(100, java.time.Duration.ofMinutes(1)));

                // Configure login URL for authc filter
                org.apache.shiro.web.filter.mgt.DefaultFilterChainManager fcm = filterChainManager;
                org.apache.shiro.web.filter.authc.FormAuthenticationFilter authcFilter = (org.apache.shiro.web.filter.authc.FormAuthenticationFilter) fcm
                                .getFilter("authc");
                authcFilter.setLoginUrl("/");

                // Configure chains
                filterChainManager.createChain("/api/providers", "tabIdMaster, headers, anon");
                filterChainManager.createChain("/api/session", "tabIdMaster, headers, anon");
                filterChainManager.createChain("/api/login", "tabIdMaster, headers, rateLimitAuth, contentType, csrf");
                filterChainManager.createChain("/portal/oidc/login", "tabIdMaster, headers, rateLimitAuth");
                filterChainManager.createChain("/portal/oidc/callback", "tabIdMaster, headers, rateLimitAuth");
                filterChainManager.createChain("/api/rs/**", "tabIdMaster, headers, rateLimitApi, contentType, bearer");
                filterChainManager.createChain("/api/**",
                                "tabIdMaster, headers, rateLimitApi, contentType, csrf, authc");
                filterChainManager.createChain("/portal/logout", "tabIdMaster, headers, csrf, logout");
                filterChainManager.createChain("/secure.html", "tabIdMaster, headers, csrf, authc");
                filterChainManager.createChain("/**", "tabIdMaster, headers");

                // Optional: configure logout redirect
                org.apache.shiro.web.filter.authc.LogoutFilter logoutFilter = (org.apache.shiro.web.filter.authc.LogoutFilter) filterChainManager
                                .getFilter("logout");
                logoutFilter.setRedirectUrl("/");

                org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver resolver = new org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver();
                resolver.setFilterChainManager(filterChainManager);
                environment.setFilterChainResolver(resolver);

                // 6. Wire up environment
                environment.setSecurityManager(securityManager);

                // Note: EnvironmentLoaderListener.contextInitialized() calls initEnvironment()
                // which calls createEnvironment() (this method), and then stores it in
                // ServletContext.

                return environment;
        }
}
