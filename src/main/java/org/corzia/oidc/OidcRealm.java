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

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * Shiro Realm that integrates external OpenID Connect (OIDC) identity
 * providers (Microsoft Entra, Google, etc.) with Shiro's Subject/role
 * model.
 *
 * <h2>High-level concept</h2>
 * <p>
 * The authentication flow is split into two parts:
 * </p>
 * <ol>
 * <li><b>OIDC layer (outside this Realm)</b><br/>
 * A servlet redirects the user to the OIDC provider, receives the
 * authorization code on the callback, exchanges it for tokens,
 * validates the ID token and normalizes claims into {@link OidcUserInfo}.
 * </li>
 * <li><b>Shiro layer (this Realm)</b><br/>
 * The servlet creates an {@link OidcAuthenticationToken} with the
 * {@link OidcUserInfo} and calls {@code Subject.login(token)}.
 * This Realm turns that into a Shiro {@link org.apache.shiro.subject.Subject}.
 * </li>
 * </ol>
 *
 * <p>
 * This split keeps provider-specific logic (endpoints, JWKS, claim names)
 * out of the Realm. The Realm only needs to understand:
 * </p>
 * <ul>
 * <li><b>OidcAuthenticationToken</b> – "user authenticated with an IdP"</li>
 * <li><b>OidcUserInfo</b> – "normalized identity and groups"</li>
 * <li><b>Role mapping rules</b> – how to convert IdP groups into Shiro
 * roles/permissions</li>
 * </ul>
 *
 * <h2>Where does OidcUserInfo come from?</h2>
 * <p>
 * Each provider has a corresponding {@code OidcClient} implementation:
 * </p>
 * <ul>
 * <li>{@code EntraOidcClient} for Microsoft Entra</li>
 * <li>{@code GoogleOidcClient} for Google</li>
 * <li>... any other provider-specific client</li>
 * </ul>
 *
 * <p>
 * The {@code OidcClient}:
 * </p>
 * <ul>
 * <li>Builds the authorization URL</li>
 * <li>Exchanges {@code code} for tokens</li>
 * <li>Validates the ID token</li>
 * <li>Maps provider-specific claims to {@link OidcUserInfo}</li>
 * </ul>
 *
 * <p>
 * The servlet layer then does:
 * </p>
 * 
 * <pre>
 *   OidcUserInfo info = oidcClient.exchangeCodeForUserInfo(...);
 *   subject.login(new OidcAuthenticationToken(info));
 * </pre>
 *
 * <h2>Authorization and group/role mapping</h2>
 * <p>
 * This Realm's {@link #doGetAuthorizationInfo(PrincipalCollection)} method
 * is responsible for translating the external groups / claims into
 * Shiro roles and permissions. A typical pattern:
 * </p>
 * <ol>
 * <li>Look up the {@link OidcUserInfo} for the current principal
 * from a shared directory or service</li>
 * <li>Inspect {@link OidcUserInfo#getProvider()} and
 * {@link OidcUserInfo#getGroups()}</li>
 * <li>Apply mapping rules, e.g. specific Entra group IDs → Shiro roles</li>
 * <li>Optionally combine with roles from your own database</li>
 * </ol>
 *
 * <h2>How to add a new OIDC provider</h2>
 * <p>
 * To add support for a new provider (e.g. Okta, Auth0) you typically:
 * </p>
 * <ol>
 * <li>Create a new {@code OidcClient} implementation for that provider.</li>
 * <li>Register it in {@code OidcClientFactory}.</li>
 * <li>Expose it via the login endpoint (e.g.
 * {@code /oidc/login?provider=okta}).</li>
 * <li>Decide how that provider's groups/claims should map to Shiro roles
 * in {@link #doGetAuthorizationInfo(PrincipalCollection)}.</li>
 * </ol>
 *
 * <p>
 * The Realm itself usually does not need to change when a new provider
 * is added, unless you want custom mapping logic based on
 * {@link OidcClient#getName()}.
 * </p>
 */
public class OidcRealm extends AuthorizingRealm {

    private static final Logger log = LoggerFactory.getLogger(OidcRealm.class);

    public static final String REALM_NAME = "OIDC";

    public static final String CLIENT_ID = "CLIENT_ID";
    public static final String CLIENT_SECRET = "CLIENT_SECRET";
    public static final String TENANT_ID = "TENANT_ID";
    public static final String REDIRECT_URI = "REDIRECT_URI";
    public static final String SCOPES = "SCOPES";
    public static final String TOKEN_ENDPOINT = "TOKEN_ENDPOINT";
    public static final String AUTHORIZATION_ENDPOINT = "AUTHORIZATION_ENDPOINT";
    public static final String JWKS_URI = "JWKS_URI";
    public static final String ISSUER = "ISSUER";
    public static final String AUTHORITY = "AUTHORITY";
    public static final String IMAGE_URL = "IMAGE_URL";

    private static final Properties ALL_PROVIDER_PROPS = new Properties();

    static {
        try (InputStream is = OidcRealm.class.getResourceAsStream("/oidc-providers.properties")) {
            if (is != null) {
                ALL_PROVIDER_PROPS.load(is);
            }
        } catch (IOException e) {
            log.warn("Could not load oidc-providers.properties", e);
        }
    }

    private static final OidcClientFactory CLIENT_FACTORY = OidcClientFactory.getInstance();

    public OidcRealm() {
        setAuthenticationTokenClass(OidcAuthenticationToken.class);
        setName(REALM_NAME);
    }

    /**
     * Ensures this Realm only processes {@link OidcAuthenticationToken}s.
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof OidcAuthenticationToken;
    }

    /**
     * Authentication step for OIDC-based logins.
     * <p>
     * At this point the ID token has already been validated by the OIDC client,
     * so this method is fairly trivial: it trusts the {@link OidcUserInfo}
     * and returns an {@link AuthenticationInfo} with the normalized principal.
     * </p>
     *
     * @param token the OIDC authentication token
     * @return authentication info for Shiro's {@code Subject}
     * @throws AuthenticationException if principal is missing or invalid
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {

        OidcAuthenticationToken oidcToken = (OidcAuthenticationToken) token;

        if (oidcToken.getUserInfo() == null) {
            throw new AuthenticationException("Missing OIDC user info");
        }

        // Credentials are the ID token (already validated)
        return new SimpleAuthenticationInfo(
                oidcToken.getUserInfo(),
                oidcToken.getUserInfo().getIdToken(),
                getName());
    }

    /**
     * Authorization step: maps the external identity (groups/claims)
     * to Shiro roles and permissions.
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // Just return empty info for now as requested
        return new SimpleAuthorizationInfo();
    }

    /**
     * Resolves and returns the configuration for a specific OpenID Connect (OIDC)
     * provider from the application's XML configuration.
     *
     * <p>
     * This method reads the {@code &lt;GroupMap&gt;} element whose {@code name}
     * attribute matches the supplied provider name and converts its
     * {@code &lt;Property&gt;} children into a {@link java.util.Properties}
     * instance.
     * Each Property entry becomes a key/value pair in the returned Properties
     * object.
     * </p>
     *
     * <h2>Why this matters</h2>
     * <p>
     * When adding or modifying an OIDC provider (Entra, Google, or future providers
     * like Okta/Auth0), this method is the single point where raw XML configuration
     * is transformed into a structured object used by {@code OidcClient}
     * implementations.
     * </p>
     *
     * <p>
     * Wondering what the XML is supposed to look like? Here are real, working
     * examples.
     * This is in the sitedef.xml under /Site/ServerInfo/Shiro/Realm@name="OICD"
     * </p>
     *
     * <h3>Microsoft Entra example</h3>
     *
     * <pre>
     * {@code
     * <GroupMap name="ENTRA">
     *     <Property name="CLIENT_ID" value="11111111-2222-3333-4444-555555555555"/>
     *     <Property name="CLIENT_SECRET" value=
    "very-secret-generated-by-entra-portal"/>
     *     <Property name="TENANT_ID" value="contoso-tenant-id-1234-5678-abcd"/>
     *
     *     <Property name="AUTHORITY"
     *               value=
    "https://login.microsoftonline.com/contoso-tenant-id-1234-5678-abcd"/>
     *
     *     <Property name="REDIRECT_URI"
     *               value="https://app.example.com/oidc/callback"/>
     *
     *     <Property name="SCOPES" value="openid profile email"/>
     *
     *     <Property name="JWKS_URI"
     *               value=
    "https://login.microsoftonline.com/contoso-tenant-id-1234-5678-abcd/discovery/v2.0/keys"/>
     *
     *     <Property name="ISSUER"
     *               value=
    "https://login.microsoftonline.com/contoso-tenant-id-1234-5678-abcd/v2.0"/>
     * </GroupMap>
     * }
     * </pre>
     *
     * <h3>Google example</h3>
     *
     * <pre>
     * {@code
     * <GroupMap name="GOOGLE">
     *     <Property name="CLIENT_ID" value=
    "1234567890-abcdef.apps.googleusercontent.com"/>
     *     <Property name="CLIENT_SECRET" value="google-client-secret-value"/>
     *
     *     <Property name="TENANT_ID" value="google"/>
     *
     *     <Property name="AUTHORITY"
     *               value="https://accounts.google.com"/>
     *
     *     <Property name="REDIRECT_URI"
     *               value="https://app.example.com/oidc/callback"/>
     *
     *     <Property name="SCOPES" value="openid profile email"/>
     *
     *     <Property name="JWKS_URI"
     *               value="https://www.googleapis.com/oauth2/v3/certs"/>
     *
     *     <Property name="ISSUER"
     *               value="https://accounts.google.com"/>
     * </GroupMap>
     * }
     * </pre>
     *
     * <h2>Returned Properties</h2>
     * <p>
     * The returned {@link Properties} object will contain keys such as:
     * </p>
     * <ul>
     * <li>{@code CLIENT_ID}</li>
     * <li>{@code CLIENT_SECRET}</li>
     * <li>{@code TENANT_ID}</li>
     * <li>{@code AUTHORITY}</li>
     * <li>{@code REDIRECT_URI}</li>
     * <li>{@code SCOPES}</li>
     * <li>{@code JWKS_URI}</li>
     * <li>{@code ISSUER}</li>
     * </ul>
     *
     * <p>
     * These values are typically consumed by {@code OidcClient} implementations
     * when constructing authorization URLs and validating ID tokens.
     * </p>
     *
     * <h2>Common pitfalls</h2>
     * <ul>
     * <li>Does the REDIRECT_URI exactly match what's registered in the IdP
     * console?</li>
     * <li>Does the ISSUER value match the issuer claim in the ID token?</li>
     * <li>Is the JWKS_URI reachable and returning JSON keys?</li>
     * </ul>
     *
     * <p>
     * If authentication mysteriously fails, this method and its source XML should
     * be the very first place you check.
     * </p>
     *
     * @param name logical provider name, e.g. {@code "ENTRA"} or {@code "GOOGLE"}
     * @return Properties containing all configuration values for the requested
     *         provider
     * @throws IllegalArgumentException if the provider name does not exist or has
     *                                  no configuration
     */

    /**
     * Resolves and returns the configuration for a specific OpenID Connect (OIDC)
     * provider.
     * <p>
     * It first looks for properties prefixed with the provider name (e.g.,
     * google.CLIENT_ID).
     * If not found, it falls back to a hardcoded dummy configuration for testing.
     * </p>
     *
     * @param name logical provider name, e.g. {@code "ENTRA"} or {@code "GOOGLE"}
     * @return Properties containing all configuration values for the requested
     *         provider
     */
    public static Properties getOidcProviderConfig(String name) {
        String prefix = name.toLowerCase() + ".";
        Properties p = new Properties();

        // Load from file if present
        ALL_PROVIDER_PROPS.forEach((key, value) -> {
            String k = (String) key;
            if (k.startsWith(prefix)) {
                p.setProperty(k.substring(prefix.length()), (String) value);
            }
        });

        return p;
    }

    public static OidcClientFactory getClientFactory() {
        return CLIENT_FACTORY;
    }
}
