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

import java.util.Map;
import java.util.Set;

/**
 * Immutable, provider-agnostic representation of an authenticated user
 * produced by an OpenID Connect (OIDC) provider.
 * <p>
 * The idea is that provider-specific clients (Microsoft Entra, Google, etc.)
 * normalize their OIDC ID token / user info into this type, so the rest of
 * the system (Shiro realm, application code) only needs to understand
 * {@link OidcUserInfo} and not each IdP's claim naming conventions.
 * </p>
 *
 * <p>
 * Typical mapping examples:
 * </p>
 * <ul>
 * <li>subject: Entra {@code oid}, Google {@code sub}</li>
 * <li>username: something suitable as your internal principal
 * (e.g. UPN, email address)</li>
 * <li>email: user's email, if available</li>
 * <li>groups: flattened set of group identifiers you care about,
 * usually used to derive application roles</li>
 * </ul>
 */
public class OidcUserInfo {
	private final String providerName;
	private final String subject; // stable user id
	private final String username; // what you use as principal in Shiro
	private final String email;
	private final Set<String> groups; // if available
	private final String idToken;
	private final String accessToken;
	private final String refreshToken;
	private final Map<String, Object> claims;

	/**
	 * @param providerName logical provider name (e.g., "google", "entra")
	 * @param subject      stable unique user id from the IdP (e.g. {@code sub} or
	 *                     {@code oid})
	 * @param username     string used as Shiro principal and display name
	 * @param email        user's email address, if available
	 * @param groups       group identifiers from the IdP, used for role mapping
	 * @param idToken      raw OIDC ID token (JWT) returned by the provider
	 * @param accessToken  optional access token, if the app needs to call APIs
	 * @param refreshToken optional refresh token (long-lived), for renewing access
	 *                     tokens
	 * @param claims       full claim map from the ID token for advanced use cases
	 */
	public OidcUserInfo(String providerName, String subject, String username, String email,
			Set<String> groups, String idToken, String accessToken, String refreshToken, Map<String, Object> claims) {
		super();
		this.providerName = providerName;
		this.subject = subject;
		this.username = username;
		this.email = email;
		this.groups = groups;
		this.idToken = idToken;
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.claims = claims;
	}

	public String getProviderName() {
		return providerName;
	}

	public String getSubject() {
		return subject;
	}

	public String getUsername() {
		return username;
	}

	public String getEmail() {
		return email;
	}

	public Set<String> getGroups() {
		return groups;
	}

	public String getIdToken() {
		return idToken;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public Map<String, Object> getClaims() {
		return claims;
	}

	/**
	 * Extracts a friendly display name from the user info.
	 * Tries the 'name' claim first, then falls back to the username principal.
	 *
	 * @param userInfo the user info to extract from
	 * @return a display name or null if userInfo is null
	 */
	public static String getUserName(OidcUserInfo userInfo) {
		if (userInfo == null) {
			return null;
		}
		Object name = userInfo.getClaims().get("name");
		if (name instanceof String s && !s.isBlank()) {
			return s;
		}
		return userInfo.getUsername();
	}
}
