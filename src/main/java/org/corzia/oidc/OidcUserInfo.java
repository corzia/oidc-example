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
import org.json.JSONObject;

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
public class OidcUserInfo extends UserInfo {
	private final String providerName;
	private final String subject; // stable user id
	private final String tenantId;
	private final String idToken;
	private final String accessToken;
	private final String refreshToken;
	private final Map<String, Object> claims;

	/**
	 * @param providerName  logical provider name (e.g., "google", "entra")
	 * @param subject       stable unique user id from the IdP (e.g. {@code sub} or
	 *                      {@code oid})
	 * @param username      string used as Shiro principal
	 * @param email         user's email address, if available
	 * @param fullName      user's full name, if available
	 * @param givenName     user's given (first) name, if available
	 * @param familyName    user's family (last) name, if available
	 * @param picture       user's profile picture URL, if available
	 * @param tenantId      provider-specific tenant identifier (e.g. Google hd or
	 *                      Entra tid)
	 * @param locale        user's language/locale string, if available
	 * @param emailVerified whether the email has been verified by the IdP
	 * @param groups        group identifiers from the IdP, used for role mapping
	 * @param idToken       raw OIDC ID token (JWT) returned by the provider
	 * @param accessToken   optional access token, if the app needs to call APIs
	 * @param refreshToken  optional refresh token (long-lived), for renewing access
	 *                      tokens
	 * @param claims        full claim map from the ID token for advanced use cases
	 */
	public OidcUserInfo(String providerName, String subject, String username, String email,
			String fullName, String givenName, String familyName,
			String picture, String tenantId, String locale, boolean emailVerified,
			Set<String> groups, String idToken, String accessToken, String refreshToken, Map<String, Object> claims) {
		super(username, email, fullName, givenName, familyName, picture, locale, emailVerified, groups);
		this.providerName = providerName;
		this.subject = subject;
		this.tenantId = tenantId;
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

	public String getTenantId() {
		return tenantId;
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

	@Override
	public JSONObject toJson() {
		JSONObject json = super.toJson();
		json.put("providerName", providerName);
		json.put("subject", subject);
		json.put("tenantId", tenantId);
		if (claims != null) {
			json.put("claims", new JSONObject(claims));
		}
		return json;
	}

	/**
	 * Extracts a friendly display name from the user info.
	 * Tries the 'name' claim first, then falls back to the username principal.
	 *
	 * @param userInfo the user info to extract from
	 * @return a display name or null if userInfo is null
	 */
	public static String getUserName(UserInfo userInfo) {
		if (userInfo == null) {
			return null;
		}
		if (userInfo instanceof OidcUserInfo oidc) {
			Object name = oidc.getClaims().get("name");
			if (name instanceof String s && !s.isBlank()) {
				return s;
			}
		}
		return userInfo.getUsername();
	}
}
