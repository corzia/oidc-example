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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

public class OidcUserInfoTest {

    @Test
    public void testGetUserName_PreferNameClaim() {
        OidcUserInfo info = new OidcUserInfo(
                "google", "sub123", "user@example.com", "user@example.com",
                "John Doe", "John", "Doe", // fullName, givenName, familyName
                null, null, null, true, // picture, tenantId, locale, emailVerified
                Set.of(), "id", "access", "refresh",
                Map.of("name", "John Doe"));

        assertEquals("John Doe", OidcUserInfo.getUserName(info));
    }

    @Test
    public void testGetUserName_FallbackToUsernameIfNameMissing() {
        OidcUserInfo info = new OidcUserInfo(
                "google", "sub123", "user@example.com", "user@example.com",
                null, null, null, // personal names
                null, null, null, false, // picture, tenantId, locale, emailVerified
                Set.of(), "id", "access", "refresh",
                Map.of());

        assertEquals("user@example.com", OidcUserInfo.getUserName(info));
    }

    @Test
    public void testGetUserName_FallbackToUsernameIfNameBlank() {
        OidcUserInfo info = new OidcUserInfo(
                "google", "sub123", "user@example.com", "user@example.com",
                "  ", null, null, // fullName is blank
                null, null, null, false, // picture, tenantId, locale, emailVerified
                Set.of(), "id", "access", "refresh",
                Map.of("name", "  "));

        assertEquals("user@example.com", OidcUserInfo.getUserName(info));
    }

    @Test
    public void testNewFields() {
        OidcUserInfo info = new OidcUserInfo(
                "google", "sub123", "user@example.com", "user@example.com",
                "John Doe", "John", "Doe",
                "http://picture", "example.com", "en-US", true,
                Set.of(), "id", "access", "refresh",
                Map.of());

        assertEquals("John Doe", info.getFullName());
        assertEquals("John", info.getGivenName());
        assertEquals("Doe", info.getFamilyName());
        assertEquals("http://picture", info.getPicture());
        assertEquals("example.com", info.getTenantId());
        assertEquals("en-US", info.getLocale());
    }

    @Test
    public void testGetUserName_HandlesNull() {
        assertNull(OidcUserInfo.getUserName(null));
    }
}
