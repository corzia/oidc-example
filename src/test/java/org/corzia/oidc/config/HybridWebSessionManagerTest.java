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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class HybridWebSessionManagerTest {

    private HybridWebSessionManager manager;

    @Mock
    private HttpServletRequest request;

    @BeforeEach
    public void setUp() {
        manager = new HybridWebSessionManager();
    }

    @Test
    public void testResolveTabId_FromHeader() {
        when(request.getHeader(HybridWebSessionManager.HEADER_TAB_ID)).thenReturn("tab-123");
        assertEquals("tab-123", manager.resolveTabId(request));
    }

    @Test
    public void testResolveTabId_FromParameter() {
        when(request.getHeader(HybridWebSessionManager.HEADER_TAB_ID)).thenReturn(null);
        when(request.getParameter("tabId")).thenReturn("tab-456");
        assertEquals("tab-456", manager.resolveTabId(request));
    }

    @Test
    public void testResolveTabId_FromOidcState() {
        when(request.getHeader(HybridWebSessionManager.HEADER_TAB_ID)).thenReturn(null);
        when(request.getParameter("tabId")).thenReturn(null);
        when(request.getParameter("state")).thenReturn("tab-oidc:some-nonce");
        assertEquals("tab-oidc", manager.resolveTabId(request));
    }

    @Test
    public void testResolveTabId_DefaultFallback() {
        when(request.getHeader(HybridWebSessionManager.HEADER_TAB_ID)).thenReturn(null);
        when(request.getParameter("tabId")).thenReturn(null);
        when(request.getParameter("state")).thenReturn(null);
        assertEquals("default", manager.resolveTabId(request));
    }
}
