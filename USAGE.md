# OIDC Example Project

A professional Java web application demonstrating the integration of OpenID Connect (OIDC) with Apache Shiro authentication, including local login and API token support.

## Features
- **OIDC Integration**: Support for Microsoft Entra, Google, Okta, and a local Mock provider.
- **Hybrid Session Management**: Manages sessions across browser tabs using a combination of cookies and `tabId`.
- **API Security**: Token-based authentication (Bearer JWT) for REST services.
- **Professional UI**: Dark-themed landing page, secure dashboard, and custom error handling.

---

## Getting Started

### Prerequisites
- Java 17 or higher
- Maven 3.8+

### Build and Run
```bash
mvn clean package cargo:run
```
The application will be available at: `http://localhost:8080/oidc-example/`

### Running with Docker
You can also run the application using Docker.

**1. Build the image:**
```bash
docker build -t oidc-example .
```

**2. Run the container:**
```bash
docker run -d -p 8080:8080 --name oidc-app oidc-example
```
The application will be available at: `http://localhost:8080/` (since it is deployed as `ROOT.war` in the container).

**3. Using custom configuration:**
To use your own `oidc-providers.properties`, mount it as a volume:
```bash
docker run -d -p 8080:8080 \
  -v $(pwd)/src/main/resources/oidc-providers.properties:/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/oidc-providers.properties \
  --name oidc-app oidc-example
```

---

## Authentication Methods

### 1. OpenID Connect (OIDC)
The primary authentication method for end-users.

**Configuration:**
Settings are managed in `src/main/resources/oidc-providers.properties`.

```properties
# Example for Google
google.CLIENT_ID=your-client-id
google.CLIENT_SECRET=your-client-secret
google.REDIRECT_URI=http://localhost:8080/oidc-example/portal/oidc/callback
```

**Flow:**
1. User clicks "Login with [Provider]".
2. Redirects to `/portal/oidc/login?provider=google`.
3. Identity Provider authenticates the user.
4. Callback to `/portal/oidc/callback` with `code` and `state`.
5. Application exchanges code for tokens and creates a Shiro session.

### 2. Local Password Login
Used for testing or administrative accounts.

- **Endpoint**: `POST /api/login`
- **Default Credentials**: `test` / `test`
- **Requirement**: Must include `X-Tab-Id` header (e.g., `tab-123`).

**Example Request:**
```bash
curl -X POST "http://localhost:8080/oidc-example/api/login" \
     -H "X-Tab-Id: my-tab-01" \
     -d "username=test&password=test"
```

### 3. API Token (Bearer Auth)
Secure communication for headless clients or microservices using JWT.

- **Endpoint**: `/api/rs/**`
- **Authentication**: `Authorization: Bearer <JWT_TOKEN>`

**Example Request:**
```bash
curl -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
     "http://localhost:8080/oidc-example/api/rs/hello"
```

### 4. Development Token (Internal Tool)
For rapid testing of protected APIs without performing a full OIDC or local login flow, you can generate a development JWT.

- **Generation Endpoint**: `GET /api/dev/token`
- **Output**: A raw JWT string valid for 1 hour.

**Usage Example:**
```bash
# 1. Fetch a new token
DEV_TOKEN=$(curl -s "http://localhost:8080/oidc-example/api/dev/token")

# 2. Use it to call a protected API
curl -H "Authorization: Bearer $DEV_TOKEN" \
     "http://localhost:8080/oidc-example/api/rs/hello"
```

### 5. Refreshing Access Tokens
If your OIDC provider returned a `refresh_token`, you can exchange it for a new access token without re-authenticating the user.

- **Endpoint**: `POST /api/rs/refresh-token`
- **Payload**: `refresh_token=<TOKEN>`

**Example Request:**
```bash
curl -X POST "http://localhost:8080/oidc-example/api/rs/refresh-token" \
     -d "refresh_token=your-refresh-token"
```

---

## Developer Guide

### Adding a New Provider
1. Implement `OidcClient` (extending `AbstractOidcClient` is recommended).
2. Register your implementation in `src/main/resources/META-INF/services/org.corzia.oidc.OidcClient`.
3. Add configuration to `oidc-providers.properties`.

### Session Internals
This project uses `HybridWebSessionManager`. Session IDs are composite: `<browserId>_<tabId>`.
- `browserId`: Stored in a long-lived cookie (`BROWSER_ID`).
- `tabId`: Managed client-side in `sessionStorage` and passed via `X-Tab-Id` header or `tabId` URL parameter.

### Display Name Helper
When displaying user names in your application, use the standardized helper in `OidcUserInfo`:

```java
// Logic: Returns 'name' claim if present/non-blank, otherwise fallback to username
// Now supports both UserInfo and OidcUserInfo types.
String displayName = OidcUserInfo.getUserName(userInfo);
```

---

## 🛠 Features Refinement

### Enriched Standard Profiles
Logging in with `test/test` now provides a full profile including email, full name, and locale, demonstrating how the `UserInfo` architecture standardizes identity across different authentication sources.

---

## 🛠 Troubleshooting

### 401 Unauthorized on API calls
Ensure you are passing the `X-Tab-Id` header if you are using session-based auth, or a valid `Authorization: Bearer <JWT>` for token-based auth.

### Session Mismatches
The application relies on the `OIDC_BROWSER_ID` cookie. If cookies are disabled, the `HybridWebSessionManager` will generate a new identity on every request, breaking the flow.

### "Missing auth parameters" on Callback
This usually happens if the `tabId` was lost during the redirect chain. Ensure your login links include `&tabId=...` and that the `state` parameter is correctly propagated.

---

## Identity Providers
| Provider | Status | Config Prefix |
| :--- | :--- | :--- |
| **Microsoft Entra** | Supported | `entra.` |
| **Google** | Supported | `google.` |
| **Okta** | Supported | `okta.` |
| **Mock** | Developer Tool | `mock.` |

> [!TIP]
> Use the **Mock Provider** during development to bypass external redirects. It is enabled by setting `mock.enabled=true` in properties.
