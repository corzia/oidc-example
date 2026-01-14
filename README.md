[![Java](https://img.shields.io/badge/Java-17%2B-blue.svg)](https://www.oracle.com/java/)
[![Security](https://img.shields.io/badge/Security-OpenID%20Connect-orange.svg)](https://openid.net/connect/)
[![Framework](https://img.shields.io/badge/Framework-Apache%20Shiro-green.svg)](https://shiro.apache.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)

A reference implementation showcasing a secure, multi-tenant capable OpenID Connect (OIDC) integration within a Java Web environment using **Apache Shiro**. This project addresses complex real-world requirements such as multi-tab session consistency and modern dark-themed UX.

## 🚀 Overview

This repository provides a modular blueprint for integrating external Identity Providers (IdPs) into legacy or modern Java applications. It bridges the gap between OIDC's stateless identity tokens and Apache Shiro's stateful session/permission model.

### Key Technical Pillars
- **Identity Orchestration**: Pluggable `OidcClient` architecture supporting Entra ID, Google, and Okta via Java SPI.
- **Hybrid Session Strategy**: A custom `HybridWebSessionManager` that ensures atomic session state across multiple browser tabs without cross-pollination.
- **RS-API Security**: Protects RESTful resources using Bearer-token authentication and JWT validation.
- **Mock Provider**: Built-in developer mock identity provider for rapid local testing without external dependencies.

## 📚 Standards & Specifications

This project strictly adheres to and demonstrates the following industry standards:

- **[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)**: Master specification for identity over OAuth 2.0.
- **[JSON Web Token (JWT) - RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)**: The standard for compact, URL-safe identity assertions.
- **[JSON Web Signature (JWS) - RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)**: Ensures token integrity via JWKS and RSA/ECDSA signatures.
- **[Apache Shiro](https://shiro.apache.org/architecture.html)**: Robust and flexible Java security framework.

## 🛠 Tech Stack

- **Runtime**: Java 17+, Jakarta Servlet 6.0, Apache Tomcat 10.1+.
- **Security**: Apache Shiro, Nimbus JOSE+JWT.
- **Frontend**: Vanilla HTML5/CSS3 (Modern Dark Theme, "Outfit" Typography).
- **Build**: Maven.

## 📖 Documentation

For detailed setup instructions, API references, and configuration guides, please refer to:

👉 **[USAGE.md](./USAGE.md)** - *Step-by-step guide to running and configuring the app.*

👉 **[ARCHITECTURE.md](./ARCHITECTURE.md)** - *Deep dive into the system design and OIDC flow.*

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## ⚖️ License
This project is licensed under the Apache License 2.0. See the [LICENSE](./LICENSE) file for details.
