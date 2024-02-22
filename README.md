# Quarkus - OIDC proxy
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-3-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

[![Version](https://img.shields.io/maven-central/v/io.quarkiverse.oidc-proxy/quarkus-oidc-proxy?logo=apache-maven&style=flat-square)](https://search.maven.org/artifact/io.quarkiverse.oidc-proxy/quarkus-oidc-proxy)

_Provide OpenId Connect (OIDC) authorization code flow proxy support for Quarkus OIDC `service` applications_

This project extends Quarkus OIDC extension and adds OIDC authorization code flow support for Quarkus OIDC `service` applications by proxying OIDC authorization code flow requests and delegating them to the real OIDC provider which is configured for the current Quarkus OIDC `service` application.

It allows an integration of Quarkus OIDC `service` applications without exposing internal OIDC configuration details with external Single-page applications (SPA) or Quarkus OIDC `web-app` applications which authenticate users with the OIDC authorization code.

To get started, add the dependency:

```xml
<dependency>
    <groupId>io.quarkiverse.oidc-proxy</groupId>
    <artifactId>quarkus-oidc-proxy</artifactId>
</dependency>
```

For more details, check the complete [documentation](https://quarkiverse.github.io/quarkiverse-docs/quarkus-oidc-proxy/dev/index.html).

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://github.com/sberyozkin"><img src="https://avatars.githubusercontent.com/u/467639?v=4?s=100" width="100px;" alt=""/><br /><sub><b>sberyozkin</b></sub></a><br /><a href="https://github.com/quarkiverse/quarkus-kerberos/commits?author=sberyozkin" title="Code">💻</a> <a href="#maintenance-sberyozkin" title="Maintenance">🚧</a></td>
  </tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
