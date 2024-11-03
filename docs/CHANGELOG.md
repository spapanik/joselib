# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to [Semantic Versioning].

## [Unreleased]

### Added

- JWK support: `OctKey`, `RSAKey`, `ECKey`, and `OKPKey` classes, with
  JWK/PEM import and export and RFC 7638 thumbprints
- JWS support: HS256/384/512, RS256/384/512, PS256/384/512,
  ES256/384/512, and EdDSA (Ed25519/Ed448) via the `JWS` class
- JWE support: dir, A128/192/256KW, RSA-OAEP, and RSA-OAEP-256 key
  management with A128/192/256GCM and A128/192/256CBC-HS256/384/512
  content encryption via the `JWE` class
- JWT support: the `JWT` class, with validation of the registered claims

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[0.1.0]: https://github.com/spapanik/joselib/releases/tag/v0.1.0
