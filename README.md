# cyphera-nifi

[![CI](https://github.com/cyphera-labs/cyphera-nifi/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-nifi/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/cyphera-nifi/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-nifi/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Format-preserving encryption for [Apache NiFi](https://apache-nifi.org/) — NiFi Processor powered by Cyphera.

Built on [`io.cyphera:cyphera`](https://central.sonatype.com/artifact/io.cyphera/cyphera) from Maven Central.

## Build

```bash
mvn package -DskipTests
```

## Install / Deploy

Copy the fat JAR to your NiFi processor plugin directory. See the platform documentation for details.

## Usage

Protect sensitive fields in gov/finance data flows using Cyphera format-preserving encryption. Tag-based access means no policy name is needed to decrypt — the tag embedded in the protected value identifies the policy.

## Policy File

```json
{
  "policies": {
    "ssn": { "engine": "ff1", "key_ref": "demo-key", "tag": "T01" },
    "credit_card": { "engine": "ff1", "key_ref": "demo-key", "tag": "T02" }
  },
  "keys": {
    "demo-key": { "material": "2B7E151628AED2A6ABF7158809CF4F3C" }
  }
}
```

## Future

- Demo environment with Docker
- Platform-specific documentation and examples
- Integration testing

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
