# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/HiroGitea/logblur/compare/v0.1.0...v0.2.0) - 2026-10-23

### Other

- Translate remaining comments to English
- compress .gz and .tar.gz output on all cores
- stream every entry larger than one chunk
- skip rules by required keywords and search only matching lines

## [0.1.0](https://github.com/HiroGitea/logblur/releases/tag/v0.1.0) - 2026-10-23

### Other

- Add --line-buffered stream mode
- Add README, licenses, crates.io metadata and CI
- Fix clippy warnings; add rustfmt.toml and format
- Rename CLI package to logblur; fix FQDN TLD prefix matching
