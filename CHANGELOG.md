# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/HiroGitea/logblur/compare/v0.2.1...v0.2.2) - 2026-10-30

### Added

- build only the scanner without the archive feature ([#9](https://github.com/HiroGitea/logblur/pull/9))

### Fixed

- catch short-option passwords, webhook secrets and session cookies ([#8](https://github.com/HiroGitea/logblur/pull/8))
- catch --machine-id options and UUIDs after a hyphenated word ([#11](https://github.com/HiroGitea/logblur/pull/11))

## [0.2.1](https://github.com/HiroGitea/logblur/compare/v0.2.0...v0.2.1) - 2026-10-23

### Fixed

- keep archive sinks RefUnwindSafe ([#7](https://github.com/HiroGitea/logblur/pull/7))

### Other

- mention the performance work in the README ([#4](https://github.com/HiroGitea/logblur/pull/4))
- compress large zip entries on all cores ([#6](https://github.com/HiroGitea/logblur/pull/6))

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
