# Contributing to OpenCCF

Contributions are welcome. The most valuable contributions are:

1. **Mapping corrections** — Wrong or missing framework mappings; please include the framework section/article reference.
2. **New framework mappings** — Add coverage for frameworks not yet in the [Commercial](commercial/README.md) or [FedRAMP](fedramp/README.md) editions.
3. **Control refinements** — Clearer or more accurate control descriptions based on real audit experience.
4. **Tooling** — Scripts to convert OpenCCF into specific GRC platform formats or to validate/generate artifacts.

## Guidelines

- **Keep control descriptions implementation-agnostic** — No vendor-specific language.
- **Cite framework references** — Use official section/article IDs (e.g., NIST 800-53 control IDs, SOC 2 criteria), not only prose.
- **One logical change per PR** — Don’t mix framework additions with control rewrites or unrelated edits.
- **Validate outputs** — After editing generator scripts, run them and ensure the produced JSON (and CSV, if applicable) is valid and consistent.

## Edition-specific notes

- **Commercial** — See [commercial/README.md](commercial/README.md) for control taxonomy, file formats, and how to add frameworks or controls.
- **FedRAMP** — See [fedramp/README.md](fedramp/README.md) for FedRAMP deltas, parameters, and generator usage.

## License

By contributing, you agree that your contributions will be licensed under the same [Apache License 2.0](LICENSE) that covers this project.
