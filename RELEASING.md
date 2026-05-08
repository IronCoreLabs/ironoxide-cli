# Release to GitHub

- Make sure all changes to be released are on `main`.
- Compare `main`'s commit history to `CHANGELOG.md` to ensure all public API changes are included as well as notable internal changes.
  - If necessary, PR and merge the changelog changes.
- Run the [Bump Version](.github/workflows/bump-version.yaml) workflow.
  - Give it a new release version. For example, if the current version is 0.3.1-pre.2, type in 0.4.0. This will tag the commit, create a Github release, and trigger the [release](.github/workflows/release.yaml) workflow that builds, PGP-signs, and uploads platform binaries (Linux, macOS, Windows) to the release.
