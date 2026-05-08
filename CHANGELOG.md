# Changelog

## [0.4.0] - 2026-05-08

### Added

- `user-disable-self` subcommand to deactivate the calling user via their device context.
- `user-update-status` subcommand to enable or disable a user administratively via a JWT generated from the IronCore Config and Identity Assertion Key.
- `group-delete` subcommand to permanently delete one or more groups the calling user administers.

### Changed

- `user-create`: the long form of the device-output flag was renamed from `--out` to `--output`. Scripts that passed `--out <path>` must switch to `--output <path>`. The short form `-o` is unchanged.
- `group-list`: the device context path is now passed via the `-d`/`--device` flag instead of as a positional argument, matching every other subcommand. Scripts that ran `ironoxide-cli group-list path/to/device.json` must switch to `ironoxide-cli group-list --device path/to/device.json`.
- Status arguments now use clap's built-in possible values for validation and help output.
- Internal cleanup of the config-loading path so user-creation and status-update share a single `load_config` helper.
- Dependency updates.

See git history for changes prior to 0.4.0.
