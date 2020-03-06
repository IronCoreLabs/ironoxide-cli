# IronOxide CLI

Command-line interface for IronOxide functions to create users, devices, and groups.

## Configuration

To use the IronOxide CLI, you must first obtain an Identity Assertion Key file and a configuration file
from the [IronCore Labs Admin Console](https://admin.ironcorelabs.com).

### Identity Assertion Key File

An Identity Assertion Key file must be downloaded from the admin console interface immediately after creating
a new Identity Assertion Key. To use IronOxide CLI's defaults, it should be named `assertionKey.pem`.

### IronCore Config File

An IronCore Config file can be downloaded from the admin console on creation of the very first project. For subsequent projects, it will need to be created manually. The file is of the form:

```javascript
{
  "projectId": YOUR_PROJECT_ID,
  "segmentId": "YOUR_SEGMENT_ID",
  "identityAssertionKeyId": YOUR_IDENTITY_ASSERION_KEY_ID
}
```

Note that key names are case sensitive.

To use IronOxide CLI's defaults, it should be named `config.json`.

## Installation

IronOxide CLI requires Rust to be installed in order to compile the binary for your architecture.
For information on installing Rust, visit https://www.rust-lang.org/tools/install.

Once Rust is installed, it can be used to download, compile, and install the IronOxide CLI binary with the command

```
cargo install --git https://github.com/IronCoreLabs/ironoxide-cli
```

## Usage

IronOxide CLI must be run from the directory where your Identity Assertion Key and configuration files are.
It is used by running `ironoxide-cli`, followed by your desired subcommands and options.
You can see all the available subcommands by running `ironoxide-cli -h`.
There are currently two subcommands available: `user-create` and `group-create`.

### User and Device Creation

The `user-create` subcommand is used to create a user in the IronCore service,
generate a device for that user, and output the device context to a file.
It requires the desired user's ID and password. The user's device context will be output to a file named "\<USER-ID\>.json".

### Group Creation

The `group-create` subcommand is used to create multiple groups for the given user.
As it requires the user's device context in a file named "\<USER-ID.json\>", it is typically run
immediately after `user-create`. The group will be created with the given user as the owner and with no additional administrators or members.

## Examples

```console
$ ironoxide-cli user-create ironadmin -p foobar
Creating user "ironadmin"
Generating device for user "ironadmin"
Outputting device context to "ironadmin.json"

$ ironoxide-cli group-create customers employees others -u ironadmin
Found DeviceContext in "ironadmin.json"
Generating group "employees" for user "ironadmin"
Generating group "customers" for user "ironadmin"
Generating group "others" for user "ironadmin"
```
