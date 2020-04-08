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

IronOxide CLI is used by running `ironoxide-cli`, followed by your desired subcommands and options.
You can see all the available subcommands by running `ironoxide-cli -h`.
Subcommands are currently broken into three categories: user commands, group commands, and file commands.

### User Commands

#### user-create

The `user-create` subcommand is used to create a user in the IronCore service, generate a device for that user,
and output the device context to a file. It requires the desired user's ID and password. The user's device context
will be output to a file, which will be named "\<USER-ID\>.json" by default.

### Group Commands

#### group-create

The `group-create` subcommand is used to create multiple groups for the given user. As it requires the user's
device context in a file, it is typically run immediately after `user-create`. The group will be created with
the calling user as the owner and with no additional members or administrators.

#### group-add-admins

The `group-add-admins` subcommand is used to add users to a group as administrators. These users will not automatically be group members.

#### group-remove-admins

The `group-remove-admins` subcommand is used to remove administrators from a group. These users will remain group members
if they were previously. The group owner cannot be removed as an administrator.

#### group-add-members

The `group-add-members` subcommand is used to add users to a group as members.

#### group-remove-members

The `group-remove-members` subcommand is used to remove members from a group.

#### group-list

The `group-list` subcommand is used to list all groups that the user is a member or administrator of.

### File Commands

#### file-encrypt

The `file-encrypt` subcommand is used to encrypt a file to the provided users and groups. The calling user
will also be granted access to the file. By default, the encrypted file will be output with the `.iron` extension appended.

#### file-decrypt

The `file-decrypt` subcommand is used to decrypt a file that the calling user has been granted access to. By default, the
decrypted file will be output with the `.iron` extension removed.

## Examples

```console
$ ironoxide-cli user-create ironadmin --password foobar
Creating user "ironadmin"
Generating device for user "ironadmin"
Outputting device context to "ironadmin.json"

$ ironoxide-cli group-create customers employees others --device ironadmin.json
Found DeviceContext in "ironadmin.json"
Generating group "employees" for user "ironadmin"
Generating group "customers" for user "ironadmin"
Generating group "others" for user "ironadmin"

$ ironoxide-cli user-create ironemployee --password foobar
Creating user "ironemployee"
Generating device for user "ironemployee"
Outputting device context to "ironemployee.json"

$ ironoxide-cli group-add-members ironemployee --group employees --device ironadmin.json
Adding members to group "employees"
Found DeviceContext in "ironadmin.json"
Successes: ["ironemployee"]
Failures: []

$ ironoxide-cli group-list ironemployee.json
Found DeviceContext in "ironemployee.json"
Groups found: ["employees"]

$ ironoxide-cli file-encrypt keys.json --groups employees --device ironadmin.json
Read in file "keys.json"
Found DeviceContext in "ironadmin.json"
Successfully encrypted file to: [
    "User: ironadmin",
    "Group: employees",
]
Failed to encrypt file to: []
Output encrypted file to "keys.json.iron"

$ ironoxide-cli file-decrypt keys.json.iron --device ironadmin.json
Read in file "keys.json.iron"
Found DeviceContext in "ironadmin.json"
Output decrypted file to "keys.json"
```

# License

IronOxide CLI is licensed under the [GNU Affero General Public License](LICENSE).
We also offer commercial licenses - [email](mailto:info@ironcorelabs.com) for more information.

Copyright (c) 2020 IronCore Labs, Inc.
All rights reserved.
