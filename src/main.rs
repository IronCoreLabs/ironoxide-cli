use ironoxide::document::DocumentOps;
use ironoxide::{
    config::IronOxideConfig,
    document::{DocumentEncryptOpts, ExplicitGrant, UserOrGroup},
    group::{GroupCreateOpts, GroupId, GroupOps},
    user::{UserCreateResult, UserId, UserOps},
    DeviceContext, IronOxide, IronOxideErr,
};
use itertools::EitherOrBoth;
use serde::Deserialize;
use std::{
    convert::TryFrom,
    fmt,
    fs::File,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use structopt::StructOpt;

type Result<T> = std::result::Result<T, InitAppErr>;

#[derive(StructOpt)]
enum CommandLineArgs {
    /// Generate the device context for a given user and output it to a file
    UserCreate {
        /// User to create and generate a device for
        #[structopt(parse(try_from_str = parse_user_id))]
        user_id: UserId,
        /// Password for encrypting/decrypting the user's private key
        #[structopt(short, long, parse(from_str = parse_password))]
        password: Password,
        /// Path to IronCore Config file
        #[structopt(default_value = "config.json", short, long = "config")]
        config_file_path: PathBuf,
        /// Path to Identity Assertion Key
        #[structopt(default_value = "assertionKey.pem", short, long = "iak")]
        iak_file_path: PathBuf,
        /// Where to output the device context [default: <user_id>.json]
        #[structopt(short, long = "out")]
        output_file_path: Option<PathBuf>,
    },
    /// Create groups with the calling user as owner
    GroupCreate {
        /// Space-separated list of desired groups
        #[structopt(required = true, parse(try_from_str = parse_group_id))]
        group_ids: Vec<GroupId>,
        /// Path to the calling user's device context
        #[structopt(short, long = "device")]
        device_path: PathBuf,
    },
    /// Add new admins to a group
    GroupAddAdmins {
        /// Space-separated list of users to add as group admins
        #[structopt(required = true, parse(try_from_str = parse_user_id))]
        new_admins: Vec<UserId>,
        /// Group to add admins to
        #[structopt(short, long = "group", parse(try_from_str = parse_group_id))]
        group_id: GroupId,
        /// Path to the calling user's device context
        #[structopt(short, long = "device")]
        device_path: PathBuf,
    },
    /// Remove admins from a group
    GroupRemoveAdmins {
        /// Space-separated list of users to remove as group admins
        #[structopt(required = true, parse(try_from_str = parse_user_id))]
        admins_to_remove: Vec<UserId>,
        /// Group to remove admins from
        #[structopt(short, long = "group", parse(try_from_str = parse_group_id))]
        group_id: GroupId,
        /// Path to the calling user's device context
        #[structopt(short, long = "device")]
        device_path: PathBuf,
    },
    /// Add new members to a group
    GroupAddMembers {
        /// Space-separated list of users to add as group members
        #[structopt(required = true, parse(try_from_str = parse_user_id))]
        new_members: Vec<UserId>,
        /// Group to add members to
        #[structopt(short, long = "group", parse(try_from_str = parse_group_id))]
        group_id: GroupId,
        /// Path to the calling user's device context
        #[structopt(short, long = "device")]
        device_path: PathBuf,
    },
    /// Remove members from a group
    GroupRemoveMembers {
        /// Space-separated list of users to remove as group members
        #[structopt(required = true, parse(try_from_str = parse_user_id))]
        members_to_remove: Vec<UserId>,
        /// Group to remove members from
        #[structopt(short, long = "group", parse(try_from_str = parse_group_id))]
        group_id: GroupId,
        /// Path to the calling user's device context
        #[structopt(short, long = "device")]
        device_path: PathBuf,
    },
    /// List the groups the user is a member/admin of
    GroupList {
        /// Path to the calling user's device context
        device_path: PathBuf,
    },
    /// Encrypt a file
    FileEncrypt {
        /// Path to the file being encrypted
        filename: PathBuf,
        /// Path to the calling user's device context
        #[structopt(short, long = "device")]
        device_path: PathBuf,
        /// Users who will have access to the document
        #[structopt(short, long, parse(try_from_str = parse_user_id))]
        users: Vec<UserId>,
        /// Groups who will have access to the document
        #[structopt(short, long, parse(try_from_str = parse_group_id))]
        groups: Vec<GroupId>,
        /// Encrypted output file to write [default: <filename>.iron]
        #[structopt(short, long)]
        output: Option<PathBuf>,
    },
    /// Decrypt a file
    FileDecrypt {
        /// Path to the file being decrypted
        filename: PathBuf,
        /// Path to the calling user's device context
        #[structopt(short, long = "device")]
        device_path: PathBuf,
        /// Decrypted output file to write [default: <filename> - .iron]
        #[structopt(short, long)]
        output: Option<PathBuf>,
    },
}

fn parse_user_id(user_id_string: &str) -> Result<UserId> {
    Ok(UserId::try_from(user_id_string)?)
}
fn parse_group_id(group_id_string: &str) -> Result<GroupId> {
    Ok(GroupId::try_from(group_id_string)?)
}
fn parse_password(password_string: &str) -> Password {
    Password(password_string.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = CommandLineArgs::from_args();
    match args {
        CommandLineArgs::UserCreate {
            iak_file_path,
            config_file_path,
            user_id,
            password,
            output_file_path: maybe_output_file_path,
        } => {
            if !iak_file_path.is_file() {
                Err(InitAppErr(format!(
                    "PEM file \"{}\" does not exist",
                    iak_file_path.display()
                )))?;
            }
            if !config_file_path.is_file() {
                Err(InitAppErr(format!(
                    "Config file \"{}\" does not exist",
                    config_file_path.display()
                )))?;
            }

            let config_file = File::open(config_file_path)?;
            let config: InputConfig = serde_json::from_reader(config_file)?;

            let output_file_path =
                maybe_output_file_path.unwrap_or(PathBuf::from(format!("{}.json", user_id.id())));
            if output_file_path.display().to_string().contains('/') {
                Err(InitAppErr(
                    "Output file path cannot contain any of the following characters: /"
                        .to_string(),
                ))?
            }
            if output_file_path.is_file() {
                Err(InitAppErr(format!(
                    "\"{}\" already exists",
                    &output_file_path.display()
                )))?
            }

            let device_context =
                create_user_and_device(&config, &iak_file_path, &user_id, &password).await?;
            serde_json::to_writer_pretty(File::create(&output_file_path)?, &device_context)?;
            println!(
                "{}",
                format!(
                    "Outputting device context to \"{}\"",
                    output_file_path.display()
                )
            );
        }
        CommandLineArgs::GroupCreate {
            group_ids,
            device_path,
        } => {
            let sdk = initialize_sdk_from_file(&device_path).await?;
            let group_futures = group_ids
                .iter()
                .map(|group_id| create_group(&sdk, group_id));

            futures::future::try_join_all(group_futures).await?;
        }
        CommandLineArgs::GroupAddAdmins {
            group_id,
            new_admins,
            device_path,
        } => {
            println!("Adding admins to group \"{}\"", group_id.id());
            modify_group(
                &group_id,
                &new_admins,
                &device_path,
                GroupModificationFunction::AddAdmins,
            )
            .await?;
        }
        CommandLineArgs::GroupRemoveAdmins {
            group_id,
            admins_to_remove,
            device_path,
        } => {
            println!("Removing admins from group \"{}\"", group_id.id());
            modify_group(
                &group_id,
                &admins_to_remove,
                &device_path,
                GroupModificationFunction::RemoveAdmins,
            )
            .await?;
        }
        CommandLineArgs::GroupAddMembers {
            group_id,
            new_members,
            device_path,
        } => {
            println!("Adding members to group \"{}\"", group_id.id());
            modify_group(
                &group_id,
                &new_members,
                &device_path,
                GroupModificationFunction::AddMembers,
            )
            .await?;
        }
        CommandLineArgs::GroupRemoveMembers {
            group_id,
            members_to_remove,
            device_path,
        } => {
            println!("Removing members from group \"{}\"", group_id.id());
            modify_group(
                &group_id,
                &members_to_remove,
                &device_path,
                GroupModificationFunction::RemoveMembers,
            )
            .await?;
        }
        CommandLineArgs::GroupList { device_path } => {
            let sdk = initialize_sdk_from_file(&device_path).await?;
            let groups = sdk.group_list().await?;
            let group_ids = groups
                .result()
                .iter()
                .map(|meta_result| meta_result.id().id())
                .collect::<Vec<_>>();
            println!("Groups found: {:?}", group_ids)
        }
        CommandLineArgs::FileEncrypt {
            filename: infile,
            device_path,
            users: user_ids,
            groups: group_ids,
            output: maybe_output,
        } => {
            let file = std::fs::read(infile.clone())?;
            let sdk = initialize_sdk_from_file(&device_path).await?;
            let output = match maybe_output {
                // User specified an output path.
                Some(desired) => {
                    if desired.is_dir() {
                        // This is the file component of infile.
                        let mut filename = match infile.file_name() {
                            Some(name) => std::result::Result::Ok(name),
                            None => std::result::Result::Err(InitAppErr(
                                "Trying to write output to directory, unable to infer file name"
                                    .to_string(),
                            )),
                        }?
                        .to_os_string();
                        filename.push(".iron");
                        let mut desired = desired.clone();
                        desired.push(filename);
                        desired
                    } else {
                        desired
                    }
                }
                // User didn't specify an output path. Add ".iron" to the input path.
                None => {
                    let mut output_path = infile.clone();
                    let new_extension = match output_path.extension() {
                        Some(extension) => {
                            let mut ext_os = extension.to_os_string();
                            ext_os.push(".iron");
                            ext_os
                        }
                        None => std::ffi::OsString::from(".iron"),
                    };
                    output_path.set_extension(new_extension);
                    output_path
                }
            };
            let mut users_or_groups = group_ids
                .iter()
                .map(|group| group.into())
                .collect::<Vec<UserOrGroup>>();
            let mut users = user_ids
                .iter()
                .map(|user| user.into())
                .collect::<Vec<UserOrGroup>>();
            users_or_groups.append(&mut users);
            let grants = ExplicitGrant::new(true, &users_or_groups);
            let opts = DocumentEncryptOpts::new(None, None, EitherOrBoth::Left(grants));
            let encrypt_result = sdk.document_encrypt(&file, &opts).await?;
            std::fs::write(output, encrypt_result.encrypted_data())?;
        }
        CommandLineArgs::FileDecrypt {
            filename,
            device_path,
            output: maybe_output,
        } => {
            let output = match maybe_output {
                // they told us what the output should be. use it
                Some(desired) => desired,
                // they haven't given us an output. let's guess
                None => {
                    match filename.extension() {
                        // the filename has an extension. check if it's .iron and remove it
                        Some(extension) => {
                            // the extension is ".iron". remove it
                            if extension.to_os_string() == std::ffi::OsString::from("iron") {
                                let mut output_path = filename.clone();
                                output_path.set_extension("");
                                std::result::Result::Ok(output_path)
                            // the extension isn't ".iron". Can't safely choose an output file, so bail out.
                            } else {
                                std::result::Result::Err(InitAppErr(
                                    "No output file given, and unable to infer.".to_string(),
                                ))
                            }
                        }
                        // the filename has no extension. Can't safely choose an output file, so bail out.
                        None => std::result::Result::Err(InitAppErr(
                            "No output file given, and unable to infer.".to_string(),
                        )),
                    }?
                }
            };
            let file = std::fs::read(filename.clone())?;
            let sdk = initialize_sdk_from_file(&device_path).await?;
            let decrypt_result = sdk.document_decrypt(&file).await?;
            std::fs::write(output, decrypt_result.decrypted_data())?;
        }
    }
    Ok(())
}

enum GroupModificationFunction {
    AddMembers,
    AddAdmins,
    RemoveMembers,
    RemoveAdmins,
}

async fn modify_group(
    group_id: &GroupId,
    user_ids: &Vec<UserId>,
    device_path: &PathBuf,
    modification_function: GroupModificationFunction,
) -> Result<()> {
    let sdk = initialize_sdk_from_file(device_path).await?;
    let modify_result = match modification_function {
        GroupModificationFunction::AddAdmins => sdk.group_add_admins(&group_id, &user_ids),
        GroupModificationFunction::RemoveAdmins => sdk.group_remove_admins(&group_id, &user_ids),
        GroupModificationFunction::AddMembers => sdk.group_add_members(&group_id, &user_ids),
        GroupModificationFunction::RemoveMembers => sdk.group_remove_members(&group_id, &user_ids),
    }
    .await?;
    let successes = modify_result
        .succeeded()
        .iter()
        .map(|user| user.id())
        .collect::<Vec<_>>();
    let failures = modify_result
        .failed()
        .iter()
        .map(|err| format!("User: {}, Error: {}", err.user().id(), err.error()))
        .collect::<Vec<_>>();
    println!("Successes: {:?}", successes);
    println!("Failures: {:?}", failures);
    Ok(())
}

async fn initialize_sdk_from_file(device_path: &PathBuf) -> Result<IronOxide> {
    if device_path.is_file() {
        let device_context_file = File::open(&device_path)?;
        let device_context: DeviceContext = serde_json::from_reader(device_context_file)?;
        println!("Found DeviceContext in \"{}\"", device_path.display());
        Ok(ironoxide::initialize(&device_context, &Default::default()).await?)
    } else {
        Err(InitAppErr(format!(
            "No DeviceContext found in \"{}\"",
            device_path.display()
        )))
    }
}

struct Jwt(String);
struct Password(String);
#[derive(Deserialize)]
struct SegmentId(String);
#[derive(Deserialize)]
struct ProjectId(usize);
#[derive(Deserialize)]
struct IdentityAssertionKeyId(usize);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InputConfig {
    project_id: ProjectId,
    segment_id: SegmentId,
    identity_assertion_key_id: IdentityAssertionKeyId,
}

struct InitAppErr(String);

impl fmt::Display for InitAppErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<IronOxideErr> for InitAppErr {
    fn from(e: IronOxideErr) -> Self {
        match e {
            IronOxideErr::AesError(_) => {
                Self("There was an error with the provided password.".to_string())
            }
            _ => Self(e.to_string()),
        }
    }
}
impl From<serde_json::Error> for InitAppErr {
    fn from(e: serde_json::Error) -> Self {
        Self(e.to_string())
    }
}
impl From<std::io::Error> for InitAppErr {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

// Whenever an InitAppError happens, the default derived debug output is ugly and convoluted,
// so using the Display for the internal String is cleaner and easier to understand
impl fmt::Debug for InitAppErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

async fn create_user_and_device(
    cfg: &InputConfig,
    path_to_pem: &PathBuf,
    user_id: &UserId,
    password: &Password,
) -> Result<DeviceContext> {
    let user_create = UserCreate {
        project_id: &cfg.project_id,
        seg_id: &cfg.segment_id,
        iak: &cfg.identity_assertion_key_id,
        pem_file: path_to_pem,
        user_id,
    };
    let jwt = gen_jwt(&user_create);
    let user_verify =
        IronOxide::user_verify(&jwt.0, IronOxideConfig::default().sdk_operation_timeout).await?;
    if user_verify.is_some() {
        println!("Found user \"{}\"", &user_id.id());
    } else {
        println!("Creating user \"{}\"", &user_id.id());
        gen_user(&jwt, password).await?;
    }
    println!("Generating device for user \"{}\"", &user_id.id());
    gen_device(&jwt, password).await
}

async fn create_group(sdk: &IronOxide, group_id: &GroupId) -> Result<()> {
    let opts = GroupCreateOpts::new(
        Some(group_id.to_owned()),
        None,
        true,
        true,
        None,
        vec![],
        vec![],
        false,
    );
    sdk.group_create(&opts).await?;
    println!(
        "Generating group \"{}\" for user \"{}\"",
        group_id.id(),
        sdk.device().account_id().id()
    );
    Ok(())
}

struct UserCreate<'a> {
    project_id: &'a ProjectId,
    seg_id: &'a SegmentId,
    iak: &'a IdentityAssertionKeyId,
    pem_file: &'a PathBuf,
    user_id: &'a UserId,
}

async fn gen_device(jwt: &Jwt, password: &Password) -> Result<DeviceContext> {
    Ok(IronOxide::generate_new_device(
        &jwt.0,
        &password.0,
        &ironoxide::user::DeviceCreateOpts::default(),
        IronOxideConfig::default().sdk_operation_timeout,
    )
    .await?
    .into())
}

async fn gen_user(jwt: &Jwt, password: &Password) -> Result<UserCreateResult> {
    Ok(IronOxide::user_create(
        &jwt.0,
        &password.0,
        &ironoxide::user::UserCreateOpts::default(),
        IronOxideConfig::default().sdk_operation_timeout,
    )
    .await?)
}

fn gen_jwt(user: &UserCreate) -> Jwt {
    let start = SystemTime::now();
    let iat_seconds = start
        .duration_since(UNIX_EPOCH)
        .expect("Time before epoch? Something's wrong.")
        .as_secs();

    let jwt_header = serde_json::json!({});
    let jwt_payload = serde_json::json!({
        "pid" : user.project_id.0,
        "sid" : user.seg_id.0,
        "kid" : user.iak.0,
        "iat" : iat_seconds,
        "exp" : iat_seconds + 120,
        "sub" : user.user_id
    });
    let jwt = frank_jwt::encode(
        jwt_header,
        user.pem_file,
        &jwt_payload,
        frank_jwt::Algorithm::ES256,
    )
    .expect("You don't appear to have the proper identity assertion key to sign the JWT.");

    Jwt(jwt)
}
