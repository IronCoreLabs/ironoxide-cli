use ironoxide::{
    config::IronOxideConfig,
    group::{GroupCreateOpts, GroupId, GroupOps},
    user::{UserCreateResult, UserId, UserOps},
    DeviceContext, IronOxide, IronOxideErr,
};
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
    /// Generates and outputs the DeviceContext for a given user to the file "<user_id>.json".
    UserCreate {
        #[structopt(
            parse(from_os_str),
            default_value = "config.json",
            short,
            long = "config"
        )]
        config_file_path: PathBuf,

        #[structopt(
            parse(from_os_str),
            default_value = "assertionKey.pem",
            short,
            long = "iak"
        )]
        iak_file_path: PathBuf,

        /// UserId to create and generate a device for
        user_id: String,

        /// Password for encrypting/decrypting the user's private key
        #[structopt(short, long)]
        password: String,
    },
    /// Creates groups for a given user. Note: requires the user's DeviceContext in the file "<user_id>.json".
    GroupCreate {
        /// UserId for the group owner
        #[structopt(short, long = "user")]
        user_id: String,

        /// Space-separated list of desired GroupIds
        #[structopt(required = true)]
        group_ids: Vec<String>,
    },
    /// Adds new members to a group. Note: requires the user's DeviceContext in the file "<user_id>.json".
    GroupAddMembers {
        /// Space-separated list of users to add to the group
        #[structopt(required = true)]
        new_members: Vec<String>,

        /// GroupId to add members to
        #[structopt(short, long = "group")]
        group_id: String,

        /// UserId to use for adding members
        #[structopt(short, long = "user")]
        user_id: String,
    },
    /// Lists the groups the user is a member/admin of. Note: requires the user's DeviceContext in the file "<user_id>.json".
    GroupList {
        /// UserId to list groups for
        #[structopt(required = true)]
        user_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = CommandLineArgs::from_args();
    match args {
        CommandLineArgs::UserCreate {
            iak_file_path,
            config_file_path,
            user_id: user_id_string,
            password,
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
            // this check is because the output filename can't have a '/' in it, not an actual restriction on UserIds
            if user_id_string.contains('/') {
                Err(InitAppErr(
                    "UserId cannot contain any of the following characters: /".to_string(),
                ))?
            }
            let user_id = UserId::try_from(user_id_string)?;

            let config_file = File::open(config_file_path)?;
            let config: InputConfig = serde_json::from_reader(config_file)?;

            let output_filename = format!("{}.json", user_id.id());
            let user_id_path = PathBuf::from(&output_filename);
            if user_id_path.is_file() {
                Err(InitAppErr(format!(
                    "\"{}\" already exists",
                    &output_filename
                )))?
            }

            let device_context =
                create_user_and_device(&config, &iak_file_path, &user_id, &Password(password))
                    .await?;
            serde_json::to_writer_pretty(File::create(&output_filename)?, &device_context)?;
            println!(
                "{}",
                format!("Outputting device context to \"{}.json\"", user_id.id())
            );
        }

        CommandLineArgs::GroupCreate {
            user_id,
            group_ids: group_id_strings,
        } => {
            let sdk = initialize_sdk_from_file(&user_id).await?;
            let group_ids = group_id_strings
                .iter()
                .map(|group_id| GroupId::try_from(group_id.as_str()))
                .collect::<std::result::Result<Vec<_>, _>>()?;

            let group_futures = group_ids
                .iter()
                .map(|group_id| create_group(&sdk, group_id));

            futures::future::try_join_all(group_futures).await?;
        }

        CommandLineArgs::GroupList { user_id } => {
            let sdk = initialize_sdk_from_file(&user_id).await?;
            let groups = sdk.group_list().await?;
            let group_ids = groups
                .result()
                .iter()
                .map(|meta_result| meta_result.id().id())
                .collect::<Vec<_>>();
            println!("Groups found: {:?}", group_ids)
        }

        CommandLineArgs::GroupAddMembers {
            user_id,
            group_id: group_id_string,
            new_members: member_id_strings,
        } => {
            let sdk = initialize_sdk_from_file(&user_id).await?;
            let group_id = GroupId::try_from(group_id_string)?;
            let members_ids = member_id_strings
                .iter()
                .map(|u| UserId::try_from(u.as_str()))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let add_result = sdk.group_add_members(&group_id, &members_ids).await?;
            let successes = add_result
                .succeeded()
                .iter()
                .map(|user| user.id())
                .collect::<Vec<_>>();
            let failures = add_result
                .failed()
                .iter()
                .map(|err| format!("User: {}, Error: {}", err.user().id(), err.error()))
                .collect::<Vec<_>>();
            println!("Successful adds: {:?}", successes);
            println!("Failed adds: {:?}", failures);
        }
    }

    Ok(())
}

async fn initialize_sdk_from_file(user_id: &str) -> Result<IronOxide> {
    let device_context_filename = format!("{}.json", user_id);
    let device_context_path = PathBuf::from(&device_context_filename);
    if device_context_path.is_file() {
        let device_context_file = File::open(device_context_path)?;
        let device_context: DeviceContext = serde_json::from_reader(device_context_file)?;
        println!("Found DeviceContext in \"{}\"", device_context_filename);
        Ok(ironoxide::initialize(&device_context, &Default::default()).await?)
    } else {
        Err(InitAppErr(format!(
            "No DeviceContext found in \"{}\"",
            device_context_filename
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
