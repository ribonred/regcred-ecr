use std::collections::BTreeMap;
use aws_credential_types::Credentials;
use aws_types::region::Region;
use aws_sdk_ecr::config::Config as EcrConfig;
use aws_sdk_ecr::operation::get_authorization_token::GetAuthorizationTokenOutput;
use aws_sdk_ecr::types::AuthorizationData;
use k8s_openapi::api::core::v1::{Namespace, Secret};
use base64::engine::general_purpose::STANDARD;
use base64::{Engine};
use kube::{api::{Api, DeleteParams, PostParams}, runtime::wait::{await_condition, conditions}, Client, Error};
mod creds;
use log::{info, error, warn};
use env_logger;
use k8s_openapi::ByteString;
use serde_json::json;
use dotenv::dotenv;
use std::env;


async fn create_docker_registry_secret(namespace: &str, secret_name: &String, server: &String, username: &str, password: &str) -> Result<Secret, kube::Error> {
    let client = Client::try_default().await?;
    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    if let Ok(_) = secrets.delete(secret_name, &DeleteParams::default()).await {
        warn!("Deleted secret: {}", secret_name);
    }else {
        info!("No secret to update");
    }
    let auth = format!("{}:{}", username, password);
    let encoded_auth = STANDARD.encode(auth);
    let dockerconfigjson = json!({
        "auths": {
            server: {
                "username": username,
                "password": password,
                "email": "none",
                "auth": encoded_auth,
            }
        }
    }).to_string();
    let mut data = BTreeMap::new();
    let byte_string_data = ByteString((dockerconfigjson.as_bytes()).to_vec());
    data.insert(".dockerconfigjson".to_string(), byte_string_data);
    let secret = Secret {
        metadata: kube::api::ObjectMeta {
            name: Some(secret_name.to_string()),
            ..Default::default()
        },
        data: Some(data),
        type_: Some("kubernetes.io/dockerconfigjson".to_string()),
        ..Default::default()
    };

    let pp = PostParams::default();
    match secrets.create(&pp, &secret).await {
        Ok(created_secret) => {
            info!("secret renewed: {} at namespace {}", created_secret.metadata.name.as_deref().unwrap_or("???"), namespace);
            Ok(created_secret)
        },
        Err(e) => Err(e),
    }
}

async fn parse_auth_data(auth_data:GetAuthorizationTokenOutput) -> Option<AuthorizationData> {
    for auth in auth_data.authorization_data().iter() {
        info!("Succeeded in getting Authorization token for registry");
        return Some(auth.clone());
    }
    None
}
async fn get_token() -> Option<String> {
    let config = creds::Config::new();
    let credentials = Credentials::from_keys(config.access, config.secret, config.session);
    let region = Region::new(config.region);
    let ecr_config = EcrConfig::builder()
        .region(region)
        .credentials_provider(credentials)
        .build();
    let client = aws_sdk_ecr::Client::from_conf(ecr_config);

    let auth = client.get_authorization_token().send().await;
    match auth {
        Ok(auth_data) => {
            if let Some(auth_data) = parse_auth_data(auth_data).await {
                info!("Authorization token received");
                if let Some(token) = auth_data.authorization_token {


                    // Decode the token
                    if let Ok(decoded_token) = STANDARD.decode(&token) {
                        if let Ok(decoded_str) = String::from_utf8(decoded_token) {
                            let parts: Vec<&str> = decoded_str.split(':').collect();
                            if parts.len() == 2 {
                                let password = parts[1];
                                let censored_password = "********".to_string() + &password.chars().rev().take(10).collect::<String>().chars().rev().collect::<String>();
                                info!("Authorization token: {:?}", censored_password);
                                return Some(password.to_string());
                            } else {
                                error!("Decoded token does not contain a valid username:password format");
                            }
                        } else {
                            error!("Failed to convert decoded token to string");
                        }
                    } else {
                        error!("Failed to decode the authorization token");
                    }
                } else {
                    error!("No authorization token found");
                }
            }
        }
        Err(e) => error!("Error getting authorization token: {:?}", e),
    }
    None
}

async fn create_namespace(namespace_name: &str) -> Result<Namespace, kube::Error> {
    let client = Client::try_default().await?;
    let namespaces: Api<Namespace> = Api::all(client);
    let ns = Namespace {
        metadata: kube::api::ObjectMeta {
            name: Some(namespace_name.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let pp = PostParams::default();
    match namespaces.create(&pp, &ns).await {
        Ok(created_ns) => {
            info!("Created namespace: {}", created_ns.metadata.name.as_deref().unwrap());
            Ok(created_ns)
        },
        Err(kube::Error::Api(e)) if e.code == 409 => {
            info!("Namespace {} already exists", namespace_name);
            namespaces.get(namespace_name).await
        },
        Err(e) => Err(e),
    }
}



#[::tokio::main]
async fn main() -> Result<(), Error> {
    dotenv().ok();
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    let registry_server = env::var("REGISTRY").expect("REGISTRY must be set");
    let secret_name = env::var("SECRET_NAME").unwrap_or("docker-registry-secret".to_string());
    let namespaces = env::var("NAMESPACES").expect("NAMESPACES must be set");
    let ns_list: Vec<&str> = namespaces.split(',').collect();
   if let Some(token) = get_token().await {
       for new_ns  in ns_list {
           let _ = create_namespace(new_ns).await;
           let _ = create_docker_registry_secret(new_ns, &secret_name, &registry_server, "AWS", &token).await;

       }
    }
    Ok(())
}
