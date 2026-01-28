use crate::error::{ApiError, ApiResult};
use crate::load::load_config;
use reqwest::{ClientBuilder, Url};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Clone)]
pub(crate) struct UserManager {
    client: reqwest::Client,
    base: Url,
}

#[derive(Deserialize, Debug)]
pub struct UserResp {
    pub(crate) id: uuid::Uuid,
    pub(crate) username: String,
    pub(crate) email: Option<String>,
}

#[derive(Deserialize)]
struct JsonResp {
    result: serde_json::Value,
    success: bool,
}

impl UserManager {
    pub fn load_from_config() -> ApiResult<Option<Self>> {
        let config = load_config();
        let user_config = config.api.predefine.as_ref();
        if let Some(user_config) = user_config {
            let user_url = user_config.user_url.as_ref();
            let user_auth = user_config.user_auth.as_ref();

            if let (Some(user_url), Some(user_auth)) = (user_url, user_auth) {
                let url = Url::parse(user_url.as_str()).map_err(|e| ApiError::Server {
                    case: "user_url",
                    msg: e.to_string().into(),
                })?;
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    user_auth.parse().map_err(|e| ApiError::Server {
                        case: "user_auth",
                        msg: format!("{}", e).into(),
                    })?,
                );
                let client = ClientBuilder::new().default_headers(headers).build()?;
                return Ok(Some(UserManager { client, base: url }));
            }
        }
        Ok(None)
    }
}

impl UserManager {
    fn check_state<T: serde::de::DeserializeOwned>(rep: JsonResp) -> ApiResult<T> {
        if rep.success {
            Ok(serde_json::from_value(rep.result)?)
        } else {
            Err(ApiError::User("password not match".into()))
        }
    }
    pub(crate) async fn password_login(
        &self,
        username: &str,
        password: &str,
    ) -> ApiResult<UserResp> {
        let url = self.base.join("/api/v1/login/username").unwrap();
        let mut body = HashMap::new();
        body.insert("username", username);
        body.insert("password", password);
        let res = self.client.post(url).json(&body).send().await?;
        let s = res.json::<JsonResp>().await?;
        Self::check_state(s)
    }

    pub(crate) async fn password_signup(
        &self,
        username: &str,
        password: &str,
        email: &str,
    ) -> ApiResult<UserResp> {
        let url = self.base.join("/api/v1/signup/username").unwrap();
        let mut body = HashMap::new();
        body.insert("email", email);
        body.insert("username", username);
        body.insert("password", password);
        let res = self.client.post(url).json(&body).send().await?;
        let s = res.json::<JsonResp>().await?;
        Self::check_state(s)
    }

    pub(crate) async fn active_email(&self, id: uuid::Uuid, email: &str) -> ApiResult<UserResp> {
        let url = self.base.join("/api/v1/active/email").unwrap();
        let mut body = HashMap::new();
        let id = id.to_string();
        body.insert("email", email);
        body.insert("id", id.as_str());
        let res = self.client.post(url).json(&body).send().await?;
        let s = res.json::<JsonResp>().await?;
        Self::check_state(s)
    }

    pub(crate) async fn change_password(
        &self,
        id: uuid::Uuid,
        password: &str,
        old_password: &str,
    ) -> ApiResult<UserResp> {
        let url = self.base.join("/api/v1/change/password").unwrap();
        let mut body = HashMap::new();
        let id = id.to_string();
        body.insert("old_password", old_password);
        body.insert("password", password);
        body.insert("id", id.as_str());
        let res = self.client.post(url).json(&body).send().await?;
        let s = res.json::<JsonResp>().await?;
        Self::check_state(s)
    }

    pub(crate) async fn check_email(&self, email: &str) -> ApiResult<Option<UserResp>> {
        let url = self.base.join("/api/v1/check/email").unwrap();
        let mut body = HashMap::new();
        body.insert("email", email);
        let res = self.client.post(url).json(&body).send().await?;
        let s = res.json::<JsonResp>().await?;
        if s.success {
            Ok(serde_json::from_value(s.result)?)
        } else {
            Err(ApiError::User("email is exist".into()))
        }
    }

    pub(crate) async fn reset_password(
        &self,
        id: uuid::Uuid,
        password: &str,
    ) -> ApiResult<UserResp> {
        let url = self.base.join("/api/v1/reset/password").unwrap();
        let mut body = HashMap::new();
        let id = id.to_string();
        body.insert("password", password);
        body.insert("id", id.as_str());
        let res = self.client.post(url).json(&body).send().await?;
        let s = res.json::<JsonResp>().await?;
        Self::check_state(s)
    }

    pub(crate) async fn delete_user(&self, id: uuid::Uuid) -> ApiResult<()> {
        let url = self
            .base
            .join(&format!("/api/v1/user/{}", id))
            .map_err(|_| ApiError::User("invalid url".into()))?;
        let res = self.client.delete(url).send().await?;
        let s = res.json::<JsonResp>().await?;
        Self::check_state(s)
    }
}
