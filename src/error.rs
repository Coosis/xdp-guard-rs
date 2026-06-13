// SPDX-License-Identifier: MIT

use axum::{http::StatusCode, response::IntoResponse};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid toml body {0}")]
    InvalidToml(#[from] toml::de::Error),
    #[error("empty rule is forbidden: {r:?}")]
    EmptyRule{ r: crate::ruleset::FirewallRule },
    #[error("map update error")]
    MapUpdateErr,
    #[error("metrics error")]
    MetricsErr,
    #[error("invalid rule: {r:?}")]
    InvalidRule{ r: crate::ruleset::FirewallRule }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}
