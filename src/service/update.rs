// SPDX-License-Identifier: MIT

use std::sync::{Arc, Mutex};
use std::result::Result;
use axum::extract::State;

use crate::ctypes::{fw_rule, fw_ruleset};
use crate::{AppState, error::Error, ruleset::{FirewallRule, Ruleset}};

pub async fn handle_toml_ruleset(
    State(state): State<Arc<Mutex<AppState>>>,
    str: String,
) -> Result<String, Error> {
    let rs: Ruleset = toml::from_str(&str)
        .map_err(|e| Error::InvalidToml(e))?;

    if let Some(r) = rs.rules.iter().find(|r| r.empty_rule()) {
        return Err(Error::EmptyRule { r: r.clone() });
    }

    if let Some(r) = rs.rules.iter().find(|r| r.invalid_rule()) {
        return Err(Error::InvalidRule { r: r.clone() });
    }

    let mut rules: Vec<(u64, fw_rule)> = rs.rules.clone().into_iter()
        .map(|f| match FirewallRule::to_ctype(&f) {
            Ok(fwr) => Ok((
                    f.priority.unwrap_or(0),
                    fwr
            )),
            Err(_) => Err(f)}
        )
        .collect::<Result<Vec<(u64, fw_rule)>, _>>()
        .map_err(|e| Error::InvalidRule { r: e })?;

    rules.sort_by(|a, b| b.0.cmp(&a.0));
    let sorted: Vec<fw_rule> = rules.into_iter()
        .map(|(_, r)| r)
        .collect();
    let ruleset: fw_ruleset = fw_ruleset::from_rules(sorted, match rs.default {
        crate::ruleset::DefaultAction::Block => { true },
        _ => { false }
    });

    {
        let mut state = state.lock().unwrap();
        state.update_ruleset(&ruleset)
            .map_err(|_| Error::MapUpdateErr)?;
    }

    Ok(format!("done! decoded:\n{:?}", rs))
}
