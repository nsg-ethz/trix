//! Module containing some utility functions that didn't fit anywhere else.

//use std::process::Command;

use time::{format_description, OffsetDateTime};

/// Use a Slack webhook to send a message to @roschmi's private channel
pub fn send_slack_notification(message: impl AsRef<str>) {
    log::debug!(
        "Sending message to user @roschmi on slack: {}",
        message.as_ref()
    );
    log::error!("Cannot send slack message, requires updating the API endpoint");
    /*
    let _ = Command::new("curl")
        .args([
            "-X",
            "POST",
            "https://hooks.slack.com/services/ENTER/YOUR/SLACK/ENDPOINT",
            "--data",
            &format!("payload={{\"text\": \"{}\"}}", message.as_ref()),
        ])
        .output();
    */
}

/// Produces a timestamp `String` of the current time in YYYY-MM-DD_HH-mm-SS format.
pub fn get_timestamp() -> String {
    OffsetDateTime::now_local()
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
        .format(
            &format_description::parse("[year]-[month]-[day]_[hour]-[minute]-[second]").unwrap(),
        )
        .unwrap()
}
