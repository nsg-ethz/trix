// TRIX: Inference of Transient Violation Times from Logged Routing Events or Collected BGP Messages
// Copyright (C) 2024-2025 Roland Schmid <roschmi@ethz.ch> and Tibor Schneider <sctibor@ethz.ch>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
use crate::{records::Router, Prefix};
use std::{
    collections::HashMap,
    error::Error,
    fs::OpenOptions,
    io::{BufWriter, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr,
};

use bgpsim::{ospf::OspfImpl, prelude::NetworkFormatter, types::RouterId};
use router_lab::{
    router::CiscoSession,
    ssh::{SshError, SshSession},
    Active, RouterLab, RouterLabError,
};
use ipnet::Ipv4Net;
use itertools::Itertools;
use regex::Regex;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Debug, thiserror::Error)]
pub enum LogParserError {
    #[error("Cisco Lab Error: {0}")]
    RouterLab(#[from] RouterLabError),
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Join Error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("SSH Error: {0}")]
    Ssh(#[from] SshError),
    #[error("Called parse_new on an offline parser")]
    OfflineParser,
    #[error("Lost some log messages, as old ones were overwritten.")]
    TooManyLogMessages,
}

#[async_trait::async_trait]
pub trait LogParser<R, T>: Sized {
    /// Create a new Log Parser.
    ///
    /// The parser must be created *before* the experiment. Once you call `parse_new`, it will fetch
    /// all current IPFIB log messages that are added since the thing was created (or since the last
    /// call to `parse_new`).
    async fn new(
        rid: RouterId,
        router_name: Option<Router>,
        session: CiscoSession,
    ) -> Result<Self, LogParserError>;

    /// Fetch all current log messages that are added since the `LogParser` was created (or since
    /// the last call to `parse_new`).
    async fn parse_new(&mut self, raw_log_root: Option<PathBuf>) -> Result<Vec<R>, LogParserError>;

    /// Return the list of all regexes.
    fn re() -> Vec<(T, Regex)>;

    /// Return a description of the logger
    fn description() -> &'static str;
}

pub trait LogRecord {
    fn time(&self) -> f64;
}

/// Setup all log parsers and return them.
pub async fn setup_parsers<'a, P, R, T, Q, Ospf: OspfImpl>(
    lab: &'a RouterLab<'a, Prefix, Q, Ospf, Active>,
) -> Result<HashMap<RouterId, P>, LogParserError>
where
    P: LogParser<R, T> + Send + Sync + 'static,
    T: Send + Sync + 'static,
{
    log::debug!("Create loggers for {}", P::description());
    let jobs = lab
        .routers()
        .keys()
        .copied()
        .filter_map(|rid| {
            lab.get_router_session(rid)
                .map(|s| (rid, Router::from_str(rid.fmt(lab.net())).ok(), s))
                .ok()
        })
        .map(|(rid, name, session)| {
            tokio::spawn(async move { P::new(rid, name, session).await.map(|x| (rid, x)) })
        })
        .collect::<Vec<_>>();

    let mut parsers = HashMap::new();
    for job in jobs {
        let (rid, p) = job.await??;
        parsers.insert(rid, p);
    }

    Ok(parsers)
}

/// Parse all logs and write the result to a file.
pub async fn store_logs<R, T, P>(
    parsers: HashMap<RouterId, P>,
    file_path: impl AsRef<Path>,
    log_root: Option<impl AsRef<Path>>,
) -> Result<(), Box<dyn Error>>
where
    R: LogRecord + Serialize + Send + Sync + 'static,
    P: LogParser<R, T> + Send + Sync + 'static,
{
    log::debug!("Collect logs of {}", P::description());
    let log_root = log_root.map(|x| x.as_ref().to_path_buf());
    let jobs = parsers
        .into_values()
        .map(|p| (p, log_root.clone()))
        .map(|(mut p, log_root)| tokio::spawn(async move { p.parse_new(log_root).await }))
        .collect::<Vec<_>>();

    let mut logs: Vec<R> = Vec::new();
    for job in jobs {
        logs.extend(job.await??);
    }

    let mut csv = csv::WriterBuilder::new().has_headers(true).from_writer(
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path)
            .unwrap(),
    );

    for l in logs
        .into_iter()
        .sorted_by(|a, b| a.time().total_cmp(&b.time()))
    {
        csv.serialize(l)?;
    }

    Ok(())
}

/// Setup all log parsers and return them.
pub async fn clear_event_history<'a, Q, Ospf: OspfImpl>(
    lab: &'a RouterLab<'a, Prefix, Q, Ospf, Active>,
) -> Result<(), LogParserError> {
    log::debug!("Clearing the event-history!");
    let jobs = lab
        .routers()
        .keys()
        .filter_map(|r| lab.get_router_session(*r).ok())
        .map(|session| {
            tokio::spawn(async move {
                if let Err(e) = session.execute_cmd("clear bgp event-history all").await {
                    return Err(LogParserError::Ssh(e));
                };
                if let Err(e) = session
                    .execute_cmd("clear routing event-history add-route")
                    .await
                {
                    return Err(LogParserError::Ssh(e));
                }
                if let Err(e) = session
                    .execute_cmd("clear routing event-history delete-route")
                    .await
                {
                    return Err(LogParserError::Ssh(e));
                }
                if let Err(e) = session
                    .execute_cmd("clear routing event-history modify-route")
                    .await
                {
                    return Err(LogParserError::Ssh(e));
                }
                if let Err(e) = session
                    .execute_cmd("clear routing event-history ufdm-detail")
                    .await
                {
                    return Err(LogParserError::Ssh(e));
                }
                Ok::<(), LogParserError>(())
            })
        })
        .collect::<Vec<_>>();

    for job in jobs {
        job.await??;
    }
    Ok(())
}

/// The generic log parser can execute the log command and parse lines out of that trace.
pub struct GenericLogParser<T> {
    #[allow(dead_code)]
    rid: RouterId,
    router_name: Option<Router>,
    first_line: Option<String>,
    session: Option<SshSession>,
    command: String,
    re: Vec<(T, Regex)>,
    drop_first: usize,
    must_be_non_empty: bool,
}

pub struct GenericLog<T> {
    pub kind: T,
    pub time: f64,
    /// All matched groups. The first one always corresponds to the entire matched line (without the
    /// timestamp).
    pub groups: Vec<String>,
}

lazy_static::lazy_static! {
    static ref TIME_RE: Regex = Regex::new(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d*\+\d{2}:\d{2}) (.*)$").unwrap();
    static ref TIME_RE2: Regex = Regex::new(r"^(\d{4} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}.\d+) (.*)$").unwrap();
}

impl<T: Clone> GenericLogParser<T> {
    /// Create a new generic log parser.
    ///
    /// The parser must be created *before* the experiment. Once you call `parse_new`, it will fetch
    /// all current log messages that are added since the thing was created (or since the last call
    /// to `parse_new`).
    ///
    /// The `command` is the command to execute, that generates all log messages. This command is
    /// executed at the beginning, and every time you call `parse_new`.
    ///
    /// The `re` contains a list of regular expressions that will be evaluated on every line (in the
    /// given order). If a regular expression matches, then this is returned in the parsed list.
    /// The regular expression *must not* contain the date and the subsequent space; these will be
    /// parsed out by the generic log parser automatically.
    pub async fn new(
        rid: RouterId,
        router_name: Option<Router>,
        session: CiscoSession,
        command: impl Into<String>,
        re: Vec<(T, Regex)>,
        drop_first: usize,
        must_be_non_empty: bool,
    ) -> Result<Self, LogParserError> {
        let command = command.into();
        let session = session.ssh_session();

        // get the first line
        let mut proc = session
            .command("-T")
            .arg(&command)
            .stdout(Stdio::piped())
            .spawn()?;
        let mut stdout = BufReader::new(proc.stdout.take().unwrap()).lines();

        // drop the first few messages if required
        for _ in 0..drop_first {
            let _ = stdout.next_line().await?;
        }

        let first_line = stdout.next_line().await?;

        if first_line.is_none() {
            log::warn!(
                "[{}] Empty log messages for command {}",
                session.name(),
                command
            );
        }

        // kill the process
        proc.kill().await?;

        Ok(Self {
            rid,
            router_name,
            first_line,
            session: Some(session),
            command,
            re,
            drop_first,
            must_be_non_empty,
        })
    }

    pub async fn parse_new(
        &mut self,
        raw_log_root: Option<impl AsRef<Path>>,
    ) -> Result<Vec<GenericLog<T>>, LogParserError> {
        let Some(session) = self.session.as_mut() else {
            return Err(LogParserError::OfflineParser);
        };
        let name = session.name().to_string();

        let mut result: Vec<GenericLog<T>> = Vec::new();

        let mut log_file = if let Some(path) = raw_log_root {
            let mut path = path.as_ref().to_path_buf();
            std::fs::create_dir_all(&path)?;
            path.push(format!(
                "{}_{:?}_{}",
                session.name(),
                self.router_name,
                self.command.replace(' ', "_"),
            ));

            Some(BufWriter::new(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)?,
            ))
        } else {
            None
        };

        let mut proc = session
            .command("-T")
            .arg(&self.command)
            .stdout(Stdio::piped())
            .spawn()?;
        let mut stdout = BufReader::new(proc.stdout.take().unwrap()).lines();

        // drop the first few messages if required
        for _ in 0..self.drop_first {
            let _ = stdout.next_line().await?;
        }

        let mut new_first_line: Option<String> = None;

        let mut seen_last_line = false;

        while let Some(line) = stdout.next_line().await? {
            if new_first_line.is_none() {
                new_first_line = Some(line.clone());
            }

            // breaking condition
            if Some(&line) == self.first_line.as_ref() {
                seen_last_line = true;
                break;
            }

            // store the log
            if let Some(f) = log_file.as_mut() {
                writeln!(f, "{}", line)?;
            }

            result.extend(self.parse_line(&line));
        }

        if !seen_last_line && self.first_line.is_some() {
            log::error!(
                "[{name}]: Did not receive enough log lines to find the last line marker! Command: {}",
                self.command
            );
            return Err(LogParserError::TooManyLogMessages);
        }

        if self.must_be_non_empty && result.is_empty() {
            log::warn!(
                "[{name}]: Received no new log messages!! Command: {}",
                self.command
            );
        }

        // update the first_line
        self.first_line = new_first_line;

        Ok(result)
    }

    pub fn parse_line(&self, line: &str) -> Option<GenericLog<T>> {
        // parse the timestamp
        let m = TIME_RE.captures(line).or_else(|| TIME_RE2.captures(line))?;
        let time = parse_time(m.get(1)?.as_str())?;
        let rest = m.get(2)?.as_str();

        // try all the given regexes
        for (t, re) in &self.re {
            if let Some(m) = re.captures(rest) {
                let groups = m
                    .iter()
                    .map(|x| x.map(|x| x.as_str().to_string()).unwrap_or_default())
                    .collect();
                return Some(GenericLog {
                    kind: t.clone(),
                    time,
                    groups,
                });
            }
        }

        None
    }

    #[cfg(test)]
    pub fn new_offline(re: Vec<(T, Regex)>) -> Self {
        Self {
            rid: 0.into(),
            router_name: None,
            first_line: None,
            session: None,
            command: Default::default(),
            re,
            drop_first: 0,
            must_be_non_empty: false,
        }
    }

    #[cfg(test)]
    pub fn new_offline_from<P: LogParser<R, T>, R>() -> Self {
        Self::new_offline(P::re())
    }
}

impl<T: Clone + std::fmt::Debug + PartialEq> GenericLogParser<T> {
    #[cfg(test)]
    #[track_caller]
    /// Test whether a given line matches. The timestamp is ignored. The expected groups *must not*
    /// contain the group 0 (which matches the entire line), but immediately start with the first one.
    pub fn test_line<const N: usize>(&self, line: &str, exp: Option<(T, [&str; N])>) {
        match (self.parse_line(line), exp) {
            (Some(got), Some((want_kind, want_groups))) => {
                assert_eq!(got.kind, want_kind, "Invalid line kind");
                assert_eq!(
                    got.groups.len() - 1,
                    want_groups.len(),
                    "Unexpected number of matched groups."
                );
                for (i, (got_g, want_g)) in got
                    .groups
                    .iter()
                    .map(String::as_str)
                    .skip(1)
                    .zip(want_groups)
                    .enumerate()
                {
                    assert_eq!(got_g, want_g, "Capture group {} doesn't match", i + 1)
                }
            }
            (None, None) => {}
            (Some(got), None) => panic!(
                "Line matched with kind {:?} and groups {:?}",
                got.kind,
                &got.groups[1..]
            ),
            (None, Some((want_kind, want_groups))) => {
                panic!("Line did not match. Expected kind {want_kind:?} and groups {want_groups:?}",)
            }
        }
    }
}

fn parse_time(time: impl AsRef<str>) -> Option<f64> {
    let time = time.as_ref();
    let rfc3339 = || chrono::DateTime::parse_from_rfc3339(time).ok();
    let rfc2822 = || chrono::DateTime::parse_from_rfc2822(time).ok();
    if let Some(t) = rfc3339().or_else(rfc2822) {
        Some(t.timestamp() as f64 + t.timestamp_subsec_nanos() as f64 * 1e-9)
    } else if let Ok(t) =
        chrono::NaiveDateTime::parse_from_str(time, "%Y %b %d %H:%M:%S%.6f").map(|x| x.and_utc())
    {
        Some(t.timestamp() as f64 + t.timestamp_subsec_nanos() as f64 * 1e-9)
    } else {
        None
    }
}

pub fn parse_pfx(pfx: impl AsRef<str>) -> Option<Ipv4Net> {
    Ipv4Net::from_str(pfx.as_ref()).ok()
}

pub fn parse_ip(pfx: impl AsRef<str>) -> Option<Ipv4Addr> {
    Ipv4Addr::from_str(pfx.as_ref()).ok()
}

pub fn parse_num(num: impl AsRef<str>) -> Option<usize> {
    usize::from_str(num.as_ref()).ok()
}

pub fn parse_hex(num: impl AsRef<str>) -> Option<usize> {
    usize::from_str_radix(num.as_ref(), 16).ok()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn iso8601_to_f64() {
        assert_eq!(
            parse_time("2024-11-12T18:00:44.142341000+00:00").unwrap(),
            1731434444.142341
        );
    }

    #[test]
    fn ufdm_to_f64() {
        assert_eq!(
            parse_time("2024 Nov 18 09:14:39.191295").unwrap(),
            1731921279.191295
        );
    }
}
