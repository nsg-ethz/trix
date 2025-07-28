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
//! Allows to (de-)serialize an experiment to and from a file.

use std::{io::Write, path::PathBuf};

use crate::prelude::*;

/// Serialize an `Analyzer<_>` instance and store it at the given file location.
pub fn serialize_to_file(
    path: &PathBuf,
    experiment: &Analyzer<TimingModel<crate::Prefix>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // serialize experiment (i.e. network, timing model and scenario config)
    let serialized_experiment = serde_json::to_string(&experiment)?;

    // open file, ensuring that an existing file is overwritten
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;

    // write the serialized experiment to the file
    file.write_all(serialized_experiment.as_bytes())?;

    Ok(())
}

/// Deserialize an `Analyzer<_>` instance from the given file path.
pub fn deserialize_from_file(
    path: &PathBuf,
) -> Result<Analyzer<TimingModel<crate::Prefix>>, Box<dyn std::error::Error>> {
    // read serialized_experiment from file
    let serialized_experiment = std::fs::read_to_string(path)?;
    // try to deserialize the experiment
    match serde_json::from_str(&serialized_experiment) {
        Ok(analyzer) => Ok(analyzer),
        Err(e) => {
            log::debug!("{e:?}");
            Err("Deserialization failed!".into())
        }
    }
}

/// Try to deserialize an instance of `Analyzer<_>` at the given file location and return whether
/// the attempt was successful or not.
pub fn try_deserialize(path: &PathBuf) -> bool {
    match deserialize_from_file(path) {
        Ok(_) => true,
        Err(e) => {
            log::debug!("Deserialization of experiment failed:\n{e:?}");
            false
        }
    }
}
