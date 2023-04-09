use crate::file_structure::VerificationDirectory;

use super::error::{VerificationError, VerificationFailure};
use super::{VerificationCategory, VerificationPeriod, VerificationStatus};
use log::{info, warn};
use std::time::{Duration, SystemTime};

pub struct VerificationMetaData {
    pub id: String,
    pub nr: String,
    pub name: String,
    pub period: VerificationPeriod,
    pub category: VerificationCategory,
}

pub struct Verification {
    pub meta_data: VerificationMetaData,
    status: VerificationStatus,
    verification_fn: Box<dyn Fn(&VerificationDirectory, &mut VerificationResult)>,
    duration: Option<Duration>,
    result: Box<VerificationResult>,
}

pub struct VerificationResult {
    errors: Vec<VerificationError>,
    failures: Vec<VerificationFailure>,
}

pub trait VerificationResultTrait {
    fn is_ok(&self) -> Option<bool>;
    fn has_errors(&self) -> Option<bool>;
    fn has_failures(&self) -> Option<bool>;
    fn errors(&self) -> &Vec<VerificationError>;
    fn failures(&self) -> &Vec<VerificationFailure>;
}

impl VerificationResult {
    pub fn new() -> Self {
        VerificationResult {
            errors: vec![],
            failures: vec![],
        }
    }

    fn errors_mut(&mut self) -> &mut Vec<VerificationError> {
        &mut self.errors
    }

    fn failures_mut(&mut self) -> &mut Vec<VerificationFailure> {
        &mut self.failures
    }

    pub fn push_error(&mut self, e: VerificationError) {
        self.errors.push(e)
    }

    pub fn push_failure(&mut self, f: VerificationFailure) {
        self.failures.push(f)
    }

    // Append the results of ohter to self, emptying the vectors of other
    pub fn append(&mut self, other: &mut Self) {
        self.errors.append(&mut other.errors_mut());
        self.failures.append(&mut other.failures_mut());
    }
}

impl VerificationResultTrait for VerificationResult {
    fn is_ok(&self) -> Option<bool> {
        Some(!self.has_errors().unwrap() && !self.has_failures().unwrap())
    }

    fn has_errors(&self) -> Option<bool> {
        Some(!self.errors.is_empty())
    }

    fn has_failures(&self) -> Option<bool> {
        Some(!self.failures.is_empty())
    }

    fn errors(&self) -> &Vec<VerificationError> {
        &self.errors
    }

    fn failures(&self) -> &Vec<VerificationFailure> {
        &self.failures
    }
}

impl Verification {
    pub fn new(
        meta_data: VerificationMetaData,
        verification_fn: impl Fn(&VerificationDirectory, &mut VerificationResult) + 'static,
    ) -> Self {
        Verification {
            meta_data,
            status: VerificationStatus::Stopped,
            verification_fn: Box::new(verification_fn),
            duration: None,
            result: Box::new(VerificationResult::new()),
        }
    }

    pub fn run(&mut self, directory: &VerificationDirectory) {
        self.status = VerificationStatus::Running;
        let start_time = SystemTime::now();
        info!(
            "Verification {} ({}) started",
            self.meta_data.name, self.meta_data.id
        );
        (self.verification_fn)(directory, self.result.as_mut());
        self.duration = Some(start_time.elapsed().unwrap());
        self.status = VerificationStatus::Finished;
        if self.is_ok().unwrap() {
            info!(
                "Verification {} ({}) finished successfully. Duration: {}s",
                self.meta_data.name,
                self.meta_data.id,
                self.duration.unwrap().as_secs_f32()
            );
        }
        if self.has_errors().unwrap() {
            warn!(
                "Verification {} ({}) finished with errors. Duration: {}s",
                self.meta_data.name,
                self.meta_data.id,
                self.duration.unwrap().as_secs_f32()
            );
        }
        if self.has_failures().unwrap() {
            warn!(
                "Verification {} ({}) finished with failures. Duration: {}s",
                self.meta_data.name,
                self.meta_data.id,
                self.duration.unwrap().as_secs_f32()
            );
        }
    }
}

impl VerificationResultTrait for Verification {
    fn is_ok(&self) -> Option<bool> {
        match self.status {
            VerificationStatus::Stopped => None,
            VerificationStatus::Running => None,
            VerificationStatus::Finished => self.result.is_ok(),
        }
    }

    fn has_errors(&self) -> Option<bool> {
        match self.status {
            VerificationStatus::Stopped => None,
            VerificationStatus::Running => None,
            VerificationStatus::Finished => self.result.has_errors(),
        }
    }

    fn has_failures(&self) -> Option<bool> {
        match self.status {
            VerificationStatus::Stopped => None,
            VerificationStatus::Running => None,
            VerificationStatus::Finished => self.result.has_failures(),
        }
    }

    fn errors(&self) -> &Vec<VerificationError> {
        self.result.errors()
    }

    fn failures(&self) -> &Vec<VerificationFailure> {
        self.result.failures()
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use crate::error::{create_verifier_error, VerifierError};
    use crate::verification::error::{VerificationErrorType, VerificationFailureType};

    use super::*;

    #[test]
    fn run_ok() {
        fn ok(_: &VerificationDirectory, _: &mut VerificationResult) {}
        let mut verif = Verification::new(
            VerificationMetaData {
                id: "test_ok".to_string(),
                nr: "1".to_string(),
                name: "test_ok".to_string(),
                period: VerificationPeriod::Setup,
                category: VerificationCategory::Authenticity,
            },
            Box::new(ok),
        );
        assert_eq!(verif.status, VerificationStatus::Stopped);
        assert!(verif.is_ok().is_none());
        assert!(verif.has_errors().is_none());
        assert!(verif.has_failures().is_none());
        verif.run(&VerificationDirectory::new(
            VerificationPeriod::Setup,
            &Path::new("."),
        ));
        assert_eq!(verif.status, VerificationStatus::Finished);
        assert!(verif.is_ok().unwrap());
        assert!(!verif.has_errors().unwrap());
        assert!(!verif.has_failures().unwrap());
    }

    #[test]
    fn run_error() {
        fn error(_: &VerificationDirectory, result: &mut VerificationResult) {
            result.push_error(create_verifier_error!(VerificationErrorType::Error, "toto"));
            result.push_error(create_verifier_error!(
                VerificationErrorType::Error,
                "toto2"
            ));
            result.push_failure(create_verifier_error!(
                VerificationFailureType::Failure,
                "toto"
            ));
        }
        let mut verif = Verification::new(
            VerificationMetaData {
                id: "test_ok".to_string(),
                nr: "1".to_string(),
                name: "test_ok".to_string(),
                period: VerificationPeriod::Setup,
                category: VerificationCategory::Authenticity,
            },
            Box::new(error),
        );
        assert_eq!(verif.status, VerificationStatus::Stopped);
        assert!(verif.is_ok().is_none());
        assert!(verif.has_errors().is_none());
        assert!(verif.has_failures().is_none());
        verif.run(&VerificationDirectory::new(
            VerificationPeriod::Setup,
            &Path::new("."),
        ));
        assert_eq!(verif.status, VerificationStatus::Finished);
        assert!(!verif.is_ok().unwrap());
        assert!(verif.has_errors().unwrap());
        assert!(verif.has_failures().unwrap());
        assert_eq!(verif.errors().len(), 2);
        assert_eq!(verif.failures().len(), 1);
    }

    #[test]
    fn run_failure() {
        fn failure(_: &VerificationDirectory, result: &mut VerificationResult) {
            result.push_failure(create_verifier_error!(
                VerificationFailureType::Failure,
                "toto"
            ));
            result.push_failure(create_verifier_error!(
                VerificationFailureType::Failure,
                "toto2"
            ));
        }
        let mut verif = Verification::new(
            VerificationMetaData {
                id: "test_ok".to_string(),
                nr: "1".to_string(),
                name: "test_ok".to_string(),
                period: VerificationPeriod::Setup,
                category: VerificationCategory::Authenticity,
            },
            Box::new(failure),
        );
        assert_eq!(verif.status, VerificationStatus::Stopped);
        assert!(verif.is_ok().is_none());
        assert!(verif.has_errors().is_none());
        assert!(verif.has_failures().is_none());
        verif.run(&VerificationDirectory::new(
            VerificationPeriod::Setup,
            &Path::new("."),
        ));
        assert_eq!(verif.status, VerificationStatus::Finished);
        assert!(!verif.is_ok().unwrap());
        assert!(!verif.has_errors().unwrap());
        assert!(verif.has_failures().unwrap());
        assert_eq!(verif.errors().len(), 0);
        assert_eq!(verif.failures().len(), 2);
    }
}
