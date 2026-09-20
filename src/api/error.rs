use std::fmt::Display;

use napi::{Error, Status};
use napi_derive::napi;

pub(crate) fn napi_error(error: impl Display) -> Error {
    Error::new(Status::GenericFailure, error.to_string())
}

#[napi]
pub fn security_framework_error_message(code: i32) -> Option<String> {
    security_framework::base::Error::from_code(code).message()
}
