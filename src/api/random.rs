use napi::bindgen_prelude::{Buffer, Result};
use napi_derive::napi;
use security_framework::random::SecRandom as NativeSecRandom;

use super::error::napi_error;

#[derive(Default)]
#[napi]
pub struct SecRandom {
    inner: NativeSecRandom,
}

#[napi]
impl SecRandom {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn copy_bytes(&self, length: u32) -> Result<Buffer> {
        let mut bytes = vec![0; length as usize];
        self.inner.copy_bytes(&mut bytes).map_err(napi_error)?;
        Ok(bytes.into())
    }
}
