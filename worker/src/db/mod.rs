pub mod error;
pub mod models;

#[allow(unused_imports)]
pub use error::{DbError, DbResult};

use worker::{D1Database, Env};

#[allow(dead_code)]
pub fn d1(env: &Env) -> DbResult<D1Database> {
    Ok(env.d1("DB")?)
}
