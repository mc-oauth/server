use std::time::{Instant,Duration};
use std::io::{Error, ErrorKind};
use std::collections::HashMap;
use serde_json::Value;
use serde::Serialize;
use rand::Rng;

use crate::serializer::IOResult;

pub struct Store {
    map: HashMap<i32, (Profile, Instant)>
}

#[derive(Serialize)]
pub struct Profile {
    pub id: String,
    pub name: String
}

impl Profile {
    pub fn from_json(value: &Value) -> IOResult<Self> {
        let id = Self::read_string(value, "id")?;
        let name = Self::read_string(value, "name")?;
        Ok(Self { id, name })
    }

    fn read_string(value: &Value, field: &str) -> IOResult<String> {
        match value.get(field) {
            Some(val) => Ok(val.to_string()),
            None => Err(Error::new(ErrorKind::InvalidInput, "Could not read json value"))
        }
    }
}

impl Store {
    const EXPIRATION: Duration = Duration::from_secs(60 * 5);

    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    pub fn generate(&mut self, profile: Profile) -> i32 {
        self.remove_expired();
        let mut rng = rand::thread_rng();
        let mut token = rng.gen_range(100000..999999);
        while self.map.contains_key(&token) {
            token = rng.gen_range(100000..999999);
        }
        self.map.insert(token, (profile, Instant::now()));
        token
    }

    pub fn lookup(&mut self, token: i32) -> Option<Profile> {
        self.remove_expired();
        let result = self.map.remove(&token);
        if let Some((profile, _)) = result {
            return Some(profile)
        }
        None
    }

    #[allow(unused)]
    fn remove_expired(&mut self) {
        let now = Instant::now();
        self.map.retain(|_, (_, mut time)| {
            (now - time) < Self::EXPIRATION
        });
    }
}
