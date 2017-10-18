

#[macro_use]
use serde_derive;

use serde::{Serialize, Deserialize, Deserializer};

use serde_json::Error;


#[derive(Serialize, Deserialize, Debug)]
pub struct ShareDataJson {
    pub shamir_data: String,
    pub signature: Option<Vec<String>>,
    pub proof: Option<String>,
}
