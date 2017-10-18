

#[macro_use]
use serde_derive;
use serde::{Serializer, Deserialize, Deserializer};

#[macro_use]
use base64_serde;


#[derive(Serialize, Deserialize)]
pub struct ShareDataJson {
    pub shamir_data: String,
    pub signature: Option<Vec<String>>,
    pub proof: Option<String>,
}
