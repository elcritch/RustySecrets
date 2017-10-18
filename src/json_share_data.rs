

#[macro_use]
use serde_derive;

use serde_json::Error;

#[derive(Serialize, Deserialize)]
pub struct ShareDataJson {
    // message fields
    pub shamir_data: Vec<u8>,
    pub signature: Option<Vec<Vec<u8>>>,
    pub proof: Option<Vec<u8>>,
}
