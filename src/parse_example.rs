use anyhow::{Context, Result};
use serde::{de, Deserialize};

#[derive(Deserialize, Debug)]
struct CommonHash([u8; 32]);

impl CommonHash {
    fn from_str(hex_str: &str) -> Result<Self> {
        let mut data: [u8; 32] = [0; 32];
        let str_stripped = hex_str
            .strip_prefix("0x")
            .context("error stripping the prefix 0x")?;
        hex::decode_to_slice(str_stripped, &mut data)?;
        Ok(CommonHash(data))
    }
}

fn deserialize_json_string<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<CommonHash, D::Error> {
    let s: &str = de::Deserialize::deserialize(deserializer)?;
    CommonHash::from_str(s).map_err(de::Error::custom)
}

fn deserialize_json_list<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<CommonHash>, D::Error> {
    let arr: Vec<&str> = de::Deserialize::deserialize(deserializer)?;
    arr.into_iter()
        .map(|s| CommonHash::from_str(&s))
        .collect::<Result<Vec<CommonHash>>>()
        .map_err(de::Error::custom)
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct VectorData {
    #[serde(deserialize_with = "deserialize_json_list")]
    data_value_array: Vec<CommonHash>,

    #[serde(deserialize_with = "deserialize_json_string")]
    data_value: CommonHash,
}

fn main() {
    let file_content = r#"[
        {
            "dataValueArray": ["0xa4bfa0908dc7b06d98da4309f859023d6947561bc19bc00d77f763dea1a0b9f5"],
            "dataValue": "0x27ae5ba08d7291c96c8cbddcc148bf48a6d68c7974b94356f53754ef6171d757"
        }
    ]"#;
    let json_file: Vec<VectorData> =
        serde_json::from_str(&file_content).expect("JSON was not well-formatted");
    println!("{:?}", json_file[0]);
}