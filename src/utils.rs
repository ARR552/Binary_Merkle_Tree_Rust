
use sha3::{Digest, Keccak256};

pub fn genearate_zero_hashes(height: usize) -> Vec<[u8; 32]> {
    let mut zero_hashes: Vec<[u8; 32]> = vec![[0; 32]; height];
    let mut h:usize = 1;
    loop {
        if h > height - 1 {
            break;
        }
        let a: [u8; 32] = zero_hashes[h-1];
        let new_hash = hash(a, a);
        zero_hashes[h] = new_hash;
        h = h+1;
    }
    zero_hashes
}

pub fn hash(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut data_to_hash: [u8; 64] = [0; 64];
    data_to_hash[..32].copy_from_slice(&a);
    data_to_hash[32..].copy_from_slice(&b);
    let mut hasher = Keccak256::new();
    hasher.update(data_to_hash);
    let result = hasher.finalize();
    return result.into()
}

#[test]
fn test_hash() {
    let expected_hash = "829ed6c93d93efa027967605a8ccce0799e5cc7229c2ed5b0d31883760eb148d";
    let data_to_hash_1 = "16994edfddddb9480667b64174fc00d3b6da7290d37b8db3a16571b4ddf0789f";
	let data_to_hash_2 = "24a5871d68723340d9eadc674aa8ad75f3e33b61d5a9db7db92af856a19270bb";
    let mut decoded_1: [u8; 32] = [0; 32];
    let mut decoded_2: [u8; 32] = [0; 32];
    hex::decode_to_slice(data_to_hash_1, &mut decoded_1).expect("Decoding 1 failed");
    hex::decode_to_slice(data_to_hash_2, &mut decoded_2).expect("Decoding 2 failed");

	let result = hash(decoded_1, decoded_2);
    let encode_string = hex::encode(result);
    assert_eq!(expected_hash, encode_string)
}