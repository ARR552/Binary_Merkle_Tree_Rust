mod utils;

use std::fs;
use serde::{de, Deserialize};
use anyhow::{Ok, Result};

fn main() -> Result<(), anyhow::Error> {
    Ok(())
}

pub struct MerkleTree
{
    zero_hashes: Vec<[u8; 32]>,
    height: usize,
    count: usize,
    siblings: Vec<[u8; 32]>,
    current_root: [u8; 32],
}

impl MerkleTree {
    pub fn new_merkle_tree(height: usize, initial_leaves: Vec<[u8; 32]>) -> MerkleTree {
        let init_leaves_length: usize = initial_leaves.len();
        let zero_hashes = utils::genearate_zero_hashes(height);
        let mut mt = MerkleTree {
            height: height,
            count: init_leaves_length,
            zero_hashes: zero_hashes,
            siblings: vec![],
            current_root: [0; 32],
        };
        let siblings: Vec<[u8;32]>;
        let current_root: [u8; 32];
        (siblings, current_root, mt) = mt.init_siblings(initial_leaves).expect("error initializing siblings");
        mt.siblings = siblings;
        mt.current_root = current_root;
        println!("Initial count: {:?}", init_leaves_length);
        println!("Initial root: {:?}", mt.current_root);
        mt
        
    }
    pub fn show(self)
    {
        println!("count: {}, root: {:?}", self.count, self.current_root);
    }

    pub fn add_leaf(mut self, index: u32, leaf: [u8;32]) -> Result<([u8;32], MerkleTree), anyhow::Error> {
        let cu32 = u32::try_from(self.count).ok().expect("error converting usize to u32");
        if index != cu32 {
            return Err(anyhow::format_err!("error: mismatched leaf count: {:?}, expected: {:?}", index, cu32));
        }
        let mut cur = leaf.clone();
        let mut is_filled_subtree = true;
        for h in 0..=self.height-1 {
            if index&(1<<h) > 0 {
                let child: [u8; 32] = cur.clone();
                let parent = utils::hash(self.siblings[h], child);
                cur = parent;
            } else {
                if is_filled_subtree {
                    // we will update the sibling when the sub tree is complete
                    self.siblings[h] = cur;
                    // we have a left child in this layer, it means the right child is empty so the sub tree is not completed
                    is_filled_subtree = false;
                }
                let child: [u8; 32] = cur;
                let parent = utils::hash(child, self.zero_hashes[h]);
                cur = parent;
                // the sibling of 0 bit should be the zero hash, since we are in the last node of the tree
            }
        }
        self.current_root = cur;
        self.count += 1;

        Ok((cur, self))
        
    }
    
    pub fn compute_merkle_proof(&self, ger_index: usize, mut leaves:Vec<[u8; 32]>) -> Result<(Vec<[u8;32]>, [u8;32]), anyhow::Error>{ // Result<mt_siblings, Box<dyn std::error::Error>>{
        let mut ns: Vec<Vec<[u8; 32]>> = vec![vec![]];
        if leaves.len() == 0 {
            leaves.push(self.zero_hashes[0]);
        }
        let mut siblings: Vec<[u8;32]> = vec![];
        let mut index = ger_index;
        for h in 0..=self.height-1 {
            if leaves.len()%2 == 1 {
                leaves.push(self.zero_hashes[h]);
            }
            if index >= leaves.len() {
                siblings.push(self.zero_hashes[h]);
            } else {
                if index%2 == 1 { // if it is odd
                    siblings.push(leaves[index-1]);
                } else { // It is even
                    siblings.push(leaves[index+1]);
                }
            }
            let mut nsi: Vec<Vec<[u8; 32]>> = vec![];
            let mut hashes: Vec<[u8;32]> = vec![];
            let mut i = 0;
            loop {
                if i>leaves.len()-1 {
                    break;
                }
                let left = i;
                let right = i+1;
                let hash_data = utils::hash(leaves[left], leaves[right]);
                let node: Vec<[u8; 32]> = vec![hash_data, leaves[left], leaves[right]];
                nsi.push(node);
                hashes.push(hash_data);
                i+=2;
            }
            // Find the index of the leaf in the next level of the tree.
            // Divide the index by 2 to find the position in the upper level.
            index = index/2;
            ns = nsi;
            leaves = hashes;
        }
        if ns.len() != 1 {
            println!("ns.len() = {}", ns.len());
            println!("error: more than one root detected. Nodes: {:?}", ns);
            Err(anyhow::format_err!("error: more than one root detected"))
        } else {
            Ok((siblings, ns[0][0]))
        }
    }
    
    pub fn init_siblings(self, init_leaves: Vec<[u8; 32]>) -> Result<(Vec<[u8;32]>, [u8;32], MerkleTree), anyhow::Error> {
        if init_leaves.len() != self.count {
            return Err(anyhow::format_err!("error: mt.count and initialLeaves length mismatch. init_leaves: {:?}, count: {:?}", init_leaves.len(), self.count));
        }
        let root: [u8;32];
        let mut siblings: Vec<[u8;32]>;
        if init_leaves.len() == 0 {
            siblings = vec![];
            for h in 0..=self.height-1 {
                let left: [u8; 32] = self.zero_hashes[h];
                siblings.push(left);            
            }
            root = self.build_root(init_leaves).expect("error build_root initializing the siblings");
        } else {
            (siblings, root) = self.compute_merkle_proof(init_leaves.len(), init_leaves).expect("error compute_merkle_proof initializing the siblings");
        }
        Ok((siblings, root, self))
    }

    fn build_root(&self, mut leaves:Vec<[u8; 32]>) -> Result<[u8; 32], anyhow::Error>{
        let mut nodes: Vec<Vec<Vec<[u8; 32]>>> = vec![];
        let mut ns: Vec<Vec<[u8; 32]>> = vec![];
        if leaves.len() == 0 {
            let leaf = self.zero_hashes[0];
            leaves.push(leaf);
        }
        let mut h: usize = 0;
        loop {
            if h>=self.height {
                break;
            }
            if leaves.len()%2 == 1 {
                leaves.push(self.zero_hashes[h]);
            }
            (ns, leaves) = build_intermediate(leaves);
            nodes.push(ns.to_vec());
            h+=1;
        }
        if ns.len() != 1 {
            println!("error: more than one root detected. Nodes: {:?}", nodes);
            Err(anyhow::format_err!("error: more than one root detected"))
        } else {
            Ok(ns[0][0])
        }
    
    }

    // get_current_root_count_and_siblings returns the latest root, count and sibblings
    pub fn get_current_root_count_and_siblings(self) -> ([u8; 32], usize, MerkleTree) {
        (self.current_root, self.count, self)
    }

}

#[test]
fn test_compute_merkle_proof() {
    let mut l_1: [u8; 32] = [0; 32];
    let mut l_2: [u8; 32] = [0; 32];
    let mut l_3: [u8; 32] = [0; 32];
    let mut l_4: [u8; 32] = [0; 32];
    let mut l_5: [u8; 32] = [0; 32];
    let mut l_6: [u8; 32] = [0; 32];
    let mut l_7: [u8; 32] = [0; 32];
    let mut l_8: [u8; 32] = [0; 32];
    let mut l_9: [u8; 32] = [0; 32];
    let mut l_10: [u8; 32] = [0; 32];
    let mut l_11: [u8; 32] = [0; 32];
    let mut l_12: [u8; 32] = [0; 32];
    let mut l_13: [u8; 32] = [0; 32];
    let mut l_14: [u8; 32] = [0; 32];
    let mut l_15: [u8; 32] = [0; 32];
    let mut l_16: [u8; 32] = [0; 32];
    let mut l_17: [u8; 32] = [0; 32];
    let mut l_18: [u8; 32] = [0; 32];
    let mut l_19: [u8; 32] = [0; 32];
    let mut l_20: [u8; 32] = [0; 32];
    let mut l_21: [u8; 32] = [0; 32];
    let mut l_22: [u8; 32] = [0; 32];
    let mut l_23: [u8; 32] = [0; 32];
    let mut l_24: [u8; 32] = [0; 32];
    let mut l_25: [u8; 32] = [0; 32];
    let mut l_26: [u8; 32] = [0; 32];
    hex::decode_to_slice("83fc198de31e1b2b1a8212d2430fbb7766c13d9ad305637dea3759065606475d", &mut l_1).expect("Decoding l_1 failed");
    hex::decode_to_slice("83fc198de31e1b2b1a8212d2430fbb7766c13d9ad305637dea3759065606475d", &mut l_2).expect("Decoding l_2 failed");
    hex::decode_to_slice("0349657c7850dc9b2b73010501b01cd6a38911b6a2ad2167c164c5b2a5b344de", &mut l_3).expect("Decoding l_3 failed");
    hex::decode_to_slice("b32f96fad8af99f3b3cb90dfbb4849f73435dbee1877e4ac2c213127379549ce", &mut l_4).expect("Decoding l_4 failed");
    hex::decode_to_slice("79ffa1294bf48e0dd41afcb23b2929921e4e17f2f81b7163c23078375b06ba4f", &mut l_5).expect("Decoding l_5 failed");
    hex::decode_to_slice("0004063b5c83f56a17f580db0908339c01206cdf8b59beb13ce6f146bb025fe2", &mut l_6).expect("Decoding l_6 failed");
    hex::decode_to_slice("68e4f2c517c7f60c3664ac6bbe78f904eacdbe84790aa0d15d79ddd6216c556e", &mut l_7).expect("Decoding l_7 failed");
    hex::decode_to_slice("f7245f4d84367a189b90873e4563a000702dbfe974b872fdb13323a828c8fb71", &mut l_8).expect("Decoding l_8 failed");
    hex::decode_to_slice("0e43332c71c6e2f4a48326258ea17b75d77d3063a4127047dd32a4cb089e62a4", &mut l_9).expect("Decoding l_9 failed");
    hex::decode_to_slice("d35a1dc90098c0869a69891094c119eb281cee1a7829d210df1bf8afbea08adc", &mut l_10).expect("Decoding l_10 failed");
    hex::decode_to_slice("13bffd0da370d1e80a470821f1bee9607f116881feb708f1ec255da1689164b3", &mut l_11).expect("Decoding l_11 failed");
    hex::decode_to_slice("5fa79a24c9bc73cd507b02e5917cef9782529080aa75eacb2bf4e1d45fda7f1d", &mut l_12).expect("Decoding l_12 failed");
    hex::decode_to_slice("975b5bbc67345adc6ee6d1d67d1d5cd2a430c231d93e5a8b5a6f00b0c0862215", &mut l_13).expect("Decoding l_13 failed");
    hex::decode_to_slice("0d0fa887c045a53ec6212dee58964d0ae89595b7d11745a05c397240a4dceb20", &mut l_14).expect("Decoding l_14 failed");
    hex::decode_to_slice("a6ae5bc494a2ee0e5173d0e0b546533973104e0031c69d0cd65cdc7bb4d64670", &mut l_15).expect("Decoding l_15 failed");
    hex::decode_to_slice("21ccc18196a8fd74e720c6c129977d80bb804d3331673d6411871df14f7e7ae4", &mut l_16).expect("Decoding l_16 failed");
    hex::decode_to_slice("f8b1b98ac75bea8dbed034d0b3cd08b4c9275644c2242781a827e53deb2386c3", &mut l_17).expect("Decoding l_17 failed");
    hex::decode_to_slice("26401c418ef8bc5a80380f25f16dfc78b7053a26c0ca425fda294b1678b779fc", &mut l_18).expect("Decoding l_18 failed");
    hex::decode_to_slice("c53fd99005361738fc811ce87d194deed34a7f06ebd5371b19a008e8d1e8799f", &mut l_19).expect("Decoding l_19 failed");
    hex::decode_to_slice("570bd643e35fbcda95393994812d9212335e6bd4504b3b1dc8f3c6f1eeb247b2", &mut l_20).expect("Decoding l_20 failed");
    hex::decode_to_slice("b21ac971d007810540583bd3c0d4f35e0c2f4b62753e51c104a5753c6372caf8", &mut l_21).expect("Decoding l_21 failed");
    hex::decode_to_slice("b8dae305b34c749cbbd98993bfd71ec2323e8364861f25b4c5e0ac3c9587e16d", &mut l_22).expect("Decoding l_22 failed");
    hex::decode_to_slice("57c7fabd0f70e0059e871953fcb3dd43c6b8a5f348dbe771190cc8b0320336a5", &mut l_23).expect("Decoding l_23 failed");
    hex::decode_to_slice("95b0d23c347e2a88fc8e2ab900b09212a1295ab8f169075aa27e8719557d9b06", &mut l_24).expect("Decoding l_24 failed");
    hex::decode_to_slice("95b0d23c347e2a88fc8e2ab900b09212a1295ab8f169075aa27e8719557d9b06", &mut l_25).expect("Decoding l_25 failed");
    hex::decode_to_slice("95b0d23c347e2a88fc8e2ab900b09212a1295ab8f169075aa27e8719557d9b06", &mut l_26).expect("Decoding l_26 failed");

	let leaves: Vec<[u8;32]> = vec![
        l_1,
        l_2,
        l_3,
        l_4,
        l_5,
        l_6,
        l_7,
        l_8,
        l_9,
        l_10,
        l_11,
        l_12,
        l_13,
        l_14,
        l_15,
        l_16,
        l_17,
        l_18,
        l_19,
        l_20,
        l_21,
        l_22,
        l_23,
        l_24,
        l_25,
        l_26,
    ];

	assert_eq!(26, leaves.len());
    let mt = MerkleTree {
        height: 32,
        count: 0,
        zero_hashes: utils::genearate_zero_hashes(32),
        siblings: vec![],
        current_root: [0; 32],
    };
	let (siblings, root) = mt.compute_merkle_proof(1, leaves).expect("error computing the merkle proof");
    let root_string: String = hex::encode(root);

	assert_eq!("4ed479841384358f765966486782abb598ece1d4f834a22474050d66a18ad296", root_string);
	let expected_proof = vec!["83fc198de31e1b2b1a8212d2430fbb7766c13d9ad305637dea3759065606475d", "2815e0bbb1ec18b8b1bc64454a86d072e12ee5d43bb559b44059e01edff0af7a", "7fb6cc0f2120368a845cf435da7102ff6e369280f787bc51b8a989fc178f7252", "407db5edcdc0ddd4f7327f208f46db40c4c4dbcc46c94a757e1d1654acbd8b72", "ce2cdd1ef2e87e82264532285998ff37024404ab3a2b77b50eb1ad856ae83e14", "0eb01ebfc9ed27500cd4dfc979272d1f0913cc9f66540d7e8005811109e1cf2d", "887c22bd8750d34016ac3c66b5ff102dacdd73f6b014e710b51e8022af9a1968", "ffd70157e48063fc33c97a050f7f640233bf646cc98d9524c6b92bcf3ab56f83", "9867cc5f7f196b93bae1e27e6320742445d290f2263827498b54fec539f756af", "cefad4e508c098b9a7e1d8feb19955fb02ba9675585078710969d3440f5054e0", "f9dc3e7fe016e050eff260334f18a5d4fe391d82092319f5964f2e2eb7c1c3a5", "f8b13a49e282f609c317a833fb8d976d11517c571d1221a265d25af778ecf892", "3490c6ceeb450aecdc82e28293031d10c7d73bf85e57bf041a97360aa2c5d99c", "c1df82d9c4b87413eae2ef048f94b4d3554cea73d92b0f7af96e0271c691e2bb", "5c67add7c6caf302256adedf7ab114da0acfe870d449a3a489f781d659e8becc", "da7bce9f4e8618b6bd2f4132ce798cdc7a60e7e1460a7299e3c6342a579626d2", "2733e50f526ec2fa19a22b31e8ed50f23cd1fdf94c9154ed3a7609a2f1ff981f", "e1d3b5c807b281e4683cc6d6315cf95b9ade8641defcb32372f1c126e398ef7a", "5a2dce0a8a7f68bb74560f8f71837c2c2ebbcbf7fffb42ae1896f13f7c7479a0", "b46a28b6f55540f89444f63de0378e3d121be09e06cc9ded1c20e65876d36aa0", "c65e9645644786b620e2dd2ad648ddfcbf4a7e5b1a3a4ecfe7f64667a3f0b7e2", "f4418588ed35a2458cffeb39b93d26f18d2ab13bdce6aee58e7b99359ec2dfd9", "5a9c16dc00d6ef18b7933a6f8dc65ccb55667138776f7dea101070dc8796e377", "4df84f40ae0c8229d0d6069e5c8f39a7c299677a09d367fc7b05e3bc380ee652", "cdc72595f74c7b1043d0e1ffbab734648c838dfb0527d971b602bc216c9619ef", "0abf5ac974a1ed57f4050aa510dd9c74f508277b39d7973bb2dfccc5eeb0618d", "b8cd74046ff337f0a7bf2c8e03e10f642c1886798d71806ab1e888d9e5ee87d0", "838c5655cb21c6cb83313b5a631175dff4963772cce9108188b34ac87c81c41e", "662ee4dd2dd7b2bc707961b1e646c4047669dcb6584f0d8d770daf5d7e7deb2e", "388ab20e2573d171a88108e79d820e98f26c0b84aa8b2f4aa4968dbb818ea322", "93237c50ba75ee485f4c22adf2f741400bdf8d6a9cc7df7ecae576221665d735", "8448818bb4ae4562849e949e17ac16e0be16688e156b5cf15e098c627c0056a9"];
    // for sibling in siblings.iter() {
    for i in 0..=siblings.len()-1 {
        let sibling_string = hex::encode(siblings[i]);
        assert_eq!(expected_proof[i], sibling_string);
	}
}

fn build_intermediate(leaves:Vec<[u8; 32]>) -> (Vec<Vec<[u8; 32]>>, Vec<[u8; 32]>) {
    let mut hashes: Vec<[u8; 32]> = vec![];
    let mut nodes: Vec<Vec<[u8; 32]>> = vec![];
    let mut i: usize = 0;
    loop {
        if i>=leaves.len() {
            break;
        }
        let left = i;
        let right = i+1;
        let hash = utils::hash(leaves[left], leaves[right]);
        let node: Vec<[u8; 32]> = vec![hash, leaves[left], leaves[right]];
        nodes.push(node);
        hashes.push(hash);
        i+=2;
    }
    (nodes, hashes)

}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct VectorData {
    #[serde(deserialize_with = "deserialize_json_hex_list")]
    previous_leaf_values: Vec<CommonHash>,
    #[serde(deserialize_with = "deserialize_json_hex_string")]
    current_root: CommonHash,
    #[serde(deserialize_with = "deserialize_json_hex_string")]
    new_leaf_value: CommonHash,
    #[serde(deserialize_with = "deserialize_json_hex_string")]
    new_root: CommonHash,
}
#[derive(Deserialize, Debug)]
struct CommonHash([u8;32]);

impl CommonHash {
    // Parses a hex string into an instance of CommonHash that it is an alias of [u8;32]
    fn from_str(hex_str: &str) -> Result<Self> {
        let mut data: [u8; 32] = [0; 32];
        let str_stripped = hex_str.strip_prefix("0x").expect("error stripping the prefix 0x");
        hex::decode_to_slice(str_stripped, &mut data).expect("Decoding hex string failed");
        Ok(CommonHash(data))
    }
}

fn deserialize_json_hex_string<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<CommonHash, D::Error> {
    let s: &str = de::Deserialize::deserialize(deserializer)?;
    CommonHash::from_str(s).map_err(de::Error::custom)
}

fn deserialize_json_hex_list<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<CommonHash>, D::Error> {
    let arr: Vec<&str> = de::Deserialize::deserialize(deserializer)?;
    arr.into_iter()
        .map(|s| CommonHash::from_str(&s))
        .collect::<Result<Vec<CommonHash>>>()
        .map_err(de::Error::custom)
}

#[test]
fn test_build_root() {
    let file_path = "./src/test/vectors/root_vectors.json";
    let file_content = fs::read_to_string(file_path).expect("It should be able to read the file");
    let test_vectors: Vec<VectorData> = serde_json::from_str(&file_content).expect("JSON was not well-formatted");
    for test_vector in test_vectors.iter() {
        let mut leaves: Vec<[u8;32]> = vec![];
        for leaf in test_vector.previous_leaf_values.iter() {
            leaves.push(leaf.0);
        }
        if leaves.len() != 0 {
            let mt = MerkleTree {
                height: 32,
                count: 0,
                zero_hashes: utils::genearate_zero_hashes(32),
                siblings: vec![],
                current_root: [0; 32],
            };
            let root = mt.build_root(leaves.clone()).expect("error building root for initial leaves");
            assert_eq!(test_vector.current_root.0, root, "fail building root for initial leaves");
        }
        let new_leave = test_vector.new_leaf_value.0;
        leaves.push(new_leave);
        let mt = MerkleTree {
            height: 32,
            count: 0,
            zero_hashes: utils::genearate_zero_hashes(32),
            siblings: vec![],
            current_root: [0; 32],
        };
        let new_root = mt.build_root(leaves).expect("error building root");
        assert_eq!(test_vector.new_root.0, new_root, "fail building root");
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ProofVector {
    #[serde(deserialize_with = "deserialize_json_hex_list")]
    leaves: Vec<CommonHash>,
    index: u64, 
    #[serde(deserialize_with = "deserialize_json_hex_list")]
    proof: Vec<CommonHash>,
    #[serde(deserialize_with = "deserialize_json_hex_string")]
    root: CommonHash,
}

#[test]
fn test_add_leaf() {
	let file_path = "./src/test/vectors/proof_vectors.json";
	let file_content = fs::read_to_string(file_path).expect("It should be able to read the file");
    let test_vectors: Vec<ProofVector> = serde_json::from_str(&file_content).expect("JSON was not well-formatted");
    
	let test_vector = &test_vectors[3];
	let leaves: Vec<[u8; 32]> = vec![];
	let mut mt = MerkleTree::new_merkle_tree(32, leaves);
    
	for leaf in test_vector.leaves.iter() {
        let count: usize;
		(_, count, mt) = mt.get_current_root_count_and_siblings();
        let cu32 = u32::try_from(count).ok().expect("error converting usize to u32");
		(_, mt) = mt.add_leaf(cu32, leaf.0).expect("error adding new leaf to the merkle tree");
	}
    let (current_root, count, _) = mt.get_current_root_count_and_siblings();
    assert_eq!(test_vector.leaves.len(), count, "error checking the number of leaves");
	assert_eq!(test_vector.root.0, current_root, "error checking the root");
    println!("{} leaves added successfully", test_vector.leaves.len());
	println!("Final root: {:?}", current_root);
}

#[test]
fn test_add_leaf_2() {
    let file_path = "./src/test/vectors/root_vectors.json";
    let file_content = fs::read_to_string(file_path).expect("It should be able to read the file");
    let test_vectors: Vec<VectorData> = serde_json::from_str(&file_content).expect("JSON was not well-formatted");
    for test_vector in test_vectors.iter() {
		let mut leaves: Vec<[u8;32]> = vec![];
		for l in test_vector.previous_leaf_values.iter() {
			leaves.push(l.0);
		}
        let mt = MerkleTree::new_merkle_tree(32, leaves);

		let (initial_root, count, mt) = mt.get_current_root_count_and_siblings();
		assert_eq!(test_vector.current_root.0, initial_root, "error checking initial root");

        let cu32 = u32::try_from(count).ok().expect("error converting usize to u32");
        let (new_root, _) = mt.add_leaf(cu32, test_vector.new_leaf_value.0).expect("error adding new leaf to the merkle tree");
		assert_eq!(test_vector.new_root.0, new_root);
	}
}