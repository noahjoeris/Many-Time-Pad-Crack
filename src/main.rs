use hex::decode;
use std::str;

const SPACE: u8 = b' ';

const CIPHERS: [&str; 9] = [
    "160111433b00035f536110435a380402561240555c526e1c0e431300091e4f04451d1d490d1c49010d000a0a4510111100000d434202081f0755034f13031600030d0204040e", 
    "050602061d07035f4e3553501400004c1e4f1f01451359540c5804110c1c47560a1415491b06454f0e45040816431b144f0f4900450d1501094c1b16550f0b4e151e03031b450b4e020c1a124f020a0a4d09071f16003a0e5011114501494e16551049021011114c291236520108541801174b03411e1d124554284e141a0a1804045241190d543c00075453020a044e134f540a174f1d080444084e01491a090b0a1b4103570740", 
    "000000000000001a49320017071704185941034504524b1b1d40500a0352441f021b0708034e4d0008451c40450101064f071d1000100201015003061b0b444c00020b1a16470a4e051a4e114f1f410e08040554154f064f410c1c00180c0010000b0f5216060605165515520e09560e00064514411304094c1d0c411507001a1b45064f570b11480d001d4c134f060047541b185c", 
    "0b07540c1d0d0b4800354f501d131309594150010011481a1b5f11090c0845124516121d0e0c411c030c45150a16541c0a0b0d43540c411b0956124f0609075513051816590026004c061c014502410d024506150545541c450110521a111758001d0607450d11091d00121d4f0541190b45491e02171a0d49020a534f", 
    "031a5410000a075f5438001210110a011c5350080a0048540e431445081d521345111c041f0245174a0006040002001b01094914490f0d53014e570214021d00160d151c57420a0d03040b4550020e1e1f001d071a56110359420041000c0b06000507164506151f104514521b02000b0145411e05521c1852100a52411a0054180a1e49140c54071d5511560201491b0944111a011b14090c0e41", 
    "0b4916060808001a542e0002101309050345500b00050d04005e030c071b4c1f111b161a4f01500a08490b0b451604520d0b1d1445060f531c48124f1305014c051f4c001100262d38490f0b4450061800004e001b451b1d594e45411d014e004801491b0b0602050d41041e0a4d53000d0c411c41111c184e130a0015014f03000c1148571d1c011c55034f12030d4e0b45150c5c", 
    "011b0d131b060d4f5233451e161b001f59411c090a0548104f431f0b48115505111d17000e02000a1e430d0d0b04115e4f190017480c14074855040a071f4448001a050110001b014c1a07024e5014094d0a1c541052110e54074541100601014e101a5c", 
    "0c06004316061b48002a4509065e45221654501c0a075f540c42190b165c", 
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
];

// use * as a wildcard character. Copy console outputs and fill out as much as possible. Ensure array indices match with ciphers. Latest guess overrides the others.
const CLEARTEXT_GUESSES: [&str; 9] = [
    "The",
    "Government",
    "",
    "",
    "",
    "",
    "Cryptocurrencies",
    "Not your keys, Not your coins.",
    "Bitcoin: A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution",
];

// Key guess as Hex
const KEY_GUESS: &str = "";

fn main() {
    let ciphers: Vec<Vec<u8>> = CIPHERS
        .iter()
        .map(|&cipher| decode(cipher).expect("Invalid hex string"))
        .collect();

    let mut plaintext_templates = get_plaintext_templates(&ciphers);

    start_cracking(&ciphers, &mut plaintext_templates);
}

fn start_cracking(ciphertexts: &[Vec<u8>], cleartexts: &mut [Vec<u8>]) {
    let key_length = get_max_cipher_length(ciphertexts);
    let mut key = vec![0; key_length];
    let mut key_mask = vec![false; key_length];

    // Use space characters to find parts of the key
    for column_index in 0..key_length {
        update_key_and_cleartexts_with_space_checks(
            &mut key,
            &mut key_mask,
            ciphertexts,
            cleartexts,
            column_index,
        );
    }

    /* print_key(&key, &key_mask, "---Key after space XOR---"); */
    /* print_cleartexts(&cleartexts, "---Cleartexts after space XOR---"); */

    // Use guesses to find parts of the key
    apply_cleartext_guesses(
        &CLEARTEXT_GUESSES,
        ciphertexts,
        cleartexts,
        &mut key,
        &mut key_mask,
    );

    print_key(&key, &key_mask, "---Key after space XOR and guesses---");
    print_cleartexts(&cleartexts, "---Cleartexts after space XOR and guesses---");

    if !KEY_GUESS.is_empty() {
        let key_guess: Vec<u8> = decode(KEY_GUESS).expect("Invalid hex string");
        let cleartexts_from_key_guess = apply_key_guess(&key_guess, ciphertexts);
        print_cleartexts(
            &cleartexts_from_key_guess,
            "---Cleartexts after key guess---",
        );
    }
}

fn update_key_and_cleartexts_with_space_checks(
    key: &mut Vec<u8>,
    key_mask: &mut Vec<bool>,
    ciphertexts: &[Vec<u8>],
    cleartexts: &mut [Vec<u8>],
    column_index: usize,
) {
    let filtered_ciphers = filter_ciphers_by_length(ciphertexts, column_index);

    for cipher in &filtered_ciphers {
        if is_space(&filtered_ciphers, cipher[column_index], column_index) {
            key[column_index] = cipher[column_index] ^ SPACE;
            key_mask[column_index] = true;
            update_cleartexts(&filtered_ciphers, cleartexts, cipher, column_index);
            break;
        }
    }
}

fn update_cleartexts(
    filtered_ciphers: &[Vec<u8>],
    cleartexts: &mut [Vec<u8>],
    cipher: &[u8],
    column_index: usize,
) {
    let mut i = 0;
    for cleartext in cleartexts.iter_mut() {
        if !cleartext.is_empty() && column_index < cleartext.len() {
            if i < filtered_ciphers.len() {
                let result = cipher[column_index] ^ filtered_ciphers[i][column_index];
                cleartext[column_index] = get_decrypted_char(result);
                i += 1;
            }
        }
    }
}

fn get_decrypted_char(result: u8) -> u8 {
    if result == 0 {
        SPACE
    } else {
        // Swap case if the result is an alphabetic character
        match char::from(result).to_ascii_uppercase() {
            upper if upper as u8 == result => upper.to_ascii_lowercase() as u8,
            _ => result.to_ascii_uppercase(),
        }
    }
}

fn filter_ciphers_by_length(ciphertexts: &[Vec<u8>], length: usize) -> Vec<Vec<u8>> {
    ciphertexts
        .iter()
        .filter(|&cipher| cipher.len() > length)
        .cloned()
        .collect()
}

fn get_plaintext_templates(ciphertexts: &[Vec<u8>]) -> Vec<Vec<u8>> {
    ciphertexts
        .iter()
        .map(|cipher| vec![b'*'; cipher.len()])
        .collect()
}

fn get_max_cipher_length(ciphertexts: &[Vec<u8>]) -> usize {
    ciphertexts
        .iter()
        .map(|cipher| cipher.len())
        .max()
        .unwrap_or(0)
}

fn is_space(ciphers: &[Vec<u8>], cipher_value_to_check: u8, column_index: usize) -> bool {
    for cipher in ciphers {
        // Ensure the column index is within the cipher length
        if column_index >= cipher.len() {
            continue;
        }

        let result = cipher[column_index] ^ cipher_value_to_check;

        // Space XOR alphabet is an alphabet and space XOR space is 0
        if !(result.is_ascii_alphabetic() || result == 0) {
            return false;
        }
    }
    true
}

fn print_key(key: &[u8], key_mask: &[bool], header: &str) {
    println!("{}", header);
    println!("Key (Hex):");
    let hex_key: String = key
        .iter()
        .zip(key_mask)
        .map(|(&byte, &mask)| {
            if mask {
                format!("{:02x}", byte)
            } else {
                "__".to_string()
            }
        })
        .collect();
    println!("{}\n", hex_key);

    println!("Key (ASCII):");
    let ascii_key: String = key
        .iter()
        .zip(key_mask)
        .map(|(&byte, &mask)| {
            if mask && is_valid_ascii_byte(byte) {
                byte as char
            } else {
                '*'
            }
        })
        .collect();
    println!("{}", ascii_key);
}

fn print_cleartexts(cleartexts: &[Vec<u8>], header: &str) {
    println!("\n{}:", header);
    for cleartext in cleartexts {
        let line = String::from_utf8_lossy(cleartext);
        println!("{}", line);
    }
}

fn is_valid_ascii_byte(byte: u8) -> bool {
    byte.is_ascii()
}

fn apply_cleartext_guesses(
    guesses: &[&str],
    ciphertexts: &[Vec<u8>],
    cleartexts: &mut [Vec<u8>],
    key: &mut Vec<u8>,
    key_mask: &mut Vec<bool>,
) {
    // Iterate over each guess and its corresponding ciphertext
    for (index, (&guess, cipher)) in guesses.iter().zip(ciphertexts.iter()).enumerate() {
        for (i, &char_byte) in guess.as_bytes().iter().enumerate() {
            if char_byte == b'*' || i >= cipher.len() {
                continue; // Skip out-of-bound indices
            }

            let possible_key = cipher[i] ^ char_byte;

            // Update the key and key mask, regardless of previous state
            key[i] = possible_key;
            key_mask[i] = true;

            // Update only the corresponding part of the cleartext with the guess
            if i < cleartexts[index].len() {
                cleartexts[index][i] = char_byte;
            } else {
                cleartexts[index].push(char_byte);
            }
        }

        // Use the updated key to update all other cleartexts
        for (other_index, other_cipher) in ciphertexts.iter().enumerate() {
            if other_index != index {
                for (i, &key_byte) in key.iter().enumerate().take(other_cipher.len()) {
                    if key_mask[i] {
                        if i < cleartexts[other_index].len() {
                            cleartexts[other_index][i] = key_byte ^ other_cipher[i];
                        }
                    }
                }
            }
        }
    }
}

fn apply_key_guess(key_guess: &[u8], ciphertexts: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut resulting_cleartexts = Vec::new();

    for cipher in ciphertexts {
        let mut cleartext = Vec::with_capacity(cipher.len());
        for (i, &cipher_byte) in cipher.iter().enumerate() {
            // repeat the key if too short
            let key_byte = key_guess[i % key_guess.len()];
            cleartext.push(cipher_byte ^ key_byte);
        }
        resulting_cleartexts.push(cleartext);
    }

    resulting_cleartexts
}
