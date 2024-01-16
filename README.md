# Many Time Pad Crack
This is a tool I developed to crack the one time pad cipher when the key was used multiple times. It is written in Rust.

### How it works
For this you need some ciphertexts encrypted with the same OTP key. The plain text is expected to be readable text. An XOR operation is applied to each cipher character with the space character to discover plaintext characters. <br>Note: XOR an ascii letter with space just results in a shift in capitalization. The XOR of two ciphertexts is the same as the XOR of their plaintexts. 
The tool's results are displayed in the console.

### How to use
First, replace the ciphers with your own (as hex). Run it with `cargo run` and then make some guesses about what the plaintext could be and replace the guesses in the code with your own.
