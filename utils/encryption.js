const crypto = require("crypto");

const algorithm = "aes-256-cbc";
// Pull a permanent 32-byte hex string from your .env file
// DO NOT generate it randomly here!
const secretKey = Buffer.from(process.env.ENCRYPTION_KEY, "hex");

function encrypt(text) {
    // 1. Generate a fresh, unique IV for THIS specific encryption
    const iv = crypto.randomBytes(16);

    // 2. Create the cipher
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);

    // 3. Encrypt the text
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");

    // 4. Return BOTH the IV and the encrypted text. 
    // You must save the IV in your database alongside the encrypted text, 
    // otherwise you can never decrypt it!
    return {
        iv: iv.toString("hex"),
        encryptedData: encrypted
    };
}

module.exports = { encrypt };