import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';

const app = express();
app.use(express.json({ limit: '2mb' }));

// Load PRIVATE KEY from environment (Render: Environment → Add Secret)
const rawPrivateKey = process.env.WHATSAPP_RSA_PRIVATE_KEY;
const PRIVATE_KEY = rawPrivateKey ? rawPrivateKey.replace(/\\n/g, '\n') : undefined;

app.post('/flows-crypto', (req, res) => {
  try {
    const { encrypted_flow_data, encrypted_aes_key, initial_vector, reply } = req.body ?? {};
    if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
      return res.status(400).json({ error: 'missing fields' });
    }
    if (!PRIVATE_KEY) {
      return res.status(500).json({ error: 'missing_private_key' });
    }

    // 1) Decrypt AES key (RSA-OAEP SHA-256)
    const aesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(encrypted_aes_key, 'base64')
    );

    // 2) Decrypt payload (AES-128/192/256-CBC depending on key size)
    const ivBuffer = Buffer.from(initial_vector, 'base64');
    const dataBuffer = Buffer.from(encrypted_flow_data, 'base64');

    // Validate IV length (AES block size is 16 bytes)
    if (ivBuffer.length !== 16) {
      return res.status(421).json({ error: 'invalid_iv_length' });
    }

    // Resolve AES algorithm from session key length
    let algorithm;
    if (aesKey.length === 16) algorithm = 'aes-128-cbc';
    else if (aesKey.length === 24) algorithm = 'aes-192-cbc';
    else if (aesKey.length === 32) algorithm = 'aes-256-cbc';
    else return res.status(421).json({ error: 'invalid_aes_key_length' });

    const decipher = crypto.createDecipheriv(algorithm, aesKey, ivBuffer);
    const plaintext = Buffer.concat([decipher.update(dataBuffer), decipher.final()]);
    const flowRequest = JSON.parse(plaintext.toString('utf8'));

    // Build clear response (or use req.body.reply for a specific response)
    const clearResponse = reply ?? { version: '3.0', data: { pong: true, echo: flowRequest } };

    // 3) Re-encrypt response WITH THE SAME AES + IV
    const cipher = crypto.createCipheriv(algorithm, aesKey, ivBuffer);
    const encryptedResponse = Buffer.concat([
      cipher.update(Buffer.from(JSON.stringify(clearResponse), 'utf8')),
      cipher.final()
    ]);

    // 4) Return in the expected WhatsApp format
    return res.json({
      encrypted_flow_data: encryptedResponse.toString('base64'),
      encrypted_aes_key,
      initial_vector
    });
  } catch (error) {
    console.error(error);
    // 421 is the indicated status when decryption fails
    return res.status(421).json({ error: 'decryption_failed' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true }));

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`crypto-helper running on :${port}`);
});


