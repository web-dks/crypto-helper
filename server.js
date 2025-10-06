import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';

const app = express();
// Capture raw body for signature verification while still parsing JSON
app.use(
  express.json({
    limit: '2mb',
    verify: (req, _res, buf) => {
      // Preserve raw body for HMAC validation (Meta X-Hub-Signature-256)
      req.rawBody = Buffer.from(buf);
    }
  })
);

// Load PRIVATE KEY from environment (Render: Environment → Add Secret)
const rawPrivateKey = process.env.WHATSAPP_RSA_PRIVATE_KEY;
const PRIVATE_KEY = rawPrivateKey ? rawPrivateKey.replace(/\\n/g, '\n') : undefined;
const PRIVATE_PASSPHRASE = process.env.WHATSAPP_RSA_PASSPHRASE;
const APP_SECRET_NEW = process.env.WHATSAPP_APP_SECRET; // current secret
const APP_SECRET_OLD = process.env.WHATSAPP_APP_SECRET_OLD; // optional for rotation

// Normalize base64 or base64url and decode safely
function decodeBase64Flexible(input) {
  if (typeof input !== 'string') throw new Error('invalid_base64');
  let normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const remainder = normalized.length % 4;
  if (remainder === 2) normalized += '==';
  else if (remainder === 3) normalized += '=';
  else if (remainder === 1) throw new Error('invalid_base64');
  return Buffer.from(normalized, 'base64');
}

function timingSafeEq(a, b) {
  const aBuf = Buffer.isBuffer(a) ? a : Buffer.from(String(a));
  const bBuf = Buffer.isBuffer(b) ? b : Buffer.from(String(b));
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function verifyMetaSignatureIfConfigured(req) {
  if (!APP_SECRET_NEW && !APP_SECRET_OLD) return { ok: true };
  const header = req.get('x-hub-signature-256') || '';
  const prefix = 'sha256=';
  if (!header.startsWith(prefix)) return { ok: false, error: 'missing_or_malformed_signature' };
  const body = req.rawBody || Buffer.from('');
  const compute = (secret) =>
    `${prefix}${crypto.createHmac('sha256', secret).update(body).digest('hex')}`;

  const expectedNew = APP_SECRET_NEW ? compute(APP_SECRET_NEW) : undefined;
  const expectedOld = APP_SECRET_OLD ? compute(APP_SECRET_OLD) : undefined;

  if (expectedNew && timingSafeEq(header, expectedNew)) return { ok: true };
  if (expectedOld && timingSafeEq(header, expectedOld)) return { ok: true };
  return { ok: false, error: 'invalid_signature' };
}

function invertBits(buffer) {
  const out = Buffer.allocUnsafe(buffer.length);
  for (let i = 0; i < buffer.length; i++) out[i] = (~buffer[i]) & 0xff;
  return out;
}

function resolveAesAlgo(keyLength, mode) {
  // mode: 'gcm' | 'cbc'
  if (keyLength === 16) return `aes-128-${mode}`;
  if (keyLength === 24) return `aes-192-${mode}`;
  if (keyLength === 32) return `aes-256-${mode}`;
  return null;
}

app.post('/flows-crypto', (req, res) => {
  try {
    // 0) Optional: Verify Meta HMAC signature if app secrets are configured
    const sig = verifyMetaSignatureIfConfigured(req);
    if (!sig.ok) return res.status(401).json({ error: sig.error });

    const { encrypted_flow_data, encrypted_aes_key, initial_vector, reply } = req.body ?? {};
    if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
      return res.status(400).json({ error: 'missing fields' });
    }
    if (!PRIVATE_KEY) {
      return res.status(500).json({ error: 'missing_private_key' });
    }

    // 1) Decrypt AES key (RSA-OAEP SHA-256)
    const privateKeyObject = crypto.createPrivateKey({
      key: PRIVATE_KEY,
      format: 'pem',
      passphrase: PRIVATE_PASSPHRASE
    });
    let encAesKeyBuffer;
    try {
      encAesKeyBuffer = decodeBase64Flexible(encrypted_aes_key);
    } catch {
      return res.status(421).json({ error: 'invalid_base64_encrypted_aes_key' });
    }
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKeyObject,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      encAesKeyBuffer
    );

    // 2) Decrypt payload (prefer AES-GCM v3.0; fallback to CBC)
    let ivBuffer;
    let dataBuffer;
    try {
      ivBuffer = decodeBase64Flexible(initial_vector);
    } catch {
      return res.status(421).json({ error: 'invalid_base64_initial_vector' });
    }
    try {
      dataBuffer = decodeBase64Flexible(encrypted_flow_data);
    } catch {
      return res.status(421).json({ error: 'invalid_base64_encrypted_flow_data' });
    }
    
    if (ivBuffer.length !== 16) {
      return res.status(421).json({ error: 'invalid_iv_length' });
    }
    if (![16, 24, 32].includes(aesKey.length)) {
      return res.status(421).json({ error: 'invalid_aes_key_length' });
    }

    // Try GCM first (v3.0): dataBuffer = ciphertext||tag (tag last 16 bytes)
    let flowRequest;
    let usedMode = 'gcm';
    try {
      const tagLength = 16;
      if (dataBuffer.length <= tagLength) throw new Error('too_short');
      const ciphertext = dataBuffer.subarray(0, dataBuffer.length - tagLength);
      const authTag = dataBuffer.subarray(dataBuffer.length - tagLength);
      const algoGcm = resolveAesAlgo(aesKey.length, 'gcm');
      if (!algoGcm) throw new Error('bad_key');
      const decipherGcm = crypto.createDecipheriv(algoGcm, aesKey, ivBuffer);
      decipherGcm.setAuthTag(authTag);
      const plainGcm = Buffer.concat([decipherGcm.update(ciphertext), decipherGcm.final()]);
      flowRequest = JSON.parse(plainGcm.toString('utf8'));
    } catch (e) {
      // Fallback to CBC for backward compatibility
      usedMode = 'cbc';
      const algoCbc = resolveAesAlgo(aesKey.length, 'cbc');
      try {
        const decipherCbc = crypto.createDecipheriv(algoCbc, aesKey, ivBuffer);
        const plainCbc = Buffer.concat([decipherCbc.update(dataBuffer), decipherCbc.final()]);
        flowRequest = JSON.parse(plainCbc.toString('utf8'));
      } catch {
        throw e; // propagate original GCM error to return 421
      }
    }

    // Build clear response (Meta Health Check or normal)
    let clearResponse;
    if (
      flowRequest?.action === 'ping' ||
      flowRequest?.type === 'health_check' ||
      flowRequest?.data?.health_check === true
    ) {
      // Health Check expected by Meta (no version field)
      clearResponse = { data: { status: 'active' } };
    } else if (typeof reply !== 'undefined') {fazer 
      clearResponse = reply;
    } else {
      clearResponse = { data: { ok: true } };
    }

    // Optional debug echo: include decrypted request and the data being sent
    const shouldEcho = (req.get('x-debug-echo') === '1') || (process.env.ECHO_REQUEST_IN_RESPONSE === '1');
    const responsePayload = shouldEcho
      ? { data: clearResponse?.data, request: flowRequest }
      : clearResponse;

    // 3) Encrypt response
    if (usedMode === 'gcm') {
      const algoGcm = resolveAesAlgo(aesKey.length, 'gcm');
      const responseIv = invertBits(ivBuffer); // invert bits for response
      const cipherGcm = crypto.createCipheriv(algoGcm, aesKey, responseIv);
      const enc = Buffer.concat([
        cipherGcm.update(Buffer.from(JSON.stringify(responsePayload), 'utf8')),
        cipherGcm.final()
      ]);
      const tag = cipherGcm.getAuthTag();
      const out = Buffer.concat([enc, tag]).toString('base64');
      res.set('Content-Type', 'text/plain');
      return res.send(out);
    }

    // CBC legacy response with same AES + IV
    const algoCbc = resolveAesAlgo(aesKey.length, 'cbc');
    const cipherCbc = crypto.createCipheriv(algoCbc, aesKey, ivBuffer);
    const encryptedResponse = Buffer.concat([
      cipherCbc.update(Buffer.from(JSON.stringify(responsePayload), 'utf8')),
      cipherCbc.final()
    ]);
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


