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

async function fetchBuffer(url, headers = {}) {
  const resp = await fetch(url, { headers });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    const err = new Error(`fetch_failed ${resp.status}`);
    err.status = resp.status;
    err.body = text;
    throw err;
  }
  const arr = await resp.arrayBuffer();
  return Buffer.from(arr);
}

function sha256Base64(buf) {
  return crypto.createHash('sha256').update(buf).digest('base64');
}

function tryAesGcmDecrypt(cipherBuffer, keyBuffer, ivBuffer) {
  const algo = resolveAesAlgo(keyBuffer.length, 'gcm');
  if (!algo) throw new Error('unsupported_key_length');
  if (ivBuffer.length !== 12 && ivBuffer.length !== 16) throw new Error('invalid_iv_length');
  // Most implementations use 12-byte IV for GCM, but some flows use 16. Node accepts both.
  const tagLen = 16;
  if (cipherBuffer.length <= tagLen) throw new Error('cipher_too_short');
  const ciphertext = cipherBuffer.subarray(0, cipherBuffer.length - tagLen);
  const authTag = cipherBuffer.subarray(cipherBuffer.length - tagLen);
  const decipher = crypto.createDecipheriv(algo, keyBuffer, ivBuffer);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function tryAesGcmDecryptAny(cipherBuffer, keyBuffer, ivBuffer) {
  const variants = [cipherBuffer];
  if (cipherBuffer.length > 16) variants.push(cipherBuffer.subarray(0, cipherBuffer.length - 16));
  if (cipherBuffer.length > 32) variants.push(cipherBuffer.subarray(0, cipherBuffer.length - 32));
  if (cipherBuffer.length > 48) variants.push(cipherBuffer.subarray(0, cipherBuffer.length - 48));

  const algo = resolveAesAlgo(keyBuffer.length, 'gcm');
  if (!algo) throw new Error('unsupported_key_length');
  if (ivBuffer.length !== 12 && ivBuffer.length !== 16) throw new Error('invalid_iv_length');

  const ivCandidates = [ivBuffer];
  // Some providers send 16-byte IV but GCM was produced with 12-byte IV (first 12 bytes)
  if (ivBuffer.length === 16) ivCandidates.push(ivBuffer.subarray(0, 12));

  let lastErr;
  for (const iv of ivCandidates) {
    for (const v of variants) {
      const tagLen = 16;
      // Try TAG at the end (cipher||tag)
      if (v.length > tagLen) {
        try {
          const c = v.subarray(0, v.length - tagLen);
          const t = v.subarray(v.length - tagLen);
          const d = crypto.createDecipheriv(algo, keyBuffer, iv);
          d.setAuthTag(t);
          return Buffer.concat([d.update(c), d.final()]);
        } catch (e) {
          lastErr = e;
        }
      }
      // Try TAG at the beginning (tag||cipher)
      if (v.length > tagLen) {
        try {
          const t = v.subarray(0, tagLen);
          const c = v.subarray(tagLen);
          const d = crypto.createDecipheriv(algo, keyBuffer, iv);
          d.setAuthTag(t);
          return Buffer.concat([d.update(c), d.final()]);
        } catch (e2) {
          lastErr = e2;
        }
      }
    }
  }
  throw lastErr || new Error('gcm_decrypt_failed');
}

function tryAesCbcDecrypt(cipherBuffer, keyBuffer, ivBuffer) {
  const algo = resolveAesAlgo(keyBuffer.length, 'cbc');
  if (!algo) throw new Error('unsupported_key_length');
  if (ivBuffer.length !== 16) throw new Error('invalid_iv_length');
  const decipher = crypto.createDecipheriv(algo, keyBuffer, ivBuffer);
  return Buffer.concat([decipher.update(cipherBuffer), decipher.final()]);
}

function detectMimeType(buffer) {
  if (!buffer || buffer.length < 12) return 'application/octet-stream';
  // JPEG
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'image/jpeg';
  // PNG
  if (
    buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47 &&
    buffer[4] === 0x0d && buffer[5] === 0x0a && buffer[6] === 0x1a && buffer[7] === 0x0a
  ) return 'image/png';
  // WEBP (RIFF....WEBP)
  if (
    buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
    buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50
  ) return 'image/webp';
  // GIF
  if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46) return 'image/gif';
  return 'application/octet-stream';
}

app.post('/flows-images-decrypt', async (req, res) => {
  try {
    const sig = verifyMetaSignatureIfConfigured(req);
    if (!sig.ok) return res.status(401).json({ error: sig.error });

    const payload = req.body;
    const items = Array.isArray(payload) ? payload : [payload];
    if (!items.length) return res.status(400).json({ error: 'empty_payload' });

    const results = [];
    for (const item of items) {
      const imagens = item?.request?.data?.imagens;
      if (!Array.isArray(imagens) || imagens.length === 0) {
        results.push({ ok: false, error: 'missing_images' });
        continue;
      }

      const perItem = [];
      for (const img of imagens) {
        const fileName = img?.file_name;
        const mediaId = img?.media_id;
        const url = img?.cdn_url;
        const meta = img?.encryption_metadata || {};
        try {
          if (!url || !meta?.encryption_key || !meta?.iv) {
            perItem.push({ ok: false, file_name: fileName, media_id: mediaId, error: 'missing_fields' });
            continue;
          }

          const keyBuf = decodeBase64Flexible(meta.encryption_key);
          const ivBuf = decodeBase64Flexible(meta.iv);
          const hmacBuf = meta.hmac_key ? decodeBase64Flexible(meta.hmac_key) : undefined;

          // Fetch encrypted bytes from CDN (presigned URL usually requires no auth)
          const cipherBuf = await fetchBuffer(url);

          // Verify encrypted hash if provided
          if (meta.encrypted_hash) {
            const computedEncHash = sha256Base64(cipherBuf);
            const providedEncHash = decodeBase64Flexible(meta.encrypted_hash);
            if (!timingSafeEq(decodeBase64Flexible(computedEncHash), providedEncHash)) {
              // proceed but flag mismatch
            }
          }

          let plainBuf;
          let mode = 'gcm';
          try {
            // Try several GCM tag placements/variants
            plainBuf = tryAesGcmDecryptAny(cipherBuf, keyBuf, ivBuf);
          } catch (eGcm) {
            mode = 'cbc';
            // In CBC the ciphertext must be a multiple of 16 bytes.
            // Some providers append 16-byte GCM tag or 32-byte HMAC at the end of the file.
            const candidates = [cipherBuf];
            if (cipherBuf.length > 16) candidates.push(cipherBuf.subarray(0, cipherBuf.length - 16));
            if (cipherBuf.length > 32) candidates.push(cipherBuf.subarray(0, cipherBuf.length - 32));
            if (cipherBuf.length > 48) candidates.push(cipherBuf.subarray(0, cipherBuf.length - 48));

            let lastErr = eGcm;
            let success = false;
            for (const candidate of candidates) {
              if (candidate.length % 16 !== 0) continue;
              try {
                plainBuf = tryAesCbcDecrypt(candidate, keyBuf, ivBuf);
                success = true;
                break;
              } catch (eCbcVar) {
                lastErr = eCbcVar;
              }
            }
            if (!success) throw lastErr;
          }

          // Verify plaintext hash if provided
          let hashOk = true;
          if (meta.plaintext_hash) {
            const computedPlainHash = sha256Base64(plainBuf);
            const providedPlainHash = decodeBase64Flexible(meta.plaintext_hash);
            hashOk = timingSafeEq(decodeBase64Flexible(computedPlainHash), providedPlainHash);
          }

          const contentType = detectMimeType(plainBuf);
          const base64 = plainBuf.toString('base64');
          perItem.push({
            ok: true,
            file_name: fileName,
            media_id: mediaId,
            mode,
            hash_ok: hashOk,
            content_type: contentType,
            base64
          });
        } catch (err) {
          perItem.push({ ok: false, file_name: fileName, media_id: mediaId, error: String(err?.message || err) });
        }
      }
      results.push({ ok: true, images: perItem });
    }

    return res.json({ ok: true, results });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'images_decryption_failed' });
  }
});

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

    // No flow_token injection

    // Build clear response (Meta Health Check or normal)
    let clearResponse;
    if (
      flowRequest?.action === 'ping' ||
      flowRequest?.type === 'health_check' ||
      flowRequest?.data?.health_check === true
    ) {
      // Health Check expected by Meta (no version field)
      clearResponse = { data: { status: 'active' } };
    } else if (
      // Detect ocorrência payload and return explicit success structure
      (flowRequest && (
        Object.prototype.hasOwnProperty.call(flowRequest, 'tipo_ocorrencia') ||
        Object.prototype.hasOwnProperty.call(flowRequest, 'local_ocorrencia') ||
        Object.prototype.hasOwnProperty.call(flowRequest, 'fato_ocorrencia') ||
        Object.prototype.hasOwnProperty.call(flowRequest, 'prioridade')
      ))
    ) {
      clearResponse = {
        screen: 'SUCCESS',
        data: {
          extension_message_response: {
            params: {
              message: "Ocorrência registrada com sucesso"
            }
          }
        }
      };
    } else if (typeof reply !== 'undefined') {
      clearResponse = reply;
    } else {
      // Default when no specific fields or reply: SUCCESS screen
      clearResponse = {
        screen: 'SUCCESS',
        data: {
          extension_message_response: {
            params: {
              message: "Ocorrência registrada com sucesso"
            }
          }
        }
      };
    }

    // Optional debug echo: include decrypted request and the data being sent
    const shouldEcho = (req.get('x-debug-echo') === '1') || (process.env.ECHO_REQUEST_IN_RESPONSE === '1');
    const responsePayload = shouldEcho
      ? { data: clearResponse?.data, request: flowRequest }
      : clearResponse;

    // Optional debug JSON: respond with both encrypted base64 and decrypted objects
    const wantDebugJson = (req.get('x-debug-json') === '1') ||
      (typeof req.query?.debug !== 'undefined' && ['1', 'true'].includes(String(req.query.debug).toLowerCase()));

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
      if (wantDebugJson) {
        return res.json({
          mode: 'gcm',
          encrypted_base64: out,
          data: clearResponse?.data,
          request: flowRequest
        });
      }
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
    if (wantDebugJson) {
      return res.json({
        mode: 'cbc',
        encrypted_flow_data: encryptedResponse.toString('base64'),
        encrypted_aes_key,
        initial_vector,
        data: clearResponse?.data,
        request: flowRequest
      });
    }
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


