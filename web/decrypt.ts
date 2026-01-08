/**
 * Decodes a base64url encoded string to a Uint8Array.
 * @param {string} base64url 
 * @returns {Uint8Array}
 */
function base64urlToUint8Array(base64url: string): Uint8Array {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Decodes a standard base64 string to a Uint8Array.
 * @param {string} base64 
 * @returns {Uint8Array}
 */
function base64ToUint8Array(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Decrypts a ciphertext blob or object using a given secret.
 * @param {any} ciphertext - The ciphertext as an object (LinkCardCipher) or ArrayBuffer.
 * @param {string} secret - The secret key as a base64url encoded string.
 * @returns {Promise<any>} - A promise that resolves to the decrypted and parsed JSON object.
 */
export async function decryptBlob(ciphertext: any, secret: string): Promise<any> {
  const keyBytes = base64urlToUint8Array(secret);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes as BufferSource,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  let iv: Uint8Array, data: Uint8Array;

  if (ciphertext instanceof ArrayBuffer || ciphertext instanceof Uint8Array) {
    const bytes = ciphertext instanceof ArrayBuffer ? new Uint8Array(ciphertext) : ciphertext;
    iv = bytes.slice(0, 12);
    data = bytes.slice(12);
  } else if (ciphertext.nonce && ciphertext.ct && ciphertext.tag) {
    iv = base64ToUint8Array(ciphertext.nonce);
    const ct = base64ToUint8Array(ciphertext.ct);
    const tag = base64ToUint8Array(ciphertext.tag);
    
    // Combine ciphertext and tag for Web Crypto API AES-GCM
    data = new Uint8Array(ct.length + tag.length);
    data.set(ct);
    data.set(tag, ct.length);
  } else {
    throw new Error("Invalid ciphertext format");
  }

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    data as BufferSource
  );

  const decoded = new TextDecoder().decode(decrypted);
  return JSON.parse(decoded);
}