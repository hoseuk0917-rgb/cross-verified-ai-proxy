const crypto = require('crypto');

// AES-256-GCM 암호화 설정
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16;
const SALT_LENGTH = 64;
const TAG_LENGTH = 16;

/**
 * PBKDF2를 사용하여 마스터 키 생성
 * @param {string} password - 마스터 비밀번호
 * @param {Buffer} salt - Salt 값
 * @returns {Buffer} 파생된 키
 */
function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(
    password,
    salt,
    100000, // iterations
    KEY_LENGTH,
    'sha256'
  );
}

/**
 * API Key 암호화
 * @param {string} plaintext - 암호화할 텍스트 (API Key)
 * @param {string} masterPassword - 마스터 비밀번호
 * @returns {Object} 암호화된 데이터 (encrypted, iv, salt, tag)
 */
function encryptKey(plaintext, masterPassword) {
  try {
    // Salt 생성
    const salt = crypto.randomBytes(SALT_LENGTH);
    
    // 키 파생
    const key = deriveKey(masterPassword, salt);
    
    // IV 생성
    const iv = crypto.randomBytes(IV_LENGTH);
    
    // 암호화
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Authentication tag 획득
    const tag = cipher.getAuthTag();
    
    return {
      encrypted: encrypted,
      iv: iv.toString('hex'),
      salt: salt.toString('hex'),
      tag: tag.toString('hex')
    };
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt key');
  }
}

/**
 * API Key 복호화
 * @param {Object} encryptedData - 암호화된 데이터
 * @param {string} masterPassword - 마스터 비밀번호
 * @returns {string} 복호화된 텍스트
 */
function decryptKey(encryptedData, masterPassword) {
  try {
    const { encrypted, iv, salt, tag } = encryptedData;
    
    // 키 파생
    const key = deriveKey(masterPassword, Buffer.from(salt, 'hex'));
    
    // 복호화
    const decipher = crypto.createDecipheriv(
      ALGORITHM,
      key,
      Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt key');
  }
}

/**
 * UUID 생성
 * @returns {string} UUID v4
 */
function generateUUID() {
  return crypto.randomUUID();
}

/**
 * SHA-256 해시 생성
 * @param {string} data - 해시할 데이터
 * @returns {string} 해시 값
 */
function hashSHA256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = {
  encryptKey,
  decryptKey,
  generateUUID,
  hashSHA256
};
