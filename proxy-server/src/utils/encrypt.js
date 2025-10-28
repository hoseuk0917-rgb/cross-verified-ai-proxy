// src/utils/encrypt.js
const crypto = require('crypto');

// 환경변수에서 암호화 키 가져오기 (32바이트 = 256비트)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // GCM 모드의 IV 길이
const AUTH_TAG_LENGTH = 16; // GCM 인증 태그 길이

/**
 * AES-256-GCM으로 데이터 암호화
 * @param {string} text - 암호화할 평문
 * @returns {object} - { encryptedData, iv, authTag }
 */
function encrypt(text) {
  try {
    // IV (Initialization Vector) 생성
    const iv = crypto.randomBytes(IV_LENGTH);
    
    // 암호화 키를 Buffer로 변환 (hex string -> Buffer)
    const key = Buffer.from(ENCRYPTION_KEY.slice(0, 64), 'hex');
    
    // Cipher 생성
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    // 암호화 수행
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // 인증 태그 가져오기 (무결성 검증용)
    const authTag = cipher.getAuthTag();
    
    return {
      encryptedData: encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  } catch (error) {
    console.error('❌ Encryption error:', error);
    throw new Error('Encryption failed');
  }
}

/**
 * AES-256-GCM으로 데이터 복호화
 * @param {string} encryptedData - 암호화된 데이터 (hex)
 * @param {string} ivHex - IV (hex)
 * @param {string} authTagHex - 인증 태그 (hex)
 * @returns {string} - 복호화된 평문
 */
function decrypt(encryptedData, ivHex, authTagHex) {
  try {
    // 암호화 키를 Buffer로 변환
    const key = Buffer.from(ENCRYPTION_KEY.slice(0, 64), 'hex');
    
    // IV와 인증 태그를 Buffer로 변환
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    
    // Decipher 생성
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    
    // 인증 태그 설정 (무결성 검증)
    decipher.setAuthTag(authTag);
    
    // 복호화 수행
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('❌ Decryption error:', error);
    throw new Error('Decryption failed - data may be corrupted or tampered');
  }
}

/**
 * SHA-256 해시 생성
 * @param {string} data - 해시할 데이터
 * @returns {string} - SHA-256 해시 (hex)
 */
function hash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * HMAC-SHA256 서명 생성
 * @param {string} data - 서명할 데이터
 * @param {string} secret - HMAC 비밀키
 * @returns {string} - HMAC 서명 (hex)
 */
function hmacSign(data, secret = process.env.HMAC_SECRET) {
  if (!secret) {
    throw new Error('HMAC_SECRET not configured');
  }
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

/**
 * HMAC 서명 검증
 * @param {string} data - 원본 데이터
 * @param {string} signature - 검증할 서명
 * @param {string} secret - HMAC 비밀키
 * @returns {boolean} - 서명 유효 여부
 */
function hmacVerify(data, signature, secret = process.env.HMAC_SECRET) {
  if (!secret) {
    throw new Error('HMAC_SECRET not configured');
  }
  const expectedSignature = hmacSign(data, secret);
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex')
  );
}

/**
 * 랜덤 토큰 생성
 * @param {number} length - 바이트 길이 (기본 32)
 * @returns {string} - 랜덤 토큰 (hex)
 */
function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * PBKDF2 키 유도 (비밀번호 해싱용)
 * @param {string} password - 비밀번호
 * @param {string} salt - Salt (없으면 자동 생성)
 * @returns {object} - { hash, salt }
 */
function deriveKey(password, salt = null) {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(
    password,
    actualSalt,
    100000, // iterations
    64,     // key length
    'sha512'
  ).toString('hex');
  
  return {
    hash,
    salt: actualSalt
  };
}

/**
 * 비밀번호 검증
 * @param {string} password - 입력된 비밀번호
 * @param {string} hash - 저장된 해시
 * @param {string} salt - Salt
 * @returns {boolean} - 비밀번호 일치 여부
 */
function verifyPassword(password, hash, salt) {
  const derived = deriveKey(password, salt);
  return crypto.timingSafeEqual(
    Buffer.from(hash, 'hex'),
    Buffer.from(derived.hash, 'hex')
  );
}

// 초기화 체크
if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length < 64) {
  console.warn('⚠️  WARNING: ENCRYPTION_KEY is not properly configured. Using auto-generated key (not recommended for production)');
}

module.exports = {
  encrypt,
  decrypt,
  hash,
  hmacSign,
  hmacVerify,
  generateToken,
  deriveKey,
  verifyPassword
};
