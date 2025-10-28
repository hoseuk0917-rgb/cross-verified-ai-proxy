// src/utils/db.js
const { Pool } = require('pg');

// PostgreSQL 연결 풀 설정
const pool = new Pool({
  connectionString: process.env.DATABASE_URL_INTERNAL || process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// 연결 테스트
pool.on('connect', () => {
  console.log('✅ PostgreSQL connected successfully');
});

pool.on('error', (err) => {
  console.error('❌ PostgreSQL connection error:', err);
});

// 데이터베이스 초기화 함수
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. User 테이블
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        google_id VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255),
        profile_picture TEXT,
        refresh_token TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        last_login TIMESTAMP DEFAULT NOW(),
        is_active BOOLEAN DEFAULT TRUE
      );
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
    `);

    // 2. ApiKey 테이블 (AES-256-GCM 암호화된 키 저장)
    await client.query(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        service VARCHAR(50) NOT NULL,
        encrypted_key TEXT NOT NULL,
        iv TEXT NOT NULL,
        auth_tag TEXT NOT NULL,
        key_index SMALLINT DEFAULT 1,
        is_active BOOLEAN DEFAULT TRUE,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, service, key_index)
      );
      CREATE INDEX IF NOT EXISTS idx_api_keys_user_service ON api_keys(user_id, service);
    `);

    // 3. Request Logs 테이블
    await client.query(`
      CREATE TABLE IF NOT EXISTS request_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        service VARCHAR(50) NOT NULL,
        endpoint TEXT NOT NULL,
        method VARCHAR(10),
        status_code INTEGER,
        latency_ms INTEGER,
        request_size INTEGER,
        response_size INTEGER,
        success BOOLEAN,
        error_message TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_logs_user_service ON request_logs(user_id, service);
      CREATE INDEX IF NOT EXISTS idx_logs_created_at ON request_logs(created_at);
    `);

    // 4. Naver Whitelist 테이블
    await client.query(`
      CREATE TABLE IF NOT EXISTS nav_whitelist (
        id SERIAL PRIMARY KEY,
        tier SMALLINT NOT NULL CHECK (tier BETWEEN 1 AND 5),
        name TEXT NOT NULL,
        domain TEXT,
        q_score FLOAT DEFAULT 1.0 CHECK (q_score BETWEEN 0 AND 1),
        active BOOLEAN DEFAULT TRUE,
        last_verified TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(name, domain)
      );
      CREATE INDEX IF NOT EXISTS idx_nav_whitelist_tier ON nav_whitelist(tier);
      CREATE INDEX IF NOT EXISTS idx_nav_whitelist_active ON nav_whitelist(active);
    `);

    // 5. Monitoring Logs 테이블 (Naver API Latency 추적)
    await client.query(`
      CREATE TABLE IF NOT EXISTS monitoring_logs (
        id SERIAL PRIMARY KEY,
        service VARCHAR(50) NOT NULL,
        metric_name VARCHAR(100) NOT NULL,
        metric_value FLOAT NOT NULL,
        unit VARCHAR(20),
        metadata JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_monitoring_service ON monitoring_logs(service);
      CREATE INDEX IF NOT EXISTS idx_monitoring_created_at ON monitoring_logs(created_at);
    `);

    // 6. Audit Logs 테이블 (보안 감사)
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(100) NOT NULL,
        resource VARCHAR(100),
        details JSONB,
        ip_address INET,
        user_agent TEXT,
        success BOOLEAN,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
      CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at);
    `);

    // Naver Whitelist 초기 데이터 삽입 (53개 매체)
    await initializeNaverWhitelist(client);

    await client.query('COMMIT');
    console.log('✅ Database schema initialized successfully');
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Database initialization failed:', error);
    throw error;
  } finally {
    client.release();
  }
}

// Naver Whitelist 초기 데이터
async function initializeNaverWhitelist(client) {
  const whitelistData = [
    // Tier 1: 공공 및 공영 언론
    { tier: 1, name: '연합뉴스', domain: 'yna.co.kr', q_score: 0.95 },
    { tier: 1, name: 'KBS', domain: 'kbs.co.kr', q_score: 0.93 },
    { tier: 1, name: 'MBC', domain: 'imbc.com', q_score: 0.92 },
    { tier: 1, name: 'SBS', domain: 'sbs.co.kr', q_score: 0.92 },
    { tier: 1, name: 'YTN', domain: 'ytn.co.kr', q_score: 0.91 },
    { tier: 1, name: '뉴스1', domain: 'news1.kr', q_score: 0.90 },
    
    // Tier 2: 종합 일간지
    { tier: 2, name: '조선일보', domain: 'chosun.com', q_score: 0.88 },
    { tier: 2, name: '중앙일보', domain: 'joongang.co.kr', q_score: 0.88 },
    { tier: 2, name: '동아일보', domain: 'donga.com', q_score: 0.87 },
    { tier: 2, name: '한겨레', domain: 'hani.co.kr', q_score: 0.87 },
    { tier: 2, name: '경향신문', domain: 'khan.co.kr', q_score: 0.86 },
    { tier: 2, name: '국민일보', domain: 'kmib.co.kr', q_score: 0.85 },
    { tier: 2, name: '세계일보', domain: 'segye.com', q_score: 0.85 },
    { tier: 2, name: '한국일보', domain: 'hankookilbo.com', q_score: 0.85 },
    { tier: 2, name: '서울신문', domain: 'seoul.co.kr', q_score: 0.84 },
    
    // Tier 3: 경제·과학기술 전문지
    { tier: 3, name: '매일경제', domain: 'mk.co.kr', q_score: 0.86 },
    { tier: 3, name: '한국경제', domain: 'hankyung.com', q_score: 0.86 },
    { tier: 3, name: '전자신문', domain: 'etnews.com', q_score: 0.85 },
    { tier: 3, name: 'ZDNet Korea', domain: 'zdnet.co.kr', q_score: 0.84 },
    { tier: 3, name: '동아사이언스', domain: 'dongascience.com', q_score: 0.83 },
    { tier: 3, name: '디지털타임스', domain: 'dt.co.kr', q_score: 0.83 },
    { tier: 3, name: '서울경제', domain: 'sedaily.com', q_score: 0.82 },
    { tier: 3, name: '아시아경제', domain: 'asiae.co.kr', q_score: 0.82 },
    { tier: 3, name: '파이낸셜뉴스', domain: 'fnnews.com', q_score: 0.82 },
    { tier: 3, name: '머니투데이', domain: 'mt.co.kr', q_score: 0.81 },
    
    // Tier 4: 정부·국책 연구기관
    { tier: 4, name: '과학기술정보통신부', domain: 'msit.go.kr', q_score: 0.94 },
    { tier: 4, name: '국토교통부', domain: 'molit.go.kr', q_score: 0.93 },
    { tier: 4, name: 'KISTI', domain: 'kisti.re.kr', q_score: 0.92 },
    { tier: 4, name: 'ETRI', domain: 'etri.re.kr', q_score: 0.92 },
    { tier: 4, name: 'KARI', domain: 'kari.re.kr', q_score: 0.91 },
    { tier: 4, name: 'KAIST', domain: 'kaist.ac.kr', q_score: 0.90 },
    { tier: 4, name: 'KAIA', domain: 'kaia.re.kr', q_score: 0.89 },
    
    // Tier 5: 해외 주요 통신사
    { tier: 5, name: 'BBC', domain: 'bbc.com', q_score: 0.96 },
    { tier: 5, name: 'Reuters', domain: 'reuters.com', q_score: 0.96 },
    { tier: 5, name: 'Bloomberg', domain: 'bloomberg.com', q_score: 0.95 },
    { tier: 5, name: 'CNN', domain: 'cnn.com', q_score: 0.94 },
    { tier: 5, name: 'AFP', domain: 'afp.com', q_score: 0.94 },
    { tier: 5, name: 'The Wall Street Journal', domain: 'wsj.com', q_score: 0.93 },
    { tier: 5, name: 'The New York Times', domain: 'nytimes.com', q_score: 0.93 },
    { tier: 5, name: 'The Guardian', domain: 'theguardian.com', q_score: 0.92 },
    { tier: 5, name: 'Associated Press', domain: 'apnews.com', q_score: 0.92 },
    { tier: 5, name: 'Financial Times', domain: 'ft.com', q_score: 0.91 },
    
    // 추가 국내 언론
    { tier: 2, name: '문화일보', domain: 'munhwa.com', q_score: 0.84 },
    { tier: 3, name: '헤럴드경제', domain: 'heraldk.com', q_score: 0.81 },
    { tier: 3, name: '이데일리', domain: 'edaily.co.kr', q_score: 0.81 },
    { tier: 3, name: '뉴시스', domain: 'newsis.com', q_score: 0.80 },
    { tier: 3, name: '뉴스핌', domain: 'newspim.com', q_score: 0.80 },
    { tier: 3, name: '연합인포맥스', domain: 'yonhapinfomax.co.kr', q_score: 0.80 },
    { tier: 3, name: '이투데이', domain: 'etoday.co.kr', q_score: 0.79 },
    { tier: 3, name: '더벨', domain: 'thebell.co.kr', q_score: 0.78 },
    { tier: 3, name: '비즈니스워치', domain: 'bizwatch.co.kr', q_score: 0.78 }
  ];

  for (const media of whitelistData) {
    await client.query(`
      INSERT INTO nav_whitelist (tier, name, domain, q_score, active)
      VALUES ($1, $2, $3, $4, true)
      ON CONFLICT (name, domain) DO UPDATE
      SET q_score = EXCLUDED.q_score, last_verified = NOW()
    `, [media.tier, media.name, media.domain, media.q_score]);
  }

  console.log('✅ Naver Whitelist initialized with 53 media outlets');
}

// DB 쿼리 헬퍼 함수들
async function query(text, params) {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    // console.log('Query executed', { text, duration, rows: res.rowCount });
    return res;
  } catch (error) {
    console.error('Query error:', { text, error: error.message });
    throw error;
  }
}

async function getClient() {
  return await pool.connect();
}

// 로그 정리 함수 (오래된 로그 자동 삭제)
async function cleanupOldLogs() {
  try {
    // Request logs: 30일 이상 삭제
    await pool.query(`
      DELETE FROM request_logs 
      WHERE created_at < NOW() - INTERVAL '30 days'
    `);

    // Audit logs: 90일 이상 삭제
    await pool.query(`
      DELETE FROM audit_logs 
      WHERE created_at < NOW() - INTERVAL '90 days'
    `);

    // Monitoring logs: 7일 이상 삭제
    await pool.query(`
      DELETE FROM monitoring_logs 
      WHERE created_at < NOW() - INTERVAL '7 days'
    `);

    console.log('✅ Old logs cleaned up successfully');
  } catch (error) {
    console.error('❌ Log cleanup failed:', error);
  }
}

module.exports = {
  pool,
  query,
  getClient,
  initializeDatabase,
  cleanupOldLogs
};
