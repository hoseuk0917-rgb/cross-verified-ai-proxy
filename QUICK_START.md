# 빠른 시작 가이드 🚀

## 1️⃣ 설치

```bash
# 의존성 설치
npm install
```

## 2️⃣ 환경 설정

```bash
# .env 파일 생성
cp .env.template .env
```

`.env` 파일을 열어서 최소한 다음 값을 설정하세요:
```
PORT=3000
MASTER_PASSWORD=your-secure-password
```

## 3️⃣ 서버 실행

```bash
# 서버 시작
npm start
```

성공하면 다음 메시지가 표시됩니다:
```
╔══════════════════════════════════════════════════════════╗
║   Cross-Verified AI Proxy Server v9.7.7                  ║
║   Server running on http://localhost:3000               ║
╚══════════════════════════════════════════════════════════╝
```

## 4️⃣ 테스트

새 터미널을 열고:
```bash
# Ping 테스트
curl http://localhost:3000/ping

# 또는 전체 테스트 실행
node test.js
```

## 5️⃣ 주요 API 엔드포인트

### 서버 상태 확인
```bash
curl http://localhost:3000/ping
```

### TruthScore 계산
```bash
curl -X POST http://localhost:3000/api/truthscore/calculate \
  -H "Content-Type: application/json" \
  -d '{
    "engines": [
      {
        "name": "crossref",
        "isActive": true,
        "sourceDetected": true,
        "quality": 0.95,
        "keywordMatch": 0.85,
        "weight": 1.0,
        "deltaW": 1.0,
        "timeDelta": 0
      }
    ]
  }'
```

### 암호화/복호화
```bash
# 암호화
curl -X POST http://localhost:3000/api/keys/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "my-api-key",
    "masterPassword": "test-password"
  }'

# 복호화
curl -X POST http://localhost:3000/api/keys/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "encryptedData": {
      "encrypted": "...",
      "iv": "...",
      "salt": "...",
      "tag": "..."
    },
    "masterPassword": "test-password"
  }'
```

## 📱 Flutter 앱 연동

### HTTP 패키지 추가
```yaml
dependencies:
  http: ^1.1.0
```

### API 서비스 클래스
```dart
import 'dart:convert';
import 'package:http/http.dart' as http;

class CrossVerifyApi {
  final String baseUrl;
  
  CrossVerifyApi({this.baseUrl = 'http://localhost:3000'});
  
  Future<Map<String, dynamic>> ping() async {
    final response = await http.get(Uri.parse('$baseUrl/ping'));
    return json.decode(response.body);
  }
  
  Future<Map<String, dynamic>> calculateTruthScore(
    List<Map<String, dynamic>> engines
  ) async {
    final response = await http.post(
      Uri.parse('$baseUrl/api/truthscore/calculate'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode({'engines': engines}),
    );
    return json.decode(response.body);
  }
}
```

## 🔧 문제 해결

### 포트가 이미 사용 중인 경우
```bash
# 포트 확인
lsof -i :3000

# 다른 포트 사용 (.env 파일 수정)
PORT=3001
```

### npm install 오류
```bash
# 캐시 삭제 후 재설치
rm -rf node_modules package-lock.json
npm cache clean --force
npm install
```

## 📚 추가 문서

- `README.md` - 전체 프로젝트 설명
- `SUMMARY.md` - 프로젝트 요약
- `INSTALL.txt` - 설치 안내

## 💡 다음 단계

1. ✅ 프록시 서버 실행 확인
2. ✅ 기본 테스트 완료
3. 🔜 Gemini API Key 발급 및 등록
4. 🔜 Flutter 앱 개발 시작
5. 🔜 UI 구현 및 통합 테스트

---

**Cross-Verified AI v9.7.7** | 2025
