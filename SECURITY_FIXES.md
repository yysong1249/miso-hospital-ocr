# 🔒 미소 병원 3-Tier 웹 프로젝트 보안 강화 내역

원본(취약점 실습용) 프로젝트에서 발견된 11건의 취약점을 전부 수정한 안전한 버전입니다.
원본은 `miso-hospital-3tier/`, 수정본은 `miso-hospital-3tier-secure/`에 각각 보존되어 있어 대조 확인이 가능합니다.

## 실행 방법 (수정본)

```bash
cd miso-hospital-3tier-secure/was
npm install
node seed.js      # 더미 계정/게시글 생성 (비밀번호 해시·주민번호 암호화는 이 스크립트가 처리)
node server.js

cd ../frontend
python3 -m http.server 5500
```

환경변수(선택, 운영 배포 시 필수): `SESSION_SECRET`, `RRN_ENCRYPTION_KEY`(32바이트 hex), `FRONTEND_ORIGIN`, `USE_HTTPS=true`

---

## 1. SQL Injection → Prepared Statement 적용

| | 원본 | 수정본 |
|---|---|---|
| 파일 | `was/routes/auth.js` | 동일 |
| 문제 | 입력값을 쿼리 문자열에 직접 결합 | 파라미터 바인딩(`?`)으로 입력값과 쿼리 구조 분리 |

**수정 전**
```js
const query = `SELECT * FROM patients WHERE username = '${username}' AND password = '${password}'`;
const [rows] = await pool.query(query);
```

**수정 후**
```js
const [rows] = await pool.query("SELECT * FROM patients WHERE username = ?", [username]);
```

**왜 이렇게 고쳤나**: Prepared Statement는 쿼리 구조를 먼저 컴파일하고 사용자 입력은 "값"으로만 바인딩하므로, 입력값에 `' OR '1'='1`이 들어있어도 SQL 문법으로 해석되지 않고 리터럴 문자열로만 취급됩니다. 비밀번호는 아예 SQL 조건에서 빼고 애플리케이션 코드(bcrypt)에서 비교하도록 구조 자체를 바꿨습니다 (8번 항목과 연결).

---

## 2. Stored XSS → 서버 측 Sanitize + 클라이언트 textContent

| | 원본 | 수정본 |
|---|---|---|
| 파일 | `was/routes/board.js`, `frontend/js/board.js`, `frontend/js/view.js` | 동일 |
| 문제 | 저장 시 정제 없음 + 렌더링 시 `innerHTML` 사용 | 저장 전 `sanitize-html`로 태그 제거 + 렌더링은 `textContent` |

**수정 전 (서버)**
```js
const [result] = await pool.query(
  "INSERT INTO board_posts (patient_id, title, content) VALUES (?, ?, ?)",
  [req.session.patientId, title, content] // 검증/정제 없음
);
```

**수정 후 (서버)**
```js
const safeTitle = sanitizeHtml(title, { allowedTags: [], allowedAttributes: {} });
const safeContent = sanitizeHtml(content || "", { allowedTags: [], allowedAttributes: {} });
// safeTitle, safeContent를 저장
```

**수정 전 (클라이언트)**
```js
li.innerHTML = `<a href="view.html?patient_id=${post.patient_id}">${post.title}</a>`;
```

**수정 후 (클라이언트)**
```js
const a = document.createElement('a');
a.href = `view.html?patient_id=${encodeURIComponent(post.patient_id)}`;
a.textContent = post.title; // 텍스트로만 대입 - 스크립트 태그가 있어도 실행되지 않음
li.appendChild(a);
```

**왜 이렇게 고쳤나**: 저장 단계와 출력 단계 양쪽에 방어선을 뒀습니다 (Defense in Depth). 서버가 저장 전에 태그를 모두 제거하면 애초에 악성 스크립트가 DB에 남지 않고, 혹시 다른 경로로 스크립트가 섞여 들어오더라도 클라이언트가 `textContent`로만 대입하면 브라우저는 그 값을 "실행 가능한 HTML"이 아니라 "화면에 보여줄 문자열"로만 취급합니다. `view.js`도 동일한 방식(`textContent` 기반 DOM 조립)으로 교체했습니다.

---

## 3. BOLA / IDOR → 소유권 검증 추가

| | 원본 | 수정본 |
|---|---|---|
| 파일 | `was/routes/board.js` `GET /:patientId` | 동일 |
| 문제 | 로그인 여부만 확인, URL의 patientId 검증 안 함 | 세션 소유자와 URL 값 일치 여부 확인 후 불일치 시 403 |

**수정 전**
```js
router.get("/:patientId", async (req, res) => {
  if (!req.session.patientId) { /* 인증만 체크 */ }
  const [rows] = await pool.query(`... WHERE bp.patient_id = ?`, [req.params.patientId]);
  res.json(rows);
});
```

**수정 후**
```js
router.get("/:patientId", async (req, res) => {
  if (!req.session.patientId) {
    return res.status(401).json({ message: "로그인이 필요합니다." });
  }
  if (Number(req.params.patientId) !== req.session.patientId) {
    return res.status(403).json({ message: "접근 권한이 없습니다." });
  }
  const [rows] = await pool.query(`... WHERE bp.patient_id = ?`, [req.params.patientId]);
  res.json(rows);
});
```

**왜 이렇게 고쳤나**: "인증(로그인 여부)"과 "인가(그 리소스에 대한 권한)"는 별개의 검증입니다. 기존 코드는 인증만 확인하고 인가 검증이 빠져있었는데, URL 파라미터와 세션 값을 직접 비교하는 한 줄을 추가해 "본인 것이 아니면 조회 자체가 안 되도록" 막았습니다. 목록 조회(`GET /`)는 원래부터 세션 값만 사용해 안전했으므로 그 패턴을 상세 조회에도 그대로 적용한 것입니다.

---

## 4. 불충분한 세션 관리 → 쿠키 보안 속성 전체 적용 + 세션 고정 방지

| | 원본 | 수정본 |
|---|---|---|
| 파일 | `was/server.js` | 동일 |
| 문제 | `httpOnly:false`, `secure` 미설정, `sameSite` 미설정, 만료시간 없음, 로그인 시 세션 재사용 | 4개 속성 모두 설정 + 로그인 성공 시 세션 ID 재발급 |

**수정 전**
```js
cookie: { httpOnly: false }
```

**수정 후**
```js
cookie: {
  httpOnly: true,
  secure: config.useHttps,     // HTTPS 배포 환경에서만 true (11번 항목과 연동)
  sameSite: "strict",
  maxAge: 30 * 60 * 1000,      // 30분 유휴 만료
}
```
```js
// 로그인 성공 시 (routes/auth.js)
req.session.regenerate((err) => {
  req.session.patientId = patient.id;
  // ...
});
```

**왜 이렇게 고쳤나**: `httpOnly:true`는 JavaScript가 `document.cookie`로 세션 값을 읽지 못하게 막아, 2번(XSS) 취약점이 설령 다른 경로로 뚫리더라도 쿠키까지 탈취되는 최악의 상황을 차단합니다. `secure`는 HTTPS에서만 쿠키가 전송되게 강제하고, `sameSite:strict`는 다른 사이트에서 발생한 요청에 쿠키가 자동으로 실리지 않게 해 5번(CSRF) 방어에도 기여합니다. 추가로 로그인 성공 시 세션 ID를 재발급(`regenerate`)하도록 넣었는데, 이는 "세션 고정(Session Fixation)" 공격 — 공격자가 미리 세션 ID를 정해두고 피해자가 그 ID로 로그인하게 유도하는 공격 — 을 막기 위한 조치입니다.

---

## 5. CSRF → 신뢰 오리진 제한 + 토큰 검증

| | 원본 | 수정본 |
|---|---|---|
| 파일 | `was/server.js`, `was/routes/board.js` | + `was/middleware/csrf.js` 신규 |
| 문제 | `cors({origin:true})`로 모든 오리진 허용, 토큰 검증 없음 | 특정 오리진만 허용 + Synchronizer Token Pattern 적용 |

**수정 전**
```js
app.use(cors({ origin: true, credentials: true }));
```

**수정 후**
```js
app.use(cors({ origin: config.allowedOrigin, credentials: true })); // 기본값: http://localhost:5500
```
```js
// was/middleware/csrf.js (신규)
function verifyCsrfToken(req, res, next) {
  const headerToken = req.headers["x-csrf-token"];
  if (!headerToken || headerToken !== req.session.csrfToken) {
    return res.status(403).json({ message: "유효하지 않은 CSRF 토큰입니다." });
  }
  next();
}
```
```js
// routes/board.js - 상태 변경 라우트에 적용
router.post("/", verifyCsrfToken, async (req, res) => { ... });
```
```js
// routes/auth.js - 로그인 성공 시 토큰 발급
req.session.csrfToken = crypto.randomBytes(24).toString("hex");
res.json({ success: true, ..., csrfToken: req.session.csrfToken });
```

**왜 이렇게 고쳤나**: CORS를 특정 오리진으로 제한하면 공격자 페이지의 `credentials:'include'` 요청 자체가 브라우저 단에서 차단됩니다. 여기에 더해 CSRF 토큰까지 적용한 이유는 CORS 제한만으로는 막지 못하는 경우(예: HTML `<form>` 자동 제출을 이용한 전통적 CSRF)까지 방어하기 위한 이중 방어입니다. 서버만 아는 세션과 결부된 토큰을 클라이언트가 매 요청마다 헤더로 첨부해야 하므로, 공격자는 피해자의 쿠키는 훔치지 않고도 요청을 흉내 낼 수 있지만 이 토큰 값은 알아낼 방법이 없습니다.

---

## 6. Rate Limiting 부재 → 로그인 시도 횟수 제한

| | 원본 | 수정본 |
|---|---|---|
| 파일 | `was/routes/auth.js` `/login` | 동일 |
| 문제 | 요청 횟수 제한 없음 | `express-rate-limit`으로 15분당 5회 제한 |

**수정 후**
```js
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, message: "로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요." },
});
router.post("/login", loginLimiter, async (req, res) => { ... });
```

**왜 이렇게 고쳤나**: IP 단위로 15분 내 5회를 초과하면 429 응답과 함께 차단되도록 해서, 브루트포스나 크리덴셜 스터핑처럼 짧은 시간에 대량 시도가 필요한 공격의 실효성을 크게 떨어뜨립니다. 정상 사용자가 비밀번호를 몇 번 잘못 입력하는 정도로는 걸리지 않을 값(5회/15분)으로 설정했습니다.

---

## 7-a. 정보 노출 (테스트 계정 주석) → 주석 완전 제거

| | 원본 | 수정본 |
|---|---|---|
| 파일 | `frontend/index.html` | 동일 |
| 문제 | 관리자 테스트 계정이 HTML 주석에 그대로 남음 | 주석 삭제 |

**수정 전**
```html
<!-- Admin Test Account: admin / admin_test_123! -->
```

**수정 후**: 해당 주석 자체를 삭제. (테스트 계정이 필요하면 `was/seed.js`처럼 코드 밖에서, 소스에 남지 않는 방식으로 관리)

**왜 이렇게 고쳤나**: 브라우저로 전송되는 모든 텍스트(HTML 주석 포함)는 "페이지 소스 보기"만으로 누구나 열람 가능합니다. 개발 편의를 위한 메모라도 배포본에는 절대 남기지 않아야 합니다.

---

## 7-b. 정보 노출 (에러 메시지) → 일반 메시지로 통일 + 서버 로그로 분리

| | 원본 | 수정본 |
|---|---|---|
| 파일 | `was/routes/auth.js` | 동일 |
| 문제 | `err.sqlMessage`를 응답에 그대로 포함 | 사용자에게는 일반 메시지, 상세는 `console.error`로만 기록 |

**수정 전**
```js
catch (err) {
  res.status(500).json({ success: false, message: "쿼리 오류", detail: err.sqlMessage });
}
```

**수정 후**
```js
catch (err) {
  console.error("[login error]", err); // 서버 로그에만 기록
  res.status(500).json({ success: false, message: "서버 오류가 발생했습니다." });
}
```

**왜 이렇게 고쳤나**: `sqlMessage`에는 테이블/컬럼명, DB 종류 등 내부 구조 정보가 담겨 있어 공격자가 후속 공격(SQLi 등)을 정교화하는 데 악용할 수 있습니다. 문제 진단에 필요한 상세 정보는 서버 로그로만 남기고, 사용자(및 잠재적 공격자)에게는 최소한의 일반 메시지만 노출하도록 분리했습니다.

---

## 8. 평문 비밀번호 저장 → bcrypt 해시

| | 원본 | 수정본 |
|---|---|---|
| 파일 | `was/routes/auth.js` `/signup`, `/login` | 동일 + `db/init.sql`(컬럼 유지), `was/seed.js`(신규) |
| 문제 | 비밀번호를 평문 그대로 저장·비교 | 가입 시 `bcrypt.hash`, 로그인 시 `bcrypt.compare` |

**수정 전**
```js
// 가입
"INSERT INTO patients (..., password, ...) VALUES (..., ?, ...)", [..., password, ...]
// 로그인
const query = `... AND password = '${password}'`; // 평문 비교
```

**수정 후**
```js
// 가입
const hashedPassword = await bcrypt.hash(password, 12);
"INSERT INTO patients (..., password, ...) VALUES (..., ?, ...)", [..., hashedPassword, ...]
// 로그인
const passwordMatches = await bcrypt.compare(password, patient.password);
```
계정이 존재하지 않을 때도 더미 해시와 비교해 응답 시간 차이로 계정 존재 여부가 추론되지 않도록 처리:
```js
const hashToCompare = patient ? patient.password : "$2b$10$invalidsaltinvalidsaltinvalidsaltinvalidsalt";
const passwordMatches = await bcrypt.compare(password, hashToCompare);
```

**왜 이렇게 고쳤나**: bcrypt는 단방향 해시(복호화 불가능)이며 자동으로 salt를 생성하고 계산 비용(cost factor, 여기선 12)을 조절할 수 있어 레인보우테이블이나 무차별 대입에 강합니다. DB가 통째로 유출되더라도 원문 비밀번호를 알아낼 수 없습니다. 추가로, "계정이 없어서 즉시 실패"와 "계정은 있는데 비밀번호가 틀려서 실패"의 응답 속도 차이로 계정 존재 여부를 추론하는 타이밍 공격까지 막기 위해 계정이 없을 때도 동일하게 해시 비교 연산을 수행하도록 만들었습니다.

---

## 9. 고유식별정보(주민등록번호) 미암호화 → AES-256-GCM 암호화

| | 원본 | 수정본 |
|---|---|---|
| 파일 | `db/init.sql`, `was/routes/auth.js` `/signup` | + `was/crypto-utils.js` 신규 |
| 문제 | 주민번호를 평문으로 저장 | AES-256-GCM으로 암호화 후 저장 |

**수정 전**
```sql
rrn VARCHAR(14) NOT NULL  -- 평문
```
```js
[username, password, name, rrn]  // rrn 평문 그대로 INSERT
```

**수정 후**
```sql
rrn VARCHAR(100) NOT NULL  -- 암호문(base64) 저장을 위해 컬럼 확장
```
```js
// was/crypto-utils.js
function encryptRrn(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", config.rrnEncryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString("base64");
}
```
```js
// routes/auth.js
const encryptedRrn = encryptRrn(rrn);
[username, hashedPassword, name, encryptedRrn]
```

**왜 이렇게 고쳤나**: 비밀번호와 달리 주민번호는 (신원 확인 등으로) 나중에 다시 복호화해서 봐야 할 가능성이 있어 단방향 해시가 아닌 대칭키 암호화를 적용했습니다. AES-256-GCM은 암호화와 함께 위변조 여부를 검증하는 인증 태그(authTag)를 생성해, 암호문이 조작되었는지도 확인할 수 있는 방식입니다. 암호화 키(`RRN_ENCRYPTION_KEY`)는 코드가 아닌 환경변수로 분리해, 소스코드가 유출되어도 키까지 함께 노출되지 않도록 했습니다. 화면에 표시할 일이 생기면 `maskRrn()` 헬퍼로 뒷자리를 마스킹하도록 함께 준비해뒀습니다.

---

## 10. User Enumeration → 응답 메시지 통일

| | 원본 | 수정본 |
|---|---|---|
| 파일 | `was/routes/auth.js` `/signup` | 동일 |
| 문제 | "이미 존재하는 아이디입니다" 메시지로 계정 존재 여부 노출 | 모든 실패를 동일한 일반 메시지로 응답 |

**수정 전**
```js
if (existing.length > 0) {
  return res.status(409).json({ success: false, message: "이미 존재하는 아이디입니다." });
}
```

**수정 후**
```js
if (existing.length > 0) {
  return res.status(400).json({ success: false, message: "가입 처리 중 문제가 발생했습니다. 입력값을 확인해주세요." });
}
```

**왜 이렇게 고쳤나**: 메시지만으로는 "아이디 중복 때문에 실패했는지" 다른 이유인지 구분할 수 없게 만들어, 공격자가 이 API를 계정 존재 여부를 확인하는 도구로 악용하지 못하도록 했습니다.

---

## 11. 전송 구간 암호화 부재 → HTTPS 전환 대비 구성

| | 원본 | 수정본 |
|---|---|---|
| 파일 | `was/server.js`, `was/config.js` | 동일 |
| 문제 | HTTP로만 서비스, `secure` 쿠키 옵션 없음 | `USE_HTTPS` 환경변수로 `secure` 쿠키 제어 가능하게 구성 |

**수정 후**
```js
// config.js
useHttps: process.env.USE_HTTPS === "true",
// server.js
cookie: { ..., secure: config.useHttps, ... }
```

**왜 이렇게 고쳤나**: 실제 TLS 인증서 발급·적용은 배포 환경(도메인, 리버스 프록시 등)에 따라 달라지는 인프라 작업이라 코드 수정만으로 끝나지 않습니다. 대신 애플리케이션 코드는 "HTTPS로 배포되면 `secure:true`가 즉시 활성화되도록" 미리 준비해뒀습니다. 로컬 개발(HTTP)에서는 `USE_HTTPS`를 설정하지 않으면 기존처럼 동작해 개발 편의성을 해치지 않으면서, 운영 배포 시 환경변수 하나로 전환 가능합니다. 실제 운영 반영 시에는 Nginx/Caddy 등 리버스 프록시로 TLS 종단을 구성하고 `USE_HTTPS=true`로 배포하는 것을 권장합니다.

---

## 취약점 뱃지/툴팁 제거 내역

수정 완료된 취약점에 대응하는 안내 뱃지(`vuln-badge`)와 툴팁을 1:1로 전부 제거했습니다.

| HTML 파일 | 제거된 뱃지 |
|---|---|
| `index.html` | 정보 노출(관리자 계정 주석), SQL Injection, 자동화 공격, CSRF/세션관리 — 4개 + 주석 자체도 삭제 |
| `board.html` | Stored XSS, BOLA/IDOR — 2개 |
| `view.html` | BOLA/IDOR — 1개 |
| `signup.html` | User Enumeration, 평문 비밀번호 저장 — 2개 |

`frontend/css/vuln-tooltip.css`, `frontend/js/vuln-tooltip.js` 파일 자체와 모든 HTML의 관련 `<link>`/`<script>` 참조도 함께 삭제했습니다.

---

## 종합 대조표

| # | 취약점 | 상태 | 핵심 조치 |
|---|---|---|---|
| 1 | SQL Injection | ✅ 수정 | Prepared Statement |
| 2 | Stored XSS | ✅ 수정 | sanitize-html + textContent |
| 3 | BOLA/IDOR | ✅ 수정 | 세션-URL 소유권 검증 |
| 4 | 불충분한 세션 관리 | ✅ 수정 | httpOnly/secure/sameSite/maxAge + 세션 재발급 |
| 5 | CSRF | ✅ 수정 | CORS 오리진 제한 + CSRF 토큰 |
| 6 | Rate Limiting 부재 | ✅ 수정 | express-rate-limit (15분/5회) |
| 7-a | 정보 노출 (주석) | ✅ 수정 | 주석 삭제 |
| 7-b | 정보 노출 (에러메시지) | ✅ 수정 | 일반 메시지 + 서버 로그 분리 |
| 8 | 평문 비밀번호 저장 | ✅ 수정 | bcrypt 해시 (cost 12) |
| 9 | 주민번호 미암호화 | ✅ 수정 | AES-256-GCM |
| 10 | User Enumeration | ✅ 수정 | 응답 메시지 통일 |
| 11 | 전송 구간 암호화 부재 | ✅ 대응 준비 | secure 쿠키 환경변수화 (실배포 시 HTTPS 전환 필요) |

11번 항목은 애플리케이션 코드만으로는 완결되지 않고 실제 배포 시 TLS 인증서 적용이 함께 필요하다는 점을 유의해주세요.
