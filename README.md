# 🔒 미소 병원 3-Tier 웹 프로젝트

이 저장소는 취약점 실습용 원본 프로젝트의 보안 강화 버전입니다. 이 문서는 그 위에 **새로 추가/수정된 사항**만 기록합니다.

## 실행 방법

```bash
cd was
npm install
node seed.js      # 더미 계정/게시글 생성 (비밀번호 해시·주민번호 암호화·역할(role) 부여를 이 스크립트가 처리)
node server.js

cd ../frontend
python3 -m http.server 5500
```

환경변수(선택, 운영 배포 시 필수): `SESSION_SECRET`, `RRN_ENCRYPTION_KEY`(32바이트 hex), `FRONTEND_ORIGIN`, `USE_HTTPS=true`

테스트 계정 (`was/seed.js` 참고): `patient1`/`pass1234`, `patient2`/`pw5678`, `patient3`/`qwerty1`(모두 일반 환자), `admin`/`admin_test_123!`(문서 스캔 기능 사용 가능한 관리자)

> OCR 기능은 첫 실행 시 `tesseract.js`가 언어 데이터(`kor`/`eng`, 약 7MB)를 인터넷에서 자동으로 내려받습니다. 오프라인 환경에 배포한다면 사전에 받아둔 `.traineddata` 파일을 `was/`에 미리 배치해야 합니다.

> 로그인 rate limit(IP당 15분에 5회)은 같은 컴퓨터에서 자동화 테스트와 실제 로그인을 동시에 하면 카운트를 공유해 서로 영향을 줄 수 있습니다. 원인 모를 429가 뜬다면 이걸 의심해보세요.

---

## 신규 기능: 문서 스캔 (OCR, 관리자 전용)

처방전/진단서/영수증 이미지에서 텍스트를 추출해 환자 기록으로 저장하는 기능을 추가했습니다. 원본 저장소(`miso-hospital-3tier/`)에서 먼저 설계·구현한 뒤, 이 저장소의 기존 보안 패턴(CSRF 토큰, bcrypt, AES 암호화 등)에 맞춰 이식했습니다. 설계 과정에서의 세부 의사결정(문서 종류 분류 도입 경위, 필드 파싱 규칙, 신뢰도 강조 표시를 만들었다가 뺀 이유 등)은 원본 저장소의 `OCR.md`에 기록되어 있습니다.

| | 내용 |
|---|---|
| 신규 파일 | `was/middleware/requireAdmin.js`, `was/routes/ocr.js`, `was/routes/patients.js`, `was/routes/documents.js`, `frontend/admin.html`, `frontend/js/admin.js` |
| 수정 파일 | `db/init.sql`(`patients.role` 컬럼, `scanned_documents` 테이블 추가), `was/seed.js`(admin 계정에 `role='admin'` 부여), `was/routes/auth.js`(로그인/`/api/me` 응답에 `role` 포함), `was/server.js`(라우트 등록), `was/package.json`(`multer`, `tesseract.js` 추가), `frontend/board.html`/`frontend/js/board.js`(관리자에게만 보이는 이동 버튼), `frontend/css/style.css` |
| 접근 권한 | `patients.role`이 `admin`인 계정만 사용 가능 — 일반 환자 계정은 관련 API가 전부 403 |

### 동작 흐름

1. 로그인 후 `board.html`에서 "문서 스캔 페이지로 이동" 버튼 클릭 (이 버튼은 관리자 계정에게만 보임) → `admin.html`로 이동
2. 이미지 업로드 → `POST /api/ocr` — `tesseract.js`(`kor+eng`)로 텍스트 추출. 파일은 디스크에 쓰지 않고 메모리 버퍼로만 처리하며, 업로드된 파일의 매직 바이트를 검사해 실제 이미지 형식인지 확인 (`Content-Type`/확장자는 신뢰하지 않음)
3. 추출된 텍스트를 관리자가 확인/수정한 뒤, 환자와 문서종류(처방전/진단서/영수증)를 선택해 `POST /api/documents`로 저장
4. 저장 시 원문에서 날짜·금액·기타 "라벨: 값" 형태의 필드를 정규식으로 함께 파싱해 저장 (OCR 인식 오류가 그대로 이어질 수 있는 참고용 데이터 — best-effort)

### 이 저장소의 기존 보안 패턴에 맞춰 통합한 부분

```js
// was/routes/ocr.js, was/routes/documents.js
// 다른 상태 변경 POST(board.js)와 동일하게 CSRF 토큰 검증을 첫 게이트로 적용
router.post("/", verifyCsrfToken, requireAdmin, ...);
```

- **역할(role) 기반 접근 제어**: 이 프로젝트에 원래 없던 개념이라 `patients.role ENUM('patient','admin')` 컬럼을 새로 추가하고, 공통 `requireAdmin` 미들웨어로 모든 관리자 전용 라우트를 보호
- **비밀번호/주민번호 처리(bcrypt, AES-256-GCM)는 그대로 유지** — OCR 관련 코드는 이 부분을 건드리지 않음
- **`express-rate-limit` 버전**: 이 저장소가 이미 쓰던 v7 방식(`const rateLimit = require(...)`)에 맞춰 작성

### 보안 설계 포인트

- **파일 업로드**: `multer.memoryStorage()`로 디스크에 절대 쓰지 않음 — 경로 조작/웹쉘 업로드 같은 "저장된 파일" 계열 취약점이 애초에 성립하지 않는 구조
- **원문 비노출**: 저장된 문서 목록 조회(`GET /api/documents`)는 OCR 원문(`extracted_text`)과 파싱된 필드(`parsed_fields`)를 응답에 아예 포함하지 않음 — 화면에서 숨기는 게 아니라 서버가 애초에 내려주지 않는 방식
- **민감정보 차단**: 파싱 결과(`parsed_fields`)에서 주민등록번호/연락처/카드번호/계좌번호에 해당하는 라벨은 제외
- **환자 조회 라우트 없음**: 환자가 스캔 문서를 조회할 수 있는 라우트 자체를 아예 만들지 않음 (관리자만 조회 가능)
- **rate limit**: OCR은 CPU 비용이 크므로 로그인 사용자 단위로 분당 10회 제한

### 알려진 한계

- OCR 인식 오류는 구조적으로 피할 수 없음 (특히 라틴 문자와 한글 자모가 비슷하게 생겨 혼동되는 경우)
- 필드 파싱은 정규식 기반 best-effort이며 완벽한 정확도를 보장하지 않음 — 진료비 정산 등 중요한 판단에 그대로 쓰면 안 되고 참고용으로만 취급해야 함
- 저장된 문서의 원문을 나중에 다시 조회하는 상세보기 기능은 아직 없음
