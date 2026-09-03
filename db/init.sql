-- 스키마만 정의. 더미 데이터는 was/seed.js에서 비밀번호 해시/주민번호 암호화 후 삽입한다.
-- (비밀번호 해시, 주민번호 암호화는 SQL이 아닌 애플리케이션 코드에서 수행되어야 하므로
--  평문 INSERT문을 여기 두지 않는다.)
CREATE DATABASE IF NOT EXISTS vulnapp CHARACTER SET utf8mb4;
USE vulnapp;

-- 재실행 시 이전 스키마(예: 취약점 버전의 짧은 rrn 컬럼)가 남아있지 않도록 항상 깨끗하게 초기화.
-- scanned_documents/board_posts가 patients를 외래키로 참조하므로 반드시 먼저 삭제.
DROP TABLE IF EXISTS scanned_documents;
DROP TABLE IF EXISTS board_posts;
DROP TABLE IF EXISTS patients;

CREATE TABLE patients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,       -- [보안 강화] bcrypt 해시 저장 (60자 고정 길이, 평문 저장 금지)
    name VARCHAR(20) NOT NULL,
    rrn VARCHAR(100) NOT NULL,            -- [보안 강화] AES-256-GCM 암호문(base64) 저장. 평문보다 길어져 컬럼 확장
    role ENUM('patient', 'admin') NOT NULL DEFAULT 'patient'  -- 관리자 전용 기능(문서 OCR 스캔) 접근 제어용
);

-- board.html/view.html이 참조하는 "진료 문의 게시글" 테이블
CREATE TABLE board_posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    title VARCHAR(200) NOT NULL,
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

-- 관리자가 admin.html에서 스캔한 문서(OCR 결과)를 환자와 연결해 저장하는 테이블.
-- 조회는 관리자 전용(GET /api/documents) — 환자용 조회 라우트는 만들지 않는다.
CREATE TABLE scanned_documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,            -- 이 스캔 결과가 속한 환자
    scanned_by INT NOT NULL,            -- 스캔을 수행한 관리자(patients.id, role='admin')
    document_type ENUM('prescription', 'diagnosis', 'receipt') NOT NULL,
    extracted_text TEXT,                 -- OCR 원문. 목록 조회 API는 이 컬럼을 응답에 포함하지 않음
    parsed_date DATE NULL,               -- extracted_text에서 정규식으로 뽑아낸 날짜 (best-effort)
    parsed_amount INT NULL,              -- extracted_text에서 정규식으로 뽑아낸 금액(원) (best-effort)
    parsed_fields JSON NULL,             -- "라벨:값" 형태 줄에서 뽑아낸 나머지 필드. 주민등록번호 등 민감 라벨은 제외
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id),
    FOREIGN KEY (scanned_by) REFERENCES patients(id)
);
