const express = require("express");
const sanitizeHtml = require("sanitize-html");
const pool = require("../db");
const { verifyCsrfToken } = require("../middleware/csrf");

const router = express.Router();

// 로그인한 본인의 문의 목록만 반환
router.get("/", async (req, res) => {
  if (!req.session.patientId) {
    return res.status(401).json({ message: "로그인이 필요합니다." });
  }
  const [rows] = await pool.query(
    "SELECT id, patient_id, title FROM board_posts WHERE patient_id = ?",
    [req.session.patientId]
  );
  res.json(rows);
});

// [보안 강화 #5 CSRF] 상태 변경 요청(POST)에 CSRF 토큰 검증 미들웨어 적용.
router.post("/", verifyCsrfToken, async (req, res) => {
  if (!req.session.patientId) {
    return res.status(401).json({ message: "로그인이 필요합니다." });
  }

  const { title, content } = req.body;
  if (!title || typeof title !== "string" || title.length > 200) {
    return res.status(400).json({ message: "제목을 확인해주세요." });
  }

  // [보안 강화 #2 Stored XSS] 저장 전 HTML 태그/속성을 모두 제거해 스크립트 삽입을 원천 차단.
  // allowedTags/allowedAttributes를 빈 배열로 두어 순수 텍스트만 남긴다.
  const safeTitle = sanitizeHtml(title, { allowedTags: [], allowedAttributes: {} });
  const safeContent = sanitizeHtml(content || "", { allowedTags: [], allowedAttributes: {} });

  const [result] = await pool.query(
    "INSERT INTO board_posts (patient_id, title, content) VALUES (?, ?, ?)",
    [req.session.patientId, safeTitle, safeContent]
  );
  res.json({ id: result.insertId, patient_id: req.session.patientId, title: safeTitle, content: safeContent });
});

// [보안 강화 #3 BOLA/IDOR] URL의 patientId가 세션 소유자와 일치하는지 반드시 검증.
// 일치하지 않으면 403으로 즉시 차단 - "로그인 여부"만이 아니라 "이 리소스의 소유자인지"까지 확인.
router.get("/:patientId", async (req, res) => {
  if (!req.session.patientId) {
    return res.status(401).json({ message: "로그인이 필요합니다." });
  }
  if (Number(req.params.patientId) !== req.session.patientId) {
    return res.status(403).json({ message: "접근 권한이 없습니다." });
  }

  const [rows] = await pool.query(
    `SELECT bp.id, bp.patient_id, bp.title, bp.content, p.name
     FROM board_posts bp JOIN patients p ON p.id = bp.patient_id
     WHERE bp.patient_id = ?`,
    [req.params.patientId]
  );
  res.json(rows);
});

module.exports = router;
