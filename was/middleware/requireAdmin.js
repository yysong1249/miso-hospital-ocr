// 문서 스캔(OCR)/환자 목록/저장된 스캔 문서 조회 등 관리자 전용 API에서 공통으로 쓰는 인증 체크
module.exports = function requireAdmin(req, res, next) {
  if (!req.session.patientId) {
    return res.status(401).json({ message: "로그인이 필요합니다." });
  }
  if (req.session.role !== "admin") {
    return res.status(403).json({ message: "관리자만 이용할 수 있습니다." });
  }
  next();
};
