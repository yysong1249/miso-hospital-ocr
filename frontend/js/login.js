document.getElementById('loginForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const userid = document.getElementById('userid').value;
    const userpw = document.getElementById('password').value;

    const res = await fetch(`${WAS_BASE}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include', // 세션 쿠키를 주고받기 위해 필요
        body: JSON.stringify({ username: userid, password: userpw }),
    });
    const data = await res.json();

    if (data.success) {
        setCsrfToken(data.csrfToken); // [보안 강화 #5] 로그인 시 발급된 CSRF 토큰 저장
        // 관리자도 일단 board.html로 이동. 문서 스캔 페이지 이동은 board.html의 버튼(관리자에게만 노출)을 눌러서 함
        window.location.href = 'board.html';
    } else {
        showToast(data.message || '로그인 실패');
    }
});
