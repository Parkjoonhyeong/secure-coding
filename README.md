# 🛒 중고거래 플랫폼

간단하고 직관적인 웹 기반 **중고거래 플랫폼**입니다.  
사용자는 상품을 등록하고, 포인트로 거래하며, 채팅 기능으로 소통할 수 있습니다.  
**관리자는 전체 데이터를 관리**하고, **보안 요소**가 강화된 구조로 안전한 사용 환경을 제공합니다.

---

## 🚀 주요 기능

| 기능 영역   | 기능 설명                                                                                                                             |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| 사용자 기능 | 회원가입, 로그인, 로그아웃, 마이페이지, 거래 내역 확인                                                                                |
| 상품 기능   | 상품 등록, 수정, 삭제, 검색, 상세 보기                                                                                                |
| 채팅 기능   | 사용자 간 1:1 채팅                                                                                                                    |
| 거래 기능   | 포인트 기반 송금, 거래 내역 확인                                                                                                      |
| 관리자 기능 | 사용자/상품/거래 내역 관리, 관리자 대시보드 통계 제공                                                                                 |
| 보안 기능   | 비밀번호 해시 저장(`bcrypt`)<br>CSRF 방어<br>XSS 방지<br>HTTPS 통신<br>세션 인증 관리<br>자기 자신 송금 방지 및 관리자 자기 삭제 방지 |

---

## 💻 설치 및 실행 방법

### 1. 요구 환경

- **Python 3.10 이상**
- **SQLite3**
- **Flask**
- **Flask-Bcrypt**
- **Flask-SQLAlchemy**
- 기타 라이브러리는 `requirements.txt` 참고

---

### 2. 프로젝트 클론

````bash
git clone https://github.com/Parkjoonhyeong/secure-coding.git
cd secure-coding


### 3. 가상환경 생성 및 의존성 설치
```bash
python -m venv venv
venv\Scripts\activate        # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
````

### 4. 인증서 생성 (HTTPS)

```bash
mkdir certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes
```

### 5. 실행

```bash
python app.py
```

- 기본 접속 주소: [https://localhost:5000](https://localhost:5000)
- `certs` 디렉토리에 인증서가 있으면 자동으로 **HTTPS 모드**로 실행됩니다.
- 인증서가 없으면 실행 시 경고 메시지가 표시됩니다.

---

## 🔐 기본 관리자 계정

최초 실행 시 자동으로 생성되는 관리자 계정 정보입니다:

- 👤 **아이디**: `admin`
- 🔑 **비밀번호**: `admin`

**관리자 권한 기능**:

- 사용자 관리 (삭제 등)
- 상품 관리
- 거래 내역 확인
- 관리자 전용 대시보드

---

## 🛠 기술 스택

- **Python 3**
- **Flask**
  - Jinja2
  - SQLAlchemy
  - Bcrypt
- **SQLite**
- **HTML5 + CSS3**
- **SimpleCSS (CDN)**
- **HTTPS (OpenSSL self-signed 인증서)**
