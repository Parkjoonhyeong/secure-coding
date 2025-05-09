# 🛒 중고거래 플랫폼

간단하고 직관적인 웹 기반 **중고거래 플랫폼**입니다.  
사용자는 상품을 등록하고, 포인트로 거래하며, 채팅 기능으로 소통할 수 있습니다.  
**관리자는 전체 데이터를 관리**하고, **보안 요소**가 강화된 구조로 안전한 사용 환경을 제공합니다.

---

## 🚀 주요 기능

| 기능 영역   | 기능 설명                                                                                                                                                    |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 사용자 기능 | 회원가입, 로그인, 로그아웃 기능 제공<br>비밀번호 변경 가능 (마이페이지)<br>본인의 포인트 거래 내역 조회 가능                                                 |
| 상품 기능   | 상품 등록, 수정, 삭제 가능<br>상품명 검색 기능 제공<br>상품 상세 페이지 열람 가능                                                                            |
| 채팅 기능   | 상품 판매자와 구매자 간의 1:1 채팅 기능 제공<br>모든 사용자 참여 가능한 전체 채팅방 기능 제공                                                                |
| 거래 기능   | 포인트 기반의 사용자 간 송금 기능 제공<br>거래 내역(보낸/받은) 확인 가능                                                                                     |
| 신고 기능   | 사용자 및 상품 신고 기능 제공<br>신고 사유 입력 필수<br>관리자 페이지에서 신고 내역 조회 및 삭제 가능                                                        |
| 관리자 기능 | 관리자 전용 대시보드 제공<br>사용자/상품/거래 데이터 전체 조회<br>사용자 및 상품 삭제 가능<br>휴면 계정 수동 처리 및 해제 기능<br>신고 누적 자동 휴면 처리   |
| 보안 기능   | bcrypt 비밀번호 해싱 저장<br>세션 기반 인증 및 권한 관리<br>관리자 자기 삭제 및 자기 송금 방지<br>CSRF/XSS 대응 구조<br>HTTPS 통신 지원 (self-signed 인증서) |

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

```bash
git clone https://github.com/Parkjoonhyeong/secure-coding.git
cd secure-coding
```

### 3. 가상환경 생성 및 의존성 설치

```bash
python -m venv venv
venv\Scripts\activate        # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
```

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
