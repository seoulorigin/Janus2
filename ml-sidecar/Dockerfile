# 경량화된 Python 3.12 슬림 이미지 사용
FROM python:3.12-slim

# 작업 디렉토리 설정
WORKDIR /app

# 의존성 패키지 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 생성된 패키지 폴더, 모델 파일, 메인 스크립트 복사
COPY tetragon/ ./tetragon/
COPY cryptojacking_dt_model.joblib .
COPY main.py .

# 컨테이너 실행 시 ML 추론 엔진 자동 구동
CMD ["python", "main.py"]