import grpc
import time
import logging
import joblib
import numpy as np
import requests
from collections import deque
from datetime import datetime

from tetragon import events_pb2
from tetragon import sensors_pb2_grpc

SYSCALL_MAP = {
    "sys_enter_read": 0,
    "sys_enter_write": 1,
    "sys_enter_poll": 7,
    "sys_enter_ioctl": 16,
    "sys_enter_sched_yield": 24,
    "sys_enter_sendto": 44,
    "sys_enter_recvfrom": 45,
    "sys_enter_futex": 202,
    "sys_enter_epoll_ctl": 233,
    "sys_enter_newfstatat": 262,
    "sys_enter_epoll_pwait": 281
}

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
ALERT_THRESHOLD = 5

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

def send_slack_alert(pod_name, count, pattern):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    message = {
        "text": f"🚨 *크립토재킹 탐지 경보*\n• Pod: `{pod_name}`\n• 탐지 시간: {now}\n• 악성 판별 횟수: *{count}회* (기준: {ALERT_THRESHOLD}회 이상)\n• 시스템콜 패턴: `{pattern}`"
    }
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=message)
        if response.status_code == 200:
            logging.info(f"Slack 알림 전송 성공 (Pod: {pod_name})")
        else:
            logging.error(f"Slack 알림 전송 실패: {response.status_code}")
    except Exception as e:
        logging.error(f"Slack 알림 전송 중 오류: {e}")

def connect_and_stream(model):
    target_address = 'localhost:54321'
    backoff = 1
    max_backoff = 64
    syscall_buffer = deque(maxlen=5)
    detection_count = {}

    while True:
        try:
            logging.info(f"Tetragon gRPC 엔드포인트({target_address}) 연결 수립 시도 중...")
            channel = grpc.insecure_channel(target_address)
            stub = sensors_pb2_grpc.FineGuidanceSensorsStub(channel)
            request = events_pb2.GetEventsRequest()
            response_iterator = stub.GetEvents(request)
            logging.info("Tetragon gRPC API 핸드셰이크 성공. 실시간 분류 파이프라인 개통 완료.")
            backoff = 1

            for response in response_iterator:
                if response.HasField("process_tracepoint"):
                    tp_event = response.process_tracepoint
                    if tp_event.subsys == "syscalls":
                        syscall_number = SYSCALL_MAP.get(tp_event.event)
                        if syscall_number is not None:
                            syscall_buffer.append(syscall_number)
                            if len(syscall_buffer) == 5:
                                input_data = np.array(syscall_buffer).reshape(1, -1)
                                prediction = model.predict(input_data)[0]
                                pod_name = tp_event.process.pod.name if tp_event.process.pod else "unknown"
                                if prediction == 1:
                                    detection_count[pod_name] = detection_count.get(pod_name, 0) + 1
                                    count = detection_count[pod_name]
                                    logging.warning(f"🚨 [탐지] 크립토재킹 의심! Pod: {pod_name} | 횟수: {count}회 | 패턴: {list(syscall_buffer)}")
                                    if count >= ALERT_THRESHOLD and count % ALERT_THRESHOLD == 0:
                                        send_slack_alert(pod_name, count, list(syscall_buffer))
                                else:
                                    logging.info(f"✅ [정상] Pod: {pod_name} | 패턴: {list(syscall_buffer)}")

        except grpc.RpcError as e:
            logging.error(f"gRPC 세션 강제 단절 발생 (상세: {e.details()})")
            logging.info(f"시스템 안정성을 위해 {backoff}초 동안 실행 유예 후 재연결 루프를 수행합니다...")
            time.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

if __name__ == '__main__':
    logging.info("========================================================")
    logging.info("Project Janus - eBPF 기반 ML 탐지 엔진 구동")
    logging.info("========================================================")
    model_path = 'cryptojacking_dt_model.joblib'
    try:
        logging.info(f"추론 엔진(Decision Tree) 로드 중: {model_path}")
        dt_model = joblib.load(model_path)
        logging.info("모델 적재 완료. 실시간 스트리밍 대기 모드로 진입합니다.")
        connect_and_stream(dt_model)
    except Exception as e:
        logging.error(f"모델 로드 실패. 파일 경로와 환경을 다시 확인하십시오: {e}")
