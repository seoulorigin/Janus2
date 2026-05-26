import grpc
import time
import logging
import joblib
import numpy as np
from collections import deque

# 캡슐화된 tetragon 패키지 내부에서 통신 및 데이터 구조체 모듈 호출
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

# 실무 디버깅용 로그 포맷팅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

def connect_and_stream(model):
    target_address = 'localhost:54321'
    backoff = 1
    max_backoff = 64
    
    # 5-gram Non-overlapping 데이터를 쌓을 논리적 메모리 버퍼 
    syscall_buffer = deque(maxlen=5)

    while True:
        try:
            logging.info(f"Tetragon gRPC 엔드포인트({target_address}) 연결 수립 시도 중...")
            
            # gRPC 채널 및 Stub 생성
            channel = grpc.insecure_channel(target_address)
            stub = sensors_pb2_grpc.FineGuidanceSensorsStub(channel)
            request = events_pb2.GetEventsRequest()
            
            # Server Streaming RPC 호출
            response_iterator = stub.GetEvents(request)
            logging.info("Tetragon gRPC API 핸드셰이크 성공. 실시간 분류 파이프라인 개통 완료.")
            
            backoff = 1 

            for response in response_iterator:
                # tracepoint가 아닌 kprobe 이벤트를 수신
                if response.HasField("process_tracepoint"):
                    tp_event = response.process_tracepoint
        
                    # 3. 서브시스템이 'syscalls' 인 이벤트만 처리
                    if tp_event.subsys == "syscalls":
                        # "sys_enter_read" 같은 이벤트 이름을 숫자로 변환
                        syscall_number = SYSCALL_MAP.get(tp_event.event)
        
                        # 매핑 테이블에 존재하는 11개의 타겟 함수인 경우에만 버퍼에 적재
                        if syscall_number is not None:
                            syscall_buffer.append(syscall_number)
            
                            # 5-gram 배열 완성 시 ML 추론
                            if len(syscall_buffer) == 5:
                                input_data = np.array(syscall_buffer).reshape(1, -1)
                                prediction = model.predict(input_data)[0]
                
                                if prediction == 1:
                                    logging.warning(f"🚨 [탐지] 크립토재킹 의심 행위 발견! 패턴: {list(syscall_buffer)}")
                                else:
                                    logging.info(f"✅ [정상] 일반 프로세스 패턴: {list(syscall_buffer)}")

        except grpc.RpcError as e:
            logging.error(f"gRPC 세션 강제 단절 발생 (상세: {e.details()})")
            logging.info(f"시스템 안정성을 위해 {backoff}초 동안 실행 유예 후 재연결 루프를 수행합니다...")
            time.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

if __name__ == '__main__':
    logging.info("========================================================")
    logging.info("Project Janus - eBPF 기반 ML 탐지 엔진 구동")
    logging.info("========================================================")
    
    # K8s 사이드카 컨테이너 구동 시, 메모리에 모델을 단 한 번만 적재(Singleton Pattern)
    model_path = 'cryptojacking_dt_model.joblib'
    
    try:
        logging.info(f"추론 엔진(Decision Tree) 로드 중: {model_path}")
        dt_model = joblib.load(model_path)
        logging.info("모델 적재 완료. 실시간 스트리밍 대기 모드로 진입합니다.")
        
        # 모델 객체를 통신 함수로 주입하여 무한 루프 실행
        connect_and_stream(dt_model)
        
    except Exception as e:
        logging.error(f"모델 로드 실패. 파일 경로와 환경을 다시 확인하십시오: {e}")