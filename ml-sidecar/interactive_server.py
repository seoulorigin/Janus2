import grpc
from concurrent import futures
import queue
import threading
import os

# 컴파일된 패키지 임포트
from tetragon import events_pb2
from tetragon import sensors_pb2_grpc
from tetragon import tetragon_pb2

# 사용자가 키보드로 친 숫자를 gRPC 스레드로 전달할 큐(Queue)
syscall_queue = queue.Queue()

class InteractiveTetragon(sensors_pb2_grpc.FineGuidanceSensorsServicer):
    def GetEvents(self, request, context):
        print("\n[System] ML 사이드카 엔진이 연결되었습니다! 데이터를 보낼 준비가 완료되었습니다.")
        print("[System] 아래 입력창에 숫자를 치고 엔터를 누르세요.\n")
        
        while context.is_active():
            try:
                # 큐에 데이터가 들어올 때까지 대기
                user_input = syscall_queue.get(timeout=1)
                
                try:
                    sys_id = int(user_input)
                except ValueError:
                    print("숫자만 입력해주세요.")
                    continue

                # Protobuf 규격에 맞게 데이터 조립
                response = events_pb2.GetEventsResponse()
                tp = response.process_tracepoint
                tp.subsys = "raw_syscalls"
                tp.event = "sys_enter"
                
                arg = tetragon_pb2.KprobeArgument()
                arg.long_arg = sys_id
                tp.args.append(arg)
                
                # main.py로 데이터 발사!
                yield response
                
            except queue.Empty:
                continue

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    sensors_pb2_grpc.add_FineGuidanceSensorsServicer_to_server(InteractiveTetragon(), server)
    
    # main.py 코드가 TCP로 되어있든, 소켓으로 되어있든 코드 수정 없이 무조건 연결되도록 두 개 모두 바인딩
    server.add_insecure_port('[::]:50051')
    
    socket_path = '/var/run/tetragon/tetragon.sock'
    if os.path.exists(socket_path):
        os.remove(socket_path) # 기존 찌꺼기 소켓 제거
    server.add_insecure_port(f'unix://{socket_path}')
    
    server.start()
    print("=====================================================")
    print(" 🚀 대화형 모의 서버 가동 (키보드 입력을 대기합니다)")
    print("=====================================================")
    
    # 키보드 입력 루프 (메인 스레드)
    try:
        while True:
            val = input("전송할 시스템 콜 번호: ")
            if val.strip():
                syscall_queue.put(val.strip())
    except KeyboardInterrupt:
        server.stop(0)

if __name__ == '__main__':
    serve()