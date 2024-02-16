import os
import signal
import sys
import psutil
import time

def supervisor_proc_run(run_path, my_engine_pid, user_app_pid):
    while True:
        if not psutil.pid_exists(my_engine_pid):
            print(f"MyEngine with PID {my_engine_pid} has died. Terminating all processes.")
            if psutil.pid_exists(user_app_pid):
                os.kill(user_app_pid, signal.SIGTERM)
                time.sleep(1)
                if not psutil.pid_exists(user_app_pid):
                    os.remove(run_path)
            sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python MySupervisor.py run_path my_engine_pid user_app_pid")
        sys.exit(1)

    run_path = sys.argv[1]
    my_engine_pid = int(sys.argv[2])
    user_app_pid = int(sys.argv[3])
    
    supervisor_proc_run(run_path, my_engine_pid, user_app_pid)
