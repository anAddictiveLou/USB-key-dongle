import os
import signal
import sys
import psutil
import time

def wait_process_dead_in_timeout(process_name, timeout_seconds):
    start_time = time.time()

    while time.time() - start_time < timeout_seconds:
        # Check if the process is still running
        if not any(process.info['name'] == process_name for process in psutil.process_iter(['name'])):
            # print(f"Process {process_name} terminated.")
            return True

        # Wait for a short duration before checking again
        time.sleep(0.1)

    # print(f"Timeout reached. Unable to terminate {process_name} within {timeout_seconds} seconds.")
    return False

def wait_process_boot_in_timeout(process_name, timeout_seconds):
    start_time = time.time()

    while time.time() - start_time < timeout_seconds:
        # Check if the process is still running
        if any(process.info['name'] == process_name for process in psutil.process_iter(['name'])):
            # print(f"Process {process_name} started.")
            return True

        # Wait for a short duration before checking again
        time.sleep(0.1)

    # print(f"Timeout reached. {process_name} did not start within {timeout_seconds} seconds.")
    return False

def kill_process_by_name(process_name):
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == process_name:
            try:
                pid = process.info['pid']
                process = psutil.Process(pid)
                process.terminate()
                # print(f"Process {process_name} with PID {pid} terminated.")
            except Exception as e:
                print(f"Error terminating process {process_name}: {e}")

def is_process_dead(process_name):
    found_processes = []

    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == process_name:
            found_processes.append(process.info)

    if found_processes:
        for found_process in found_processes:
            if not psutil.pid_exists(found_process['pid']):
                print(f"Process {process_name} with PID {found_process['pid']} is dead.")
                return True  # At least one process is dead

        print(f"All processes with the name {process_name} are still running.")
        return False  # All processes are still running

    print(f"No process found with the name {process_name}.")
    return True  # Process is dead

def supervisor_proc_run(my_engine_name, user_app_name):
    while True:
        if is_process_dead(my_engine_name):
            if not is_process_dead(user_app_name):
                kill_process_by_name(user_app_name)
                wait_process_dead_in_timeout(user_app_name, 5)
                return

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python MySupervisor.py run_path my_engine user_app")
        sys.exit(1)

    run_path = sys.argv[1]
    my_engine_name = sys.argv[2]
    user_app_name = sys.argv[3]
    
    supervisor_proc_run(my_engine_name, user_app_name)
    if is_process_dead(user_app_name):
        os.remove(run_path)