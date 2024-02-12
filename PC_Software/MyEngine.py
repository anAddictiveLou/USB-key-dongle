import sys
import os, stat
import signal
import io
from os import stat, remove
from multiprocessing import Process, Value, Array
import multiprocessing as mp
import subprocess
import pyAesCrypt
import hid
import platform
import psutil
import tkinter as tk
from tkinter import messagebox

# Constant 
PID = 0x0483
VID = 0x5762

MYENGINE_IDX       = 0
SUPERVISOR_IDX     = 1
USERPROC_IDX       = 2
USERAPP_IDX        = 3

# core states
INTERGRITY_VERIFY  = 0
MUTAL_AUTHENCATION = 1 
KEY_EXCHANGE       = 2
DECRYPT            = 3
START_APP          = 4
APP_RUNNING        = 5
ABNORMAL_BEHAVIOR  = 6
FINISH             = 7

# intergrity verify states

# define
SUCCESS            = 0
FAIL               = -1
bufferSize         = 64 * 1024
encryptedFile      = None
decryptedFile      = None
isProcRun          = False
userProc           = None

def change_file_permissions(file_path, permissions):
    system_platform = platform.system()

    if system_platform == 'Windows':
        command = (
                f'icacls "{file_path}" /inheritance:r '
                f'/grant:r "BUILTIN\\Administrators:(OI)(CI)F" '
                f'"NT AUTHORITY\\SYSTEM:(OI)(CI)F" '
                f'"NT AUTHORITY\\Authenticated Users:(OI)(CI)F" '
                f'"BUILTIN\\Users:(OI)(CI)F"'
            )
        subprocess.run(command, shell=True)
    elif system_platform == 'Linux':
        os.chmod(file_path, int(permissions, 8))
    else:
        print("Unsupported operating system")

def terminate_all_processes(shared_memory, run_file, calling_pid , dead_pid):
    my_engine_pid, supervisor_pid, user_proc_pid, user_app_pid = shared_memory
    # Terminate all processes
    if psutil.pid_exists(user_app_pid) & dead_pid != user_app_pid & calling_pid != user_app_pid:
        os.kill(user_app_pid, signal.SIGTERM)

    if psutil.pid_exists(user_proc_pid) & dead_pid != user_proc_pid & calling_pid != user_proc_pid:
        os.kill(user_proc_pid, signal.SIGTERM)

    if psutil.pid_exists(supervisor_pid) & dead_pid != supervisor_pid & calling_pid != supervisor_pid:
        os.kill(supervisor_pid, signal.SIGTERM)

    if psutil.pid_exists(my_engine_pid) & dead_pid != my_engine_pid & calling_pid != my_engine_pid:
        os.kill(my_engine_pid, signal.SIGTERM)


def check_and_terminate(shared_memory, calling_pid, run_file):
    my_engine_pid, supervisor_pid, user_proc_pid, user_app_pid = shared_memory
    # Exclude the calling process PID
    process_pids = [my_engine_pid, supervisor_pid, user_proc_pid, user_app_pid]
    process_pids.remove(calling_pid)
    # Check if any of the processes have died
    while True:
        for pid in process_pids:
            if not psutil.pid_exists(pid):
                print(f"Process with PID {pid} has died. Terminating all processes.")
                terminate_all_processes(shared_memory, run_file, calling_pid , pid)
                remove_file(run_file)
                return

def log_pid(shared_memory, proc_name):
    idx = 0
    while idx < len(shared_memory):
        pid = shared_memory[idx]
        if pid == 0:
            idx = 0  # Reset the index to start again
            continue
        idx+=1

    print("")
    print("Main proc from ", proc_name, shared_memory[MYENGINE_IDX])
    print("Supervisor PID from ", proc_name, shared_memory[SUPERVISOR_IDX])
    print("UserProc from ", proc_name, shared_memory[USERPROC_IDX])
    print("UserApp PID from ", proc_name, shared_memory[USERAPP_IDX])
    print("")

def create_shared_memory():
    my_engine_pid = Value('i', 0)
    user_proc_pid = Value('i', 0)
    supervisor_proc_pid = Value('i', 0)
    user_app_pid = Value('i', 0)
    shared_memory = Array('i', [my_engine_pid.value, user_proc_pid.value, supervisor_proc_pid.value, user_app_pid.value])
    return shared_memory

def remove_file(file):
    try:
        os.remove(file)
        print(f"File '{file}' removed successfully.")
    except Exception as e:
        print(f"Error removing '{file}': {e}")

# utility function
def isEncryptedFile(filePath):
    _, file_extension = os.path.splitext(filePath)
    return file_extension.lower() == '.aes'

def createOutputFileName(filePath):
    directory, oldFileName = os.path.split(filePath)
    filename_without_extension, _ = os.path.splitext(oldFileName)
    if platform.system() == 'Windows':
        newExtension = 'exe'
    elif platform.system() == 'Linux':
        newExtension = 'out'
    else:
        print("Unsupported operating system")
        return None
    newFileName = filename_without_extension + '.' + newExtension
    newFilePath = os.path.join(directory, newFileName)
    return newFilePath

# state handler function
def integrityVerifyHandle():
    try:
        h = hid.device()
        h.open(PID, VID)
    except IOError as ex:
        messagebox.showinfo(ex)
        return FAIL
    return SUCCESS

def mutualAuthenticationHandle():
    print("Mutual authentication in progress...")
    # Your mutual authentication logic goes here
    return True  # For the sake of example, assuming it always succeeds

def keyExchangeHandle():
    print("Key exchange in progress...")
    # Your key exchange logic goes here
    return True  # For the sake of example, assuming it always succeeds

def startAppHandle():
    global decryptedFile
    global encryptedFile
    global userProc

    # decrypt file
    password = "abcde"
    decryptedFile=createOutputFileName(encryptedFile)
    with open(encryptedFile, "rb") as fIn:
        try:
            with open(decryptedFile, "wb") as fOut:
                pyAesCrypt.decryptStream(fIn, fOut, password, bufferSize)
        except ValueError:
            remove(decryptedFile)
            messagebox.showinfo("Decrypt failed!")
    if platform.system() == 'Linux':
        os.system(f'chmod +x {decryptedFile}')

    # run program
    mp.set_start_method('spawn')
    decryptedFileRunPath = os.path.abspath(decryptedFile)

    # create shared mem
    shared_memory = create_shared_memory()
    # Set the MyEngine PID in shared memory
    shared_memory[MYENGINE_IDX] = os.getpid()

    userProc = Process(target=userProcRun, args=(decryptedFileRunPath, shared_memory, ))
    userProc.start()

    supervisorProc = Process(target=supervisorProcRun, args=(decryptedFileRunPath, shared_memory, ))
    supervisorProc.start()

    log_pid(shared_memory, "myEngine")
    check_and_terminate(shared_memory, shared_memory[MYENGINE_IDX], decryptedFileRunPath)
    return


# supervisor Process Handle
def supervisorProcRun(runPath, shared_memory):
    shared_memory[SUPERVISOR_IDX] = os.getpid()
    log_pid(shared_memory, "supervisorProc")
    check_and_terminate(shared_memory, shared_memory[SUPERVISOR_IDX], runPath)
    
def userProcRun(runPath, shared_memory):
    shared_memory[USERPROC_IDX] = os.getpid()
    userApp = subprocess.Popen([runPath])
    shared_memory[USERAPP_IDX] = userApp.pid
    log_pid(shared_memory, "userProc")
    check_and_terminate(shared_memory, shared_memory[USERPROC_IDX], runPath)

def coreRun():
    state = START_APP
    while state != FINISH:
        if state == INTERGRITY_VERIFY:
            if SUCCESS == integrityVerifyHandle():
                state = MUTAL_AUTHENCATION
            else:
                state = FINISH

        elif state == MUTAL_AUTHENCATION:
            if SUCCESS == mutualAuthenticationHandle():
                state = KEY_EXCHANGE
            else:
                state = FINISH

        elif state == KEY_EXCHANGE:
            if SUCCESS == keyExchangeHandle():
                state = START_APP
            else:
                state = FINISH

        elif state == START_APP:
            startAppHandle()
            state = FINISH

# main function
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <encrypted file>")

    else:
        encryptedFile = sys.argv[1]
        if isEncryptedFile(encryptedFile) == True:
            coreRun()
        else:
            messagebox.showinfo("Invalid file")
