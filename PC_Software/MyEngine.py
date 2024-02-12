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
import hashlib

# USB
vendor_id = 1155
product_id = 22352
serial_number = "403F5C5F3030"
P = "910"
SN = "1706"
r = "2001"

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
INTERGRITY_VERIFY_SEND_C1 = 0
INTERGRITY_VERIFY_RECV_C2 = 1
INTERGRITY_VERIFY_SEND_C3 = 2
INTERGRITY_VERIFY_FINISH  = 3

# mutal Authentication states
MUTUAL_AUTHENTICATION_GENR_SENDV_VP = 0
MUTUAL_AUTHENTICATION_RECVC4_VERIFYR = 1
MUTUAL_AUTHENTICATION_FINISH = 2

# key Exchane states
KEY_EXCHANGE_REQKEY = 0
KEY_EXCHANGE_DECRYPT_KEY = 1
KEY_EXCHANGE_FINISH = 2

# define
SUCCESS            = 0
FAIL               = -1
bufferSize         = 64 * 1024
encryptedFile      = None
decryptedFile      = None
isProcRun          = False
userProc           = None
usb_hid            = None

# Packet def
C1_PREFIX = "0x01"

def open_hid_device(vendor_id, product_id, serial_number):
    try:
        device_info = None
        devices = hid.enumerate()
        for info in devices:
            if info['vendor_id'] == vendor_id and info['product_id'] == product_id and info['serial_number'] == serial_number:
                device_info = info
                break

        if not device_info:
            print("Device not found.")
            return None

        device = hid.device()
        device.open_path(device_info['path'])
        print("Device opened successfully.")
        return device

    except Exception as e:
        print(f"Error opening the device: {e}")
        return None


def recv_packet_from_hid_device(device, packet_size):
    try:
        received_data = device.read(packet_size)
        if received_data:
            return received_data
        else:
            print("No data received.")

    except Exception as e:
        print(f"Error receiving data from the device: {e}")


def send_packet_to_hid_device(device, packet_data):
    try:
        device.write(packet_data)
        print(f"Packet written to the device successfully.")
    except Exception as e:
        print(f"Error sending data to the device: {e}")

def trim_zero_byte(array):
    index = 0

    # Find the index of the first non-zero byte
    for i in range(len(array)):
        if array[i] != 0:
            index = i
            break

    if index != 0:
        # Create a new array containing only the non-zero bytes
        result = array[index:]
        return bytes(result)

    return array

def compute_sha1_hash(data):
    sha1 = hashlib.sha1()
    sha1.update(data)
    return sha1.digest()

def concat_arrays(array1, array2):
    result = bytearray(array1)
    result.extend(array2)
    return result

def bitwise_xor(array1, array2):
    max_length = max(len(array1), len(array2))
    min_length = min(len(array1), len(array2))

    add_zero = bytes([0] * (max_length - min_length))

    if len(array1) > len(array2):
        array2 = concat_arrays(add_zero, array2)
    elif len(array1) < len(array2):
        array1 = concat_arrays(add_zero, array1)

    result = bytearray(max_length)

    for i in range(max_length):
        result[i] = array1[i] ^ array2[i]

    return result

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

def integrityVerifyHandle_sendC1():
    ret = SUCCESS
    global usb_hid
    # Convert strings to bytes
    byteSN = serial_number.encode('utf-8')
    hashedByteSN = compute_sha1_hash(byteSN)
    byteP = P.encode('utf-8')

    # Calculate C1
    C1 = bitwise_xor(hashedByteSN, byteP)
    C1Prefix = bytes([0x01])
    C1Sent = concat_arrays(C1Prefix, C1)
    C1Test = bytes([0x00])
    C1Sent = concat_arrays(C1Test, C1Sent)

    # Print decimal values of C1
    decimal_values = list(C1Sent)
    print("C1 in decimal:", decimal_values)

    # Call the function to send the 21-byte packet and receive data from the HID device
    send_packet_to_hid_device(usb_hid, C1Sent)
    return ret

def integrityVerifyHandle_recvC2():
    ret = SUCCESS
    global usb_hid
    global r

    # C2 Verification    
    # byteSN = serial_number.encode('utf-8')
    # hashedByteSN = compute_sha1_hash(byteSN)
    # byte_r = r.encode('utf-8')
    # C2_USB = bitwise_xor(hashedByteSN, byte_r)
    # decimal_values = list(C2_USB)
    # print("C2 generated by PC: ", decimal_values)
    # r_PC = bitwise_xor(hashedByteSN, C2_USB)
    # r_PC_str = r_PC.decode('utf-8')
    # print("r_pc: ", r_PC_str)
    
    C2Recv = recv_packet_from_hid_device(usb_hid, 21)
    if C2Recv[0] == 0x02:
        ret = SUCCESS
        C2 = C2Recv[1:]
        # Print decimal values of C1
        decimal_values = list(C2)
        print("C2 from USB in decimal: ", decimal_values)
        # Convert strings to bytes
        byteSN = serial_number.encode('utf-8')
        hashedByteSN = compute_sha1_hash(byteSN)
        r_USB = bitwise_xor(hashedByteSN, C2)
        r_USB_trimzero = trim_zero_byte(r_USB)
        r_USB_str = r_USB_trimzero.decode('utf-8')
        # Print decimal values of C1
        # decimal_values = list(r_USB_trimzero)
        # print("r_USB in decimal:", decimal_values)
        # print("r_usb and r: ", r_USB_str, r)
        # print("Length of r_USB_str:", len(r_USB_str))
        # print("Length of r_str:", len(r))
        if r_USB_str == r:
            # print("r_usb: ", r_USB_str)
            ret = SUCCESS
        else:
            ret = FAIL
    else:
        ret = FAIL
    return ret

def integrityVerifyHandle_sendC3():
    ret = SUCCESS
    
    return ret
# state handler function
def integrityVerifyHandle():
    global usb_hid
    integrityVerifyState = INTERGRITY_VERIFY_SEND_C1
    usb_hid = open_hid_device(vendor_id, product_id, serial_number)
    while integrityVerifyState != INTERGRITY_VERIFY_FINISH:
        if integrityVerifyState == INTERGRITY_VERIFY_SEND_C1:
            if SUCCESS == integrityVerifyHandle_sendC1():
                integrityVerifyState = INTERGRITY_VERIFY_RECV_C2
            else:
                ret = FAIL

        elif integrityVerifyState == INTERGRITY_VERIFY_RECV_C2:
            if SUCCESS == integrityVerifyHandle_recvC2():
                integrityVerifyState = INTERGRITY_VERIFY_FINISH
                ret = SUCCESS
            else:
                ret = FAIL

        else:
            ret = FAIL
            
    return ret

def mutualAuthenticationHandle_genR_sendV_VP():
    ret = SUCCESS
    return ret

def mutualAuthenticationHandle_recvC4_verifyR():
    ret = SUCCESS
    return ret

def mutualAuthenticationHandle():
    ret = SUCCESS
    mutualAuthenticationState = MUTUAL_AUTHENTICATION_GENR_SENDV_VP
    while mutualAuthenticationState != MUTUAL_AUTHENTICATION_FINISH:
        if mutualAuthenticationState == MUTUAL_AUTHENTICATION_GENR_SENDV_VP:
            if SUCCESS == mutualAuthenticationHandle_genR_sendV_VP():
                mutualAuthenticationState = MUTUAL_AUTHENTICATION_RECVC4_VERIFYR
            else:
                ret = FAIL

        elif mutualAuthenticationState == MUTUAL_AUTHENTICATION_RECVC4_VERIFYR:
            if SUCCESS == mutualAuthenticationHandle_recvC4_verifyR():
                mutualAuthenticationState = MUTUAL_AUTHENTICATION_FINISH
                ret = SUCCESS
            else:
                ret = FAIL
    return ret

def keyExchangeHandle_reqKey():
    ret = SUCCESS
    return ret

def keyExchangeHandle_decryptKey():
    ret = SUCCESS
    return ret

def keyExchangeHandle():
    ret = SUCCESS
    keyExchangeState = KEY_EXCHANGE_REQKEY
    while keyExchangeState != KEY_EXCHANGE_FINISH:
        if keyExchangeState == KEY_EXCHANGE_REQKEY:
            if SUCCESS == keyExchangeHandle_reqKey():
                keyExchangeState = KEY_EXCHANGE_DECRYPT_KEY
            else:
                ret = FAIL

        elif keyExchangeState == KEY_EXCHANGE_DECRYPT_KEY:
            if SUCCESS == keyExchangeHandle_decryptKey():
                keyExchangeState = KEY_EXCHANGE_FINISH
                ret = SUCCESS
            else:
                ret = FAIL
    return ret

def startAppHandle():
    ret = SUCCESS
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
    return ret


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
    ret = SUCCESS
    state = INTERGRITY_VERIFY
    while state != FINISH:
        if state == INTERGRITY_VERIFY:
            if SUCCESS == integrityVerifyHandle():
                state = MUTAL_AUTHENCATION
            else:
                ret = FAIL

        elif state == MUTAL_AUTHENCATION:
            if SUCCESS == mutualAuthenticationHandle():
                state = KEY_EXCHANGE
            else:
                ret = FAIL

        elif state == KEY_EXCHANGE:
            if SUCCESS == keyExchangeHandle():
                state = START_APP
            else:
                ret = FAIL

        elif state == START_APP:
            if SUCCESS == startAppHandle():
                state = FINISH
                ret = SUCCESS
            else:
                ret = FAIL
    return ret

# main function
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <encrypted file>")

    else:
        encryptedFile = sys.argv[1]
        if isEncryptedFile(encryptedFile) == True:
            if SUCCESS == coreRun():
                exit(SUCCESS)
            else:
                exit(FAIL)
        else:
            messagebox.showinfo("Invalid file")
