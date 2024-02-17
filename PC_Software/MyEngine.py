import sys
import os, stat
import signal
import io
from os import stat, remove
from multiprocessing import Process
import time
import multiprocessing as mp
import subprocess
import pyAesCrypt
import hid
import platform
import psutil
import tkinter as tk
from tkinter import messagebox
import hashlib
import secrets
from Crypto.Cipher import AES

# idx
MYENGINE_IDX       = 0
SUPERVISOR_IDX     = 1
USERAPP_IDX        = 2

# core states
INTERGRITY_VERIFY  = 0
MUTAL_AUTHENCATION = 1 
KEY_EXCHANGE       = 2
START_APP          = 3
FINISH             = 4

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
AES_KEY_SIZE       = 16
MAX_R_LENGTH       = AES_KEY_SIZE
bufferSize         = 64 * 1024
encryptedFile      = None
decryptedFile      = None
isProcRun          = False
userProc           = None
usb_hid            = None

# USB
vendor_id = 1155
product_id = 22352
serial_number = "403F5C5F3030"
P = "1234526"
r = "2001123a"
R = secrets.token_bytes(MAX_R_LENGTH)
DecryptedKey = None
r_file_path = "encrypted_data.txt.aes"
r_file_password = "your_secure_password"

def subprocess_args(include_stdout=True):
    # The following is true only on Windows.
    if hasattr(subprocess, 'STARTUPINFO'):
        # On Windows, subprocess calls will pop up a command window by default
        # when run from Pyinstaller with the ``--noconsole`` option. Avoid this
        # distraction.
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        # Windows doesn't search the path by default. Pass it an environment so
        # it will.
        env = os.environ
    else:
        si = None
        env = None

    # ``subprocess.check_output`` doesn't allow specifying ``stdout``::
    #
    #   Traceback (most recent call last):
    #     File "test_subprocess.py", line 58, in <module>
    #       **subprocess_args(stdout=None))
    #     File "C:\Python27\lib\subprocess.py", line 567, in check_output
    #       raise ValueError('stdout argument not allowed, it will be overridden.')
    #   ValueError: stdout argument not allowed, it will be overridden.
    #
    # So, add it only if it's needed.
    if include_stdout:
        ret = {'stdout': subprocess.PIPE}
    else:
        ret = {}

    # On Windows, running this from the binary produced by Pyinstaller
    # with the ``--noconsole`` option requires redirecting everything
    # (stdin, stdout, stderr) to avoid an OSError exception
    # "[Error 6] the handle is invalid."
    ret.update({'stdin': subprocess.PIPE,
                'stderr': subprocess.PIPE,
                'startupinfo': si,
                'env': env })
    return ret

def sigchld_handler(signum, frame):
    while True:
        try:
            # -1 means any child process
            pid, status = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break  # No more child processes to reap
            else:
                print(f"Child process {pid} terminated with status {status}")
        except OSError:
            break

def get_r_value_from_file(file_path, password):
    try:
        return read_encrypted_string(file_path, password)
    except Exception as e:
        print("Error:", e)

def put_r_value_to_file(file_path, password, value):
    try:
        write_encrypt_string(file_path, password, value)
        print("File updated and encrypted successfully.")
    except Exception as e:
        print("Error:", e)

def encrypt_file(password, input_file, output_file):
    bufferSize = 64 * 1024
    pyAesCrypt.encryptFile(input_file, output_file, password, bufferSize)

def decrypt_file(password, input_file, output_file):
    bufferSize = 64 * 1024
    pyAesCrypt.decryptFile(input_file, output_file, password, bufferSize)

def read_encrypted_string(file_path, password):
    decrypt_temp_file = "temp_decrypted.txt"
    decrypt_file(password, file_path, decrypt_temp_file)

    with open(decrypt_temp_file, "r") as f:
        decrypted_string = f.read()

    os.remove(decrypt_temp_file)
    return decrypted_string

def write_encrypt_string(file_path, password, new_string):
    encrypt_temp_file = "temp_encrypted.txt"

    with open(encrypt_temp_file, "w") as f:
        f.write(new_string)

    encrypt_file(password, encrypt_temp_file, file_path)
    os.remove(encrypt_temp_file)

def encrypt_aes_ecb(key, plaintext):
    # Ensure the key length is correct (128 bits = 16 bytes)
    assert len(key) == AES_KEY_SIZE

    # Create AES cipher object with ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext

def decrypt_aes_ecb(key, ciphertext):
    # Ensure the key length is correct (128 bits = 16 bytes)
    assert len(key) == AES_KEY_SIZE

    # Create AES cipher object with ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt the ciphertext
    decrypted_data = cipher.decrypt(ciphertext)

    return decrypted_data

def open_hid_device(vendor_id, product_id, serial_number):
    try:
        device_info = None
        devices = hid.enumerate()
        for info in devices:
            if info['vendor_id'] == vendor_id and info['product_id'] == product_id and info['serial_number'] == serial_number:
                device_info = info
                break

        if not device_info:
            messagebox.showerror("Device not found.")
            sys.exit(FAIL)

        device = hid.device()
        device.open_path(device_info['path'])
        # print("Device opened successfully.")
        return device

    except Exception as e:
        # print(f"Error opening the device: {e}")
        return None

def close_hid_device(device):
    try:
        if device:
            device.close()
            # print("Device closed successfully.")
        else:
            print("No device to close.")

    except Exception as e:
        sys.exit(1)
        # gprint(f"Error closing the device: {e}")

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
        # prin(f"Packet written to the device successfully.")
    except Exception as e:
        print(f"Error sending data to the device: {e}")

def is_usb_device_connected(vendor_id, product_id, serial_number):
    devices = hid.enumerate()
    for info in devices:
        if (
            info['vendor_id'] == vendor_id
            and info['product_id'] == product_id
            and info['serial_number'] == serial_number
        ):
            return True
    return False

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

def print_decimal_values(name, data):
    decimal_values = list(data)
    print(f"{name} in decimal: {decimal_values}")

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
        # print("Unsupported operating system")
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
    C1Sent = concat_arrays(bytes([0x00]), C1Sent)

    # Print decimal values of C1
    decimal_values = list(C1Sent)
    # print("C1 in decimal:", decimal_values)

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
        # print("C2 from USB in decimal: ", decimal_values)
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
    global R
    global usb_hid

    # Compute V and send V xor r
    byte_P = P.encode('utf-8')
    byte_r = r.encode('utf-8')
    byte_r_concat_P = concat_arrays(byte_r, byte_P)
    V = compute_sha1_hash(byte_r_concat_P)
    decimal_values = list(V)
    # print("V from PC in decimal: ", decimal_values)
    V_xor_r = bitwise_xor(V, byte_r)
    V_xor_r_Prefix = bytes([0x04])
    V_xor_r_Sent = concat_arrays(V_xor_r_Prefix, V_xor_r)
    V_xor_r_first_byte = bytes([0x00])
    V_xor_r_Sent = concat_arrays(V_xor_r_first_byte, V_xor_r_Sent)
    decimal_values = list(V_xor_r_Sent)
    # print("V xor r packet from PC in decimal: ", decimal_values)
    send_packet_to_hid_device(usb_hid, V_xor_r_Sent)

    # verify V
    V_test = bitwise_xor(V_xor_r, byte_r)
    decimal_values = list(V_test)
    # print("V test from PC in decimal: ", decimal_values)

    # Compute Vp and send Vp xor r
    byte_R_concat_P = concat_arrays(R, byte_P)
    Vp = compute_sha1_hash(byte_R_concat_P)
    Vp_xor_r = bitwise_xor(Vp, byte_r)
    Vp_xor_r_Prefix = bytes([0x05])
    Vp_xor_r_Sent = concat_arrays(Vp_xor_r_Prefix, Vp_xor_r)
    Vp_xor_r_first_byte = bytes([0x00])
    Vp_xor_r_Sent = concat_arrays(Vp_xor_r_first_byte, Vp_xor_r_Sent)
    decimal_values = list(Vp_xor_r_Sent)
    # print("Vp xor r packet from PC in decimal: ", decimal_values)
    send_packet_to_hid_device(usb_hid, Vp_xor_r_Sent)

    # Send R to USB
    decimal_values = list(R)
    # print("R from PC in decimal: ", decimal_values)
    R_Prefix = bytes([0x06])
    R_Sent = concat_arrays(R_Prefix, R)
    R_test = bytes([0x00])
    R_Sent = concat_arrays(R_test, R_Sent)
    decimal_values = list(R_Sent)
    # print("R from PC in decimal: ", decimal_values)
    send_packet_to_hid_device(usb_hid, R_Sent)
    return ret

def mutualAuthenticationHandle_recvC4_verifyR():
    global R
    global r
    ret = SUCCESS
    # Sk from PC, Sk = H(r) xor R
    byte_r = r.encode('utf-8')
    Hr = compute_sha1_hash(byte_r)
    decimal_values = list(Hr)
    # print("Hr from PC in decimal: ", decimal_values)
    Sk = bitwise_xor(Hr, R)
    # print_decimal_values("Sk", Sk)
    # Use Sk and R truncate 16bytes instead
    Sk_truncate = Sk[:16]
    Sk_truncate = bytes(Sk_truncate)

    # Cal R = De(Sk, C4)
    C4Test = encrypt_aes_ecb(Sk_truncate, R)
    # print_decimal_values("C4 from PC generate by PC for testing", C4Test)
    R_from_USB_test = decrypt_aes_ecb(Sk_truncate, C4Test)
    # print_decimal_values("R_from_USB generate by PC for testing", R_from_USB_test)

    C4Recv = recv_packet_from_hid_device(usb_hid, 21)
    if C4Recv[0] == 0x07:
        C4 = bytes(C4Recv[5:])
        # print_decimal_values("C4 from USB", C4)
        R_from_USB = decrypt_aes_ecb(Sk_truncate, C4)
        # print_decimal_values("R_from_USB", R_from_USB)
        if R_from_USB == R:
            # print("R from USB is verified", R_from_USB)
            ret = SUCCESS
        else:
            ret = FAIL
    else:
        ret = FAIL
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
    global R
    global usb_hid

    # Compute H(R) xor SN
    HR = compute_sha1_hash(R)
    # print_decimal_values("HR from PC", HR)
    byteSN = serial_number.encode('utf-8')
    HR_xor_SN = bitwise_xor(HR, byteSN)
    # # print_decimal_values("HR_xor_SN from PC", HR_xor_SN)
    HR_xor_SN_Prefix = bytes([0x08])
    HR_xor_SN_Sent = concat_arrays(HR_xor_SN_Prefix, HR_xor_SN)
    HR_xor_SN_Sent = concat_arrays(bytes([0x00]), HR_xor_SN_Sent)
    # # print_decimal_values("HR_xor_SN_Sent from PC", HR_xor_SN_Sent)
    send_packet_to_hid_device(usb_hid, HR_xor_SN_Sent)

    return ret

def keyExchangeHandle_decryptKey():
    ret = SUCCESS
    global DecryptedKey
    # Sk from PC, Sk = H(r) xor R
    byte_r = r.encode('utf-8')
    Hr = compute_sha1_hash(byte_r)
    Sk = bitwise_xor(Hr, R)
    # Use Sk and R truncate 16bytes instead
    Sk_truncate = bytes(Sk[:16])

    # Decrypt Key
    EncryptedKeyRecv = recv_packet_from_hid_device(usb_hid, 21)
    # print_decimal_values("EncryptedKeyRecv from USB", EncryptedKeyRecv)
    if EncryptedKeyRecv[0] == 0x09:
        EncryptedKey = bytes(EncryptedKeyRecv[5:])
        # print_decimal_values("EncryptedKey from USB", EncryptedKey)
        DecryptedKey = decrypt_aes_ecb(Sk_truncate, EncryptedKey)
        # print_decimal_values("DecryptedKey:", DecryptedKey)
        close_hid_device(usb_hid)
        ret = SUCCESS
    else:
        ret = FAIL

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


def terminate_all_processes(user_app_pid, supervisor_pid):
    # Terminate all processes
    if psutil.pid_exists(user_app_pid):
        os.kill(user_app_pid, signal.SIGTERM)

    if psutil.pid_exists(supervisor_pid):
        os.kill(supervisor_pid, signal.SIGTERM)

def check_and_terminate(user_app_pid, supervisor_pid, run_file):
    global vendor_id
    global product_id
    global serial_number
    # Exclude the calling process PID
    process_pids = [user_app_pid, supervisor_pid]
    while True:
        for pid in process_pids:
            if not psutil.pid_exists(pid):
                if pid == user_app_pid:
                    if psutil.pid_exists(supervisor_pid):
                        os.kill(supervisor_pid, signal.SIGTERM)
                elif pid == supervisor_pid:
                    if psutil.pid_exists(user_app_pid):
                        os.kill(user_app_pid, signal.SIGTERM)
                        time.sleep(2)
                # print(f"Process with PID {pid} has died. Terminating all processes.")
                if not psutil.pid_exists(user_app_pid):
                    os.remove(run_file)
                sys.exit(0)
        if not is_usb_device_connected(vendor_id, product_id, serial_number):
            terminate_all_processes(user_app_pid, supervisor_pid)
            messagebox.showerror("USB is plugged out!")
            time.sleep(1)
            if not psutil.pid_exists(user_app_pid):
                os.remove(run_file)
            sys.exit(0)

def startAppHandle():
    ret = SUCCESS
    global decryptedFile
    global encryptedFile
    global DecryptedKey
    global userProc

    if DecryptedKey == None:
        return FAIL

    # decrypt file
    DecryptedKey = DecryptedKey.decode('utf-8')
    decryptedFile=createOutputFileName(encryptedFile)
    with open(encryptedFile, "rb") as fIn:
        try:
            with open(decryptedFile, "wb") as fOut:
                pyAesCrypt.decryptStream(fIn, fOut, DecryptedKey, bufferSize)
        except ValueError:
            remove(decryptedFile)
            messagebox.showerror("Decrypt failed!")
            sys.exit(FAIL)
    if platform.system() == 'Linux':
        os.system(f'chmod +x {decryptedFile}')

    # run program
    mp.set_start_method('spawn')
    decryptedFileRunPath = os.path.abspath(decryptedFile)

    # Set the MyEngine PID in shared memory
    my_engine_pid = os.getpid()

    if platform.system() == 'Linux':
        #sigchld handler
        signal.signal(signal.SIGCHLD, sigchld_handler)


    # Start user process
    userApp = subprocess.Popen([decryptedFileRunPath])
    user_app_pid = userApp.pid

    time.sleep(1)

    # Start supervisor process
    supervisor_cmd = ['.\dist\MySupervisor.exe', decryptedFileRunPath, str(my_engine_pid), str(user_app_pid)]
    supervisor_proc = subprocess.Popen(supervisor_cmd)
    supervisor_pid = supervisor_proc.pid

    time.sleep(1)

    check_and_terminate(user_app_pid, supervisor_pid, decryptedFileRunPath)
    return ret

def coreRun():
    global r
    ret = SUCCESS
    #r = get_r_value_from_file(r_file_path, r_file_password)
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
                sys.exit(SUCCESS)
            else:
                sys.exit(FAIL)
        else:
            messagebox.showerror("Invalid file")
            sys.exit(FAIL)