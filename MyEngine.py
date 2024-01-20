import sys
import os
import signal
import io
from os import stat, remove
from multiprocessing import Process
import subprocess
import pyAesCrypt
import hid
import platform
import tkinter as tk
from tkinter import messagebox

# Constant 
PID = 0x0483
VID = 0x5762

# core states
INTERGRITY_VERIFY  = 0
MUTAL_AUTHENCATION = 1 
KEY_EXCHANGE       = 2
DECRYPT            = 3
START_APP          = 4
APP_RUNNING        = 5
ABNORMAL_BEHAVIOR  = 6
FINISH             = 7

# intergrity verify

SUCCESS            = 0
FAIL               = -1
bufferSize         = 64 * 1024
encryptedFile      = None
decryptedFile      = None
isProcRun          = False
appPID             = None
supervisorPID      = None

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
    global appPID
    global supervisorPID
    
    # decrypt file
    password = "abcde"
    if encryptedFile == None:
        return FAIL
    decryptedFile=createOutputFileName(encryptedFile)
    if decryptedFile == None:
        return FAIL
    with open(encryptedFile, "rb") as fIn:
        try:
            with open(decryptedFile, "wb") as fOut:
                pyAesCrypt.decryptStream(fIn, fOut, password, bufferSize)
        except ValueError:
            remove(decryptedFile)
            messagebox.showinfo("Decrypt failed!")
            return FAIL
    if platform.system() == 'Linux':
        os.system(f'chmod +x {decryptedFile}')
    
    # run program
    decryptedFileRunPath = os.path.abspath(decryptedFile)
    if decryptedFile == None:
        return
    if platform.system() == 'Linux':
        supervisorPID = os.fork()
        if supervisorPID > 0:
            # main process
            print("main PID:", os.getpid())
            print("Child's process - supervisor PID:", supervisorPID)
            appPID = os.fork()
            if appPID > 0:
                # still main process
                print("main PID:", os.getpid())
                print("Child's process - app PID:", appPID)
                while True:
                    pass
            else:
                # app process
                print("app PID:", os.getpid())
                print("Parent's process ID:", os.getppid())
                os.execl(decryptedFileRunPath, decryptedFileRunPath)
        else:
            # supervisor process
            print("super PID:", os.getpid())
            print("Parent's process ID:", os.getppid())
            while True:
                pass
    
    elif platform.system() == "Windows":        
        print("Windows")


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

    
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <encrypted file>")

    else:
        encryptedFile = sys.argv[1]
        if isEncryptedFile(encryptedFile) == True:
            #signal.signal(signal.CTRL_C_EVENT, handler)
            coreRun()
        else:
            messagebox.showinfo("Invalid file")
