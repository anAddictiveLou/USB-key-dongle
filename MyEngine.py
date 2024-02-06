import sys
import os
import signal
import io
from os import stat, remove
from multiprocessing import Process
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

# child process function
def supervisorProcRun():
    print("Supervisor PID = ", os.getpid())
    while True:
        pass
        
def userProcRun():
    print("User PID = ", os.getpid())
    while True:
        pass

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
    print("MyEngine PID = ", os.getpid())
    supervisorProc = Process(target=supervisorProcRun, args=())
    userProc = Process(target=userProcRun, args=())
    supervisorProc.start()
    if (supervisorProc.is_alive()):
        userProc.start()

    while userProc.is_alive() & supervisorProc.is_alive():
        pass
    
    # if not (supervisorProc.is_alive() & userProc.is_alive()):
    #     userProc.join()
    #     supervisorProc.join()    
    #     userProc.close()
    #     supervisorProc.close()
    #     return
                
    if not (supervisorProc.is_alive()):
        if (userProc.is_alive()):
            userProc.kill()

    if not (userProc.is_alive()):
        if (supervisorProc.is_alive()):
            supervisorProc.kill()

    userProc.join()
    supervisorProc.join()
    userProc.close()
    supervisorProc.close()
    return
    
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
