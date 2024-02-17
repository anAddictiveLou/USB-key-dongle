# Project Title: Design a USB Dongle for software protection.
## Introduction
- PC Software: Python code for computer software(MyEngine, MyEncrypt, MySupervisor)
  - Linux: build directory for software on Linux OS.
  - Windows: build directory for software on Windows OS.
- USB Firmware: C code for USB Dongle
## How to build
### PC_Software
- Make sure you have Python3 installed on your system and install pyinstaller module:
  - pip3 install pyinstaller
- For Windows:
  - pyinstaller --specpath ./Windows/spec --distpath ./Windows/dist --workpath ./Windows/build --onefile MyEncrypt.py
  - pyinstaller --specpath ./Windows/spec --distpath ./Windows/dist --workpath ./Windows/build --onefile MyEngine.py
  - pyinstaller --specpath ./Windows/spec --distpath ./Windows/dist --workpath ./Windows/build --onefile MySupervisor.py
- For Linux:
  - pyinstaller --specpath ./Linux/spec --distpath ./Linux/dist --workpath ./Linux/build --onefile MyEncrypt.py
  - pyinstaller --specpath ./Linux/spec --distpath ./Linux/dist --workpath ./Linux/build --onefile MyEngine.py
  - pyinstaller --specpath ./Linux/spec --distpath ./Linux/dist --workpath ./Linux/build --onefile MySupervisor.py
### USB_Firmware
  - STM32Cube_IDE FW_F1 V1.8.5
