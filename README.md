# This is N4 graduation thesis project.
## how to build
### PC_Software
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
