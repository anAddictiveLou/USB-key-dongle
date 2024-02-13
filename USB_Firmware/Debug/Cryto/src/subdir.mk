################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (11.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Cryto/src/aes.c \
../Cryto/src/sha1.c 

OBJS += \
./Cryto/src/aes.o \
./Cryto/src/sha1.o 

C_DEPS += \
./Cryto/src/aes.d \
./Cryto/src/sha1.d 


# Each subdirectory must supply rules for building sources it contributes
Cryto/src/%.o Cryto/src/%.su Cryto/src/%.cyclo: ../Cryto/src/%.c Cryto/src/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m3 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32F103xB -c -I../Core/Inc -I../Drivers/STM32F1xx_HAL_Driver/Inc/Legacy -I../Drivers/STM32F1xx_HAL_Driver/Inc -I../Drivers/CMSIS/Device/ST/STM32F1xx/Include -I../Drivers/CMSIS/Include -I../USB_DEVICE/App -I../USB_DEVICE/Target -I../Middlewares/ST/STM32_USB_Device_Library/Core/Inc -I../Middlewares/ST/STM32_USB_Device_Library/Class/CustomHID/Inc -I"D:/College/DATN_final/USB-key-dongle/USB_Firmware/Cryto/Inc" -I"D:/College/DATN_final/USB-key-dongle/USB_Firmware/Arr_Byte/Inc" -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfloat-abi=soft -mthumb -o "$@"

clean: clean-Cryto-2f-src

clean-Cryto-2f-src:
	-$(RM) ./Cryto/src/aes.cyclo ./Cryto/src/aes.d ./Cryto/src/aes.o ./Cryto/src/aes.su ./Cryto/src/sha1.cyclo ./Cryto/src/sha1.d ./Cryto/src/sha1.o ./Cryto/src/sha1.su

.PHONY: clean-Cryto-2f-src

