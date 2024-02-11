################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (11.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Arr_Byte/Src/arr_opr.c 

OBJS += \
./Arr_Byte/Src/arr_opr.o 

C_DEPS += \
./Arr_Byte/Src/arr_opr.d 


# Each subdirectory must supply rules for building sources it contributes
Arr_Byte/Src/%.o Arr_Byte/Src/%.su Arr_Byte/Src/%.cyclo: ../Arr_Byte/Src/%.c Arr_Byte/Src/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m3 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32F103xB -c -I../Core/Inc -I../Drivers/STM32F1xx_HAL_Driver/Inc/Legacy -I../Drivers/STM32F1xx_HAL_Driver/Inc -I../Drivers/CMSIS/Device/ST/STM32F1xx/Include -I../Drivers/CMSIS/Include -I../USB_DEVICE/App -I../USB_DEVICE/Target -I../Middlewares/ST/STM32_USB_Device_Library/Core/Inc -I../Middlewares/ST/STM32_USB_Device_Library/Class/CustomHID/Inc -I"C:/Users/Admin/STM32CubeIDE/workspace_1.12.0/usb_test/Cryto/Inc" -I"C:/Users/Admin/STM32CubeIDE/workspace_1.12.0/usb_test/Arr_Byte/Inc" -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfloat-abi=soft -mthumb -o "$@"

clean: clean-Arr_Byte-2f-Src

clean-Arr_Byte-2f-Src:
	-$(RM) ./Arr_Byte/Src/arr_opr.cyclo ./Arr_Byte/Src/arr_opr.d ./Arr_Byte/Src/arr_opr.o ./Arr_Byte/Src/arr_opr.su

.PHONY: clean-Arr_Byte-2f-Src

