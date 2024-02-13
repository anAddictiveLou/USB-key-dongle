import os
import pyAesCrypt

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

if __name__ == "__main__":
    file_path = "encrypted_data.txt.aes"
    password = "your_secure_password"

    try:
        current_string = get_r_value_from_file(file_path, password)
        print("Current encrypted string:", current_string)

        new_string = input("Enter the new string: ")

        if new_string != current_string:
            write_encrypt_string(file_path, password, new_string)
            print("File updated and encrypted successfully.")
        else:
            print("No change in the string.")
    except Exception as e:
        print("Error:", e)
