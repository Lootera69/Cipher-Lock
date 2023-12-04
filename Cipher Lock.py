from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

def generate_aes_key():
    return Fernet.generate_key()

encryption_key = generate_aes_key()

def decrypt():
    selected_algorithm = algorithm_choice.get()
    message = text1.get(1.0, END)
    decrypted_message = ""
    if selected_algorithm == "Base64":
        password = code.get()
        if password == "1234":
            decrypted_message = base64_decrypt(message)
        else:
            messagebox.showerror("Decryption", "Invalid Password")
            return
    elif selected_algorithm == "Caesar Cipher":
        shift = int(shift_entry.get())
        decrypted_message = caesar_decrypt(message, shift)
    elif selected_algorithm == "XOR Cipher":
        key = key_entry.get()
        decrypted_message = xor_decrypt(message, key)
    elif selected_algorithm == "AES":
        decrypted_message = aes_decrypt(message, encryption_key)
        #key = aes_key_entry.get()
        #decrypted_message = aes_decrypt(message, b'key1g2OabaDu6GuSMfqlkTdXjYxlVThEDT-ip8oqN7D1yI=')
    elif selected_algorithm == "DES":
        key = des_key_entry.get()
        decrypted_message = des_decrypt(message, key)

    screen2 = Toplevel(screen)
    screen2.title("Decryption")
    screen2.geometry("400x200")
    screen2.configure(bg="#00bd56")

    Label(screen2, text="DECRYPT", font="arial", fg="white", bg="#00bd56").place(x=10, y=0)
    text2 = Text(screen2, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text2.place(x=10, y=40, width=380, height=150)

    text2.insert(END, decrypted_message)

def encrypt():
    selected_algorithm = algorithm_choice.get()
    message = text1.get(1.0, END)

    if selected_algorithm == "Base64":
        password = code.get()
        if password == "1234":
            encrypted_message = base64_encrypt(message)
        else:
            messagebox.showerror("Encryption", "Invalid Password")
            return
    elif selected_algorithm == "Caesar Cipher":
        shift = int(shift_entry.get())
        encrypted_message = caesar_encrypt(message, shift)
    elif selected_algorithm == "XOR Cipher":
        key = key_entry.get()
        encrypted_message = xor_encrypt(message, key)
    elif selected_algorithm == "AES":
        encrypted_message = aes_encrypt(message, encryption_key)
        #key = aes_key_entry.get()
        #encrypted_message = aes_encrypt(message, b'1g2OabaDu6GuSMfqlkTdXjYxlVThEDT-ip8oqN7D1yI=')
    elif selected_algorithm == "DES":
        key = des_key_entry.get()
        encrypted_message = des_encrypt(message, key)

    screen1 = Toplevel(screen)
    screen1.title("Encryption")
    screen1.geometry("400x200")
    screen1.configure(bg="#ed3833")

    Label(screen1, text="ENCRYPT", font="arial", fg="white", bg="#ed3833").place(x=10, y=0)
    text2 = Text(screen1, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text2.place(x=10, y=40, width=380, height=150)

    text2.insert(END, encrypted_message)

def base64_encrypt(message):
    encode_msg = message.encode("ascii")
    base64_bytes = base64.b64encode(encode_msg)
    encrypted_message = base64_bytes.decode("ascii")
    return encrypted_message

def base64_decrypt(message):
    decode_msg = message.encode("ascii")
    base64_bytes = base64.b64decode(decode_msg)
    decrypted_message = base64_bytes.decode("ascii")
    return decrypted_message

def caesar_encrypt(message, shift):
    encrypted_message = caesar_cipher(message, shift, "encrypt")
    return encrypted_message

def caesar_decrypt(message, shift):
    decrypted_message = caesar_cipher(message, shift, "decrypt")
    return decrypted_message

def xor_encrypt(message, key):
    encrypted_message = xor_cipher(message, key)
    return encrypted_message

def xor_decrypt(message, key):
    decrypted_message = xor_cipher(message, key)
    return decrypted_message

def caesar_cipher(text, shift, mode):
    result = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                result += chr((ord(char) - ord('a') + shift) % 26 + ord('a')) if mode == "encrypt" else chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') + shift) % 26 + ord('A')) if mode == "encrypt" else chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
        else:
            result += char
    return result

def xor_cipher(text, key):
    result = ""
    for i in range(len(text)):
        result += chr(ord(text[i]) ^ ord(key[i % len(key)]))
    return result


def aes_encrypt(message, key):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode('utf-8'))
    return encrypted_message

def aes_decrypt(encrypted_message, key):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode('utf-8')
    return decrypted_message

def des_encrypt(message, key):
    key = key.encode('utf-8')
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    data = padder.update(message.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    encrypted_message = base64.b64encode(ciphertext).decode('utf-8')
    return encrypted_message

def des_decrypt(message, key):
    key = key.encode('utf-8')
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
    decryptor = cipher.decryptor()
    ciphertext = base64.b64decode(message.encode('utf-8'))
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    data = unpadder.update(decrypted_data) + unpadder.finalize()
    decrypted_message = data.decode('utf-8')
    return decrypted_message

def reset():
    code.set("")
    text1.delete("1.0", "end")
    shift_entry.delete(0, "end")
    key_entry.delete(0, "end")
    aes_key_entry.delete(0, "end")
    des_key_entry.delete(0, "end")

def main_screen():
    global screen
    global text1
    global algorithm_choice
    global code
    global key_entry
    global shift_entry
    global aes_key_entry
    global des_key_entry

    screen = Tk()
    screen.geometry("375x480")
    screen.title("Encryption App")

    Label(text="Enter text for encryption and decryption", fg="black", font=("calibri", 13)).place(x=10, y=10)
    text1 = Text(font="Roboto 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=50, width=355, height=100)

    Label(text="Select encryption method:", fg="black", font=("calibri", 13)).place(x=10, y=170)

    algorithm_choice = StringVar()
    algorithm_choice.set("Base64")  # Default choice
    OptionMenu(screen, algorithm_choice, "Base64", "Caesar Cipher", "XOR Cipher", "AES", "DES").place(x=200, y=170)

    Label(text="Enter secret key for Base64:", fg="black", font=("calibri", 13)).place(x=10, y=200)
    code = StringVar()
    Entry(textvariable=code, width=19, bd=1, font=("arial", 14), show="*").place(x=220, y=200)

    Label(text="Enter Caesar Cipher shift (0-25):", fg="black", font=("calibri", 13)).place(x=10, y=230)
    shift_entry = Entry(width=19, bd=1, font=("arial", 14))
    shift_entry.place(x=240, y=230)

    Label(text="Enter XOR key:", fg="black", font=("calibri", 13)).place(x=10, y=260)
    key_entry = Entry(width=19, bd=1, font=("arial", 14))
    key_entry.place(x=200, y=260)
    
    #Label(text="AES key (32-byte):", fg="black", font=("calibri", 13)).place(x=10, y=290)
    #aes_key_entry = Entry(width=19, bd=1, font=("arial", 14))
    #aes_key_entry.place(x=200, y=290)
    aes_key_label = Label(text="AES Key (32-byte):", fg="black", font=("calibri", 13))
    aes_key_label.place(x=10, y=290)
    aes_key_display = Text(font=("arial", 10), width=30, height=2, wrap=WORD, bd=1)
    aes_key_display.place(height= 40, x=150, y=290)
    aes_key_display.insert(END, encryption_key.decode())  # Display the AES key
    aes_key_display.config(state=DISABLED) 


    Label(text="Enter DES key (8-byte):", fg="black", font=("calibri", 13)).place(x=10, y=340)
    des_key_entry = Entry(width=19, bd=1, font=("arial", 14))
    des_key_entry.place(x=200, y=340)

    Button(text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=380)
    Button(text="DECRYPT", height="2", width=23, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=200, y=380)
    Button(text="RESET", height="2", width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=430)

    screen.mainloop()

main_screen()