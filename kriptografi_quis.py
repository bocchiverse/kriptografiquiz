import tkinter as tk
from tkinter import filedialog, messagebox, Text

#VIGENERE CIPHER
def vigenere_encrypt(plaintext, key):
    encrypted = []
    key = key.upper().replace(" ", "")
    plaintext = plaintext.upper().replace(" ", "")
    
    for i in range(len(plaintext)):
        p = ord(plaintext[i]) - 65
        k = ord(key[i % len(key)]) - 65
        encrypted.append(chr((p + k) % 26 + 65))
    
    return ''.join(encrypted)

def vigenere_decrypt(ciphertext, key):
    decrypted = []
    key = key.upper().replace(" ", "")
    ciphertext = ciphertext.upper().replace(" ", "")
    
    for i in range(len(ciphertext)):
        c = ord(ciphertext[i]) - 65
        k = ord(key[i % len(key)]) - 65
        decrypted.append(chr((c - k) % 26 + 65))
    
    return ''.join(decrypted)

#PLAYFAIR CIPHER
def generate_playfair_matrix(key):
    key = ''.join(sorted(set(key.upper()), key=lambda x: key.index(x))).replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix = []
    for char in key + alphabet:
        if char not in ''.join(matrix):
            matrix.append(char)
    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def find_position(char, matrix):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = plaintext.upper().replace(" ", "").replace("J", "I")
    if len(plaintext) % 2 != 0:
        plaintext += 'X' 
    
    encrypted = []
    i = 0
    while i < len(plaintext):
        a, b = plaintext[i], plaintext[i + 1]
        if a == b:
            b = 'X'
        
        row1, col1 = find_position(a, matrix)
        row2, col2 = find_position(b, matrix)
        
        if row1 == row2:
            encrypted.append(matrix[row1][(col1 + 1) % 5])
            encrypted.append(matrix[row2][(col2 + 1) % 5])
        elif col1 == col2:
            encrypted.append(matrix[(row1 + 1) % 5][col1])
            encrypted.append(matrix[(row2 + 1) % 5][col2])
        else:
            encrypted.append(matrix[row1][col2])
            encrypted.append(matrix[row2][col1])
        
        i += 2

    return ''.join(encrypted)

def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    ciphertext = ciphertext.upper().replace(" ", "")
    
    decrypted = []
    i = 0
    while i < len(ciphertext):
        a, b = ciphertext[i], ciphertext[i + 1]
        
        row1, col1 = find_position(a, matrix)
        row2, col2 = find_position(b, matrix)
        
        if row1 == row2:
            decrypted.append(matrix[row1][(col1 - 1) % 5])
            decrypted.append(matrix[row2][(col2 - 1) % 5])
        elif col1 == col2:
            decrypted.append(matrix[(row1 - 1) % 5][col1])
            decrypted.append(matrix[(row2 - 1) % 5][col2])
        else:
            decrypted.append(matrix[row1][col2])
            decrypted.append(matrix[row2][col1])
        
        i += 2

    return ''.join(decrypted)

#HILL CIPHER
def mod_inv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def get_determinant(matrix):
    return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0])

def get_matrix_inverse(matrix, mod):
    det = get_determinant(matrix)
    det_inv = mod_inv(det % mod, mod)
    if det_inv is None:
        raise ValueError("Determinan tidak memiliki invers dalam mod 26.")
    
    return [[(matrix[1][1] * det_inv) % mod, (-matrix[0][1] * det_inv) % mod],
            [(-matrix[1][0] * det_inv) % mod, (matrix[0][0] * det_inv) % mod]]

def create_key_matrix(key, size):
    if len(key) != size * size:
        raise ValueError(f"Kunci harus sepanjang {size*size} karakter.")
    key_matrix = []
    for i in range(size):
        row = [ord(char) % 65 for char in key[i * size:(i + 1) * size]]
        key_matrix.append(row)
    return key_matrix

def matrix_multiply(matrix, vector, mod):
    size = len(matrix)
    result = [0] * size
    for i in range(size):
        for j in range(size):
            result[i] += matrix[i][j] * vector[j]
        result[i] = result[i] % mod
    return result

def hill_encrypt(message, key_matrix):
    size = len(key_matrix)
    while len(message) % size != 0:
        message += 'X'  

    message_vector = [ord(char) % 65 for char in message]
    encrypted_message = ""

    for i in range(0, len(message_vector), size):
        vector = message_vector[i:i + size]
        encrypted_vector = matrix_multiply(key_matrix, vector, 26)
        encrypted_message += ''.join(chr(num + 65) for num in encrypted_vector)
    
    return encrypted_message

def hill_decrypt(ciphertext, key_matrix):
    size = len(key_matrix)
    inverse_key_matrix = get_matrix_inverse(key_matrix, 26)
    
    cipher_vector = [ord(char) % 65 for char in ciphertext]
    decrypted_message = ""

    for i in range(0, len(cipher_vector), size):
        vector = cipher_vector[i:i + size]
        decrypted_vector = matrix_multiply(inverse_key_matrix, vector, 26)
        decrypted_message += ''.join(chr(num + 65) for num in decrypted_vector)

    return decrypted_message

#GUI IMPLEMENTATION
def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as file:
            input_text.delete(1.0, tk.END)
            input_text.insert(tk.END, file.read())

def process_encryption():
    message = input_text.get(1.0, tk.END).strip().upper().replace(" ", "")
    key = key_entry.get().strip().upper().replace(" ", "")
    if len(key) < 12:
        messagebox.showerror("Error", "Kunci harus minimal 12 karakter.")
        return

    cipher_type = cipher_var.get()

    try:
        if cipher_type == "Vigenere":
            encrypted_message = vigenere_encrypt(message, key)
        elif cipher_type == "Playfair":
            encrypted_message = playfair_encrypt(message, key)
        elif cipher_type == "Hill":
            size = int(len(key) ** 0.5)
            key_matrix = create_key_matrix(key, size)
            encrypted_message = hill_encrypt(message, key_matrix)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, encrypted_message)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def process_decryption():
    ciphertext = input_text.get(1.0, tk.END).strip().upper().replace(" ", "")
    key = key_entry.get().strip().upper().replace(" ", "")
    if len(key) < 12:
        messagebox.showerror("Error", "Kunci harus minimal 12 karakter.")
        return

    cipher_type = cipher_var.get()

    try:
        if cipher_type == "Vigenere":
            decrypted_message = vigenere_decrypt(ciphertext, key)
        elif cipher_type == "Playfair":
            decrypted_message = playfair_decrypt(ciphertext, key)
        elif cipher_type == "Hill":
            size = int(len(key) ** 0.5)
            key_matrix = create_key_matrix(key, size)
            decrypted_message = hill_decrypt(ciphertext, key_matrix)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, decrypted_message)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Membuat GUI dengan tkinter
root = tk.Tk()
root.title("Vigenere, Playfair, Hill Cipher")
root.geometry("600x600")

cipher_var = tk.StringVar(value="Vigenere")
key_entry = tk.Entry(root)
key_entry.grid(row=1, column=1, padx=10, pady=10)

tk.Label(root, text="Pilih Cipher:").grid(row=0, column=0, padx=10, pady=10)
tk.Label(root, text="Masukkan Kunci:").grid(row=1, column=0, padx=10, pady=10)

tk.Radiobutton(root, text="Vigenere Cipher", variable=cipher_var, value="Vigenere").grid(row=0, column=1, sticky="W")
tk.Radiobutton(root, text="Playfair Cipher", variable=cipher_var, value="Playfair").grid(row=0, column=2, sticky="W")
tk.Radiobutton(root, text="Hill Cipher", variable=cipher_var, value="Hill").grid(row=0, column=3, sticky="W")

input_text = Text(root, height=10, width=50)
input_text.grid(row=2, column=1, columnspan=3, padx=10, pady=10)

tk.Button(root, text="Buka File", command=open_file).grid(row=2, column=0, padx=10, pady=10)
tk.Button(root, text="Enkripsi", command=process_encryption).grid(row=3, column=1, padx=10, pady=10)
tk.Button(root, text="Dekripsi", command=process_decryption).grid(row=3, column=2, padx=10, pady=10)

output_text = Text(root, height=10, width=50)
output_text.grid(row=4, column=1, columnspan=3, padx=10, pady=10)

tk.Label(root, text="Output:").grid(row=4, column=0, padx=10, pady=10)

root.mainloop()
