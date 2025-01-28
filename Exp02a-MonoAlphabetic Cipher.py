import tkinter as tk
from tkinter import messagebox

class MonoAlphabeticCipher:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Mono Alphabetic Cipher")
        self.window.geometry("800x400")
        
        # Input frame
        input_frame = tk.Frame(self.window)
        input_frame.pack(pady=20)
        
        # Input text label and entry
        tk.Label(input_frame, text="Enter Text:").pack()
        self.input_text = tk.Entry(input_frame, width=50)
        self.input_text.pack(pady=5)
        
        # Shift value frame
        shift_frame = tk.Frame(self.window)
        shift_frame.pack(pady=10)
        
        tk.Label(shift_frame, text="Shift Value (0-25):").pack()
        self.shift_value = tk.Entry(shift_frame, width=10)
        self.shift_value.pack(pady=5)
        
        # Result frame
        result_frame = tk.Frame(self.window)
        result_frame.pack(pady=20)
        
        # Encryption section
        encrypt_frame = tk.Frame(result_frame)
        encrypt_frame.pack(side=tk.LEFT, padx=10)

        tk.Label(encrypt_frame, text="Cipher Text:").pack()  # Place the label inside encrypt_frame
        self.encrypt_button = tk.Button(encrypt_frame, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack()
        self.encrypted_text = tk.Entry(encrypt_frame, width=30)
        self.encrypted_text.pack(pady=5)

        # Decryption section
        decrypt_frame = tk.Frame(result_frame)
        decrypt_frame.pack(side=tk.LEFT, padx=10)

        tk.Label(decrypt_frame, text="Decrypted Text:").pack()  # Place the label inside decrypt_frame
        self.decrypt_button = tk.Button(decrypt_frame, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack()
        self.decrypted_text = tk.Entry(decrypt_frame, width=30)
        self.decrypted_text.pack(pady=5)

        
    def validate_shift(self):
        try:
            shift = int(self.shift_value.get())
            if shift < 0 or shift > 25:
                messagebox.showerror("Error", "Shift value must be between 0 and 25")
                return None
            return shift
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for shift value")
            return None
    
    def process_text(self, text, shift, encrypt=True):
        if shift is None:
            return
        
    def process_text(self, text, shift, encrypt=True):
        if shift is None:
            return
        
        result = ""
        for char in text:
            # Get the ASCII value of the character
            ascii_value = ord(char)
            
            # Calculate the shift
            if encrypt:
                new_ascii = (ascii_value + shift) % 256  # ASCII range (0-255)
            else:
                new_ascii = (ascii_value - shift) % 256
            
            # Convert back to character
            result += chr(new_ascii)
        
        return result


    
    def encrypt(self):
        shift = self.validate_shift()
        if shift is not None:
            text = self.input_text.get()
            if not text.strip():  # Check if the input text is empty or only contains whitespace
                messagebox.showerror("Error", "Please enter text to encrypt")
                return
            encrypted = self.process_text(text, shift, encrypt=True)
            self.encrypted_text.delete(0, tk.END)
            self.encrypted_text.insert(0, encrypted)

    def decrypt(self):
        shift = self.validate_shift()
        if shift is not None:
            text = self.encrypted_text.get()
            if not text.strip():  # Check if the input text is empty or only contains whitespace
                messagebox.showerror("Error", "Please enter text to decrypt")
                return
            decrypted = self.process_text(text, shift, encrypt=False)
            self.decrypted_text.delete(0, tk.END)
            self.decrypted_text.insert(0, decrypted)

    
    def clear(self):
        self.input_text.delete(0, tk.END)
        self.shift_value.delete(0, tk.END)
        self.encrypted_text.delete(0, tk.END)
        self.decrypted_text.delete(0, tk.END)
    
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = MonoAlphabeticCipher()
    app.run()