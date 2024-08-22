import base64
from tkinter import *
from PIL import ImageTk, Image
from cryptography.fernet import Fernet
import os
import messagebox

window = Tk()
window.title("Secret Notes")
window.minsize(300,500)
window.config(padx=30,pady=30)

#Şifreleme ve Dosyaya Kaydetme Fonksiyonu
def encryptAndSave():
    title = titleEntry.get()
    text = secretText.get("1.0", END).strip()  # Metni boşluklardan arındırır
    key = keyEntry.get()

    # Boş alan kontrolü
    if not title or not text or not key:
        messagebox.showerror("Dikkat", "Boş Alanlar Var")
        return  # Boş alan varsa şifreleme yapılmaz

    try:
        # Anahtarı 32 byte uzunluğunda olacak şekilde ayarlar
        key = key.ljust(32)[:32]
        key = base64.urlsafe_b64encode(key.encode('utf-8'))
        cipher_suite = Fernet(key)

        # Şifreleme işlemi
        encoded_text = cipher_suite.encrypt(text.encode('utf-8'))

        # Dosyaya Yazdırma
        with open('encrypted_messages.txt', 'a') as file:
            file.write(f"Başlık: {title}\n")
            file.write(f"Şifreli Mesaj: {encoded_text.decode('utf-8')}\n")
            file.write("\n")  # Bir boş satır ekleyerek ayırma yapar

        print(f"Başlık: {title}")
        print(f"Şifreli Mesaj: {encoded_text.decode('utf-8')}")

    except Exception as e:
        # Bilinmeyen hata için mesaj kutusu
        messagebox.showerror("Hata", f"Bilinmeyen Bir Hata Oluştu: {str(e)}")

def decryptText():
    key = keyEntry.get()
    encrypted_text = secretText.get("1.0", END).strip()  # Şifreli metni boşluklardan arındırır

    # Boş alan kontrolü
    if not key or not encrypted_text:
        messagebox.showerror("Dikkat", "Boş Alanlar Var")
        return  # Boş alan varsa deşifreleme yapılmaz

    try:
        # Anahtarı 32 byte uzunluğunda olacak şekilde ayarlar
        key = key.ljust(32)[:32]
        key = base64.urlsafe_b64encode(key.encode('utf-8'))
        cipher_suite = Fernet(key)

        # Şifreli metni çözme işlemi
        decoded_text = cipher_suite.decrypt(encrypted_text.encode('utf-8')).decode('utf-8')

        # Deşifrelenmiş metni secretText widget'ında gösterme
        secretText.delete("1.0", END)  # Eski metni siler
        secretText.insert("1.0", decoded_text)  # Yeni metni ekler

    except Exception as e:
        # Bilinmeyen hata için mesaj kutusu
        messagebox.showerror("Hata", f"Bilinmeyen Bir Hata Oluştu: {str(e)}")

image=Image.open('note.png')
resized_image = image.resize((70, 100), Image.Resampling.LANCZOS)  # Boyutu tuple olarak verin ve bir resampling filtresi kullanın

img = ImageTk.PhotoImage(resized_image)
panel = Label(window, image=img)
panel.pack()

titleLabel= Label(text="Enter Your Title", font=('Arial',10,"normal"))
titleLabel.config(width=30)
titleLabel.pack(pady=(20,5))

titleEntry = Entry()
titleEntry.config(width=30)
titleEntry.pack(pady=5)

secretLabel = Label(text="Enter Your Secret", font=('Arial',10,"normal"))
secretLabel.config(width=30)
secretLabel.pack(pady=5)

secretText = Text()
secretText.config(width=23,height=5)
secretText.pack(pady=5)

keyLabel = Label(text="Enter Master Key", font=('Arial',10,"normal"))
keyLabel.pack(pady=5)

keyEntry = Entry()
keyEntry.config(width=30)
keyEntry.pack(pady=5)

encryptAndSave_button = Button(text="Encrypt and Save", font=('Arial',10,"normal"), command=encryptAndSave)
encryptAndSave_button.pack()

decrypt_button= Button(text="Decrypt", font=('Arial',10,"normal"),command=decryptText)
decrypt_button.pack()

window.mainloop()