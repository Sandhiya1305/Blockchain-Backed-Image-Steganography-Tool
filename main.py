import tkinter as tk
from tkinter import *
import tkinter.filedialog
from tkinter import messagebox, simpledialog
from PIL import ImageTk, Image
from io import BytesIO
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import hashlib
import time
class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash

def create_genesis_block():
    return Block(0, "0", time.time(), "Genesis Block", "0")

def create_new_block(previous_block, data):
    index = previous_block.index + 1
    timestamp = time.time()
    data_hash = hashlib.sha256(data.encode()).hexdigest()
    hash = hashlib.sha256(f"{index}{previous_block.hash}{timestamp}{data_hash}".encode()).hexdigest()
    return Block(index, previous_block.hash, timestamp, data, hash)

class IMG_Stegno:
    def __init__(self):
        self.salt = os.urandom(16)
        self.output_image_size = 0
        self.blockchain = [create_genesis_block()] 

    def derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def verify_password(self):
        root = tk.Tk()
        root.withdraw()
        correct_password = '12345678' 
        
        password = simpledialog.askstring("Password Required", "Enter the password to access the application:", show='*')
        if password != correct_password:
            messagebox.showerror("Error", "Incorrect password!")
            root.destroy()
            return False
        
        root.destroy()
        return True

    def main(self, root):
        root.title('ImageSteganography Tool')
        root.geometry('500x600')
        root.resizable(width=False, height=False)
        root.config(bg='#e3f4f1')
        frame = Frame(root)
        frame.grid()

        title = Label(frame, text='Image Steganography Tool')
        title.config(font=('Times new roman', 25, 'bold'))
        title.grid(pady=10)
        title.config(bg='#e3f4f1')
        title.grid(row=1)

        encode = Button(frame, text="Encode", command=lambda: self.encode_frame1(frame), padx=14, bg='#e3f4f1')
        encode.config(font=('Helvetica', 14), bg='#e8c1c7')
        encode.grid(row=2)
        decode = Button(frame, text="Decode", command=lambda: self.decode_frame1(frame), padx=14, bg='#e3f4f1')
        decode.config(font=('Helvetica', 14), bg='#e8c1c7')
        decode.grid(pady=12)
        decode.grid(row=3)

        root.grid_rowconfigure(1, weight=1)
        root.grid_columnconfigure(0, weight=1)

    def back(self, frame):
        frame.destroy()
        self.main(root)

    def encode_frame1(self, F):
        F.destroy()
        F2 = Frame(root)
        label1 = Label(F2, text='Select the Image in which \nyou want to hide text:')
        label1.config(font=('Times new roman', 25, 'bold'), bg='#e3f4f1')
        label1.grid()

        button_bws = Button(F2, text='Select', command=lambda: self.encode_frame2(F2))
        button_bws.config(font=('Helvetica', 18), bg='#e8c1c7')
        button_bws.grid()
        button_back = Button(F2, text='Cancel', command=lambda: IMG_Stegno.back(self, F2))
        button_back.config(font=('Helvetica', 18), bg='#e8c1c7')
        button_back.grid(pady=15)
        button_back.grid()
        F2.grid()

    def decode_frame1(self, F):
        F.destroy()
        d_f2 = Frame(root)
        label1 = Label(d_f2, text='Select Image with Hidden text:')
        label1.config(font=('Times new roman', 25, 'bold'), bg='#e3f4f1')
        label1.grid()
        label1.config(bg='#e3f4f1')
        button_bws = Button(d_f2, text='Select', command=lambda: self.decode_frame2(d_f2))
        button_bws.config(font=('Helvetica', 18), bg='#e8c1c7')
        button_bws.grid()
        button_back = Button(d_f2, text='Cancel', command=lambda: IMG_Stegno.back(self, d_f2))
        button_back.config(font=('Helvetica', 18), bg='#e8c1c7')
        button_back.grid(pady=15)
        button_back.grid()
        d_f2.grid()

    def encode_frame2(self, e_F2):
        e_pg = Frame(root)
        myfile = tkinter.filedialog.askopenfilename(filetypes=[('png', '*.png'), ('jpeg', '*.jpeg'), ('jpg', '*.jpg'), ('All Files', '*.*')])
        if not myfile:
            messagebox.showerror("Error", "You have selected nothing!")
        else:
            my_img = Image.open(myfile)
            new_image = my_img.resize((300, 200))
            img = ImageTk.PhotoImage(new_image)
            label3 = Label(e_pg, text='Selected Image')
            label3.config(font=('Helvetica', 14, 'bold'))
            label3.grid()
            board = Label(e_pg, image=img)
            board.image = img
            self.output_image_size = os.stat(myfile)
            self.o_image_w, self.o_image_h = my_img.size
            board.grid()
            label2 = Label(e_pg, text='Enter the message')
            label2.config(font=('Helvetica', 14, 'bold'))
            label2.grid(pady=15)
            text_a = Text(e_pg, width=50, height=10)
            text_a.grid()
            encode_button = Button(e_pg, text='Cancel', command=lambda: IMG_Stegno.back(self, e_pg))
            encode_button.config(font=('Helvetica', 14), bg='#e8c1c7')
            data = text_a.get("1.0", "end-1c")
            button_back = Button(e_pg, text='Encode', command=lambda: [self.enc_fun(text_a, my_img), IMG_Stegno.back(self, e_pg)])
            button_back.config(font=('Helvetica', 14), bg='#e8c1c7')
            button_back.grid(pady=15)
            encode_button.grid()
            e_pg.grid(row=1)
            e_F2.destroy()

    def decode_frame2(self, d_F2):
        d_F3 = Frame(root)
        myfiles = tkinter.filedialog.askopenfilename(filetypes=[('png', '*.png'), ('jpeg', '*.jpeg'), ('jpg', '*.jpg'), ('All Files', '*.*')])
        if not myfiles:
            messagebox.showerror("Error", "You have selected nothing!")
        else:
            my_img = Image.open(myfiles, 'r')
            my_image = my_img.resize((300, 200))
            img = ImageTk.PhotoImage(my_image)
            label4 = Label(d_F3, text='Selected Image:')
            label4.config(font=('Helvetica', 14, 'bold'))
            label4.grid()
            board = Label(d_F3, image=img)
            board.image = img
            board.grid()
            hidden_data, data_hash = self.decode(my_img)
            label2 = Label(d_F3, text='Hidden data is:')
            label2.config(font=('Helvetica', 14, 'bold'))
            label2.grid(pady=10)
            text_a = Text(d_F3, width=60, height=10)  # Increase width to accommodate longer text
            text_a.insert(INSERT, hidden_data)
            text_a.configure(state='disabled')
            text_a.grid()

            # Increase width of the text widget to fully display the hash
            label_hash = Label(d_F3, text='Decoded Hash:')
            label_hash.config(font=('Helvetica', 14, 'bold'), bg='#e3f4f1')
            label_hash.grid(pady=10)
            text_hash = Text(d_F3, width=60, height=2)  # Add a separate text widget for the hash
            text_hash.insert(INSERT, data_hash)
            text_hash.configure(state='disabled')
            text_hash.grid()

            button_back = Button(d_F3, text='Cancel', command=lambda: self.frame_3(d_F3))
            button_back.config(font=('Helvetica', 14), bg='#e8c1c7')
            button_back.grid(pady=15)
            d_F3.grid(row=1)
            d_F2.destroy()

    def decode(self, image):
        password = simpledialog.askstring("Password", "Enter the password to decrypt:", show='*')
        if not password:
            messagebox.showinfo("Alert", "Password is required!")
            return

        key = self.derive_key(password)
        cipher_suite = Fernet(key)

        image_data = iter(image.getdata())
        data = ''
        while True:
            pixels = [value for value in image_data.__next__()[:3] +
                      image_data.__next__()[:3] +
                      image_data.__next__()[:3]]

            binstr = ''
            for i in pixels[:8]:
                if i % 2 == 0:
                    binstr += '0'
                else:
                    binstr += '1'

            data += chr(int(binstr, 2))
            if pixels[-1] % 2 != 0:
                try:
                    decrypted_data = cipher_suite.decrypt(data.encode('utf-8'))
                    # Compute hash to match with the encoded hash
                    data_hash = hashlib.sha256(data.encode()).hexdigest()
                    return decrypted_data.decode('utf-8'), data_hash
                except:
                    return "Incorrect password or corrupted data!", None

    def genData(self, data):
        newd = []

        for i in data:
            newd.append(format(ord(i), '08b'))
        return newd

    def modPix(self, pix, data):
        datalist = self.genData(data)
        lendata = len(datalist)
        imdata = iter(pix)

        for i in range(lendata):
            pix = [value for value in imdata.__next__()[:3] +
                   imdata.__next__()[:3] +
                   imdata.__next__()[:3]]

            for j in range(0, 8):
                if (datalist[i][j] == '0') and (pix[j] % 2 != 0):
                    if (pix[j] % 2 != 0):
                        pix[j] -= 1

                elif (datalist[i][j] == '1') and (pix[j] % 2 == 0):
                    pix[j] -= 1

            if (i == lendata - 1):
                if (pix[-1] % 2 == 0):
                    pix[-1] -= 1
            else:
                if (pix[-1] % 2 != 0):
                    pix[-1] -= 1

            pix = tuple(pix)
            yield pix[0:3]
            yield pix[3:6]
            yield pix[6:9]

    def encode_enc(self, newImg, data):
        w = newImg.size[0]
        (x, y) = (0, 0)

        for pixel in self.modPix(newImg.getdata(), data):

            newImg.putpixel((x, y), pixel)
            if (x == w - 1):
                x = 0
                y += 1
            else:
                x += 1

    def enc_fun(self, text_a, myImg):
        data = text_a.get("1.0", "end-1c")
        if len(data) == 0:
            messagebox.showinfo("Alert", "Kindly enter text in TextBox")
        else:
            password = simpledialog.askstring("Password", "Enter a password:", show='*')
            if not password:
                messagebox.showinfo("Alert", "Password is required!")
                return
            
            key = self.derive_key(password)
            cipher_suite = Fernet(key)
            encrypted_data = cipher_suite.encrypt(data.encode('utf-8'))

            # Generate hash of the encrypted data
            data_hash = hashlib.sha256(encrypted_data).hexdigest()

            newImg = myImg.copy()
            self.encode_enc(newImg, encrypted_data.decode('utf-8'))

            # Create a new block and add it to the blockchain
            new_block = create_new_block(self.blockchain[-1], encrypted_data.decode('utf-8'))
            self.blockchain.append(new_block)

            my_file = BytesIO()
            temp = os.path.splitext(os.path.basename(myImg.filename))[0]
            newImg.save(tkinter.filedialog.asksaveasfilename(initialfile=temp, filetypes=[('png', '*.png')], defaultextension=".png"))
            self.d_image_size = my_file.tell()
            self.d_image_w, self.d_image_h = newImg.size
            messagebox.showinfo("Success", f"Encoding Successful\nHash: {data_hash}\nFile is saved as Image_with_hiddentext.png in the same directory")
            messagebox.showinfo("Blockchain Info", f"New block added to the blockchain:\nHash: {new_block.hash}\nPrevious Hash: {new_block.previous_hash}")

    def frame_3(self, frame):
        frame.destroy()
        self.main(root)

# Start the application only if the password is correct
if __name__ == "__main__":
    app = IMG_Stegno()
    if app.verify_password():
        root = tk.Tk()
        app.main(root)
        root.mainloop()
