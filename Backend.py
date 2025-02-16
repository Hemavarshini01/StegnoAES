import numpy
from numpy import asarray
from PIL import Image, ImageOps
from Cryptodome.Cipher import AES # type: ignore
from Cryptodome.Util.Padding import pad, unpad # type: ignore
import base64
from Cryptodome.Random import get_random_bytes # type: ignore

# AES Key and Initialization Vector (IV)
KEY = b'thisisa16bytekey' 

def hide(pixel, bit):
    # Modify the least significant bit (LSB) of pixel
    pixel = pixel & 0xFE  # Clear LSB
    pixel = pixel | bit   # Set LSB to bit
    return pixel

def unhide(pixel):
    # Extract the LSB from pixel
    return pixel & 1

def encode(image1, msg):
    image1 = image1.convert('RGB')
    
    mywidth = 256
    
    wpercent = (mywidth / float(image1.size[0]))
    hsize = int((float(image1.size[1]) * float(wpercent)))
    image1 = image1.resize((mywidth, hsize))
    
    padded_text = msg + (AES.block_size - len(msg) % AES.block_size) * chr(AES.block_size - len(msg) % AES.block_size)
    
    # Generate a random IV
    iv = get_random_bytes(AES.block_size)
    
    # Initialize AES cipher in CBC mode with the provided key and IV
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    
    # Encrypt the padded text
    ciphertext = cipher.encrypt(pad(padded_text.encode('utf-8'), AES.block_size))
    
    # Combine IV and ciphertext and encode with base64
    encrypted_text = base64.b64encode(iv + ciphertext)

    # Convert encrypted message to binary
    encrypted_binary = ''.join(format(x, '08b') for x in encrypted_text)

    # Add a header to indicate the start of the message
    header = "01100011011011110110010001101111011011100110111101100100"  # 'cryptography' in binary
    msg_binary = header + encrypted_binary

    # Covert to a numpy array
    data = asarray(image1)
    data1 = data.tolist()

    # Counter for the message bits
    ctr = 0

    # Traverse the image
    for i in range(len(data1)):
        for j in range(len(data1[0])):
            if ctr < len(msg_binary):
                # Hide the message bit in the pixel
                data1[i][j][0] = hide(data1[i][j][0], int(msg_binary[ctr]))
                ctr += 1

    image_arr = numpy.array(data1).astype(numpy.uint8)
    image_arr2 = Image.fromarray(image_arr)
    return image_arr2

def decode(img):
    data = asarray(img)
    data1 = data.tolist()

    # Extract the hidden binary message
    msg_binary = ""
    for i in range(len(data1)):
        for j in range(len(data1[0])):
            msg_binary += str(unhide(data1[i][j][0]))

    # Find the header indicating the start of the message
    header = "01100011011011110110010001101111011011100110111101100100"  # 'cryptography' in binary
    try:
        msg_start = msg_binary.index(header) + len(header)
    except ValueError:
        return "Message not found or image has been modified."

    # Extract the encrypted message
    encrypted_binary = msg_binary[msg_start:]

    # Convert binary to bytes
    encrypted_bytes = bytes(int(encrypted_binary[i:i+8], 2) for i in range(0, len(encrypted_binary), 8))

    # Decode the base64 encoded text
    encrypted_text = base64.b64decode(encrypted_bytes)

    # Extract IV
    iv = encrypted_text[:AES.block_size]

    # Initialize AES cipher in CBC mode with the provided key and IV
    cipher = AES.new(KEY, AES.MODE_CBC, iv)

    # Decrypt the ciphertext and remove padding
    try:
        decrypted_text = unpad(cipher.decrypt(encrypted_text[AES.block_size:]), AES.block_size).decode('utf-8')
    except ValueError:
        return "Invalid padding or decryption key"


    return decrypted_text[:-16]



def decrypt(img):
    return decode(img)
