def is_strong_password(password):
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    return has_upper, has_lower, has_digit, has_special

def main():
    is_strong = False

    while not is_strong:
        password = input("Enter your password: ").strip()
        confirm_password = input("Enter Confirm password: ").strip()

        if len(password) < 8:
            print("Password length must be greater than 8!")
        elif password != confirm_password:
            print("Password and Confirm Password do not match")
        else:
            has_upper, has_lower, has_digit, has_special = is_strong_password(password)
            
            strength = 0
            if has_upper:
                strength += 25
            else:
                print("Password must contain at least one uppercase letter")
            if has_lower:
                strength += 25
            else:
                print("Password must contain at least one lowercase letter")
            if has_digit:
                strength += 25
            else:
                print("Password must contain at least one digit")
            if has_special:
                strength += 25
            else:
                print("Password must contain at least one special character")

            print(f"Password Strength: {strength}%")

            if strength == 100:
                print("Password is 100% strong ✅")
                is_strong = True
            else:
                print("Please try again with a stronger password.")
if __name__ == "__main__":
    main()





22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222


#include <iostream>
using namespace std;
string encrypt(string text, int shift) {
    for (char &c : text) {
        if (islower(c)) c = (c - 'a' + shift) % 26 + 'a';
        else if (isupper(c)) c = (c - 'A' + shift) % 26 + 'A';
    }
    return text;
}
string decrypt(string text, int shift) {
    return encrypt(text, 26 - shift);
}
int main() {
    string message;
    int shift;
    cout << "Enter a message to encrypt: ";
    getline(cin, message);
    cout << "Enter shift value: ";
    cin >> shift;
    string encryptedMessage = encrypt(message, shift);
    cout << "Encrypted message: " << encryptedMessage << endl;
    cout << "Decrypted message: " << decrypt(encryptedMessage, shift) << endl;

    return 0;
}


33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333

def caesar_cipher(text, shift):
    encrypted_text = []
    for c in text:
        if c.isalpha():
            base = 'A' if c.isupper() else 'a'
            # Shift the character and wrap around the alphabet
            encrypted_char = chr((ord(c) - ord(base) + shift + 26) % 26 + ord(base))
            encrypted_text.append(encrypted_char)
        else:
            encrypted_text.append(c)  # Non-alphabetic characters remain unchanged
    return ''.join(encrypted_text)

def main():
    text = input("Enter text: ")
    shift = int(input("Enter shift value: "))

    encrypted = caesar_cipher(text, shift)
    decrypted = caesar_cipher(encrypted, -shift)
    
    print("Encrypted Text:", encrypted)
    print("Decrypted Text:", decrypted)

if __name__ == "__main__":
    main()   


55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555


from Crypto.Cipher import DES
import base64

# Padding to make the message a multiple of 8 bytes
def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt(data, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    padded_data = pad(data)
    encrypted_bytes = cipher.encrypt(padded_data.encode('utf-8'))
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt(encrypted_data, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_data)
    decrypted_data = cipher.decrypt(encrypted_bytes).decode('utf-8')
    return decrypted_data.rstrip()  # remove padding spaces

# Example usage
if __name__ == "__main__":
    try:
        data = "Hello, my name is Avinash!"
        key = "12345678"  # 8-byte key for DES
        print("Original Message:", data)

        encrypted = encrypt(data, key)
        print("Encrypted Data:", encrypted)

        

decrypted = decrypt(encrypted, key)
        print("Decrypted Data:", decrypted)
    except Exception as e:
        print("Error:", str(e))


66666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666


from Crypto.Cipher import DES
import base64

def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt(data, key):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    padded_data = pad(data)
    encrypted_data = des.encrypt(padded_data.encode('utf-8'))
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt(encrypted_data, key):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    decrypted_data = des.decrypt(base64.b64decode(encrypted_data))
    return decrypted_data.decode('utf-8').rstrip()

if __name__ == "__main__":
    try:
        data = "Hello, DES Encryption!"
        key = "12345678"  # Must be 8 bytes
        encrypted = encrypt(data, key)
        print("Encrypted Data:", encrypted)

        decrypted = decrypt(encrypted, key)
        print("Decrypted Data:", decrypted)

    except Exception as e:
        print("Error:", e)


777777777777777777777777777777777777777777777777777777777777777777777777




from Crypto.Cipher import AES
import base64

# Pad the data to be multiple of 16 bytes (AES block size)
def pad(data):
    return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

# Unpad the data
def unpad(data):
    return data[:-ord(data[-1])]

def encrypt(data, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded_data = pad(data)
    encrypted_bytes = cipher.encrypt(padded_data.encode('utf-8'))
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt(encrypted_data, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_data)
    decrypted_padded = cipher.decrypt(encrypted_bytes).decode('utf-8')
    return unpad(decrypted_padded)

# Example usage
if __name__ == "__main__":
    try:
        data = "Hello, AES Encryption!"
        key = "1234567890123456"  # 16-byte key
        encrypted = encrypt(data, key)
        print("Encrypted Data:", encrypted)

        decrypted = decrypt(encrypted, key)
        print("Decrypted Data:", decrypted)
    except Exception as e:
        print("Error:", str(e))



8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888



def get_hash_code(s):
    hash = 0
    for char in s:
        hash = (31 * hash + ord(char)) & 0xFFFFFFFF  # simulate 32-bit integer overflow
    # Convert to signed 32-bit integer
    return hash if hash < 0x80000000 else hash - 0x100000000

if __name__ == "__main__":
    input_str = input("Enter a string to hash: ")
    hash_code = get_hash_code(input_str)
    print("The hash code for the input string is:", hash_code)






