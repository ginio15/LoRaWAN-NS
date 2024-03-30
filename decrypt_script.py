def construct_iv(dev_eui, message_counter):
    if message_counter is None:
        raise ValueError("Message counter is None")
    # Convert DevEUI and message counter to byte arrays (LSB first)
    dev_eui_bytes = bytes.fromhex(dev_eui)[::-1]
    counter_bytes = message_counter.to_bytes(2, 'little')

    # Construct the IV with DevEUI, counter, and 6 trailing zeros
    iv = dev_eui_bytes + counter_bytes + b'\x00' * 6
    print(f"Constructed IV: {iv.hex()}")  # Print the IV in hexadecimal format

    return iv
       
from Crypto.Cipher import AES

def decrypt_data(encrypted_data, key, iv):
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    print("Decryption successful")  # Confirmation of decryption
    return decrypted_data

def store_payload(decrypted_data, filename='decrypted_payload.txt'):
    with open(filename, 'wb') as file:
        file.write(decrypted_data)
    print(f"Decrypted payload stored in {filename}")  # Confirmation of storage

if __name__ == "__main__":
    # Sample data - replace these with actual values
    encrypted_data_hex = "0123456789abcdef"
    aes_key_hex = "00112233445566778899aabbccddeeff"
    dev_eui = "000781377000ADF3"
    message_counter = 20

    # Convert hex strings to bytesds
    encrypted_data = bytes.fromhex(encrypted_data_hex)
    aes_key = bytes.fromhex(aes_key_hex)

    print("Starting decryption process...")

    # Construct the IV
    iv = construct_iv(dev_eui, message_counter)

    # Decrypt the data
    decrypted_data = decrypt_data(encrypted_data, aes_key, iv)

    # Store the decrypted payload
    store_payload(decrypted_data)

    print("Decryption complete. Payload stored.")
