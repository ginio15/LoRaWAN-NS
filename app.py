from decrypt_script import construct_iv, decrypt_data
import base64
from Crypto.Cipher import AES
import logging
from flask import Flask, request

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

def read_existing_payloads(filename):
    try:
        with open(filename, 'rb') as file:
            return file.read()
    except FileNotFoundError:
        return b''

@app.route('/webhook', methods=['POST'])
def webhook():
    logging.info("Received webhook with headers: %s", request.headers)
    data = request.json

    if data:
        frm_payload = data.get('uplink_message', {}).get('frm_payload')
        dev_eui = data.get('end_device_ids', {}).get('dev_eui')
        frame_info = data.get('uplink_message', {}).get('decoded_payload', {}).get('frameInfo')

        # Extract frame counter and additional details from frameInfo
        frame_counter, *frame_details = frame_info.split(', ') if frame_info else (None, [])
        frame_details = ', '.join(frame_details)  # Join the remaining details back into a string

        if frame_counter is None:
            logging.error("Frame counter is missing in the payload.")
            return "Frame counter missing", 400

        # Try to extract the numeric frame counter value
        try:
            frame_counter_value = int(frame_counter.split(': ')[1])
        except (ValueError, IndexError):
            logging.error("Invalid frame counter format.")
            return "Invalid frame counter format", 400

        encrypted_data = base64.b64decode(frm_payload)[3:46]
        iv = construct_iv(dev_eui, frame_counter_value)
        aes_key = bytes.fromhex('7469291110725F8E1A457BB8150F4B18')
        decrypted_data = decrypt_data(encrypted_data, aes_key, iv)
        
        decrypted_data_hex = decrypted_data.hex()

        logging.info("Decrypted data: %s", decrypted_data)

        filename = 'decrypted_payload.txt'  # Define the filename for storing payloads
        existing_payloads = read_existing_payloads(filename)

        # Prepare new content
        new_content = f"Frame Counter: {frame_counter_value}, Frame Info: {frame_details}\nDecrypted data (hex): {decrypted_data_hex}\n\n".encode()

        # Write new content with existing payloads
        with open(filename, 'wb') as file:
            file.write(new_content + existing_payloads)
            logging.info(f"Decrypted payload stored in {filename}")

    else:
        logging.error("No JSON payload received or payload is not in JSON format.")

    return '', 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
