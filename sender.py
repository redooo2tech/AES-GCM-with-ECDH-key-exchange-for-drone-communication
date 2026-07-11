import socket
import struct
import os
import binascii
import cv2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def recvall(sock, count):
    """Helper function to ensure we receive exactly 'count' bytes over TCP."""
    buf = b''
    while count:
        newbuf = sock.recv(count)
        if not newbuf: return None
        buf += newbuf
        count -= len(newbuf)
    return buf

def main():
    # REPLACE WITH LAPTOP B's IP ADDRESS
    RECEIVER_IP = '192.168.1.14' 
    PORT = 5000

    print("--- 1. Starting Sender (Laptop A) ---")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('192.168.1.14', PORT))
    print(f"[+] Connected to Receiver at {'192.168.1.14'}:{PORT}")

    print("\n--- 2. ECDH Key Exchange (256-bit) ---")
    # Generate Sender Keypair
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Send Sender's public key
    client_socket.sendall(struct.pack("!I", len(pub_bytes)) + pub_bytes)
    print("[+] Sent Sender's Public Key.")

    # Receive Receiver's public key
    receiver_pub_size = struct.unpack("!I", recvall(client_socket, 4))[0]
    receiver_pub_bytes = recvall(client_socket, receiver_pub_size)
    receiver_public_key = serialization.load_pem_public_key(receiver_pub_bytes)
    print("[+] Received Receiver's Public Key.")

    print("\n--- 3. Key Derivation ---")
    shared_secret = private_key.exchange(ec.ECDH(), receiver_public_key)
    
    # Generate and share salt for HKDF
    salt = os.urandom(16)
    client_socket.sendall(salt)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"aes-gcm-video-stream",
    ).derive(shared_secret)
    print(f"[+] Derived AES-256 Key: {binascii.hexlify(aes_key).decode()}")

    aesgcm = AESGCM(aes_key)

    print("\n--- 4. Starting Encrypted Video Stream ---")
    cap = cv2.VideoCapture(0) # 0 is usually the default built-in webcam
    
    if not cap.isOpened():
        print("[-] Error: Cannot open webcam.")
        return

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            # Compress frame to JPEG to save network bandwidth
            encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 80]
            _, buffer = cv2.imencode('.jpg', frame, encode_param)
            frame_data = buffer.tobytes()

            # Encrypt the frame
            nonce = os.urandom(12) # Unique nonce per frame
            ciphertext = aesgcm.encrypt(nonce, frame_data, None)

            # Send payload size (4 bytes), nonce (12 bytes), and ciphertext
            payload_size = struct.pack("!I", len(ciphertext))
            
            client_socket.sendall(payload_size + nonce + ciphertext)

            # Show what is being sent locally
            cv2.imshow('Sender - Local Preview', frame)
            
            # Press 'q' to quit
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

    except ConnectionResetError:
        print("[-] Connection closed by receiver.")
    finally:
        print("\n[+] Stopping stream.")
        cap.release()
        client_socket.close()
        cv2.destroyAllWindows()

if __name__ == "__main__":
    main()