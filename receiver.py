import socket
import struct
import binascii
import cv2
import numpy as np
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
    HOST = '0.0.0.0' # Listen on all available interfaces
    PORT = 5000

    print("--- 1. Starting Receiver (Laptop B) ---")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"[+] Listening for incoming video stream on port {PORT}...")

    conn, addr = server_socket.accept()
    print(f"[+] Connection established with Sender: {addr}")

    print("\n--- 2. ECDH Key Exchange (256-bit) ---")
    # Generate Receiver Keypair
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Receive Sender's public key size and key
    sender_pub_size = struct.unpack("!I", recvall(conn, 4))[0]
    sender_pub_bytes = recvall(conn, sender_pub_size)
    sender_public_key = serialization.load_pem_public_key(sender_pub_bytes)
    print("[+] Received Sender's Public Key.")

    # Send Receiver's public key
    conn.sendall(struct.pack("!I", len(pub_bytes)) + pub_bytes)
    print("[+] Sent Receiver's Public Key.")

    # Receive HKDF Salt from Sender
    salt = recvall(conn, 16)

    print("\n--- 3. Key Derivation ---")
    shared_secret = private_key.exchange(ec.ECDH(), sender_public_key)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"aes-gcm-video-stream",
    ).derive(shared_secret)
    print(f"[+] Derived AES-256 Key: {binascii.hexlify(aes_key).decode()}")

    aesgcm = AESGCM(aes_key)

    print("\n--- 4. Receiving Encrypted Video Stream ---")
    try:
        while True:
            # Read header: 4 bytes for ciphertext length
            header = recvall(conn, 4)
            if not header:
                break
            
            ciphertext_length = struct.unpack("!I", header)[0]
            
            # Read 12 bytes for nonce
            nonce = recvall(conn, 12)
            
            # Read ciphertext
            ciphertext = recvall(conn, ciphertext_length)
            
            # Decrypt the frame
            try:
                decrypted_frame_data = aesgcm.decrypt(nonce, ciphertext, None)
            except Exception as e:
                print(f"[-] Decryption failed (tampering or data loss): {e}")
                continue
            
            # Decompress and display the frame
            nparr = np.frombuffer(decrypted_frame_data, np.uint8)
            frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if frame is not None:
                cv2.imshow('Secure Receiver Stream', frame)
                
            # Press 'q' to quit
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
                
    finally:
        print("\n[+] Closing connection.")
        conn.close()
        server_socket.close()
        cv2.destroyAllWindows()

if __name__ == "__main__":
    main()