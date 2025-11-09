# servidor.py
import socket
import datetime
import os
from dotenv import load_dotenv

load_dotenv()

HOST = '0.0.0.0'
PORT = int(os.getenv("PORT"))

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.bind((HOST, PORT))
srv.listen(1)
print("Esperando conexión en", f"{HOST}:{PORT}...")

conn, addr = srv.accept()
print("Conectado:", addr)

with conn:
    while True:
        data = conn.recv(4096)
        if not data:
            break
        # imprimimos raw y decode para legibilidad
        try:
            texto = data.decode('utf-8', errors='replace')
        except Exception:
            texto = repr(data)
        ts = datetime.datetime.now().isoformat(sep=' ',timespec='seconds')
        print(f"[{ts}] Recibido: {texto}")
        print("Recibido:", texto)

print("Conexión cerrada.")
srv.close()
