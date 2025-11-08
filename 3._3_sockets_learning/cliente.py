import socket
import os
from dotenv import load_dotenv
import socket

load_dotenv()  # carga variables de .env en os.environ

LINUX_IP = os.getenv("LINUX_IP")
PORT = int(os.getenv("PORT"))

cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #af_inet = IPV4 sock stream = TCP

cliente.connect(('LINUX_IP', PORT))

try:
    while True:
        datos = input("Introduce los datos para enviar: ")
        cliente.sendall(datos.encode())

    #enviamos datos
    #mensaje = "Hola server".encode()
    #cliente.sendall(mensaje)

    #Recibir datos server
    #respuesta = cliente.recv(1024)
    #sprint("Respuesta del servidor:", respuesta.decode())
except KeyboardInterrupt:
    cliente.close()
