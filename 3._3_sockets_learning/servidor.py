import socket
import os
from dotenv import load_dotenv
import socket

load_dotenv()  # carga variables de .env en os.environ
PORT = int(os.getenv("PORT"))

#Creamos server TCP
servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #af_inet = IPV4 sock stream = TCP

#Asignamos al local y un puerto invent

servidor.bind(('0.0.0.0', 12345))
servidor.listen()

print("Esperando conexiones....")

#Aceptar conexion
conexion, direccion = servidor.accept()

with conexion:
    print("Conectado a :",direccion)
    while True: # bucle infi
        datos = conexion.recv(1024)
        if not datos:
            break
        print(f" Datos recibidos de cliente: {datos.decode()}")
        #mensaje_respuesta = "Hola cliente".encode()
        #conexion.sendall(mensaje_respuesta)

conexion.close()