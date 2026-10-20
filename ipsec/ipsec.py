import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from comun.registro import registrar  # registro común del proyecto (JSON por línea)

class IPSecSA:
    """
    Clase que representa una Asociación de Seguridad (SA).
    Contiene los parametros acordados para una conexion segura.
    """
    def __init__(self, spi: int, key: bytes):
        self.spi = spi
        self.key = key
        self.aesgcm = AESGCM(key)
        
        # --- Variables para la ventana Anti-replay ---
        self.window_size = 64
        self.highest_seq = 0
        self.seen_seqs = set()

    def check_replay(self, seq: int, marcar: bool = True) -> bool:
        """
        Verifica si un numero de secuencia es valido según la ventana deslizante.

        Con marcar=False solo consulta la ventana sin registrar el numero;
        se usa para revisar ANTES de validar la integridad del paquete.
        """
        if seq <= 0:
            registrar("replay_detectado", "ipsec", spi=self.spi,
                      motivo="Numero de secuencia invalido", secuencia=seq)
            return False

        if seq <= self.highest_seq - self.window_size:
           
            registrar("replay_detectado", "ipsec", spi=self.spi,
                      motivo="Paquete demasiado viejo", secuencia=seq)
            return False
            
        if seq in self.seen_seqs:
            
            registrar("replay_detectado", "ipsec", spi=self.spi,
                      motivo="Paquete duplicado", secuencia=seq)
            return False

        if marcar:
            self._marcar_secuencia(seq)
        return True

    def _marcar_secuencia(self, seq: int) -> None:
        """Registra el numero como recibido y desliza la ventana."""
        self.seen_seqs.add(seq)
        if seq > self.highest_seq:
            self.highest_seq = seq
            self.seen_seqs = {s for s in self.seen_seqs if s > self.highest_seq - self.window_size}

    def recibir(self, seq: int, encrypted_data: bytes) -> bytes:
        """
        Procesa un paquete recibido en el orden correcto (como RFC 4303):
          1. Revisa la ventana anti-replay SIN marcar el numero.
          2. Verifica la integridad y descifra con AES-GCM.
          3. Solo si el paquete es autentico, marca el numero como recibido.

        Si se marcara antes de verificar, un atacante podria mandar un paquete
        falso con el numero del siguiente paquete legitimo y hacer que este se
        rechazara como duplicado.
        """
        if not self.check_replay(seq, marcar=False):
            raise ValueError("Replay detectado")
        datos = self.decrypt_payload(encrypted_data, seq)   # ValueError si fue alterado
        self._marcar_secuencia(seq)
        return datos

    def encrypt_payload(self, data: bytes, seq: int) -> bytes:
        """
        Cifra y firma los datos usando AES-GCM.
        """
        nonce = os.urandom(12)
        aad = f"{self.spi}:{seq}".encode()
        ciphertext = self.aesgcm.encrypt(nonce, data, aad)
        return nonce + ciphertext

    def decrypt_payload(self, encrypted_data: bytes, seq: int) -> bytes:
        """
        Descifra y verifica la autenticidad de los datos.
        """
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aad = f"{self.spi}:{seq}".encode()
        
        try:
            return self.aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            
            registrar("integridad_fallida", "ipsec", spi=self.spi,
                      motivo="Alteracion detectada en payload", secuencia=seq)
            raise ValueError("El paquete fue alterado")


class IPSecSimulator:
    """
    Clase que simula la aplicacion de IPSec a los paquetes de red.
    """
    def __init__(self, sa: IPSecSA):
        self.sa = sa
        self.current_seq = 1

    def modo_transporte(self, ip_header: dict, payload: str) -> dict:
        """
        Modo Transporte: Protege solo el contenido del mensaje.
        """
        seq = self.current_seq
        self.current_seq += 1
        
        encrypted_payload = self.sa.encrypt_payload(payload.encode(), seq)
        
        registrar("paquete_cifrado", "ipsec", modo="transporte",
                  spi=self.sa.spi, secuencia=seq)
        
        return {
            "ip_header": ip_header,
            "ipsec_header": {"spi": self.sa.spi, "seq": seq},
            "encrypted_payload": encrypted_payload.hex()
        }

    def modo_tunel(self, original_packet: dict, gateway_header: dict) -> dict:
        """
        Modo Tunel: Oculta el paquete completo dentro de uno nuevo.
        """
        seq = self.current_seq
        self.current_seq += 1
        
        packet_bytes = json.dumps(original_packet).encode()
        encrypted_packet = self.sa.encrypt_payload(packet_bytes, seq)
        
        registrar("paquete_cifrado", "ipsec", modo="tunel",
                  spi=self.sa.spi, secuencia=seq)
        
        return {
            "new_ip_header": gateway_header,
            "ipsec_header": {"spi": self.sa.spi, "seq": seq},
            "encrypted_packet": encrypted_packet.hex()
        }