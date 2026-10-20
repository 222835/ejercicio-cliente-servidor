import os
import json
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# cambiar estas dos líneas por algo como: from logger_comun import logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("IPSec")

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

    def check_replay(self, seq: int) -> bool:
        """
        Verifica si un numero de secuencia es valido según la ventana deslizante.
        """
        if seq <= self.highest_seq - self.window_size:
           
            logger.warning(json.dumps({
                "modulo": "IPSec",
                "evento": "Anti-replay",
                "estado": "Rechazado",
                "motivo": "Paquete demasiado viejo",
                "secuencia": seq
            }))
            return False
            
        if seq in self.seen_seqs:
            
            logger.warning(json.dumps({
                "modulo": "IPSec",
                "evento": "Anti-replay",
                "estado": "Rechazado",
                "motivo": "Paquete duplicado",
                "secuencia": seq
            }))
            return False
        
        self.seen_seqs.add(seq)
        
        if seq > self.highest_seq:
            self.highest_seq = seq
            self.seen_seqs = {s for s in self.seen_seqs if s > self.highest_seq - self.window_size}
            
        return True

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
            
            logger.error(json.dumps({
                "modulo": "IPSec",
                "evento": "Integridad GCM",
                "estado": "Alerta de Seguridad",
                "motivo": "Alteracion detectada en payload",
                "secuencia": seq
            }))
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
        
        logger.info(json.dumps({
            "modulo": "IPSec",
            "evento": "Cifrado",
            "modo": "Transporte",
            "estado": "Exitoso",
            "secuencia": seq
        }))
        
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
        
        logger.info(json.dumps({
            "modulo": "IPSec",
            "evento": "Cifrado",
            "modo": "Tunel",
            "estado": "Exitoso",
            "secuencia": seq
        }))
        
        return {
            "new_ip_header": gateway_header,
            "ipsec_header": {"spi": self.sa.spi, "seq": seq},
            "encrypted_packet": encrypted_packet.hex()
        }