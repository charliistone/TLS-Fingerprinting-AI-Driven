import hashlib
from scapy.all import sniff, load_layer
import logging
load_layer("tls")
from scapy.layers.tls.all import TLS, TLSClientHello

class JA3Processor:
    """Encapsulates the logic for JA3 fingerprint generation."""
    
    @staticmethod
    def _is_grease(val):
        """Filters out GREASE values as per RFC 8701."""
        return (val & 0x0f0f) == 0x0a0a

    def get_hash(self, packet):
        """Generates a JA3 MD5 hash from a TLS Client Hello packet."""
        try:
            tls_layer = packet[TLSClientHello]
            
            # 1. SSL/TLS Version
            version = str(tls_layer.version)
            
            # 2. Accepted Ciphers (excluding GREASE)
            ciphers = "-".join([str(c) for c in tls_layer.ciphers if not self._is_grease(c)])
            
            # 3. Extensions, 4. Elliptic Curves, 5. EC Point Formats
            # Note: Production parsing requires iterating through tls_layer.extensions
            extensions = "" 
            curves = ""
            point_formats = ""

            ja3_string = f"{version},{ciphers},{extensions},{curves},{point_formats}"
            return hashlib.md5(ja3_string.encode()).hexdigest()
        except Exception as e:
            logging.debug(f"Parsing failed: {e}")
            return None

# ... (previous imports)
class NetworkSniffer:
    def __init__(self, db_manager, predictor):
        self.db = db_manager
        self.processor = JA3Processor()
        self.predictor = predictor # Injecting the AI Brain

    def _packet_callback(self, packet):
        if packet.haslayer(TLSClientHello):
            print("\n[!] TLS Client Hello Found!")
            ja3 = self.processor.get_hash(packet)
            if ja3:
                src = packet[0][1].src
                dst = packet[0][1].dst
                
                # Use the AI to predict the nature of the hash
                prediction = self.predictor.predict(ja3)
                
                # Log to DB with the AI's verdict
                self.db.log_event(src, dst, ja3, pred=prediction)
                logging.info(f"[+] {src} -> {dst} | JA3: {ja3} | AI: {prediction}")
            

    def start(self, interface=None):
        logging.info(f"Sniffer active on {interface}...")
        if interface is None or interface == "any":
            # macOS's default environment en0. !!!! Change this for Windows.!!!!
            interface = "en0" 
    
        logging.info(f"Sniffer active on {interface}...")
        sniff(iface=interface, prn=self._packet_callback, store=0)