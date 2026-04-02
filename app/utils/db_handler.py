import psycopg2
import os

class DBHandler:
    def __init__(self):
        # Using the environment variables that we defined at Docker-compose.
        self.conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "localhost"),
            database=os.getenv("DB_NAME", "tls_db"),
            user=os.getenv("DB_USER", "user"),
            password=os.getenv("DB_PASS", "pass")
        )
        self.create_table()

    def create_table(self):
        with self.conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS fingerprints (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    ja3_hash TEXT,
                    ai_prediction TEXT,
                    threat_status TEXT DEFAULT 'Unknown'
                )
            """)
            self.conn.commit()

    def insert_fingerprint(self, src_ip, dst_ip, ja3_hash, prediction):
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO fingerprints (src_ip, dst_ip, ja3_hash, ai_prediction) VALUES (%s, %s, %s, %s)",
                (src_ip, dst_ip, ja3_hash, prediction)
            )
            self.conn.commit()