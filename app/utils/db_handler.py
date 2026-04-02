import psycopg2
from psycopg2 import pool
import os
import logging

class DatabaseManager:
    """Handles thread-safe database operations using connection pooling."""
    
    def __init__(self):
        # Using connection pool for high-concurrency packet logging
        try:
            self.connection_pool = psycopg2.pool.SimpleConnectionPool(
                1, 10,
                host=os.getenv("DB_HOST", "localhost"),
                database=os.getenv("DB_NAME", "tls_db"),
                user=os.getenv("DB_USER", "user"),
                password=os.getenv("DB_PASS", "pass")
            )
            self._create_schema()
        except Exception as e:
            logging.error(f"Could not connect to PostgreSQL: {e}")

    def _create_schema(self):
        """Initializes the database table if it doesn't exist."""
        query = """
        CREATE TABLE IF NOT EXISTS tls_events (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            src_ip VARCHAR(45),
            dst_ip VARCHAR(45),
            ja3_hash VARCHAR(32),
            prediction VARCHAR(50),
            threat_level VARCHAR(20)
        );
        """
        self.execute_query(query)

    def execute_query(self, query, params=None):
        """Thread-safe query execution."""
        conn = self.connection_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(query, params)
                conn.commit()
        except Exception as e:
            logging.error(f"Database Query Error: {e}")
            conn.rollback()
        finally:
            self.connection_pool.putconn(conn)

    def log_event(self, src, dst, ja3, pred="Analyzing", threat="Unknown"):
        """Logs a single TLS event to the database."""
        query = "INSERT INTO tls_events (src_ip, dst_ip, ja3_hash, prediction, threat_level) VALUES (%s, %s, %s, %s, %s)"
        self.execute_query(query, (src, dst, ja3, pred, threat))