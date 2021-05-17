from fastapi import FastAPI, HTTPException
from typing import Optional
from pydantic import BaseModel
from dotenv import load_dotenv
from datetime import datetime
from cryptography.fernet import InvalidToken
import psycopg2
import os
import urllib.parse
import crypto_utils


load_dotenv()

app = FastAPI()
result = urllib.parse.urlparse(os.getenv("DATABASE_URL"))
username = result.username
password = result.password
database = result.path[1:]
hostname = result.hostname

conn = psycopg2.connect(
    host=hostname,
    database=database,
    user=username,
    password=password)


def insert_secret(conn, vals):
    sql = """INSERT INTO messages(id, pub_time, text, hash) VALUES(%s,%s,%s,%s)"""
    try:
        cur = conn.cursor()
        cur.execute(sql, vals)
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)


def query_secret(conn, vals):
    row = None
    sql = """SELECT * FROM messages WHERE "id" = %s;"""
    try:
        cur = conn.cursor()
        cur.execute(sql, vals)
        row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    return row


def delete_secret(conn, vals):
    sql = """DELETE FROM messages WHERE "id" = %s;"""
    try:
        cur = conn.cursor()
        cur.execute(sql, vals)
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)


def delete_aged_secrets(conn):
    sql = """ DELETE FROM messages WHERE "pub_time" <=  NOW()+ INTERVAL '1 hours'; """
    try:
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)


class Secret(BaseModel):
    message: str
    passphrase: str


@app.post("/secrets")
def create_secret(secret: Secret):
    secret_id = crypto_utils.get_uuid()
    sha = crypto_utils.get_sha(secret.passphrase)
    ciphertext = crypto_utils.encrypt(secret.passphrase, secret.message)
    timestamp = datetime.now()
    # Delete secrets older than 1 Hour
    delete_aged_secrets(conn)
    #
    insert_secret(conn, (secret_id, timestamp, ciphertext, sha))
    return {"success": "True", "id": secret_id}


class Passphrase(BaseModel):
    passphrase: str


@app.post("/secrets/{secret_id}")
def read_secret(secret_id: str, passphrase: Passphrase):
    row = query_secret(conn, (secret_id,))
    # Delete secrets older than 1Hour
    delete_aged_secrets(conn)
    #
    delete_secret(conn, (secret_id,))
    passphrase = passphrase.passphrase
    if row is None:
        return HTTPException(404, detail="Passphrase incorrect or secret not found/available anymore.")
    ciphertext, stored_sha = row[2], row[3]
    sha = crypto_utils.get_sha(passphrase)
    if stored_sha != sha:
        return HTTPException(404, detail="Passphrase incorrect or secret not found/available anymore.")
    plaintext = crypto_utils.decrypt(passphrase, ciphertext)

    return {"success": "True", "message":  plaintext}
