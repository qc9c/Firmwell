#!/usr/bin/env python3

import os
import sys
import psycopg2
import hashlib

def io_md5(target):
    blocksize = 65536
    hasher = hashlib.md5()

    with open(target, 'rb') as ifp:
        buf = ifp.read(blocksize)
        while buf:
            hasher.update(buf)
            buf = ifp.read(blocksize)
        return hasher.hexdigest()

def query_(query, psql_ip):
    try:
        dbh = psycopg2.connect(database="firmware",
                               user="firmadyne",
                               password="firmadyne",
                               host=psql_ip)
        cur = dbh.cursor()
        cur.execute(query)
        return cur.fetchone()

    except:
        return None

def get_iid(infile, psql_ip):
    md5 = io_md5(infile)
    q = "SELECT id FROM image WHERE hash = '%s'" % md5
    image_id = query_(q, psql_ip)

    if image_id:
        return image_id[0]
    else:
        return ""

def get_brand(infile, psql_ip):
    md5 = io_md5(infile)
    q = "SELECT brand_id FROM image WHERE hash = '%s'" % md5
    brand_id = query_(q, psql_ip)

    if brand_id:
        q = "SELECT name FROM brand WHERE id = '%s'" % brand_id
        brand = query_(q, psql_ip)
        if brand:
            return brand[0]
        else:
            return ""
    else:
        return ""

def check_connection(psql_ip):
    try:
        dbh = psycopg2.connect(database="firmware",
                               user="firmadyne",
                               password="firmadyne",
                               host=psql_ip)
        dbh.close()
        return 0
    except:
        return 1
    
def update_id(src_id, dst_id, psql_ip):
    try:
        dbh = psycopg2.connect(database="firmware",
                               user="firmadyne",
                               password="firmadyne",
                               host=psql_ip)
        cur = dbh.cursor()
        
        update_query = "UPDATE image SET id = %s WHERE id = %s"
        cur.execute(update_query, (dst_id, src_id))
        
        dbh.commit()
        
        cur.close()
        dbh.close()
        
        return 0
    except (Exception, psycopg2.DatabaseError) as error:
        print(f"Error updating id from {src_id} to {dst_id}: {error}")
        return 1


def set_brand_and_id(infile, dst_iid, brand, psql_ip):
    """Update brand and image ID for the given firmware file in the database."""
    try:
        dbh = psycopg2.connect(database="firmware",
                               user="firmadyne",
                               password="firmadyne",
                               host=psql_ip)
        cur = dbh.cursor()
        
        cur.execute("SELECT id FROM brand WHERE name = %s", (brand,))
        brand_id = cur.fetchone()
        if not brand_id:
            cur.execute("INSERT INTO brand (name) VALUES (%s) RETURNING id", (brand,))
            brand_id = cur.fetchone()
        brand_id = brand_id[0]
        
        image_hash = io_md5(infile)
        
        cur.execute("SELECT id FROM image WHERE hash = %s", (image_hash,))
        image_id = cur.fetchone()
        if not image_id:
            cur.execute("INSERT INTO image (id, filename, brand_id, hash) VALUES (%s, %s, %s, %s) RETURNING id",
                        (dst_iid, os.path.basename(infile), brand_id, image_hash))
            image_id = cur.fetchone()
        else:
            cur.execute("UPDATE image SET id = %s, brand_id = %s WHERE hash = %s",
                        (dst_iid, brand_id, image_hash))
        
        dbh.commit()
        
        cur.close()
        dbh.close()
        
        return 0
    except (Exception, psycopg2.DatabaseError) as error:
        print(f"Error updating brand of {dst_iid} to {brand}: {error}")
        return 1

# command line
if __name__ == '__main__':
    [infile, psql_ip] = sys.argv[2:4]
    if sys.argv[1] == 'get_iid':
        print(get_iid(infile, psql_ip))
    if sys.argv[1] == 'get_brand':
        print(get_brand(infile, psql_ip))
    if sys.argv[1] == 'check_connection':
        exit(check_connection(psql_ip))
    if sys.argv[1] == "update_id":
        [src_id, dst_id] = sys.argv[4:6]
        exit(update_id(src_id, dst_id, psql_ip))
    if sys.argv[1] == "set_brand_and_id":
        [dst_iid, brand] = sys.argv[4:6]
        print(infile, dst_iid, brand, psql_ip)
        exit(set_brand_and_id(infile, dst_iid, brand, psql_ip))
