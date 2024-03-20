# Function creates database connection.

import mysql.connector as conn


def get_db_connection():
    return conn.connect(host="individualproject-db.czvexvqcubuf.eu-west-2.rds.amazonaws.com",
                        username="adminAWS",
                        password="Stupify2508",
                        database="User_Information")
