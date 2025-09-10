from flask import Flask, Response
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

app = Flask(__name__)

uri = "mongodb+srv://s09084711_db_user:gUuX0HPEcOhUW1oA@cluster0.udzsilh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

@app.route("/")
def index():
    try:
        client = MongoClient(uri, server_api=ServerApi('1'))
        client.admin.command('ping')
        return Response("✅ MongoDB Connect OK", mimetype="text/plain")
    except Exception as e:
        return Response(f"❌ MongoDB Connect Failed\n{str(e)}", mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
