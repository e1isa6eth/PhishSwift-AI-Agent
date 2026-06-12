import os
from dotenv import load_dotenv

# load environment vars from .env file
load_dotenv()

class Config:
    TENANT_ID = os.getenv("MICROSOFT_TENANT_ID")
    CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID")
    CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET")
    PORT = int(os.getenv("PORT", 8000))

config = Config()
