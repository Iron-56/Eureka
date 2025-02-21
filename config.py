import os
from supabase import create_client, Client

SUPABASE_URL = "https://dnilnsmspeylfgnvakhz.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRuaWxuc21zcGV5bGZnbnZha2h6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDAxNDUwMzMsImV4cCI6MjA1NTcyMTAzM30.Ih4cqpf7882Ow-zOGRKVANP6jeWCktG1qNJEZU97g-8"

def get_client():
	return create_client(SUPABASE_URL, SUPABASE_KEY)
