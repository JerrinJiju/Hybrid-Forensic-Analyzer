import random
import datetime

def generate_investigator_id():
    year = datetime.datetime.now().year
    unique = random.randint(1000, 9999)
    return f"INV-{year}-{unique}"