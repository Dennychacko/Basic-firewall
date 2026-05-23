from config import services

def get_service(port):
    return services.get(port, "OTHERS")