import ipaddress

def calculate_network_address():
    ip_cidr = "192.168.1.10/30"
    print(type(ip_cidr))
    # Converte o IP/CIDR para um objeto IPv4Network
    network_CIDR = ipaddress.IPv4Network(ip_cidr, strict=False)
    # Obtém o endereço de rede
    network_address = network_CIDR.network_address
    return str(network_address)

# Exemplo de uso

network_address = calculate_network_address()

print(f"Endereço de rede: {network_address}")
