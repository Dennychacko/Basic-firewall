def log_packet(message):
    """
    Append logs to firewall.log
    """

    with open("firewall.log", "a") as file:
        file.write(message + "\n")