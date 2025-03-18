import logging

def logger_setup():
    logging.basicConfig(
        filename=ids.log,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

def log_event(level, message):
    if level == "info":
        logging.INFO(message)
    elif level == "warning":
        logging.WARNING(message)
    elif level == "error":
        logging.ERROR(message)
    else:
        logging.ERROR("logging error.")