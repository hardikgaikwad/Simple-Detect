import logging

def logger_setup():
    logging.basicConfig(
        filename="ids.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

def log_event(level, message):
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.info(message)
    elif level == "error":
        logging.error(message)
    else:
        logging.error("logging error.")