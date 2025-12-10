import logging
import sys

def setup_logger(name_log, path_file_log):
    # Crear el logger
    logger = logging.getLogger(name_log)
    logger.setLevel(logging.DEBUG) # Capturar todo (Debug, Info, Error)

    # Evitar duplicados si llamas a la función varias veces
    if logger.handlers:
        return logger

    # Formato del mensaje: AÑO-MES-DIA HORA - NIVEL - MENSAJE
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # 1. Handler de Archivo (FileHandler)
    file_handler = logging.FileHandler(path_file_log, mode='w', encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
