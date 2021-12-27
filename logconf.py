import datetime

LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'filefmt': {
            'format': '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
            'datefmt': '%H:%M:%S'
        },
        'consolefmt': {
            'format': '%(levelname)s - %(message)s',
            'datefmt': '%H:%M:%S'
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'formatter': 'consolefmt',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',  # Default is stderr
        },
        'file': {
            'level': 'DEBUG',
            'formatter': 'filefmt',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': f'logs/{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
        },
    },
    'loggers': {
        '': {  # root logger
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': False
        },
    }
}
