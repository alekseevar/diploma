import os


if os.name == "posix":
    PATH_TO_CONFIG_DIR = f"{os.path.expanduser('~')}/.ELLICE/"
else:
    PATH_TO_CONFIG_DIR = f"{os.path.expanduser('~')}\\.ELLICE\\"

if not os.path.exists(PATH_TO_CONFIG_DIR):
    os.mkdir(PATH_TO_CONFIG_DIR)

PATH_TO_USER_CERTS = f"{PATH_TO_CONFIG_DIR}{{user_email}}.csv"

def config_file_exists(email):
    return os.path.exists(PATH_TO_USER_CERTS.format(user_email=email))

