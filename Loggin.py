import re

def LogIt(message, level):
    if re.match(r"^debug", message.lower()):
        pass
    elif re.match(r"^notice", message.lower()):
        print(message)
    else:
        print(message)
