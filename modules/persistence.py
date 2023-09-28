import json
from os import path

def save_state(file_list, opt_list):
    state = {
            "file_list": file_list,
            "opt_list": opt_list,
    }
    file = open("backup.json", "w")
    json.dump(state, file)
    return

def load_state():
    try:
        file = open("backup.json", "r")
        state = json.load(file)
        return state["file_list"], state["opt_list"]
    except:
        return [], []
