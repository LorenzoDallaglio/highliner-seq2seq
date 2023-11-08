from pickle import dump, load

def save_state(file_list, opt_list, snippet_list):
    state = {
            "file_list": file_list,
            "opt_list": opt_list,
            "snippets": snippet_list
    }
    with open("data/execution_chekpoint.pickle", "wb") as pickle_file:
        dump(state, pickle_file)

    return

def load_state():
    with open("data/execution_chekpoint.pickle", "rb") as pickle_file:
        state = load(pickle_file)

    return state["file_list"], state["opt_list"], state["snippets"]

