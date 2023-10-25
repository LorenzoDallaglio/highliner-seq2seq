""" Here are kept shared global variables! """

PROJECTS_DIR = 'projects/'
BINARIES_DIR = 'binary_dataset/'
SNIPPETS_DIR = 'snippet_dataset/'
OPT_LEVELS = ["-O2", "-O3", "-Os", "-Ofast"]
METHODS = {
    "std::deque::operator[]",
    "std::deque::pop_front",
    "std::deque::push_back",
    "std::map::find",
    "std::map::lower_bound",
    "std::map::operator[]",
    "std::map::upper_bound"
    "std::vector::clear",
    "std::vector::erase",
    "std::vector::push_back",
    "std::vector::reserve",
    "std::vector::resize"
}