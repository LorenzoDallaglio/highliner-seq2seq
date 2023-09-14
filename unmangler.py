NAMESPACE_PREFIX = '_ZNSt'
METHOD_PREFIX = 'EE'
METHODS = {
        "deque": ["operator[]", "pop_front", "push_back"],
        "map": ["operator[]", "lower_bound", "upper_bound"],
        "vector": ["clear", "erase", "push_back", "reserve", "resize"],
}

def check_prefix(mangled_name, namespace):
    prefix = NAMESPACE_PREFIX + str(len(namespace)) + namespace
    if mangled_name[0:len(prefix)] == prefix:
        return True
    else: 
        return False

def check_method_name(mangled_name, method):
    starting_pos = mangled_name.rfind(METHOD_PREFIX)
    mangled_name = mangled_name[starting_pos:]
    if method != 'operator[]':
        postfix = METHOD_PREFIX + str(len(method)) + method
    else:
    #NOTE: there is no guarantee for other operator methods to follow this encoding
    # Further examples are required to verify
        postfix = METHOD_PREFIX + "ixE"
    if mangled_name[0:len(postfix)] == postfix:
        return True
    else: 
        return False

def check_name(mangled_name, method_dict):
    for namespace in method_dict.keys():
        if check_prefix(mangled_name, namespace):
            for method in method_dict[namespace]:
                if check_method_name(mangled_name, method):
                    return True
    return False

if __name__ == "__main__":
    file = open("methods.txt")
    lines = file.readlines()
    for i in range(len(lines)):
        lines[i] = lines[i].split("-> ")[-1]
    
    for line in lines:
        print(line)
        print(check_name(line, METHODS))


