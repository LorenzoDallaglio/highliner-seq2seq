import os
import subprocess

PROJECTS_DIR = 'projects/'
BINARIES_DIR = 'binary_dataset/'
#NOTE: which version of dwarf to use?
CXXFLAGS = "-std=c++14 -lm -lpthread -g "
OPT_LEVELS = ["-O2", "-O3", "-Os", "-Ofast"]

def recursive_ls(path):
    file_paths = list()
    for elem in os.listdir(path):
        elem_path = os.path.join(path, elem)
        if os.path.isdir(elem_path):
            file_paths += recursive_ls(elem_path)
        elif os.path.isfile(elem_path):
            file_paths.append(elem_path)
    return file_paths

def is_binary(path):
    f = open(path, "rb")
    content = f.read()
    f.close()
    if b'\x7f\x45\x4c\x46' == content[0:4]:
        return True
    return False

def is_library(path):
    if path[-2:] == ".a":
        return True
    if path[-3:] == ".so":
        return True
    return False

if __name__ == '__main__':
    #For each optimization level
    for opt_level in OPT_LEVELS:
        #Build all projects with the given optimization level
        print("Build for: " + opt_level)
        make_command = ["make", "CXXFLAGS={}".format(CXXFLAGS + opt_level), "OPT_FLAGS='{}'".format(opt_level)]
        subprocess.run(make_command)

        #NOTE: what happens if the process is interrupted?
        #Create binary directory if non-existent
        if not os.path.exists(BINARIES_DIR): 
            os.mkdir(BINARIES_DIR)

        #For each project
        for proj_dir in os.listdir(PROJECTS_DIR):
            proj_path = os.path.join(PROJECTS_DIR, proj_dir)
            #List all related files
            proj_file_path = recursive_ls(proj_path)

            bin_dir = os.path.join(BINARIES_DIR, proj_dir)
            if not os.path.exists(bin_dir):
                os.mkdir(bin_dir)
            bin_dir = os.path.join(bin_dir, opt_level)
            if not os.path.exists(bin_dir):
                os.mkdir(bin_dir)
            
            for file_path in proj_file_path:
                if is_binary(file_path) and not is_library(file_path):
                    #This extension is typical of relocatable files.
                    #Due to makefile heterogeneity, clean rule is not defined
                    #Thus, the buidling procedure takes it upon itself to also remove relocatables
                    if file_path[-2:] == ".o":
                        os.remove(file_path)
                    else:
                        file_name = os.path.basename(file_path)
                        bin_path = os.path.join(bin_dir, file_name)
                        os.replace(file_path, bin_path)
