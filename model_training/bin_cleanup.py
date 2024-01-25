import os
from config.vars import BINARIES_DIR

if __name__ == "__main__":
    count = 0
    bin_list = sorted(os.listdir(BINARIES_DIR))
    to_be_removed = []
    print:("The following projects failed compilation")
    for elem in bin_list:
        path = os.path.join(BINARIES_DIR, elem, "-O2")
        if not os.listdir(path):
            count += 1
            print("{}) Project #{}: {}".format(count, bin_list.index(elem), elem))

    message = "A total of {} projects out of the {} available have failed compiling\n"
    message += "Accounting for the {}% of all projects"
    print(message.format(count, len(bin_list), count/len(bin_list) * 100))
