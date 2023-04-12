# open file for read
import os
with open('nondotnet.txt', 'r') as the_file:
    lst = the_file.readlines()
    for item in lst:
        # os remove file
        print(f'removing {item.strip()}')
        os.remove(item.strip())
# open file for write
with open('nondotnet.txt', 'w') as the_file:
    the_file.write('')