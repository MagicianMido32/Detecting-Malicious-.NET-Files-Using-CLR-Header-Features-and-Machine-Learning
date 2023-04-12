from dotnetfile import DotNetPE
import os



def read_dotnet_remove_otherwise(file_location):
    dotnet_file = None
    try:
        dotnet_file = DotNetPE(file_location)
        if dotnet_file.metadata_table_exists('Assembly'):
            return True
        else:
            print(f'file {file_location} is not dot net, removing [no except]')
            # del dotnet_file
            # os.remove(file_location)
            with open('nondotnet.txt', 'a') as the_file:
                the_file.write(f'{file_location}\n')
            return False
    except Exception as e:
        print(e)
        print(f'file {file_location} is not dot net, removing[EXCEPT!]')
        # del dotnet_file
        # os.remove(file_location)
        with open('nondotnet.txt', 'a') as the_file:
            the_file.write(f'{file_location}\n')
        return False


def parse_directory(directory):
    for filename in os.listdir(directory):
        result = read_dotnet_remove_otherwise(directory+'/'+filename)

parse_directory("C:\\Users\\medot\\Documents\\Worplace net clsfier\\benign extracted")
#parse_directory("C:\\Users\\medot\\Documents\\Worplace net clsfier\\malware extracted")