from dotnetfile import DotNetPE
import os
import pandas as pd
import numpy as np


# Malicious
dir = "C:\\Users\\medot\\Documents\\Worplace net clsfier\\malicious extracted\\"
target = 1
dfsize = 500
file_name = "mal"

# Benign
# dir = "C:\\Users\\medot\\Documents\\Worplace net clsfier\\benign extracted\\"
# target = 0
# dfsize = 500
# file_name = "ben"

# detect non dot net files and remove them
def detect_non_dotnet(file_location):
    dotnet_file = None
    try:
        dotnet_file = DotNetPE(file_location)
        if dotnet_file.metadata_table_exists('Assembly'):
            return True
        else:
            print(f'file {file_location} is not dot net, removing [no except]')
            with open(f'nondotnet{file_name}.txt', 'a+') as the_file:
                the_file.write(f'{file_location}\n')
            return False
    except Exception as e:
        print(e)
        print(f'file {file_location} is not dot net, removing[EXCEPT!]')
        with open(f'nondotnet{file_name}.txt', 'a+') as the_file:
            the_file.write(f'{file_location}\n')
        return False

def init_removal_list(directory):
    for filename in os.listdir(directory):
        result = detect_non_dotnet(directory+'/'+filename)

init_removal_list(dir)

def remove_from_list():
    # remove non dot net 
    with open(f'nondotnet{file_name}.txt', 'r') as the_file:
        lst = the_file.readlines()
        for item in lst:
            # os remove file
            print(f'removing {item.strip()}')
            os.remove(item.strip())
    # open file for write
    with open(f'nondotnet{file_name}.txt', 'w') as the_file:
        the_file.write('')

remove_from_list()

def detect_non_dotnet(file_location):
  dotnet_file = DotNetPE(file_location)
  if dotnet_file.metadata_table_exists('Assembly'):
    return dotnet_file
  else:
    print(f'file {file_location} is not dot net, removing')
    os.remove(file_location)
    return False

def parse_directory_to_pandas(directory):
    counter = 0
    rows_list = []
    for filename in os.listdir(directory):
      try:
        dotnet_file = detect_non_dotnet(directory+'/'+filename)
        dic = {}
        dic['.NET runtime target version'] =  dotnet_file.get_runtime_target_version()
        dic['Number of streams'] = dotnet_file.get_number_of_streams()
        dic['Has .NET resources'] = dotnet_file.has_resources()
        dic['Is a mixed .NET assembly'] = dotnet_file.is_mixed_assembly()
        dic['Has a native entry point'] = dotnet_file.has_native_entry_point()
        dic['Is a native image'] = dotnet_file.is_native_image()
        dic['Is a Windows Forms app'] = dotnet_file.is_windows_forms_app()
        dic['Anti analysis NET data directory hidden in PE header'] = dotnet_file.AntiMetadataAnalysis.is_dotnet_data_directory_hidden
        dic['Anti analysis Has extra data at the end of the metadata header'] = dotnet_file.AntiMetadataAnalysis.has_metadata_table_extra_data
        dic['Anti analysis Has fake types that reference each other'] =  dotnet_file.AntiMetadataAnalysis.has_self_referenced_typeref_entries
        dic['Anti analysis Has invalid entries in TypeRef table'] =  dotnet_file.AntiMetadataAnalysis.has_invalid_typeref_entries
        dic['Anti analysis Has fake data streams'] =  dotnet_file.AntiMetadataAnalysis.has_fake_data_streams
        dic['Anti analysis Has more than one row in Module table'] =  dotnet_file.AntiMetadataAnalysis.module_table_has_multiple_rows
        dic['Anti analysis Has more than one row in Assembly table'] =   dotnet_file.AntiMetadataAnalysis.assembly_table_has_multiple_rows
        dic['Anti analysis Has invalid entries in #Strings stream'] =   dotnet_file.AntiMetadataAnalysis.has_invalid_strings_stream_entries

        
        ###### Cor20 Header ######
        defined_entry_point = dotnet_file.Cor20Header.get_header_entry_point()
        # composit object decomposed
        #dic['Defined entry point'] = defined_entry_point 
        if defined_entry_point:
            # always going to be managed or NAN, NAN is going to be captured by other decomposed features
            #dic['Defined entrypoint type'] = defined_entry_point.EntryPointType
            if defined_entry_point.EntryPointType == 'Managed':
                dic['Managed Entrypoint Method'] = defined_entry_point.Method 
                dic['Managed Defined entrypoint type'] = defined_entry_point.Type 
                dic['Managed Entrypoint Namespace'] = defined_entry_point.Namespace 

                #dic['Managed Entrypoint Signature'] = defined_entry_point.Signature 
                #  low cardinality composit object but composed eitherway
                #if defined_entry_point.Signature:
                    # dic['Managed Entrypoint Signature Parameter'] = defined_entry_point.Signature["parameter"]
                    # dic['Managed Entrypoint Signature Return value'] = defined_entry_point.Signature["return"]
                    # dic['Managed Entrypoint Signature Has this pointer'] =defined_entry_point.Signature["hasthis"]
                    # TODO
# ### thoughts this part just never seems to occur because ngen images aren't executable on their own
#             elif defined_entry_point.EntryPointType == 'Native': # don't exist
#                 dic['Native Entrypoint Address'] = defined_entry_point.Address

        dic['Stream names'] = dotnet_file.get_stream_names()
        dic['All references'] = dotnet_file.get_all_references()
        # IMPRORTANT TODO but can't be used due to performance issues
        # dic['Strings stream strings'] = dotnet_file.get_strings_stream_strings()
        # dic['US stream strings'] = dotnet_file.get_user_stream_strings()
        # very computational demanding, replaced it with the len
        dic['Len Strings stream strings'] = len(dotnet_file.get_strings_stream_strings())
        dic['Len US stream strings'] = len(dotnet_file.get_user_stream_strings())

    
        
        dic['Existent metadata tables'] = dotnet_file.existent_metadata_tables()
        dic['Available tables'] = dotnet_file.existent_metadata_tables()
        available_tables = dotnet_file.existent_metadata_tables()
      #### Module Table ####
        # dic['Has Module Table'] = int('Module' in available_tables) # useless all have 1
        if 'Module' in available_tables:
            dic['Module name'] = dotnet_file.Module.get_module_name()

      #### Assembly Table ####
        # dic['Has Assembly Table'] = int('Assembly' in available_tables) useless all have 1
        if 'Assembly' in available_tables:
            dic['Assembly Name'] = dotnet_file.Assembly.get_assembly_name()
            # low cardinality usually problems
            # dic['Assembly Culture'] = dotnet_file.Assembly.get_assembly_culture()
# TODO?
            # composit object decomposed
            # dic['Assembly version info'] = dotnet_file.Assembly.get_assembly_version_information()
            assembly_version_info = dotnet_file.Assembly.get_assembly_version_information()
            if assembly_version_info:
                dic['assembly_version_info BuildNumber'] = assembly_version_info.BuildNumber
                dic['assembly_version_info MajorVersion'] = assembly_version_info.MajorVersion
                dic['assembly_version_info MinorVersion'] = assembly_version_info.MinorVersion
                dic['assembly_version_info RevisionNumber'] = assembly_version_info.RevisionNumber

      #### AssemblyRef Table ####
      # TODO
        # dic['Has AssemblyRef'] = ('AssemblyRef' in available_tables)
        if 'AssemblyRef' in available_tables:
            dic['Assembly names'] = dotnet_file.AssemblyRef.get_assemblyref_names()
            #useless low cardinality usually problems TODO
            # dic['Assembly Cultures'] = dotnet_file.AssemblyRef.get_assemblyref_cultures()

      #### ModuleRef Table #### 
        dic['Has ModuleRef'] = int('ModuleRef' in available_tables)
        if 'ModuleRef' in available_tables:
            dic['Unmanaged module names'] = dotnet_file.ModuleRef.get_unmanaged_module_names(dotnet_file.Type.UnmanagedModules.NORMALIZED)
            
      #### ImplMap Table ####
        dic['Has ImplMap'] = int('ImplMap' in available_tables)
        if 'ImplMap' in available_tables:
            dic['Unmanaged functions'] = dotnet_file.ImplMap.get_unmanaged_functions()

      #### TypeRef Table ####
        # dic['Has TypeRef'] = int('TypeRef' in available_tables)
        if 'TypeRef' in available_tables:
            dic['Referenced Types Names'] = dotnet_file.TypeRef.get_typeref_names()
            # don't seem to know what to do with ? TODO
            # dic['TypeRef hash (unsorted)'] = dotnet_file.TypeRef.get_typeref_hash()
            # dic['TypeRef hash (sorted)'] = dotnet_file.TypeRef.get_typeref_hash(dotnet_file.Type.Hash.SHA256, False, True)

      #### TypeDef Table ####
        # dic['Has TypeDef'] = int('TypeDef' in available_tables) # always true
        if 'TypeDef' in available_tables:
            dic['TypeDef Names']= dotnet_file.TypeDef.get_type_names()

      #### MethodDef Table ####
        # dic['Has MethodDef'] = int('MethodDef' in available_tables)
        if 'MethodDef' in available_tables:
            dic['Method names'] = dotnet_file.MethodDef.get_method_names()

        # TODO loop on the possible entrypoints, create lists for each item. append to the list
        # this needs to be done !!!! TODO
            dic['Len Possible method entry points'] = len(dotnet_file.MethodDef.get_entry_points())

            # dic['Possible method entry points'] = dotnet_file.MethodDef.get_entry_points()
            # entry_points = dotnet_file.MethodDef.get_entry_points()
            # ep_methods, ep_types, ep_namespaces, ep_sign_prameters, ep_sign_rtn, ep_sign_hasthis= [], [], [], [], [], []
            # for ep in entry_points:
            #   ep_methods.append( ep.Method )
            #   ep_types.append( ep.Type)
            #   ep_namespaces.append( ep.Namespace)
            #   if ep.Signature:
            #       ep_sign_prameters.append(ep.Signature["parameter"])
            #       ep_sign_rtn.append( ep.Signature["return"])
            #       ep_sign_hasthis.append(p.Signature["hasthis"])

      #### MemberRef Table ####
        # dic['Has MemberRef'] = int('MemberRef' in available_tables)
        if 'MemberRef' in available_tables:
            dic['memberref_names'] = dotnet_file.MemberRef.get_memberref_names(deduplicate=True)
            # can be used to remove duplicates???
            #dic['MemberRef hash (unsorted)'] = dotnet_file.MemberRef.get_memberref_hash()
            #dic['MemberRef hash (sorted)'] = dotnet_file.MemberRef.get_memberref_hash(strings_sorted=True)


      #### Event Table ####
        dic['Has Event'] = int('Event' in available_tables)
        if 'Event' in available_tables:
            dic['Event names'] = dotnet_file.Event.get_event_names()

      #### ManifestResource Table ####
        dic['Has ManifestResource'] = int('ManifestResource' in available_tables)
        if 'ManifestResource' in available_tables:
            dic['Resource names'] = dotnet_file.ManifestResource.get_resource_names()
        # redundent with len resources
        #dic['Has Resources'] = int(len(dotnet_file.get_resources()) > 20)
        # TODO Resources are important, but can't parse them cuz of perfromace issues
        # dic['Resources'] = dotnet_file.get_resources()
        # problem with performance
        dic['Len Resources'] = len(dotnet_file.get_resources())
        rows_list.append(dic)
        if len(rows_list) == dfsize:
            counter += 1
            df = pd.DataFrame(rows_list)
            print(f"saved to csv{counter}")
            df.to_csv(f"{file_name}{counter}.csv", index=False)
            rows_list = []
    
      except Exception as e:
        print(f'Error: {e}')
        print(type(e))
        print(e.args)
        pass

parse_directory_to_pandas(dir)