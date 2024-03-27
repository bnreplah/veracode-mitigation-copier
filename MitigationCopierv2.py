import sys
import argparse
import logging
#import requests
from lxml import etree
#from xml import etree
#import os # for the ability to check if file exists and parse csv
import csv
from helpers import api
import MitigationCopier

## Imported from main Mitigation Copier to read the credential file
## BH 9/21/23
# import datetime
# from veracode_api_py.api import VeracodeAPI as vapi

############################################################################
## DO NOT CHANGE UNLESS YOU KNOW WHAT YOU ARE DOING                        #
############################################################################
#Global Switches And Data                                                  #
MitigationCopierVersion="3.0.1"                                            #
FuzzyMatch=True                                                            #
UnmatchOut=True                                                           #
FuzzyPointsOfSimilarity=4                                                  #
FuzzyDistance=3                                                            #
itterateToFrom=False                                                       #
GLOBAL_ARG=False                                                           #
VERBOSE=True                                                             #
VERBLEVEL=0                                                               #
EXHAUSTIVE_FUZZY=False                                                     #
MANUAL_IMPORT=True
MANUAL_REVIEW=False
PRINT_OUT_UNMATCHED=True                                                         #
#INTERACTIVE=False                                                          #
############################################################################
## Internal flags                                                          #
DEBUG=True                                                                 #
vendor_account_id=None                                                     #
dryrun=True                                                                #
############################################################################

## Script Arguments 
############################################################################################################################
##
##
##
############################################################################################################################

parser = argparse.ArgumentParser(
        description='This script looks at the results set of the FROM BUILD. For any flaws that have an '
                    'accepted mitigation, it checks the TO BUILD to see if that flaw exists. If it exists, '
                    'it copies all mitigation information.')
if GLOBAL_ARG is True:
    parser.add_argument('-f', '--frombuild', help='Build ID to copy from')
    parser.add_argument('-t', '--tobuild', help='Build ID to copy to')
    parser.add_argument('-v', '--vid',  help='Veracode API ID')
    parser.add_argument('-k', '--vkey', help='Veracode API key')
    parser.add_argument('-c', '--csv', help='CSV of From and To Build IDs to copy from and to' )
    parser.add_argument('-csv', '--readfromcsv', help='Flag to read from CSV instead. Default: False', default=False)
    args = parser.parse_args()

## Script Arguments 
############################################################################################################################



# "cweid": flaw.attrib['cweid'],
#                 "module":flaw.attrib['module'],
#                 "type": flaw.attrib['type'],
#                 "scope": flaw.attrib['scope'],
#                 "function_prototype": flaw.attrib['functionprototype'],
#                 "function_relative_location": flaw.attrib['functionrelativelocation'],
#                 "source_file_path": flaw.attrib['sourcefilepath'],
#                 "source_file": flaw.attrib['sourcefile'],
#                 "line": int(flaw.attrib['line']),
#                 "mitigation_status": flaw.attrib['mitigation_status'],
#                 "mitigation_status_description": flaw.attrib['mitigation_status_desc']

## Checks 
############################################################################################################################
## - creds_expire_days_warning
## - validate_args
## - fuzzy_match
############################################################################################################################

def parse_error_messages(xml_text):
    root = etree.fromstring(xml_text)
    error_messages = []
    for error_element in root.iter('error'):
        error_messages.append(error_element.text)
    return error_messages


def fuzzy_match( compareA, compareB, fuzzyDistance = FuzzyDistance ,pointsOfComparison=FuzzyPointsOfSimilarity, enable_fuzzy=False, advanced=False ):
    # check to see if the CWE ID are the same
    matches={
        'cweid': bool(False),
        'module': bool(False),
        'type': bool(False),
        'function_prototype': bool(False),
        'function_prototype_fuzzy': bool(False),
        'function_prototype_fuzzy_second': bool(False),
        'function_relative_location': bool(False),
        'function_relative_location_fuzzy': bool(False),
        'scope': bool(False),
        'source_file_path': bool(False),
        'source_file': bool(False),
        'line': bool(False),
        'line_fuzzy': bool(False)
    }
    pointsFound = 0
    simFound = 0
    print("Issue ID From: " + str(compareA['issueid']) )
    print("Issue ID To: " + str(compareB['issueid']) )
    print("Matches Found: ")
    # Check CWE ID ##################################################################################
    if compareA['cweid'] == compareB['cweid']:
        pointsFound += 1
        matches['cweid'] = True
        print("- !CWE ID MATCH!!!")
        print(str(compareA['cweid']) + " :: " + str(compareB['cweid']))
    else:
        print("CWE ID Doesn't match")
        print(str(compareA['cweid']) + " :: " + str(compareB['cweid']))
        matches['cweid'] = False
        return False # quick fail if CWE don't match
    # Check Module Match ##################################################################################

    if compareA['module'] == compareB['module']:
        pointsFound +=1
        matches['module'] = True
        print("- Module MATCH!!!")
        print(str(compareA['module']) + " :: " + str(compareB['module']))
    else:
        print("! - Module DOESN'T Match")
        print(str(compareA['module']) + " :: " + str(compareB['module']))
        matches['module'] = False

    # Check Type Match ##################################################################################
    if compareA['type'] == compareB['type']:
        pointsFound += 1
        matches['type'] = True
        print("- Type MATCH!!!")
        print(str(compareA['type']) + " :: " + str(compareB['type']))
    else:
        print("! - Type DOESN'T match")
        print(str(compareA['type']) + " :: " + str(compareB['type']))
        matches['type'] = False
    
    # Check Function Match ##################################################################################
    if compareA['function_prototype'] == compareB['function_prototype']:
        pointsFound += 1
        matches['function_prototype'] = True
        print("- Functions MATCH!!!")
        print(str(compareA['function_prototype']) + " :: " + str(compareB['function_prototype']))
    else:
        print("Function Prototype Doesn't match")
        print(str(compareA['function_prototype']) + " :: " + str(compareB['function_prototype']))
        matches['function_prototype'] = False
        # Check Fuzzy Function Name Match ###################################################################
        if enable_fuzzy: # if fuzzy match found then simFound increases here, if not found simFound is 0 at this point
            # Check Fuzzy Function Name Match 1##############################################################
            if str(compareA['function_prototype']).split('(')[0] ==  str(compareB['function_prototype']).split('(')[0]:
                print("- Fuzzy Match(1)!! Function Prototype Match: Same function, potentially different Parameters")
                print(str(compareA['function_prototype']).split('(')[0]  + " :: " + str(compareB['function_prototype']).split('(')[0])
                pointsFound += 1
                simFound += 1
                matches['function_prototype_fuzzy'] = True

            # Check Fuzzy Function Name Match 2###############################################################
            if str(compareA['function_prototype']).split('(')[0].split(' ')[1] ==  str(compareB['function_prototype']).split('(')[0].split(' ')[1]:
                print("- Fuzzy Match(2)! Function Prototype Match Function Name: Same Function Name, potentially different location, potentially different parameters, these may not be the same, see below to compare, but they have the same function name")
                print(str(compareA['function_prototype']).split('(')[0].split(' ')[1]  + " :: " + str(compareB['function_prototype']).split('(')[0].split(' ')[1])
                simFound += 1 # if both the function prototype name and call both match simFound is increased here ( 1-2 ) otherwise no match is a 0 
                matches['function_prototype_fuzzy_second'] = True
            else:
                print("!! - Failed Fuzzy Match")
    
    # Check Function Relative Location Match ##################################################################################
    if compareA['function_relative_location'] == compareB['function_relative_location']:
        # if the relative location is matched, check what other matches
        print("- Function Relative Location MATCH!!!")
        if enable_fuzzy: # if doing a fuzzy match, then the simFound would be enabled
            if simFound == 2: # if relative function matches and simFound is 2 then that means the previous step had fuzzy matches
                pointsFound += 1
                simFound += 1 # simfound with Fuzzy makes it to 3
                
            elif simFound == 1:
                pointsFound += 1
                simFound += 1 # simFound with Fuzzy makes it to 2 for slant match
            else:
                print("    !Match(1)! Same Relative Location, however they come from potentially different function defintions, [NOTE]: add confidence with the use of the file and line if provided")
                simFound += 1 # SimFound with Fuzzy makes it to 1 if just the Relative Location matches
        matches['function_relative_location'] = True
    else:
        print("Relative Location doesn't match Checking if Fuzzy Enabled")
        matches['function_relative_location'] = False
        if enable_fuzzy: # if doesn't matche but fuzzy is enabled
            if int(compareA['function_relative_location']) != 0:
                    lowerBoundsA = 0
                    upperBoundsA = 0
                    if(int(compareA['function_relative_location']) <= fuzzyDistance ):
                        lowerBoundsA = compareA['function_relative_location']
                        upperBoundsA = compareA['function_relative_location'] + fuzzyDistance
                        if lowerBoundsA <= compareB['function_relative_location'] <= upperBoundsA:
                            print("- Fuzzy Match Found: " + str(lowerBoundsA) + "<=" + str(compareB['function_relative_location']) + "<=" + str(upperBoundsA))
                            simFound += 1 # Makes the simFound
                            matches['function_relative_location_fuzzy'] = True
                    elif (int(compareA['function_relative_location']) >= fuzzyDistance ):
                        lowerBoundsA = (int(compareA['function_relative_location']) - int(fuzzyDistance))
                        upperBoundsA = (int(compareA['function_relative_location']) + int(fuzzyDistance))
                        if lowerBoundsA <= int(compareB['function_relative_location']) <= upperBoundsA:
                            print("- Fuzzy Match Found: " + str(lowerBoundsA) + "<=" + str(compareB['function_relative_location']) + "<=" + str(upperBoundsA))
                            simFound += 1 # simFound
                            matches['function_relative_location_fuzzy'] = True

    # Check Scope Match ##################################################################################
    if compareA['scope'] == compareB['scope']:
        if simFound >= 3:
            pointsFound += 1
        elif simFound == 2:
            pointsFound += 1
            print("Either relative location and function name or function name and location match but the parameters are different, may be an overloaded function")
        elif simFound == 1:
            print("Low confidence Similiarities, likely only the function name or relative location match")
        matches['scope'] = True

    # Check source file path Match ##################################################################################
    if compareA['source_file_path'] == compareB['source_file_path']:
        pointsFound += 1
        matches['source_file_path'] = True
    else:
        matches['source_file_path'] = False
        print("The source file path doesn't match, may not include the full path")
        print(str(compareA['source_file_path']) + " :: " + str(compareB['source_file_path']))

    # Check source file Match ##################################################################################
    if compareA['source_file'] == compareB['source_file']: 
        pointsFound += 1
        matches['source_file'] = True
    else:
        matches['source_file'] = False
        print("The source file doesn't match, may not include the full path")
        print(str(compareA['source_file']) + " :: " + str(compareB['source_file']))
    
    # Check Line Match ##################################################################################
    print("Checking Line Match:")
    print(str(compareA['line']) + " :: " + str(compareB['line']))
    if int(compareA['line']) == int(compareB['line']):
        print("- Line Exact Match Found!!")
        matches['line'] = True
        pointsFound += 1
    else:
        print("! - [Note]:!: The lines may not match, this may be due to debug symbols not being provided or the lines changing")
        print(str(compareA['line']) + " :: " + str(compareB['line']))
        if pointsFound >= pointsOfComparison and simFound >= 2 and enable_fuzzy:
            print("[Check]:: Running Fuzzy Line Match")
            if int(compareA['line']) != 1:
                lowerBoundsA = 0
                upperBoundsA = 0
                if(int(compareA['line']) <= fuzzyDistance ):
                    lowerBoundsA = compareA['line']
                    upperBoundsA = compareA['line'] + fuzzyDistance
                elif (int(compareA['line']) >= fuzzyDistance ):
                    lowerBoundsA = (int(compareA['line']) - int(fuzzyDistance))
                    upperBoundsA = (int(compareA['line']) + int(fuzzyDistance))
                    if lowerBoundsA <= compareB['line'] <= upperBoundsA:
                        print("Fuzzy Match Found: " + str(lowerBoundsA) + "<=" + str(compareB['line']) + "<=" + str(upperBoundsA))
                        pointsFound += 1
                        simFound += 1
            else:
                print("! - [Note]:!: Debug symbols may not have been provided, or the flaw is not related to a file location")
    print(" Points of Similarity: " + str(simFound))
    print(" Points Matching: " + str(pointsFound))
    # Experimental

    if advanced:
        answer = input("Manual Override: Do these match: y or n: ")
        if str(answer).lower == str("y"):
            return True
        else:
            return False
    else:
        if pointsFound >=  pointsOfComparison:
            if enable_fuzzy and (matches['cweid'] and matches['type'] and ( matches['function_prototype'] or matches['function_prototype_fuzzy'] ) and ( matches['function_relative_location'] or matches['function_relative_location_fuzzy'] or matches['line_fuzzy'] or matches['line'])):
                return True
            elif matches['cweid'] and matches['type'] and matches['source_file'] and matches['line']:
                return True
            elif matches['cweid'] and matches['type'] and matches['function_prototype'] and matches['function_relative_location']:
                return True
            else:
                print("[Warning] Passing Matching Number of Points of Comparison, However, the cweid, type, source file, line and relative locations seem to not match, try setting enable_fuzzy to true and try again")
        else:
            print("Not enough matching points found")
            if matches['cweid'] and matches['type'] and matches['source_file'] and matches['line']:
                print("[Warning] Matching criteria found, but points of similarity not met, might want to investigate or adjust the number of points of comparison")
            if matches['cweid'] and matches['type'] and matches['function_prototype'] and matches['function_relative_location']:
                print("[Warning] Matching criteria found for non debug, but points of similarity not met, might want to investigate or adjust the number of points of comparison")
            if matches['cweid'] and matches['type'] and ( matches['function_prototype'] or matches['function_prototype_fuzzy'] ) and ( matches['function_relative_location'] or matches['function_relative_location_fuzzy'] or matches['line_fuzzy']):
                print("While not meeting the points of similarity you have a fuzzy match")

            return False



# ## [Overloaded]
# ## Function Name: creds_expire_days_warning
# ## Precondition:
# ## Postcondition:
# ## Type:
# ## Comments:
# ## Description:
# def creds_expire_days_warning( api_id ):
#     try:
#         creds = MitigationCopier.vapi().get_creds(api_id)
#         exp = MitigationCopier.datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
#         delta = exp - MitigationCopier.datetime.datetime.now().astimezone() #we get a datetime with timezone...
#         if (delta.days < 7):
#             print('These API credentials expire ', creds['expiration_ts'])
#     except:
#         print("[ERROR]:Credentials: There was an error and the API keys were not able to be validated. Make sure your API keys are in the correct location")
        
## Credentials need to be stored in credentials file
## Function Name: 
## Precondition:
## Postcondition:
## Type:
## Comments:
## Description:
def creds_expire_days_warning( api_id = None):
    try:
        creds = MitigationCopier.vapi().get_creds(api_id)
        exp = MitigationCopier.datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
        delta = exp - MitigationCopier.datetime.datetime.now().astimezone() #we get a datetime with timezone...
        if (delta.days < 7):
            print('These API credentials expire ', creds['expiration_ts'])
    except:
        print("[ERROR]:Credentials: There was an error and the API keys were not able to be validated. Make sure your API keys are in the correct location")
    


## Function Name: 
## Precondition:
## Postcondition:
## Type:
## Comments:
## Description:
def validate_args(args):
    if (args.vkey and args.vid):
        #creds_expire_days_warning(args.vid)
        return True
    if not ( args.readfromcsv and args.csv ) and not (args.frombuild and args.tobuild):
        parser.error("Either --frombuild and --tobuild or --csv and --readfromcsv set to true must be provided")
    if not ( args.vkey and args.vid):
        print("API Credentials not provided inline [https://docs.veracode.com/r/t_create_api_creds] \nChecking for credentials in enviornment [https://docs.veracode.com/r/c_configure_api_cred_file]")
        MitigationCopier.creds_expire_days_warning()
        return True

## Functions to Import Results 
############################################################################################################################

## Function Name: 
## Precondition:
## Postcondition:
## Type:
## Comments:
## Description:
def results_api(build_id, api_user = None, api_password = None):

    veracode_api = api.VeracodeAPI()
    
    r = veracode_api.get_detailed_report(build_id)

    if '<error>' in r.decode("utf-8"):
        if DEBUG: print(r)
        error_info = parse_error_messages(r)
        logging.info('Error downloading results for Build ID ' + str(build_id))
        logging.info('Error Info: ' + str(error_info))
        #MitigationCopier.logprint('Error downloading results for Build ID ' + str(build_id))
        #MitigationCopier.logprint('Error Info: ' + str(error_info))

        print("Error Info: " + str(error_info))
        sys.exit('[*] Error downloading results for Build ID ' + str(build_id))

    logging.info('Downloaded results for Build ID ' + str(build_id))
    #MitigationCopier.logprint('Downloaded results for Build ID ' + str(build_id))
    print ('[*] Downloaded results for Build ID ' + str(build_id))
    return r

## Function Name: 
## Precondition:
## Postcondition:
## Type:
## Comments:
## Description:
def results_api_proxy(build_id, api_user, api_password, account_id):

    veracode_api = api.VeracodeAPI()
    
    r = veracode_api.get_detailed_report_proxy(build_id, account_id)

    if '<error>' in r.decode("utf-8"):
        if DEBUG: print(r)
        logging.info('Error downloading results for Build ID ' + str(build_id))
        #MitigationCopier.logprint('[*] Error downloading results for Build ID ' + str(build_id))
        sys.exit('[*] Error downloading results for Build ID ' + str(build_id))
        
    logging.info('Downloaded results for Build ID ' + str(build_id))
    #MitigationCopier.logprint('Downloaded results for Build ID ' + str(build_id))
    print ('[*] Downloaded results for Build ID ' + str(build_id))
    return r

# def results_api_import(detailed_report):

#     f = open(detailed_report, 'rb+')
#     r = f.read()
#     if DEBUG:
#         print(r)
#     f.close()
#     return r


## Function Name: 
## Precondition:
## Postcondition:
## Type:
## Comments:
## Description:
def importDetailedReport(path_to_detailed_report):
    try:
        with open(path_to_detailed_report, 'rb') as file:
        # Read the entire content of the file as binary data
            r = file.read()
    
        
    except FileExistsError or FileNotFoundError:
        MitigationCopier.logprint("[Error]: file not found ")
    else:
        return r

## Functions to Export Results 
#############################################################################################################################
## - update_mitigation_info                                                                                                 #
## - update_mitigation_info_proxy                                                                                           #
## - export_detailed_xml                                                                                                    #
## - export_detailed_report                                                                                                 #
#############################################################################################################################

## Function Name: 
## Precondition:
## Postcondition:
## Type:
## Comments:
## Description:
def update_mitigation_info(build_id, flaw_id_list, action, comment, results_from_app_id, api_user, api_password):

    veracode_api = api.VeracodeAPI()
    if not dryrun:
        r = veracode_api.set_mitigation_info(build_id,flaw_id_list,action,comment,results_from_app_id)
        if '<error>' in r.decode("UTF-8"):
            logging.info('Error updating mitigation_info for ' + str(flaw_id_list) + ' in Build ID ' + str(build_id))
            #MitigationCopier.logprint('Error updating mitigation_info for ' + str(flaw_id_list) + ' in Build ID ' + str(build_id))
            print('Error updating mitigation_info for ' + str(flaw_id_list) + ' in Build ID ' + str(build_id))
            sys.exit('[*] Error updating mitigation_info for ' + str(flaw_id_list) + ' in Build ID ' + str(build_id))
    logging.info(
        'Updated mitigation information to ' + str(action) + ' for Flaw ID ' + str(flaw_id_list) + ' in ' +
        str(results_from_app_id) + ' in Build ID ' + str(build_id))
    MitigationCopier.logprint('Updated mitigation information to ' + str(action) + ' for Flaw ID ' + str(flaw_id_list) + ' in ' + str(results_from_app_id) + ' in Build ID ' + str(build_id))
    if DEBUG:
        print(
        'Updated mitigation information to ' + str(action) + ' for Flaw ID ' + str(flaw_id_list) + ' in ' +
        str(results_from_app_id) + ' in Build ID ' + str(build_id))

## Function Name: 
## Precondition:
## Postcondition:
## Type:
## Comments:
## Description:       
def update_mitigation_info_proxy(build_id, flaw_id_list, action, comment, results_from_app_id, api_user, api_password, account_id):

    veracode_api = api.VeracodeAPI()

    if not dryrun:
        r = veracode_api.set_mitigation_info_proxy(build_id,flaw_id_list,action,comment,results_from_app_id, account_id)
        if '<error>' in r.decode("UTF-8"):
            logging.info('Error updating mitigation_info for ' + str(flaw_id_list) + ' in Build ID ' + str(build_id))
            #MitigationCopier.logprint('Error updating mitigation_info for ' + str(flaw_id_list) + ' in Build ID ' + str(build_id))

            sys.exit('[*] Error updating mitigation_info for ' + str(flaw_id_list) + ' in Build ID ' + str(build_id))
    logging.info('Updated mitigation information to ' + str(action) + ' for Flaw ID ' + str(flaw_id_list) + ' in ' + str(results_from_app_id) + ' in Build ID ' + str(build_id))
    #MitigationCopier.logprint('Updated mitigation information to ' + str(action) + ' for Flaw ID ' + str(flaw_id_list) + ' in ' + str(results_from_app_id) + ' in Build ID ' + str(build_id))

    if DEBUG:
        print(
        'Updated mitigation information to ' + str(action) + ' for Flaw ID ' + str(flaw_id_list) + ' in ' +
        str(results_from_app_id) + ' in Build ID ' + str(build_id))




## Driver Functions
############################################################################################################################
## - manual_import                                                                                                         #
## - interactive                                                                                                           #
## - main                                                                                                                  #
############################################################################################################################

## Function Name: 
## Precondition:
## Postcondition:
## Type:
## Comments:
## Description:
def manual_import(vid, vkey, pfromDetailedXMLReport, tobuild=None, frombuild=None, ptoDetailedXMLReport=None,  accountid = None, output_unmatched = bool()): #, accountid = None, frombuild = None, tobuild = None):
    INITIALIZATION_ON=True
    IMPORT_STEP_ON=True
    STEP_ONE_ON=True
    STEP_TWO_ON=True
    STEP_THREE_ON=True
    PAUSE_ON=False


    if INITIALIZATION_ON and DEBUG:
        MitigationCopier.setup_logger()
        MitigationCopier.logprint('======== beginning MitigationCopier.py run ========')

    ## Local Variables DO NOT CHANGE THESE
    ################################################
    ##
        
    IMPORT_TO_MODE=False
    proxy_mode=False
    if accountid is not None:
        proxy_mode=True
    fromDetailedXMLReport = pfromDetailedXMLReport
    toDetailedXMLReport = ptoDetailedXMLReport
    
    #print("Testing out importDetailedReport")
    #print(importDetailedReport("DetailedXMLReport001.xml"))
    
    ###########################################################################################################################
    ## Importing Detailed XML for FromBuild
    ############################################################################################################################
    print("-" * 100)
    print("Importing Detailed XML Report for From Build")
    print("-" * 100)

    if IMPORT_STEP_ON:
        # importing the detailed xml report into the results from object
        results_from = importDetailedReport(fromDetailedXMLReport)
    
    print("-" * 100)
    print("Processing Results")
    print("-" * 100)

    results_from_root = etree.fromstring(results_from)                                                                          # Processing the results_from object through the etree class to be able to parse the xml attributes
    results_from_static_flaws = results_from_root.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')              # Populating the results_from_static_flaws with all elements that have cwe, severity, category, staticflaws, flaws populated
    
    # Initializes the from arrays
    results_from_flawid = [None] * len(results_from_static_flaws)                                                               
    results_from_unique = [None] * len(results_from_static_flaws)
    results_from_unique_four = [None] * len(results_from_static_flaws)
    results_from_unique_five = [None] * len(results_from_static_flaws)
    results_from_unique_six = [None] * len(results_from_static_flaws)
    results_from_unique_seven = [None] * len(results_from_static_flaws)
    results_from_unique_eight = [None] * len(results_from_static_flaws)
    results_from_unique_no_match = []
    results_from_app_id = 'App ID ' + results_from_root.attrib['app_id'] + ' (' + results_from_root.attrib[
        'app_name'] + ')'

    
    ###########################################################################################################################
    ## Importing Detailed XML for ToBuild
    ############################################################################################################################
    print("-" * 100)
    print("Importing Detailed XML Report for To Build")
    print("-" * 100)

    if IMPORT_TO_MODE:
        results_to = importDetailedReport(toDetailedXMLReport)
    if tobuild is not None:
        if proxy_mode:
            results_to = results_api_proxy(tobuild, vid, vkey, accountid)
        else:
            results_to = results_api(tobuild, vid, vkey)
    else:
        print("[ERROR]:: toBuild is None and import mode is off. One must be provided")
    
    print("-" * 100)
    print("Processing Results")
    print("-" * 100)

    # intialized the to arrays
    results_to_root = etree.fromstring(results_to)
    results_to_static_flaws = results_to_root.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')
    # initialized the arrays
    results_to_flawid = [None] * len(results_to_static_flaws)
    results_to_unique = [None] * len(results_to_static_flaws)
    results_to_unique_four = [None] * len(results_to_static_flaws)
    results_to_unique_five = [None] * len(results_to_static_flaws)
    results_to_unique_six = [None] * len(results_to_static_flaws)
    results_to_unique_seven = [None] * len(results_to_static_flaws)
    results_to_unique_eight = [None] * len(results_to_static_flaws)
    results_to_unique_no_match = []
    results_to_app_id = 'App ID ' + results_to_root.attrib['app_id'] + '(' + results_to_root.attrib['app_name'] + ')'
      
    if len(results_to_static_flaws) >= len(results_from_static_flaws):
        from_id_to_id = [None] * len(results_to_static_flaws)
    else:
        from_id_to_id = [None] * len(results_from_static_flaws)
        
    print("-" * 100)
    print("Itterating through the From Build Mitigations")
    print("-" * 100)
    if DEBUG:
        print("Itterating through results from static flaws:")

    ###########################################################################################################################
    ## Itterating over every flaw in results from static flaws
    ############################################################################################################################

    # GET DATA FOR BUILD COPYING FROM
    i=0
    proposediteration=0
    approvediteration=0
    matchCounter=0
    # for every flaw in the results from static flaws
    for flaw in results_from_static_flaws:
        # check to see if at the last value 
        if len(results_from_flawid) <= i: # exit condition
            break
        
        
        results_from_flawid[i] = flaw.attrib['issueid']
        results_from_unique_four[i]=flaw.attrib['cweid'] + str(":") + flaw.attrib['type'] + str(":") + flaw.attrib['functionprototype'] + str(":") + flaw.attrib['functionrelativelocation'] + str("%")   
        results_from_unique_five[i]=flaw.attrib['cweid'] + str(":") + flaw.attrib['type'] + str(":") + flaw.attrib['scope'] + str(":") + flaw.attrib['functionprototype'] + flaw.attrib['functionrelativelocation']  + str("%")
        results_from_unique_six[i]=flaw.attrib['cweid'] + str(":") + flaw.attrib['type'] + str(":") + flaw.attrib['scope'] + str(":") + flaw.attrib['functionprototype'] + flaw.attrib['functionrelativelocation']  + str("%:") +  flaw.attrib['sourcefilepath'] 
        results_from_unique_seven[i]=flaw.attrib['cweid'] + str(":") + flaw.attrib['type'] + str(":") + flaw.attrib['scope'] + str(":") + flaw.attrib['functionprototype'] + flaw.attrib['functionrelativelocation']  + str("%:") +  flaw.attrib['sourcefilepath'] + str(":") + flaw.attrib['sourcefile']  
        results_from_unique_eight[i]=flaw.attrib['cweid'] + str(":") + flaw.attrib['type'] + str(":") + flaw.attrib['scope'] + str(":") + flaw.attrib['functionprototype'] + flaw.attrib['functionrelativelocation']  + str("%:") + flaw.attrib['sourcefilepath'] + str(":") + flaw.attrib['sourcefile'] + str(":") + flaw.attrib['line']  
        results_from_unique[i] = {
            "issueid": flaw.attrib['issueid'],
            "cweid": flaw.attrib['cweid'],
            "module":flaw.attrib['module'],
            "type": flaw.attrib['type'],
            "scope": flaw.attrib['scope'],
            "function_prototype": flaw.attrib['functionprototype'],
            "function_relative_location": flaw.attrib['functionrelativelocation'],
            "source_file_path": flaw.attrib['sourcefilepath'],
            "source_file": flaw.attrib['sourcefile'],
            "line": flaw.attrib['line'],
            "mitigation_status": flaw.attrib['mitigation_status'],
            "mitigation_status_description": flaw.attrib['mitigation_status_desc'],
            "mitigations": [],
            "annotations": []
        }  

        
        
        # otherwise grab the value from the results_from_flawid and assign it the issueid
        # do the same for results_from_unique and give it the cwe id type and source file and line
        # grab all the mitigations
        mitigation_from_static_flaw = flaw.findall('./{*}mitigations/{*}mitigation')
        annotation_from_static_flaw = flaw.findall('./{*}annotations/{*}annotation')

        ##########################################################################################################################
        if DEBUG:
            print("\nFlaw " + str(flaw.attrib['issueid'])+ " =================================================================")
            print("Number of Mitigations Found: " + str(len(mitigation_from_static_flaw)))
            print("Number of Comments Found: " + str(len(annotation_from_static_flaw)) )
            print("CWE " + str(flaw.attrib['cweid']))
            print("  Date of First Occurance: " + str(flaw.attrib['date_first_occurrence']))
            print("  Category: " + str(flaw.attrib['categoryname']))
            print("  Description: " + str(flaw.attrib['description']))
            print("  Severity: " + str(flaw.attrib['severity']))
            print("  Exploit Level: " + str(flaw.attrib['exploitLevel']))
            print("  Function: " + str(flaw.attrib['functionprototype']))
            print("  Relative Location: " + str(flaw.attrib['functionrelativelocation']) + "%")
            print("  Line: " + str(flaw.attrib['line']))
            print("  Module: " + str(flaw.attrib['module']))
            print("  Scope: " + str(flaw.attrib['scope']))
            print("  Source File: " + str(flaw.attrib['sourcefile']))
            print("  Source File Path: " + str(flaw.attrib['sourcefilepath']))
            print("  Type: " + str(flaw.attrib['type']))
            print("  Remediation Status: " + str(flaw.attrib['remediation_status']))
            print("  Remediation Effort: " + str(flaw.attrib['remediationeffort']))
            print("  Mitigation Status: " + str(flaw.attrib['mitigation_status']))
            print("  Issue ID: " + str(flaw.attrib['issueid']))
            print("  ---")
            print("  Mitigations Found: ")

            for mitigation in mitigation_from_static_flaw:
                results_from_unique[i]['mitigations'].append({
                    'mitigation_action': str(mitigation.attrib['action']),
                    'mitigation_date': str(mitigation.attrib['date']),
                    'mitigation_description': str(mitigation.attrib['description']),
                    'mitigation_user': str(mitigation.attrib['user'])
                    })
                print("    ------------------------------------------------------")
                print("    Mitigation Action: " + str(mitigation.attrib['action']))
                print("    Mitigation Date: " + str(mitigation.attrib['date']))
                print("    Mitigation Proposed By: " + str(mitigation.attrib['user']))
                print("    Mitigation Description: " + str(mitigation.attrib['description']))
            
            if len(mitigation_from_static_flaw) == 0:
                print("    None")
            print("  Annotations Found: ")
            for annotation in annotation_from_static_flaw:
                results_from_unique[i]['annotations'].append({
                    'annotation_action': str(mitigation.attrib['action']),
                    'annotation_date': str(mitigation.attrib['date']),
                    'annotation_description': str(mitigation.attrib['description']),
                    'annotation_user': str(mitigation.attrib['user'])
                    })
                print("    ------------------------------------------------------")
                print("    Annotation Action: " + str(annotation.attrib['action']))
                print("    Annotation Date: " + str(annotation.attrib['date']))
                print("    Annotation Proposed By: " + str(annotation.attrib['user']))
                print("    Annotation Description: " + str(annotation.attrib['description']))
            if len(annotation_from_static_flaw) == 0:
                print("    None")
        # # check if the flaw arrtibute mitigation status is either accepted or proposed
        if flaw.attrib['mitigation_status'] == 'accepted' or flaw.attrib['mitigation_status'] =='proposed':
            if flaw.attrib['mitigation_status'] == 'accepted':
                approvediteration +=1
            if flaw.attrib['mitigation_status'] == 'proposed':
                proposediteration +=1
            if DEBUG:
                print("[DEBUG]:: Approved Found: " + str(approvediteration) + " Proposed Found: " + str(proposediteration))        
        else:
            print("Mitigation Status: " + str(flaw.attrib['mitigation_status']) + " - Mitigation Description: " + str(flaw.attrib['mitigation_status_desc']))
          
        if DEBUG:
            print("Issue Id: " + str(results_from_flawid[i]) + " : CWE: " + str(flaw.attrib['cweid']) + " |  Type: " + str(flaw.attrib['type']) + " | Source File: " + str(flaw.attrib['sourcefile']) + " | Line: " + str(flaw.attrib['line']))
            print(flaw.attrib['cweid'] + str(":") + flaw.attrib['module'] + str(":") + flaw.attrib['type'] + str(":") + flaw.attrib['scope'] + str(":") + flaw.attrib['functionprototype'] + str(":") + flaw.attrib['functionrelativelocation']  + str(":") + flaw.attrib['sourcefilepath'] + str(":") + flaw.attrib['sourcefile'] + str(":") + flaw.attrib['line'] )
            print("Mitigation Description: " + str(flaw.attrib['mitigation_status_desc']))
            print("[DEBUG]:: Results_From_Flawid:#" + str(len(results_from_flawid)))
            print("[DEBUG]:: Results_From_Unique:#" + str(len(results_from_unique)))
            # if it is then itterate the build itteration
        
        i +=1
        if MANUAL_REVIEW or PAUSE_ON:
            input("Press enter to continue")

    print("-" * 100)
    print("Itterating through the To Build Mitigations")
    print("-" * 100)
    if DEBUG:
        print("Itterating through results to static flaws:")
    
    ###########################################################################################################################
    ## Itterating over every flaw in results to static flaws
    ############################################################################################################################
    
    # CREATE LIST OF UNIQUE VALUES FOR BUILD COPYING TO
    j=0 # set to 0 since added exit condition instead of the previous method that had it set at -1
    proposediteration=0
    approvediteration=0
    matchiteration=0
    for flaw in results_to_static_flaws: # for every falw in results to static flaws
        match_found = False # reset to false each time
        if len(results_from_flawid) <= j: # exit condition
                break

        if flaw.attrib['mitigation_status'] == 'accepted':
            approvediteration +=1
        if flaw.attrib['mitigation_status'] == 'proposed':
            proposediteration +=1
        if DEBUG:
            print("[DEBUG]:: Approved Found: " + str(approvediteration) + " Proposed Found: " + str(proposediteration))
   
        results_to_unique_four[j]=flaw.attrib['cweid'] + str(":") + flaw.attrib['type'] +str(":") + flaw.attrib['functionprototype'] + str(":") + flaw.attrib['functionrelativelocation']  + str("%")
        results_to_unique_five[j]=flaw.attrib['cweid'] + str(":") + flaw.attrib['type'] +str(":") + flaw.attrib['scope'] + str(":") + flaw.attrib['functionprototype'] + str(":") + flaw.attrib['functionrelativelocation'] + str("%") 
        results_to_unique_six[j]=flaw.attrib['cweid'] + str(":") + flaw.attrib['type'] + str(":") + flaw.attrib['scope'] + str(":") + flaw.attrib['functionprototype'] +  str(":") + flaw.attrib['functionrelativelocation']  +  str("%:") + flaw.attrib['sourcefilepath'] 
        results_to_unique_seven[j]=flaw.attrib['cweid'] + str(":") + flaw.attrib['type'] + str(":") + flaw.attrib['scope'] + str(":") + flaw.attrib['functionprototype'] + str(":") + flaw.attrib['functionrelativelocation']  +  str("%:") + flaw.attrib['sourcefilepath'] + str(":") + flaw.attrib['sourcefile']  
        results_to_unique_eight[j]=flaw.attrib['cweid'] + str(":") +flaw.attrib['type'] + str(":") + flaw.attrib['scope'] + str(":") + flaw.attrib['functionprototype'] + str(":") + flaw.attrib['functionrelativelocation']  +  str("%:") + flaw.attrib['sourcefilepath'] + str(":") + flaw.attrib['sourcefile'] + str(":") + flaw.attrib['line']  
        results_to_unique[j] = {
                "issueid": flaw.attrib['issueid'],
                "cweid": flaw.attrib['cweid'],
                "module":flaw.attrib['module'],
                "type": flaw.attrib['type'],
                "scope": flaw.attrib['scope'],
                "function_prototype": flaw.attrib['functionprototype'],
                "function_relative_location": flaw.attrib['functionrelativelocation'],
                "source_file_path": flaw.attrib['sourcefilepath'],
                "source_file": flaw.attrib['sourcefile'],
                "line": int(flaw.attrib['line']),
                "mitigation_status": flaw.attrib['mitigation_status'],
                "mitigation_status_description": flaw.attrib['mitigation_status_desc']
            }  
        try:
            print("Running Matching Algorithm") 
            print("Checking for exact match")
            if results_to_unique_four[j] in results_from_unique_four:
                print("Exact Match Found With Four Points")
                print(results_from_unique[results_from_unique_four.index(results_to_unique_four[j])])
                match_found = True
                if flaw.attrib['mitigation_status'] == 'accepted' or flaw.attrib['mitigation_status'] == 'proposed':
                    matchiteration += 1
                from_id_to_id[matchiteration] = str(results_from_unique[results_from_unique_four.index(results_to_unique_four[j])]['issueid']) + "==>" + str(results_to_unique[j]['issueid'])
            print("Checking fuzzy match")
            if fuzzy_match(results_from_unique[j], results_to_unique[j], enable_fuzzy=FuzzyMatch):
                
                print("Fuzzy Match Found")
                print("Results from unique: " + results_from_unique[j]['issueid'])
                print("Results to unqiue: " + results_to_unique[j]['issueid'])
                if not match_found: # if match_found wasn't already found in the previous step
                    if flaw.attrib['mitigation_status'] == 'accepted' or flaw.attrib['mitigation_status'] == 'proposed':
                        matchiteration += 1
                    from_id_to_id[matchiteration] = str(results_from_unique[j]['issueid']) + "==>" + str(results_to_unique[j]['issueid'])

                match_found = True
            if EXHAUSTIVE_FUZZY:
                for m in range(0, len(results_from_unique)):
                    if fuzzy_match(results_from_unique[m], results_to_unique[j], enable_fuzzy=FuzzyMatch):
                        print("Fuzzy Match Found")
                        print("Results from unique: " + results_from_unique[m])
                        print("Results to unqiue: " + results_to_unique[j])
                        if not match_found:
                            if flaw.attrib['mitigation_status'] == 'accepted' or flaw.attrib['mitigation_status'] == 'proposed':
                                matchiteration += 1
                            from_id_to_id[matchiteration] = str(results_from_unique[m]['issueid']) + "==>" + str(results_to_unique[j]['issueid'])

                        match_found = True
                        #from_id_to_id[matchiteration] = str(results_from_unique[m]) + "==>" + str(results_to_unique[j])
        except ValueError:
            print("Value Error")
            j+=1
            continue
        else:

            if DEBUG:
                print("Issue Id:" + str(results_to_flawid[j]) + " : CWE: " + str(flaw.attrib['cweid']) + " |  Type:" + str(flaw.attrib['type']) + " | Source File: " + str(flaw.attrib['sourcefile']) + " | Line:" + str(flaw.attrib['line']))
                print("Mitigation Comment:" + str(flaw.attrib['mitigation_status_desc']))
                print("[DEBUG]:: Results_From_Flawid:#" + str(len(results_from_flawid)))
                print("[DEBUG]:: Results_From_Unique:" + str(len(results_from_unique)))
        j+=1  # increment the itteration
        if MANUAL_REVIEW or PAUSE_ON:
            input("Press enter to continue")
    # CREATE COUNTER VARIABLE
    print("[DEBUG]:: Approved Found: " + str(approvediteration) + " Proposed Found: " + str(proposediteration))
    print("Match Counter: " + str(matchiteration))
    counter = 0

    if DEBUG:
        print("Printing out already found matches")
        print("From =====> to")
        for match in from_id_to_id:
            if match is not None:
                print( match)
    
    print("-" * 100)
    print("Cycling through results")
    print("-" * 100)

    # Itterate over to unique
    # [DEFAULT]
    #########################################################################################
    if itterateToFrom is True:
            
        # CYCLE THROUGH RESULTS_TO_UNIQUE
        for k in range(0, len(results_to_unique)):
            fuzzyMatchRun=False
            # CHECK IF IT'S IN RESULTS FROM
            to_id = None
            from_id = None 

            print("[DEBUG] Results from unique length: "  + str(len(results_from_unique)))
            print("[DEBUG] Results to unique length: " + str(len(results_from_unique)))
            if k < len(results_from_unique): # if k is less the length of the values of results_from_unique
                # run the comparisons as itterating over
                fuzzyMatchRun = True
                print("Searching for match")
                if fuzzy_match(results_from_unique[k], results_to_unique[k], enable_fuzzy=FuzzyMatch): # checks fuzzy match
                    from_id_to_id.append(str(results_from_unique['issueid']) + "==>" + str(results_to_unique['issueid']))
                    to_id = results_to_unique[k]['issueid']
                    from_id = results_from_unique[k]['issueid']
                    if results_from_unique[k]['mitigation_status'] == 'accepted' or results_from_unique[k]['mitigation_status'] == 'proposed':
                        counter+=1
                        if from_id is not None:
                            mitigation_list = results_from_root.findall('.//{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + from_id + '"]/{*}mitigations/{*}mitigation')
                            print(str(from_id))
                            if to_id is not None:
                                flaw_copy_to_list = results_to_root.findall('.//{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + to_id + '"]')
                                for flaw_copy_to in flaw_copy_to_list: # For every flaw in the flaw copy to list check  
                                # CHECK IF COPY TO IS ALREADY ACCEPTED OR PROPOSED
                                    if flaw_copy_to.attrib['mitigation_status'] != 'accepted' or flaw_copy_to.attrib['mitigation_status'] != 'proposed':
                                        # get all mitigations for that from_id to copy over
                                        if DEBUG:
                                            print("Flaw Copy To: "+ flaw_copy_to.attrib['mitigation_status'])
                                            if flaw_copy_to.attrib['mitigation_status'] == 'accepted' or flaw_copy_to.attrib['mitigation_status'] == 'proposed':
                                                print("[DEBUG] Both are true") 
                                        
                                        mitigation_list = results_from_root.findall('.//{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + from_id + '"]/{*}mitigations/{*}mitigation')

                                        
                                        for mitigation_action in mitigation_list:
                                            proposal_action = mitigation_action.attrib['action']
                                            proposal_comment = '[MI: COPIED FROM BUILD ' + str(frombuild) + ' of ' + \
                                                            str(results_from_app_id) + ' on ' + str(MitigationCopier.datetime.datetime.utcnow()) + '] ' + mitigation_action.attrib['description']
                                            if DEBUG: 
                                                print("Adding Mitigation: " + '[MI: COPIED FROM BUILD ' + str(frombuild) + ' of ' + \
                                                            str(results_from_app_id) + ' on ' + str(MitigationCopier.datetime.datetime.utcnow()) + '] ' + mitigation_action.attrib['description'])
                                            
                                            if dryrun is True:
                                                if proxy_mode:
                                                    #pass
                                                    update_mitigation_info_proxy(tobuild, to_id, proposal_action, proposal_comment, results_from_app_id, vid, vkey, accountid)
                                                else:
                                                    #pass
                                                    update_mitigation_info(tobuild, to_id, proposal_action, proposal_comment, results_from_app_id, vid, vkey)
                                    else:
                                        logging.info('Flaw ID ' + str(to_id) + ' in ' + results_to_app_id + ' Build ID ' +
                                                    tobuild + ' already has an accepted mitigation; skipped.')
                                        #MitigationCopier.logprint('Flaw ID ' + str(to_id) + ' in ' + str(results_to_app_id) + ' Build ID ' + str(tobuild) + ' already has an accepted mitigation; skipped.')
                                        if DEBUG: 
                                            print('Flaw ID ' + str(to_id) + ' in ' + results_to_app_id + ' Build ID ' +
                                                    tobuild + ' already has an accepted mitigation; skipped.')
                                    if flaw_copy_to.attrib['mitigation_status'] == 'accepted' or flaw_copy_to.attrib['mitigation_status'] == 'proposed':
                                        counter += 1
                else:
                    print("Not a match")
                    print("Added to unmatched list")
                    results_from_unique_no_match.append(results_from_unique[k])
                    results_to_unique_no_match.append(results_to_unique[k])

                # secondary check
                if results_to_unique_four[k] in results_from_unique_four: # checks to see if the basic elements are an exact match
                    if DEBUG:
                        print("[DEBUG]:: resutls_to_unique FOUND in results_from_unique")

                    try:  # potentially rework this   
                        # FIND THE FLAW IDS FOR FROM AND TO
                        if FuzzyPointsOfSimilarity == 5:
                            from_id = results_from_flawid[results_from_unique_five.index(results_to_unique_five[k])]
                            to_id = results_to_flawid[results_to_unique_five.index(results_to_unique_five[k])]
                        elif FuzzyPointsOfSimilarity == 6:
                            from_id = results_from_flawid[results_from_unique_six.index(results_to_unique_six[k])]
                            to_id = results_to_flawid[results_to_unique_six.index(results_to_unique_six[k])]
                        elif FuzzyPointsOfSimilarity == 7:
                            from_id = results_from_flawid[results_from_unique_seven.index(results_to_unique_seven[k])]
                            to_id = results_to_flawid[results_to_unique_seven.index(results_to_unique_seven[k])]
                        elif FuzzyPointsOfSimilarity == 8:
                            from_id = results_from_flawid[results_from_unique_eight.index(results_to_unique_eight[k])]
                            to_id = results_to_flawid[results_to_unique_eight.index(results_to_unique_eight[k])]
                        # elif FuzzyPointsOfSimilarity == 9:
                        #     from_id = results_from_flawid[results_from_unique.index(results_to_unique[k])]
                        #     to_id = results_to_flawid[results_to_unique.index(results_to_unique[k])]
                        elif FuzzyPointsOfSimilarity == 4:
                            from_id = results_from_flawid[results_from_unique_four.index(results_to_unique_four[k])]
                            to_id = results_to_flawid[results_to_unique_four.index(results_to_unique_four[k])]
                        else:
                            from_id = results_from_flawid[results_from_unique_four.index(results_to_unique_four[k])]
                            to_id = results_to_flawid[results_to_unique_four.index(results_to_unique_four[k])]

                                        
                        if from_id is not None and to_id is None:
                            print("From ID is not None but To ID is")
                            mitigation_list = results_from_root.findall('.//{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + from_id + '"]/{*}mitigations/{*}mitigation')
                            print(str(from_id))
                        
                        if to_id is not None:
                            flaw_copy_to_list = results_to_root.findall('.//{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + to_id + '"]')
                            for flaw_copy_to in flaw_copy_to_list: # For every flaw in the flaw copy to list check  
                                # CHECK IF COPY TO IS ALREADY ACCEPTED OR PROPOSED
                                if flaw_copy_to.attrib['mitigation_status'] != 'accepted' or flaw_copy_to.attrib['mitigation_status'] != 'proposed':
                                    # get all mitigations for that from_id to copy over
                                    if DEBUG:
                                        print("Flaw Copy To: "+ flaw_copy_to.attrib['mitigation_status'])
                                        if flaw_copy_to.attrib['mitigation_status'] == 'accepted' or flaw_copy_to.attrib['mitigation_status'] == 'proposed':
                                            print("[DEBUG] Both are true") 
                                    
                                    mitigation_list = results_from_root.findall('.//{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + from_id + '"]/{*}mitigations/{*}mitigation')

                                    
                                    for mitigation_action in mitigation_list:
                                        proposal_action = mitigation_action.attrib['action']
                                        proposal_comment = '[MI: COPIED FROM BUILD ' + str(frombuild) + ' of ' + \
                                                        str(results_from_app_id) + ' on ' + str(MitigationCopier.datetime.datetime.utcnow()) + '] ' + mitigation_action.attrib['description']
                                        if DEBUG: 
                                            print("Adding Mitigation: " + '[MI: COPIED FROM BUILD ' + str(frombuild) + ' of ' + \
                                                        str(results_from_app_id) + ' on ' + str(MitigationCopier.datetime.datetime.utcnow()) + '] ' + mitigation_action.attrib['description'])
                                        
                                        if dryrun is True:
                                            if proxy_mode:
                                                #pass
                                                update_mitigation_info_proxy(tobuild, to_id, proposal_action, proposal_comment, results_from_app_id, vid, vkey, accountid)
                                            else:
                                                #pass
                                                update_mitigation_info(tobuild, to_id, proposal_action, proposal_comment, results_from_app_id, vid, vkey)
                                else:
                                    logging.info('Flaw ID ' + str(to_id) + ' in ' + results_to_app_id + ' Build ID ' +
                                                tobuild + ' already has an accepted mitigation; skipped.')
                                    #MitigationCopier.logprint('Flaw ID ' + str(to_id) + ' in ' + str(results_to_app_id) + ' Build ID ' + str(tobuild) + ' already has an accepted mitigation; skipped.')
                                    if DEBUG: 
                                        print('Flaw ID ' + str(to_id) + ' in ' + results_to_app_id + ' Build ID ' +
                                                tobuild + ' already has an accepted mitigation; skipped.')
                                if flaw_copy_to.attrib['mitigation_status'] == 'accepted' or flaw_copy_to.attrib['mitigation_status'] == 'proposed':
                                    counter += 1
                        if VERBOSE:
                            print("Check to see that From_id and To_id are both set")
                            print("From_id:" + str(from_id))
                            print("To_id:" + str(to_id))       
                            print("Fuzzy Match Run: " + fuzzyMatchRun )    
                    except ValueError:
                        if DEBUG and VERBOSE:
                            if FuzzyPointsOfSimilarity == 5:
                                print(" Results to Unique match not found:  " + str(results_to_unique_five[k]))
                            elif FuzzyPointsOfSimilarity == 6:
                                print(" Results to Unique match not found:  " + str(results_to_unique_six[k]))
                            elif FuzzyPointsOfSimilarity == 7:
                                print(" Results to Unique match not found:  " + str(results_to_unique_seven[k]))
                            elif FuzzyPointsOfSimilarity == 8:
                                print(" Results to Unique match not found:  " + str(results_to_unique_eight[k]))
                            elif FuzzyPointsOfSimilarity == 9:
                                print(" Results to Unique match not found:  " + str(results_to_unique[k]))
                            elif FuzzyPointsOfSimilarity == 4:
                                print(" Results to Unique match not found:  " + str(results_to_unique_four[k]))
                            else:
                                print("Results to Unique match not found:"  + str(results_to_unique_four[k]))
                        else:
                            print("Value Error:: Fuzzy Points of Similarity: " + str(FuzzyPointsOfSimilarity))
                    else:
                        pass
                # CHECK IF IT'S ALREADY MITIGATED IN TO
            else:
                if DEBUG:
                    print("Results_to_unique[k] is not found in results_from_unique ==> " + results_to_unique_eight[k] )

            if MANUAL_REVIEW or PAUSE_ON:
                input("Press enter to continue")

    # Itterate over from Unique 
    #########################################################################
    elif itterateToFrom is False:    
        for l in range(0, len(results_from_unique)):
                fuzzyMatchRun = False
                to_id = None
                from_id = None 
                if l < len (results_to_unique):
                    fuzzyMatchRun = True
                    if fuzzy_match(results_from_unique[l], results_to_unique[l], enable_fuzzy=FuzzyMatch):
                        from_id_to_id.append(str(results_from_unique[l]['issueid']) + "==>" + str(results_to_unique[l]['issueid']))
                        to_id = results_to_unique[l]['issueid']
                        from_id = results_from_unique[l]['issueid']
                        if results_from_unique[l]['mitigation_status'] == 'accepted' or results_from_unique[l]['mitigation_status'] == 'proposed':
                            counter+=1
                    else:
                        print("Not a match")
                        print("Added to unmatched list")
                        results_from_unique_no_match.append(results_from_unique[l])
                        results_to_unique_no_match.append(results_to_unique[l])
                    try:
                        # FIND THE FLAW IDS FOR FROM AND TO
                        if FuzzyPointsOfSimilarity == 5:
                            if results_from_unique_five[l] in results_to_unique_five:
                                if DEBUG:
                                    print("[DEBUG]:: resutls_from_unique_five FOUND in results_to_unique_five")
                                    print(results_from_unique_five[l])
                                from_id = results_from_flawid[results_from_unique_five.index(results_from_unique_five[l])]
                                to_id = results_to_flawid[results_to_unique_five.index(results_from_unique_five[l])]
                                if results_from_unique_five[l]['mitigation_status'] == 'accepted' or results_from_unique_five[l]['mitigation_status'] == 'proposed':
                                    counter+=1
                            else:
                                if DEBUG:
                                    print("[DEBUG]:: results_from_unqiue NOT found in results_to_unique")
                                    print(results_from_unique_five[l])
                                #from_id = results_from_flawid[results_from_unique_five.index(results_from_unique_five[l])]
                                #to_id = results_to_flawid[results_to_unique_five.index(results_from_unique_five[l])]
                        elif FuzzyPointsOfSimilarity == 6:
                            if results_from_unique_six[l] in results_to_unique_six:
                                if DEBUG:
                                    print("[DEBUG]:: resutls_from_unique_six FOUND in results_to_unique_six")
                                    print(results_from_unique_six[l])
                                from_id = results_from_flawid[results_from_unique_six.index(results_from_unique_six[l])]
                                to_id = results_to_flawid[results_to_unique_six.index(results_from_unique_six[l])]
                            else:
                                if DEBUG:
                                    print("[DEBUG]:: results_from_unqiue NOT found in results_to_unique")
                                    print(results_from_unique_six[l])
                                
                                #from_id = results_from_flawid[results_from_unique_six.index(results_from_unique_six[l])]
                                #to_id = results_to_flawid[results_to_unique_six.index(results_from_unique_six[l])]
                        elif FuzzyPointsOfSimilarity == 7:
                            if results_from_unique_seven[l] in results_to_unique_seven:
                                if DEBUG:
                                    print("[DEBUG]:: resutls_from_unique_seven FOUND in results_to_unique_seven")
                                    print(results_from_unique_seven[l])
                                from_id = results_from_flawid[results_from_unique_seven.index(results_from_unique_seven[l])]
                                to_id = results_to_flawid[results_to_unique_seven.index(results_from_unique_seven[l])]
                            else:
                                if DEBUG:
                                    print("[DEBUG]:: results_from_unqiue NOT found in results_to_unique")
                                    print(results_from_unique_seven[l])

                                #from_id = results_from_flawid[results_from_unique_seven.index(results_from_unique_seven[l])]
                                #to_id = results_to_flawid[results_to_unique_seven.index(results_from_unique_seven[l])]
                        elif FuzzyPointsOfSimilarity == 8:
                            if results_from_unique_eight[l] in results_to_unique_eight:
                                if DEBUG:
                                    print("[DEBUG]:: resutls_from_unique_eight FOUND in results_to_unique_eight")
                                    print(results_from_unique_eight[l])
                                from_id = results_from_flawid[results_from_unique_eight.index(results_from_unique_eight[l])]
                                to_id = results_to_flawid[results_to_unique_eight.index(results_from_unique_eight[l])]
                            else:
                                if DEBUG:
                                    print("[DEBUG]:: results_from_unqiue NOT found in results_to_unique")
                                    print(results_from_unique_eight[l])
                                #from_id = results_from_flawid[results_from_unique_eight.index(results_from_unique_eight[l])]
                                #to_id = results_to_flawid[results_to_unique_eight.index(results_from_unique_eight[l])]
                        elif FuzzyPointsOfSimilarity == 9:
                            if results_from_unique[l] in results_to_unique:
                                if DEBUG:
                                    print("[DEBUG]:: resutls_from_unique FOUND in results_to_unique ")
                                    print(results_from_unique[l])
                                from_id = results_from_flawid[results_from_unique.index(results_from_unique[l])]
                                to_id = results_to_flawid[results_to_unique.index(results_from_unique[l])]

                            else:
                                if DEBUG:
                                    print("[DEBUG]:: results_from_unqiue NOT found in results_to_unique")
                                    print(results_from_unique[l])
                        elif FuzzyPointsOfSimilarity == 4:
                            if results_from_unique_four[l] in results_to_unique_four:
                                if DEBUG:
                                    print("[DEBUG]:: resutls_from_unique FOUND in results_to_unique ")
                                    print(results_from_unique_four[l])
                                from_id = results_from_flawid[results_from_unique_four.index(results_from_unique_four[l])]
                                to_id = results_to_flawid[results_to_unique_four.index(results_from_unique_four[l])]
                            else:
                                if DEBUG:
                                    print("[DEBUG]:: results_from_unqiue_four NOT found in results_to_unique_four")
                                    print(results_from_unique_four[l])
                        else:
                            if results_from_unique_four[l] in results_to_unique_four:
                                if DEBUG:
                                    print("[DEBUG]:: resutls_from_unique_four FOUND in results_to_unique_four ")
                                    print(results_from_unique_four[l])
                                from_id = results_from_flawid[results_from_unique_four.index(results_from_unique_four[l])]
                                to_id = results_to_flawid[results_to_unique_four.index(results_from_unique_four[l])]
                            else:
                                if DEBUG:
                                    print("[DEBUG]:: results_from_unqiue_four NOT found in results_to_unique_four")
                                    print(results_from_unique_four[l])
                                from_id = results_from_flawid[results_from_unique_four.index(results_from_unique_four[l])]
                                to_id = results_to_flawid[results_to_unique_four.index(results_from_unique_four[l])]

                        print("Check to see that From_id and To_id are both set")
                        print("From_id:" + str(from_id))
                        print("To_id:" + str(to_id))
                        print("Fuzzy Match Run: " + str(fuzzyMatchRun) )
                    except ValueError:
                            # FIND THE FLAW IDS FOR FROM AND TO
                        if FuzzyPointsOfSimilarity == 5:
                            print("Results From Unique No Match Found: " + str(results_from_unique_five[l]))
                        elif FuzzyPointsOfSimilarity == 6:
                            print("Results From Unique No Match Found: " + str(results_from_unique_six[l]))
                        elif FuzzyPointsOfSimilarity == 7:
                            print("Results From Unique No Match Found: " + str(results_from_unique_seven[l]))
                        elif FuzzyPointsOfSimilarity == 8:
                            print("Results From Unique No Match Found: " + str(results_from_unique_eight[l]))
                        elif FuzzyPointsOfSimilarity == 9:
                            print("Results From Unique No Match Found: " + str(results_from_unique[l]))
                        elif FuzzyPointsOfSimilarity == 4:
                            print("Results From Unique No Match Found: " + str(results_from_unique_four[l]))
                        else:
                            print("Results From Unique No Match Found: " + str(results_from_unique_four[l]))
                    else:
                        # FIND THE FLAW IDS FOR FROM AND TO
                        # CHECK IF IT'S ALREADY MITIGATED IN TO
                        print("To ID value: " + str(to_id))
                        if to_id is not None:
                            flaw_copy_to_list = results_to_root.findall('.//{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + to_id + '"]')
                            for flaw_copy_to in flaw_copy_to_list: # For every flaw in the flaw copy to list check  
                                # CHECK IF COPY TO IS ALREADY ACCEPTED OR PROPOSED
                                if flaw_copy_to.attrib['mitigation_status'] != 'accepted' or flaw_copy_to.attrib['mitigation_status'] != 'proposed':
                                    # get all mitigations for that from_id to copy over

                            
                                    mitigation_list = results_from_root.findall('.//{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + str(from_id) + '"]/{*}mitigations/{*}mitigation')

                                    
                                    for mitigation_action in mitigation_list:
                                        print("" + str(mitigation_action))
                                        proposal_action = mitigation_action.attrib['action']
                                        proposal_comment = '[MI: COPIED FROM BUILD ' + str(frombuild) + ' of ' + \
                                                        str(results_from_app_id) + ' on ' + str(MitigationCopier.datetime.datetime.utcnow()) + '] :' + str(mitigation_action.attrib['description'])
                                        if DEBUG: 
                                            print("Adding Mitigation: " + '[COPIED FROM BUILD ' + str(frombuild) + ' of ' + \
                                                        str(results_from_app_id) + ' on ' + str(MitigationCopier.datetime.datetime.utcnow()) + '] : ' + mitigation_action.attrib['description'])
                                        
                                        if dryrun is True:
                                            if proxy_mode:
                                                print("to: " + str( tobuild) + "  from: " + str(to_id) + "   Proposal Action: " + str(proposal_action) + " Proposal Comment" + str(proposal_comment) + "  Results from: " + str(results_from_app_id))
                                                update_mitigation_info_proxy(tobuild, to_id, proposal_action, proposal_comment, results_from_app_id, vid, vkey, accountid)
                                            else:
                                                print("to: " + str( tobuild) + "  from: " + str(to_id) + "   Proposal Action: " + str(proposal_action) + " Proposal Comment" + str(proposal_comment) + "  Results from: " + str(results_from_app_id))
                                                update_mitigation_info(tobuild, to_id, proposal_action, proposal_comment, results_from_app_id, vid, vkey)
                                        else:
                                            if proxy_mode:
                                                update_mitigation_info_proxy(tobuild, to_id, proposal_action, proposal_comment, results_from_app_id, vid, vkey, accountid)
                                            else:
                                                update_mitigation_info(tobuild, to_id, proposal_action, proposal_comment, results_from_app_id, vid, vkey)
                                    
                                        counter += 1
                                else:
                                    logging.info('Flaw ID ' + str(to_id) + ' in ' + str(results_to_app_id) + ' Build ID ' +
                                                str(tobuild) + ' already has an accepted mitigation; skipped.')
                                    #MitigationCopier.logprint('Flaw ID ' + str(to_id) + ' in ' + str(results_to_app_id) + ' Build ID ' + tobuild + ' already has an accepted mitigation; skipped.')
                                    if DEBUG: 
                                        print('Flaw ID ' + str(to_id) + ' in ' + str(results_to_app_id) + ' Build ID ' +
                                                str(tobuild) + ' already has an accepted mitigation; skipped.')
    if PRINT_OUT_UNMATCHED: 
        outfile = open('unmatched.txt', 'w+')
        print("Mitigation Copier Run " + str(MitigationCopier.datetime.datetime.now()), file=outfile )           
        for unmatched in results_from_unique_no_match:
            print("================================================================",file = outfile)
            print("\nFlaw Issue ID:" + str(flaw.attrib['issueid']) , file = outfile)
            print("Number of Mitigations Found: " + str(len(unmatched['mitigations'])), file = outfile)
            print("Number of Comments Found: " + str(len(annotation_from_static_flaw)) ,file = outfile)
            print("CWE " + str(flaw.attrib['cweid']), file = outfile)
            print("  Date of First Occurance: " + str(flaw.attrib['date_first_occurrence']), file = outfile)
            print("  Category: " + str(flaw.attrib['categoryname']), file = outfile)
            print("  Description: " + str(flaw.attrib['description']), file = outfile)
            print("  Severity: " + str(flaw.attrib['severity']), file = outfile)
            print("  Exploit Level: " + str(flaw.attrib['exploitLevel']), file = outfile)
            print("  Function: " + str(flaw.attrib['functionprototype']), file = outfile)
            print("  Relative Location: " + str(flaw.attrib['functionrelativelocation']) + "%", file = outfile)
            print("  Line: " + str(flaw.attrib['line']), file = outfile)
            print("  Module: " + str(flaw.attrib['module']), file = outfile)
            print("  Scope: " + str(flaw.attrib['scope']), file = outfile)
            print("  Source File: " + str(flaw.attrib['sourcefile']), file = outfile)
            print("  Source File Path: " + str(flaw.attrib['sourcefilepath']), file = outfile)
            print("  Type: " + str(flaw.attrib['type']), file = outfile)
            print("  Remediation Status: " + str(flaw.attrib['remediation_status']), file = outfile)
            print("  Remediation Effort: " + str(flaw.attrib['remediationeffort']), file = outfile)
            print("  Mitigation Status: " + str(flaw.attrib['mitigation_status']), file = outfile)
            print("  Issue ID: " + str(flaw.attrib['issueid']), file = outfile)
            print("  ---", file = outfile)
            print("  Mitigations Found: ", file = outfile)

            for mitigation in unmatched['mitigations']:
                print("    ------------------------------------------------------" , file = outfile)
                print("    Mitigation Action: " + str(mitigation['mitigation_action']), file = outfile)
                print("    Mitigation Date: " + str(mitigation['mitigation_date']), file = outfile)
                print("    Mitigation Proposed By: " + str(mitigation['mitigation_user']), file = outfile)
                print("    Mitigation Description: " + str(mitigation['mitigation_description']), file = outfile)
            if len(unmatched['mitigations']) == 0:
                print("    No Mitigations", file=outfile)
            print("  Annotations:", file=outfile)
            for annotation in unmatched['annotations']:
                print("    ------------------------------------------------------" , file = outfile)
                print("    Annotation Action: " + str(annotation['annotation_action']), file = outfile)
                print("    Annotation Date: " + str(annotation['annotation_date']), file = outfile)
                print("    Annotation Proposed By: " + str(annotation['annotation_user']), file = outfile)
                print("    Annotation Description: " + str(annotation['annotation_description']), file = outfile)

            if len(unmatched['annotations']) == 0:
                print("    No annotations", file=outfile)
        print("Wrote unmatched flaws to unmatched.txt with found mitigations")
            
                            
    print('[*] Updated ' + str(counter) + ' flaw IDs in ' + str(results_to_app_id) + '. See log file for details.')

    # print("Testing out results import method")
    # results_api_import("DetailedXMLReport001.xml")

# ## Function Name: 
# ## Precondition:
# ## Postcondition:
# ## Type:
# ## Comments:
# ## Description:
# def interactive():
#     pass

## Function Name: 
## Precondition:
## Postcondition:
## Type:
## Comments:
## Description:
def main():

    accountid=None
    proxy_mode=False
    IMPORT_MODE=True
 
    MitigationCopier.setup_logger()
    #MitigationCopier.logprint('======== beginning MitigationCopier.py run ========')

    #moving parser initialization globally
    if GLOBAL_ARG is False:
        parser.add_argument('-f', '--frombuild', help='Build ID to copy from')
        parser.add_argument('-t', '--tobuild', help='Build ID to copy to')
        parser.add_argument('-v', '--vid',  help='Veracode API ID')
        parser.add_argument('-k', '--vkey', help='Veracode API key')
        parser.add_argument('-c', '--csv', help='CSV of From and To Build IDs to copy from and to' )
        parser.add_argument('-csv', '--readfromcsv', help='Flag to read from CSV instead. Default: False', action='store_true')
        args = parser.parse_args()

    

    logging.basicConfig(filename='MitigationCopierv2.log',
                        format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S%p',
                        level=logging.INFO)
    
    if validate_args(args):
        if ( not args.readfromcsv ):
            if (args.frombuild and args.tobuild):
            
                # SET VARIABLES FOR FROM AND TO APPS
                if IMPORT_MODE:
                    results_from = importDetailedReport('DetailedXMLReport.xml')
                else:
                    if proxy_mode:
                        if vendor_account_id is not None:# for vendor mitigation migrations
                            results_from = results_api_proxy(args.frombuild, args.vid, args.vkey,vendor_account_id)
                        else:
                            results_from = results_api_proxy(args.frombuild, args.vid, args.vkey,accountid)
                    else:
                        results_from = results_api(args.frombuild, args.vid, args.vkey)
                    
                results_from_root = etree.fromstring(results_from)
                results_from_static_flaws = results_from_root.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')
                results_from_flawid = [None] * len(results_from_static_flaws)
                results_from_unique = [None] * len(results_from_static_flaws)
                results_from_app_id = 'App ID ' + results_from_root.attrib['app_id'] + ' (' + results_from_root.attrib[
                    'app_name'] + ')'

                if proxy_mode:
                    results_to = results_api_proxy(args.tobuild, args.vid, args.vkey, accountid)
                else:
                    results_to = results_api(args.tobuild, args.vid, args.vkey)
                
                results_to_root = etree.fromstring(results_to)
                results_to_static_flaws = results_to_root.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')
                results_to_flawid = [None] * len(results_to_static_flaws)
                results_to_unique = [None] * len(results_to_static_flaws)
                results_to_app_id = 'App ID ' + results_to_root.attrib['app_id'] + '(' + results_to_root.attrib['app_name'] + ')'

                # GET DATA FOR BUILD COPYING FROM
                builditeration=0
                for flaw in results_from_static_flaws:
                    if flaw.attrib['mitigation_status'] == 'accepted' or flaw.attrib['mitigation_status'] =='proposed':
                        builditeration +=1
                        results_from_flawid[builditeration] = flaw.attrib['issueid']
                        results_from_unique[builditeration] = flaw.attrib['cweid'] + flaw.attrib['type'] + flaw.attrib['sourcefile'] + \
                                                        flaw.attrib['line']

                # CREATE LIST OF UNIQUE VALUES FOR BUILD COPYING TO
                iteration=-1
                for flaw in results_to_static_flaws:
                    iteration += 1
                    results_to_unique[iteration] = flaw.attrib['cweid'] + flaw.attrib['type'] + flaw.attrib['sourcefile'] + \
                                                flaw.attrib['line']
                    results_to_flawid[iteration] = flaw.attrib['issueid']

                # CREATE COUNTER VARIABLE
                counter = 0

                # CYCLE THROUGH RESULTS_TO_UNIQUE
                for i in range(0, len(results_to_unique)):
                    # CHECK IF IT'S IN RESULTS FROM
                    if results_to_unique[i] in results_from_unique:
                        # FIND THE FLAW IDS FOR FROM AND TO
                        from_id = results_from_flawid[results_from_unique.index(results_to_unique[i])]
                        to_id = results_to_flawid[results_to_unique.index(results_to_unique[i])]

                        # CHECK IF IT'S ALREADY MITIGATED IN TO
                        flaw_copy_to_list = results_to_root.findall(
                            './/{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + str(to_id) + '"]')
                        for flaw_copy_to in flaw_copy_to_list:
                            # CHECK IF COPY TO IS ALREADY ACCEPTED OR PROPOSED
                            if flaw_copy_to.attrib['mitigation_status'] != 'accepted' or flaw_copy_to.attrib['mitigation_status'] != 'proposed':

                                mitigation_list = results_from_root.findall(
                                    './/{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + str(
                                        from_id) + '"]/{*}mitigations/{*}mitigation')

                                for mitigation_action in mitigation_list:
                                    proposal_action = mitigation_action.attrib['action']
                                    proposal_comment = '[COPIED FROM BUILD ' + args.frombuild + ' of ' + \
                                                    results_from_app_id + '] ' + mitigation_action.attrib['description']
                                    if proxy_mode:
                                        update_mitigation_info_proxy(args.tobuild, to_id, proposal_action, proposal_comment,
                                                        results_from_app_id, args.vid,
                                                        args.vkey, accountid)
                                    else:
                                        update_mitigation_info(args.tobuild, to_id, proposal_action, proposal_comment,
                                                        results_from_app_id, args.vid,
                                                        args.vkey)
                                    
                                counter += 1
                            else:
                                logging.info('Flaw ID ' + str(to_id) + ' in ' + results_to_app_id + ' Build ID ' +
                                            args.tobuild + ' already has an accepted mitigation; skipped.')
                                #MitigationCopier.logprint('Flaw ID ' + str(to_id) + ' in ' + str(results_to_app_id) + ' Build ID ' + str(args.tobuild) + ' already has an accepted mitigation; skipped.')
                print('[*] Updated ' + str(counter) + ' flaw IDs in ' + results_to_app_id + '. See log file for details.')
        elif ( args.readfromcsv and args.csv ):
        
            ###################################################################################
            # Method 1
            ###################################################################################
            # Initialize empty arrays to store values
            from_build_ids = []
            to_build_ids = []

            # Replace 'your_csv_file.csv' with the actual path to your CSV file
            csv_file_path = args.csv

            try:
                with open(csv_file_path, 'r') as csvfile:
                    csv_reader = csv.reader(csvfile)
                    
                    for row in csv_reader:
                        if ( row[0] == "FromBuildID" or row[1] == "ToBuildID" ):
                            continue
                        if (len(row[0]) <= 9 and len(row[1]) <= 9):
                        # Assuming the column names are "From Build ID" and "To Build ID"
                            print("From " + row[0])
                            print("To " + row[1])
                            from_build_ids.append(row[0])
                            to_build_ids.append(row[1])
                                    # SET VARIABLES FOR FROM AND TO APPS
                            if proxy_mode:
                                if vendor_account_id is not None:
                                    results_from = results_api_proxy(row[0], args.vid, args.vkey,vendor_account_id)
                                else: 
                                    results_from = results_api_proxy(row[0], args.vid, args.vkey,accountid)
                            else:
                                results_from = results_api(row[0], args.vid, args.vkey)
                            
                            #results_from = results_api(row[0], args.vid, args.vkey)
                            results_from_root = etree.fromstring(results_from)
                            results_from_static_flaws = results_from_root.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')
                            results_from_flawid = [None] * len(results_from_static_flaws)
                            results_from_unique = [None] * len(results_from_static_flaws)
                            results_from_app_id = 'App ID ' + results_from_root.attrib['app_id'] + ' (' + results_from_root.attrib[
                                'app_name'] + ')'
                            
                            if proxy_mode:
                                results_from = results_api_proxy(row[0], args.vid, args.vkey,accountid)
                            else:
                                results_from = results_api(row[0], args.vid, args.vkey)
                            
                            #results_to = results_api(row[1], args.vid, args.vkey)
                            results_to_root = etree.fromstring(results_to)
                            results_to_static_flaws = results_to_root.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')
                            results_to_flawid = [None] * len(results_to_static_flaws)
                            results_to_unique = [None] * len(results_to_static_flaws)
                            results_to_app_id = 'App ID ' + results_to_root.attrib['app_id'] + '(' + results_to_root.attrib['app_name'] + ')'

                            # GET DATA FOR BUILD COPYING FROM
                            builditeration=0
                            for flaw in results_from_static_flaws:
                                if flaw.attrib['mitigation_status'] == 'accepted' or flaw.attrib['mitigation_status'] =='proposed':
                                    builditeration +=1
                                    results_from_flawid[builditeration] = flaw.attrib['issueid']
                                    results_from_unique[builditeration] = flaw.attrib['cweid'] + flaw.attrib['type'] + flaw.attrib['sourcefile'] + \
                                                                    flaw.attrib['line']

                            # CREATE LIST OF UNIQUE VALUES FOR BUILD COPYING TO
                            iteration=-1
                            for flaw in results_to_static_flaws:
                                iteration += 1
                                results_to_unique[iteration] = flaw.attrib['cweid'] + flaw.attrib['type'] + flaw.attrib['sourcefile'] + \
                                                            flaw.attrib['line']
                                results_to_flawid[iteration] = flaw.attrib['issueid']

                            # CREATE COUNTER VARIABLE
                            counter = 0

                            # CYCLE THROUGH RESULTS_TO_UNIQUE
                            for i in range(0, len(results_to_unique)):
                                # CHECK IF IT'S IN RESULTS FROM
                                if results_to_unique[i] in results_from_unique:
                                    # FIND THE FLAW IDS FOR FROM AND TO
                                    from_id = results_from_flawid[results_from_unique.index(results_to_unique[i])]
                                    to_id = results_to_flawid[results_to_unique.index(results_to_unique[i])]

                                    # CHECK IF IT'S ALREADY MITIGATED IN TO
                                    flaw_copy_to_list = results_to_root.findall(
                                        './/{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + str(to_id) + '"]')
                                    for flaw_copy_to in flaw_copy_to_list:
                                        # CHECK IF COPY TO IS ALREADY ACCEPTED OR PROPOSED
                                        if flaw_copy_to.attrib['mitigation_status'] != 'accepted' or flaw_copy_to.attrib['mitigation_status'] != 'proposed':

                                            mitigation_list = results_from_root.findall(
                                                './/{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + str(
                                                    from_id) + '"]/{*}mitigations/{*}mitigation')

                                            for mitigation_action in mitigation_list:
                                                proposal_action = mitigation_action.attrib['action']
                                                proposal_comment = '[COPIED FROM BUILD ' + row[0] + ' of ' + \
                                                                results_from_app_id + '] ' + mitigation_action.attrib['description']
                                                if proxy_mode:
                                                    update_mitigation_info_proxy(row[1], to_id, proposal_action, proposal_comment,
                                                                    results_from_app_id, args.vid,
                                                                    args.vkey, accountid)
                                                else:
                                                    update_mitigation_info(row[1], to_id, proposal_action, proposal_comment,
                                                                    results_from_app_id, args.vid,
                                                                    args.vkey)
                                                
                                                #update_mitigation_info(row[1], to_id, proposal_action, proposal_comment,
                                                #                    results_from_app_id, args.vid,
                                                #                    args.vkey)
                                            counter += 1
                                        else:
                                            logging.info('Flaw ID ' + str(to_id) + ' in ' + str(results_to_app_id) + ' Build ID ' +
                                                        str(row[1]) + ' already has an accepted mitigation; skipped.')
                                            #MitigationCopier.logprint('Flaw ID ' + str(to_id) + ' in ' + str(results_to_app_id) + ' Build ID ' + str(row[1]) + ' already has an accepted mitigation; skipped.')
                            print('[*] Updated ' + str(counter) + ' flaw IDs in ' + results_to_app_id + '. See log file for details.')
                            


                # Now, from_build_ids and to_build_ids contain the values from the CSV
                #print("From Build IDs:", from_build_ids)
                #print("To Build IDs:", to_build_ids)

            
            except FileNotFoundError:
                print(f"The file '{csv_file_path}' was not found.")
    else:
        parser.error("Error evaluating the arguments")


## Script Executer
############################################################################################################################


if __name__ == '__main__':
    PROMPT=True


    if MANUAL_IMPORT is True:
        if PROMPT:
            apiid = input("Please provide you Veracode API ID or leave blank to use the credentials file: ")
            apikey = input("Please provide you Veracode API key or leave blank to use the credentials file: ")
            if apiid  == "" and apikey == "" : 
                creds_expire_days_warning()
            elif apiid is not None:
                creds_expire_days_warning(api_id=apiid)
            pathToDetailReport = input("Please provide the path to the Detailed XML Report to import: ")
            toBuildId = input("Please provide the toBuild ID: " )
            manual_import(apiid, apikey, pathToDetailReport , toBuildId)

        else:
            manual_import("X","x","DetailedXMLReport-verademo.xml",x)
       
    # elif INTERACTIVE is True:
    #     interactive()
    else:
        main()


    