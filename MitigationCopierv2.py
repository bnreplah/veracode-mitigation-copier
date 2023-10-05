import sys
import argparse
import logging
import requests
from lxml import etree
import os # for the ability to check if file exists and parse csv
import csv
from helpers import api


## Imported from main Mitigation Copier to read the credential file
## BH 9/21/23
import datetime
from veracode_api_py.api import VeracodeAPI as vapi

def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone() #we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])


parser = argparse.ArgumentParser(
        description='This script looks at the results set of the FROM BUILD. For any flaws that have an '
                    'accepted mitigation, it checks the TO BUILD to see if that flaw exists. If it exists, '
                    'it copies all mitigation information.')



def results_api(build_id, api_user, api_password):

    veracode_api = api.VeracodeAPI()
    
    r = veracode_api.get_detailed_report(build_id)

    if '<error>' in r.decode("utf-8"):
        logging.info('Error downloading results for Build ID ' + build_id)
        sys.exit('[*] Error downloading results for Build ID ' + build_id)
    logging.info('Downloaded results for Build ID ' + build_id)
    print ('[*] Downloaded results for Build ID ' + build_id)
    return r


def update_mitigation_info(build_id, flaw_id_list, action, comment, results_from_app_id, api_user, api_password):

    veracode_api = api.VeracodeAPI()

    r = veracode_api.set_mitigation_info(build_id,flaw_id_list,action,comment,results_from_app_id)
    if '<error>' in r.decode("UTF-8"):
        logging.info('Error updating mitigation_info for ' + flaw_id_list + ' in Build ID ' + build_id)
        sys.exit('[*] Error updating mitigation_info for ' + flaw_id_list + ' in Build ID ' + build_id)
    logging.info(
        'Updated mitigation information to ' + action + ' for Flaw ID ' + flaw_id_list + ' in ' +
        results_from_app_id + ' in Build ID ' + build_id)

def validate_args(args):
    if not ( args.readfromcsv and args.csv ) and not (args.frombuild and args.tobuild):
        parser.error("Either --frombuild and --tobuild or --csv and --readfromcsv set to true must be provided")
    if not ( args.vkey and args.vid):
        print("API Credentials not provided [https://docs.veracode.com/r/t_create_api_creds] \nChecking for credentials in enviornment [https://docs.veracode.com/r/c_configure_api_cred_file]")



def main():
    #moving parser initialization globally
    parser.add_argument('-f', '--frombuild', help='Build ID to copy from')
    parser.add_argument('-t', '--tobuild', help='Build ID to copy to')
    parser.add_argument('-v', '--vid',  help='Veracode API ID')
    parser.add_argument('-k', '--vkey', help='Veracode API key')
    parser.add_argument('-c', '--csv', required=False, help='CSV of From and To Build IDs to copy from and to' )
    parser.add_argument('-csv', '--readfromcsv', required=False, help='Flag to read from CSV instead. Default: False', default=False)
    args = parser.parse_args()

    

    logging.basicConfig(filename='MitigationCopier.log',
                        format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S%p',
                        level=logging.INFO)
    
    validate_args(args)
    if ( not args.readfromcsv ):
        if (args.frombuild and args.tobuild):
        
            # SET VARIABLES FOR FROM AND TO APPS
            results_from = results_api(args.frombuild, args.vid, args.vkey)
            results_from_root = etree.fromstring(results_from)
            results_from_static_flaws = results_from_root.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')
            results_from_flawid = [None] * len(results_from_static_flaws)
            results_from_unique = [None] * len(results_from_static_flaws)
            results_from_app_id = 'App ID ' + results_from_root.attrib['app_id'] + ' (' + results_from_root.attrib[
                'app_name'] + ')'

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
                                update_mitigation_info(args.tobuild, to_id, proposal_action, proposal_comment,
                                                    results_from_app_id, args.vid,
                                                    args.vkey)
                            counter += 1
                        else:
                            logging.info('Flaw ID ' + str(to_id) + ' in ' + results_to_app_id + ' Build ID ' +
                                        args.tobuild + ' already has an accepted mitigation; skipped.')

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
                        results_from = results_api(row[0], args.vid, args.vkey)
                        results_from_root = etree.fromstring(results_from)
                        results_from_static_flaws = results_from_root.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')
                        results_from_flawid = [None] * len(results_from_static_flaws)
                        results_from_unique = [None] * len(results_from_static_flaws)
                        results_from_app_id = 'App ID ' + results_from_root.attrib['app_id'] + ' (' + results_from_root.attrib[
                            'app_name'] + ')'

                        results_to = results_api(row[1], args.vid, args.vkey)
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
                                            update_mitigation_info(row[1], to_id, proposal_action, proposal_comment,
                                                                results_from_app_id, args.vid,
                                                                args.vkey)
                                        counter += 1
                                    else:
                                        logging.info('Flaw ID ' + str(to_id) + ' in ' + results_to_app_id + ' Build ID ' +
                                                    row[1] + ' already has an accepted mitigation; skipped.')

                        print('[*] Updated ' + str(counter) + ' flaw IDs in ' + results_to_app_id + '. See log file for details.')
                        


            # Now, from_build_ids and to_build_ids contain the values from the CSV
            #print("From Build IDs:", from_build_ids)
            #print("To Build IDs:", to_build_ids)

           
        except FileNotFoundError:
            print(f"The file '{csv_file_path}' was not found.")



if __name__ == '__main__':
    main()
