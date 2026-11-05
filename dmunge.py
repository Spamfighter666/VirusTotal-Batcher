# version 1.5.4 May 29 2018

# Python 3.6 modules
import csv
import sys
import re
import os
import zipfile
import asyncio
from pathlib import Path

# 3rd party modules
import arrow
from tqdm import tqdm
from tldextract import TLDExtract

# local modules
import vtmachinegun as vtm
import config as cfg

# Initialize global variables
version_info = (2, 0 ,7)
version = '.'.join(str(c) for c in version_info)
debug = 0
server_mode = cfg.server_friendly
starting_nameserver = ['b.root-servers.net.']  # passed as a list because subsequent recursive calls will be lists


if debug == 0:
    tqdm_silent = True
else:
    tqdm_silent = False


def banner():
    global version
    b = r'''
      _____         __  __                             
     |  __ \       |  \/  |                            
     | |  | |______| \  / |_   _ _ __   __ _  ___ _ __ 
     | |  | |______| |\/| | | | | '_ \ / _` |/ _ \ '__|
     | |__| |      | |  | | |_| | | | | (_| |  __/ |   
     |_____/       |_|  |_|\__,_|_| |_|\__, |\___|_|   
                                        __/ |          
                                       |___/           \n
        Version {v} - Faster than a speeding lemur.
                 Made by NS and AZW
    '''.format(v=version)
    print(b)


def main():
    banner()
    home, input_file = check_required_files()
    user_choice = prompt_user()
    list_to_process, whitelist, alexa_top_1m, service_providers, extended_tlds = initialize_lists(input_file)
    domain_list, failure_list = munge(list_to_process, whitelist, alexa_top_1m, service_providers, extended_tlds)
    if user_choice == 2:
        domain_list = a_lookup(domain_list)
        domain_list.insert(0,('Reportable Element','Abuse Contact','Live Resolution'))
    else:
        domain_list.insert(0, ('Reportable Element', 'Abuse Contact'))
    save_to_file(home, domain_list, home + "/results/dMunge/d-munged Hostnames" )
    if failure_list:
        failure_list.insert(0, ('Reportable Element', 'Reason'))
        save_to_file(home, failure_list, home + "/results/dMunge/UN-munged Hostnames" )


def api(input_file):
    list_to_process, whitelist, alexa_top_1m, service_providers, extended_tlds = initialize_lists(input_file)
    domain_list, failure_list = munge(list_to_process, whitelist, alexa_top_1m, service_providers, extended_tlds)
    return domain_list,failure_list


def check_required_files():
    home = Path(cfg.home_path)
    input_file = home / "input/dmunge.txt"
    for path in (input_file, home / "support/white.txt", home / "support/splist.csv"):
        if not path.is_file():
            sys.exit(f"Required file missing: {path}")
    (home / "results/dMunge").mkdir(parents=True, exist_ok=True)
    return str(home), input_file


def prompt_user():
    while True:
        choice = input("Choose 1 to reduce domains, 2 to also resolve A records, or 0 to quit: ")
        if choice == "0":
            sys.exit()
        if choice in {"1", "2"}:
            return int(choice)


def initialize_lists(input_file):
    support = Path(cfg.home_path) / "support"
    ranks = support / "top-1m.csv"
    alexa_top_1m = set()
    if ranks.is_file():
        with ranks.open(encoding="utf-8-sig", newline="") as rank_file:
            alexa_top_1m = {row[1].strip().lower() for row in csv.reader(rank_file)
                            if len(row) >= 2 and row[0].strip().isdigit()}
    with open(input_file, encoding="utf-8-sig") as source:
        list_to_process = source.read().split()
    with (support / "white.txt").open(encoding="utf-8-sig") as source:
        whitelist = {line.strip().lower() for line in source if line.strip()}
    with (support / "splist.csv").open(encoding="utf-8-sig", newline="") as source:
        service_providers = {row[0].strip().lower(): row[1].strip() for row in csv.reader(source)
                             if len(row) >= 2 and not row[0].lstrip().startswith("#")}
    extended_tlds = list(service_providers.keys())

    return list_to_process, whitelist, alexa_top_1m, service_providers, extended_tlds


def munge(list_to_process, whitelist, alexa_top_1m, service_providers, extended_tlds):
    print("\nMunging...")

    job_start = arrow.now()
    xtract_domain = TLDExtract(suffix_list_urls=(), include_psl_private_domains=True, extra_suffixes=extended_tlds)
    domains = []          # log successful reductions
    failures = []         # log failures
    already_seen = set()  # Check to make sure we do not return the same domain twice.


    for i, line in \
            tqdm(enumerate(list_to_process), total = len(list_to_process), unit=" lines munged", disable=tqdm_silent):
        extracted = xtract_domain(line)
        domain = extracted.top_domain_under_public_suffix.lower()
        tld = extracted.suffix

        if domain and tld:
            if domain in whitelist:
                reason_code = "Whitelist"
                failures.append((line, reason_code))

            elif domain in alexa_top_1m:
                reason_code = "Popularity list"
                failures.append((line, reason_code))

            elif domain not in already_seen:
                try:
                    service_provider = service_providers[tld.lower()]
                except:
                    service_provider = "~none"

                domains.append((domain, service_provider))
                already_seen.add(domain)

        elif tld:
            if tld not in already_seen:
                already_seen.add(tld)

            reason_code = "tld only, no domain"
            failures.append((tld, reason_code))

        elif '://' in line:
            ip = re.findall(r'\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?', line)
            try:
                if ip[0] not in already_seen:
                    reason_code = "IP address"
                    domains.append((ip[0], reason_code))
                    already_seen.add(ip[0])
                else:
                    pass
            except:
                pass

        else:
            reason_code = "No domain info"
            failures.append((line, reason_code))

    domain_list = list(set(domains))
    domain_list.sort(key=lambda elem: (elem[1], elem[0].split('.')[::-1], elem[0]))

    failure_list = list(set(failures))
    failure_list.sort(key=lambda elem: (elem[1], elem[0].split('.')[::-1], elem[0]))

    job_finish = arrow.now()
    print(" ")
    print("Ended run at: ", arrow.now().format('YYYY-MM-DD HH:mm:ss'), "and took ", (job_finish - job_start), "to run.")

    return domain_list, failure_list


def a_lookup(domain_list):
    domain_only_list = [domain for domain, service_provider in domain_list]

    # Call the multi-process async loop to resolve each hostname and validate that we received results
    resolutions = asyncio.run(vtm.dnsloop(domain_only_list, 'the dMunged results'))
    try:
        resolutions_dict = dict(resolutions)
    except Exception as e:
        print(e, ' : ', resolutions)
        sys.exit()

    # Now step though the original VT results, and use each hostname as an index to grab its resolution
    # Replace the line(a tuple) with a new tuple that contains the resolved ip results
    for i, line in enumerate(domain_list):
        hostname = line[0].strip()
        try:
            host_ip = resolutions_dict[hostname]
            tuplist = list(line)
            tuplist.append(host_ip)
            domain_list[i] = tuple(tuplist)
        except:
            if hostname:
                host_ip = 'No result from Reno'
                tuplist = list(line)
                tuplist.append(host_ip)
                domain_list[i] = tuple(tuplist)

    return domain_list
    # live or dead, ip, timestamp


def save_to_file(home, some_list_of_tuples, filename):
    csvname = filename + " " + arrow.now().format('YYYY-MM-DD HH-mm-ss') + ".csv"
    zipname = filename + " " + arrow.now().format('YYYY-MM-DD HH-mm-ss') + ".zip"

    if server_mode == 'yes':
        print("Logging reduced hostnames to server...")

        with open(csvname, 'w', encoding='utf-8', newline='') as out:
            csv_out = csv.writer(out)
            for row in some_list_of_tuples:
                csv_out.writerow(row)
        with zipfile.ZipFile(zipname, 'w') as myzip:
            myzip.write(csvname, os.path.basename(csvname))
        os.remove(csvname)

    else:
        with open(csvname, 'w', encoding='utf-8', newline='') as csvfile:
            writer = csv.writer(csvfile, dialect='excel')
            writer.writerows(some_list_of_tuples)
            csvfile.flush()

if __name__ == '__main__':
    # sys.exit(main(sys.argv)) # used to give a better look to exists
    main()

