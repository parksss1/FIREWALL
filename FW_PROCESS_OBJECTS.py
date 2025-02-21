import pandas as pd
import ipaddress
import socket
import subprocess
import platform
import logging
from datetime import datetime
import concurrent.futures


    # LOG ACTIONS
log_file = f"network_tasks_{datetime.now().strftime('%Y%m%d')}.log"
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


    # FIND DELTAS FROM PREVIOUS CSV FILE
def calculate_deltas(previous_csv, current_csv):
    logging.info("Starting delta calculation.")
    df_prev = pd.read_csv(previous_csv)
    df_curr = pd.read_csv(current_csv)
    
    # COLUMNS TO COMPARE
    netaddress_column_name = 'netAddress'
    instance_column_name = 'fwNetEnv'
    fw_date_column_name = 'fwNetDateAdded'
    fw_dropped_column_name = 'fwNetDropped'
    update_date_column_name = 'netUpdDate'

    # CREATE UNIQUE KEYS TO FIND UNIQUE OBJECTS TO COMPARE TO IN OLD/NEW FILES
    df_prev['unique_key'] = df_prev[netaddress_column_name] + '|' + df_prev[instance_column_name]
    df_curr['unique_key'] = df_curr[netaddress_column_name] + '|' + df_curr[instance_column_name]

    # STORE KEYS
    prev_keys = set(df_prev['unique_key'])
    curr_keys = set(df_curr['unique_key'])

    # CALCULATE NEW OBJECTS
    new_keys = curr_keys - prev_keys
    #CALCULATE OBJECTS NO LONGER THERE (REMOVED)
    removed_keys = prev_keys - curr_keys

    # MARK REMOVED KEYS AS 'N/A' IN NEW FILE
    df_prev.loc[df_prev['unique_key'].isin(removed_keys), fw_dropped_column_name] = 'YES'
    
    # ADD NEW KEYS TO FILE ('N/A' BECAUSE HASN'T BEEN DROPPED)
    new_objects = df_curr[df_curr['unique_key'].isin(new_keys)].copy()
    new_objects[fw_dropped_column_name] = 'N/A'
    new_objects[fw_date_column_name] = datetime.now().strftime('%Y-%m-%d')

    # COMBINE
    df_combined = pd.concat([df_prev, new_objects], ignore_index=True)

    # UPDATE 'netUpdDate' COLUMN FOR OBJECTS THAT ARE ACTIVE
    current_date = datetime.now().strftime('%Y-%m-%d')
    df_combined[update_date_column_name] = df_combined.apply(
        lambda row: row[update_date_column_name] if row[fw_dropped_column_name] == 'YES' else current_date,
        axis=1
    )

    # PRESERVE ALL 'N/A' VALUES IN REPORT
    df_combined[fw_dropped_column_name] = df_combined[fw_dropped_column_name].fillna('N/A')

    # LOG
    logging.info("Delta calculation completed.")
    print("Delta calculation completed.")
    return df_combined



    # DNS LOOKUP AND COMPARE
def resolve_dns(row):
    # NET ADDRESS TO PERFORM NSLOOKUP ON
    net_address = row['netAddress']
    result = {
        "fwNetHostName": "N/A",
        "fwNetReverseLookup": "N/A",
        "nslookUpMatch": "NO MATCH"
    }

    # SKIP NETWORK RANGES
    if '/' in net_address or '-' in net_address:
        result["fwNetHostName"] = "SKIP-NETWORK RANGE"
        result["nslookUpMatch"] = "SKIP-NETWORK RANGE"
        return result

    try:
        # FORWARD DNS LOOKUP: NSLOOKUP BY ADDRESS
        hostname, _, _ = socket.gethostbyaddr(net_address)
        result["fwNetHostName"] = hostname

        # REVERSE DNS LOOKUP ON HOSTNAME
        try:
            _, _, ip_list = socket.gethostbyname_ex(hostname)
            result["fwNetReverseLookup"] = ",".join(ip_list)
        except Exception as rev_err:
            logging.warning(f"Reverse DNS lookup failed for {hostname}: {rev_err}")
            ip_list = []

        # POSSIBLE MULTIPLE LISTINGS, CONFIRM >0 EXISTS
        if net_address in ip_list:
            result["nslookUpMatch"] = "MATCH"
        else:
            result["nslookUpMatch"] = "NO MATCH"
    except Exception as e:
        logging.warning(f"DNS resolution failed for {net_address}: {e}")

    return result


    # PROCESS DNS
def process_dns(df):
    logging.info("Starting DNS resolution.")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_map = {
            index: executor.submit(resolve_dns, row) for index, row in df.iterrows()
        }
        for index, future in future_map.items():
            result = future.result()
            df.at[index, 'fwNetHostName'] = result["fwNetHostName"]
            df.at[index, 'fwNetReverseLookup'] = result["fwNetReverseLookup"]
            df.at[index, 'nslookUpMatch'] = result["nslookUpMatch"]

    logging.info("DNS resolution completed.")
    print("DNS resolution completed.")
    return df


# PROCESS AND OUTPUT SUBNETS
def calculate_subnets(df):
    logging.info("Starting subnet calculations.")

    def calculate_ranges(address):
        try:
            if '-' in address:
                lower, upper = address.split('-')
                lower_octets = list(map(int, lower.split('.')))
                upper_octets = list(map(int, upper.split('.')))
            else:
                network = ipaddress.ip_network(address, strict=False)
                lower_octets = list(map(int, str(network.network_address).split('.')))
                upper_octets = list(map(int, str(network.broadcast_address).split('.')))
            return lower_octets + upper_octets
        except Exception as e:
            logging.warning(f"Subnet calculation failed for {address}: {e}")
            return ['N/A'] * 8

    columns = [
        'netIPOct1L', 'netIPOct1U', 'netIPOct2L', 'netIPOct2U',
        'netIPOct3L', 'netIPOct3U', 'netIPOct4L', 'netIPOct4U'
    ]
    df[columns] = df['netAddress'].apply(calculate_ranges).tolist()
    logging.info("Subnet calculations completed.")
    print("Subnet calculations completed.")
    return df

    # PING OBJECTS (NO SUBNETS) '2' FREQUENCY
def ping_objects(df):
    logging.info("Starting ping tests.")

    def ping(ip):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '2', ip]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True, timeout=5)
            logging.info(f"Ping successful for IP: {ip}. Output: {output.strip()}")
            return 'YES'
        except subprocess.CalledProcessError as e:
            logging.warning(f"Ping failed for IP: {ip}. Error output: {e.output.strip()}")
            return 'NO'
        except Exception as e:
            logging.error(f"Unexpected error during ping of {ip}: {e}")
            return 'NO'
        
    # SKIP NETWORK RANGES
    df['fwNetPingable'] = df['netAddress'].apply(lambda ip: ping(ip) if '/' not in ip and '-' not in ip else 'SKIP - NETWORK RANGE')
    logging.info("Ping tests completed.")
    print("Ping tests completed.")
    return df

# Main Script Execution
if __name__ == "__main__":
    previous_csv = '.csv'
    current_csv = '.csv'
    final_csv = '.csv'

    # CALCULATE DELTAS
    combined_df = calculate_deltas(previous_csv, current_csv)

    # DNS LOOKUPS AND COMPARES
    combined_df = process_dns(combined_df)

    # SUBNET CALCULATIONS
    combined_df = calculate_subnets(combined_df)

    # SAVE FINAL CSV TO CONFIRM OUTPUT... PING TESTS TAKE AWHILE 
    combined_df.to_csv(final_csv, index=False)

    # PERFORM PING TESTS
    combined_df = ping_objects(combined_df)

    # SAVE FINAL CSV
    combined_df.to_csv(final_csv, index=False)
    logging.info(f"All tasks completed. Final output saved to {final_csv}.")
    print(f"All tasks completed. Final output saved to {final_csv}.")
