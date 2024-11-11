#!/usr/bin/env python3

import zipfile
import xml.etree.ElementTree as ET
import argparse
import glob
import os
from os.path import basename
import readline
import csv
import logging

from decrypt import KettleTwoWayPasswordEncoder

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def decrypt(encrypted_password, custom_seed=None):
    """
    Decrypts an encrypted password using the KettleTwoWayPasswordEncoder.

    Args:
        encrypted_password (str): The encrypted password to be decrypted.
        custom_seed (str, optional): A custom seed for the encoder. If not provided, the default encoder is used.

    Returns:
        str: The decrypted password.
    """
    if custom_seed:
        custom_encoder = KettleTwoWayPasswordEncoder(env_seed=custom_seed)
        decrypted_password = custom_encoder.decrypt_password_internal(encrypted_password)
    else:
        encoder = KettleTwoWayPasswordEncoder()
        decrypted_password = encoder.decrypt_password_internal(encrypted_password)
    return decrypted_password

def get_ktr_files_from_zip(zip_path):
    xml_files = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for file_info in zip_ref.infolist():
                if file_info.filename.endswith('.ktr'):
                    xml_files.append(file_info.filename)
    except zipfile.BadZipFile:
        logging.error(f"Error: {zip_path} is not a valid ZIP file.")
    return xml_files

def parse_xml_from_zip(zip_path, xml_filename):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        with zip_ref.open(xml_filename) as xml_file:
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                return root
            except ET.ParseError as e:
                logging.error(f"Error parsing {xml_filename}: {e}")
                return None

def parse_xml_file(file_path):
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        return root
    except ET.ParseError as e:
        logging.error(f"Error parsing {file_path}: {e}")
        return None

def collect_connection_details(root, ktr_file, connection_details, unique_connections, unique_user_pass_pairs, sa_user_pairs, custom_seed):
    """
    Collects connection details from the provided XML root element and appends them to the given lists and sets.
    Args:
        root (Element): The root element of the XML document to parse.
        ktr_file (str): The file path of the KTR file being processed.
        connection_details (list): A list to append connection details dictionaries.
        unique_connections (set): A set to store unique connection tuples.
        unique_user_pass_pairs (set): A set to store unique username and password pairs.
        sa_user_pairs (set): A set to store 'sa' username pairs.
        custom_seed (str): A custom seed used for decrypting passwords.
    Returns:
        None
    """
    # Parse connection elements
    for connection in root.findall('.//connection'):
        server = connection.find('server').text if connection.find('server') is not None else ''
        type_ = connection.find('type').text if connection.find('type') is not None else ''
        database = connection.find('database').text if connection.find('database') is not None else ''
        port = connection.find('port').text if connection.find('port') is not None else ''
        username = connection.find('username').text if connection.find('username') is not None else ''
        password = connection.find('password').text if connection.find('password') is not None else ''
        if password and password.startswith('Encrypted '):
            password = password[len('Encrypted '):]
        
        if any(server or type_ or database or port or username or password):
            decrypted_password = decrypt(password, custom_seed) if password else 'N/A'
            connection_details.append({
                "ktr_file": basename(ktr_file),
                "server": server if server else 'N/A',
                "type": type_ if type_ else 'N/A',
                "database": database if database else 'N/A',
                "port": port if port else 'N/A',
                "username": username if username else 'N/A',
                "password": decrypted_password if decrypted_password else 'N/A'
            })
            connection_string = (server, type_, database, port, username, decrypted_password)
            unique_connections.add(connection_string)
            user_pass_pair = (username, decrypted_password)
            unique_user_pass_pairs.add(user_pass_pair)
            if username and username.lower() == 'sa':
                sa_user_pairs.add((server, username, decrypted_password))

    # Parse step elements
    for step in root.findall('.//step'):
        host = step.find('host').text if step.find('host') is not None else ''
        type_ = step.find('type').text if step.find('type') is not None else ''
        port = step.find('port').text if step.find('port') is not None else ''
        username = step.find('username').text if step.find('username') is not None else ''
        password = step.find('password').text if step.find('password') is not None else ''
        if password and password.startswith('Encrypted '):
            password = password[len('Encrypted '):]

        if any(host or port or username or password):
            decrypted_password = decrypt(password, custom_seed) if password else 'N/A'
            connection_details.append({
                "ktr_file": os.path.basename(ktr_file),
                "server": host if host else 'N/A',
                "type": type_ if type_ else 'N/A',
                "database": 'N/A',
                "port": port if port else 'N/A',
                "username": username if username else 'N/A',
                "password": decrypted_password if decrypted_password else 'N/A'
            })
            connection_string = (host, type_, 'N/A', port, username, decrypted_password)
            unique_connections.add(connection_string)
            user_pass_pair = (username, decrypted_password)
            unique_user_pass_pairs.add(user_pass_pair)
            if username and username.lower() == 'sa':
                sa_user_pairs.add((host, username, decrypted_password))

def path_completer(text, state):
    line = readline.get_line_buffer().split()
    if not line:
        return [c + '/' for c in os.listdir('.')][state]
    else:
        return [c + '/' if os.path.isdir(c) else c for c in glob.glob(text + '*')][state]

def main():
    """
    Main function to process ZIP and KTR files, extract connection details, and output the results.
    This function parses command-line arguments to determine the path to the input files or directory,
    the output CSV file path, and an optional custom seed for decryption. It supports processing individual
    ZIP or KTR files, as well as directories containing multiple ZIP and KTR files.
    The function performs the following steps:
    1. Sets up command-line argument parsing.
    2. Configures tab completion for file paths.
    3. Validates the existence of the specified path.
    4. Processes ZIP and KTR files to extract connection details.
    5. Collects unique connection strings, user:pass pairs, and 'sa' user:pass@server pairs.
    6. Outputs the results to a CSV file or prints them to the terminal.
    Command-line arguments:
    --path, -p: Path to the ZIP file, KTR file, or directory containing ZIP and KTR files (default: current directory).
    --output, -o: Path to the output CSV file (default: None, prints to terminal).
    --seed, -s: Custom seed for decryption (default: None).
    Returns:
    None
    """
    parser = argparse.ArgumentParser(description='Process ZIP files and KTR files.')
    parser.add_argument('--path', '-p', help='Path to the ZIP file, KTR file, or directory containing ZIP and KTR files', default='.')
    parser.add_argument('--output', '-o', type=str, help='Path to the output CSV file', default=None)
    parser.add_argument('--seed', '-s', type=str, help='Custom seed for decryption', default=None)
    args = parser.parse_args()

    readline.set_completer_delims('\t')
    readline.parse_and_bind("tab: complete")
    readline.set_completer(path_completer)

    path = args.path
    output_file = args.output if args.output else 'output.csv'
    custom_seed = args.seed

    if not os.path.exists(path):
        logging.error(f"Error: {path} does not exist.")
        return

    connection_details = []
    unique_connections = set()
    unique_user_pass_pairs = set()
    sa_user_pairs = set()  # Use a set to store unique (server, username, password) pairs for 'sa' users
    zip_file_count = 0
    ktr_file_count = 0

    ktr_files_in_zip = None  # Initialize the variable

    if os.path.isfile(path):
        if path.endswith('.zip'):
            zip_file_count += 1

            ktr_files_in_zip = get_ktr_files_from_zip(path)
            if not ktr_files_in_zip:
                return

            for ktr_file in ktr_files_in_zip:
                root = parse_xml_from_zip(path, ktr_file)
                if root is not None:
                    collect_connection_details(root, ktr_file, connection_details, unique_connections, unique_user_pass_pairs, sa_user_pairs, custom_seed)
                    ktr_file_count += 1
        elif path.endswith('.ktr'):
            ktr_file_count += 1

            root = parse_xml_file(path)
            if root is not None:
                collect_connection_details(root, path, connection_details, unique_connections, unique_user_pass_pairs, sa_user_pairs, custom_seed)
    elif os.path.isdir(path):
        ktr_files = [f for f in glob.glob(os.path.join(path, '*.ktr')) if os.path.isfile(f)]
        zip_files = [f for f in glob.glob(os.path.join(path, '*.zip')) if os.path.isfile(f)]

        if not ktr_files and not zip_files:
            logging.info(f"No .ktr or .zip files found in directory: {path}")
            return

        for zip_path in zip_files:
            zip_file_count += 1

            ktr_files_in_zip = get_ktr_files_from_zip(zip_path)
            if not ktr_files_in_zip:
                continue

            for ktr_file in ktr_files_in_zip:
                root = parse_xml_from_zip(zip_path, ktr_file)
                if root is not None:
                    collect_connection_details(root, ktr_file, connection_details, unique_connections, unique_user_pass_pairs, sa_user_pairs, custom_seed)
                    ktr_file_count += 1

        for ktr_file in ktr_files:
            ktr_file_count += 1

            root = parse_xml_file(ktr_file)
            if root is not None:
                collect_connection_details(root, ktr_file, connection_details, unique_connections, unique_user_pass_pairs, sa_user_pairs, custom_seed)
    
    print(f"[+] Processed {zip_file_count} ZIP files and {ktr_file_count} KTR files.")
    print(f"[+] Unique connection strings: {len(unique_connections)}")
    print(f"[+] Unique user:pass pairs: {len(unique_user_pass_pairs)}")
    print(f"[+] Unique 'sa' user:pass@server pairs: {len(sa_user_pairs)}")

    if args.output:
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['ktr_file', 'server', 'type', 'database', 'port', 'username', 'password']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for detail in connection_details:
                writer.writerow(detail)
        print(f"[+] Output written to {output_file}")
    else:
        # Print headers to terminal
        print("ktr_file,server,type,database,port,username,password")
        # Print each detail in CSV format
        for detail in connection_details:
            print(f"{detail['ktr_file']},{detail['server']},{detail['type']},{detail['database']},{detail['port']},{detail['username']},{detail['password']}")

if __name__ == "__main__":
    main()