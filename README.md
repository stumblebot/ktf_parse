# Pentaho Kettle Decrypt Tools
## Recovering passwords from KTR files
Pentaho Kettle Transformation files may contain 'Encrypted' password values. I type in quotes because, while these strings include the text 'Encrypted', they're the result of the plaintext password and a default key (referred to in the Kettle codebase as a 'seed') [being XOR'd](https://github.com/pentaho/pentaho-kettle/blob/master/core/src/main/java/org/pentaho/di/core/encryption/KettleTwoWayPasswordEncoder.java#L123). The official documentation condeeds: 
>[Note that it's not really encryption, it's more obfuscation. Passwords are difficult to read, not impossible.](https://javadoc.pentaho.com/kettle800/kettle-core-8.0.0.0-6-javadoc/org/pentaho/di/core/encryption/KettleTwoWayPasswordEncoder.html). 

KTR files contain xml-formatted text which define some series of actions that the server should perform when they are executed. They seem to mostly contain database connection information in the `<connection>` element. Supported database types appear to include:
- Generic Database
- H2
- Hypersonic
- MSSQL
- MonetDB
- Pentaho Data Services
- PostgreSQL
- Teradata
- SparkSQL
- Cloudera Impala
- Impala
- Hadoop Hive 2
- Oracle
- MYSQL
- MS Access
- Sybase

I have also observed `<step>` elements containing spots to configure credentials for other service types, including:
- LDAP
- SMTP

Finally, `<slaveservers>` elements contain connection information for other Pentaho Data Clients servers.

An attacker who has valid credentials on an instance of Pentaho Data Client may be able to download a large number of KTR files, usually embedded in a ZIP archive, through the 'Browse Files' feature of the webapp. You might also get lucky and find them somewhere else!

There are [some](https://github.com/Riktastic/Pentaho-Kettle-Password-Decrypt) [nice](https://zineausa.com/blog/2020/07/pen-test-guide-to-pentaho-business-analytics/) [resources](https://diethardsteiner.github.io/pdi/2017/03/03/PDI-Password-Encryption.html) that I found, discussing how to recover passwords using KTR files or other Pentaho/Kettle resources. They work! I used them initially when recovering these passwords, but frankly they're a little cumbersome and/or require relatively large installs to run. I wanted to make something that was smaller and much easier to use!

`ktr_parse.py` facilitates parsing 'Encrypted' passwords and other relevant data from KTR files. The tool can be directed at individual KTR files, individual ZIP files that contain KTR files, or a directory that contains either. Passwords can be decrypted using the default key set by Pentaho or using other keys that may be recovered using `key_recovery.py`.

## Recovering non-default 'Encryption' keys

Admins of Pentaho servers that use KTR files or other Kettle resources may opt to change their key to another value to avoid using the default. This is more secure than sticking with the default key but, since the XOR operation is linear, an attacker who knows the plaintext and ciphertext can dervive the key by XORing them together. 

    plaintext xor seed == ciphertext
    plaintext xor ciphertext == seed 

An attacker who has valid credentials on an instance of Pentaho Data Client may be able to recover a plaintext/ciphertext pair by through various methods including:

1. Create or obtain a plaintext password for a service with an 'Encrypted' password that you cannot recover using the default key.
    - By creating a new database connection or other connection string, the attacker would be able to set a known plaintext.
    - By temporarily modifying the database connection from within the Pentaho Data Client webapp to reference a stand-in service which is owned by the attacker and clicking the 'test' button, an attacker may be able to coerce the into sending an authentication request to them. This may take the form of a plaintext password. 
2. By downloading the KTR file that corresponds with the connection used in step 1, the attacker would be able to recover the 'Encrypted' password string that was created using the plaintext password and the currently unknown 'seed'.
3. XORing these strings together, the attacker could recover the 'seed' and use it to to recover the other 'Encrypted' passwords that were created using it.

`key_recovery.py` facilitates recovering the XOR key (aka: 'seed') from a given plaintext password and 'Encrypted' password pair. 

## Tools

1. [KTR Parse](#ktr-parse)
2. [Key Recovery](#key-recovery)

## KTR Parse

`ktr_parse.py` is a script to process ZIP files and KTR files, extract connection details, and output the results to a CSV file or print them to the terminal.

### Usage

```
python3 ktr_parse.py --path <path_to_zip_or_ktr> [--output <output_csv>] 
    [--seed <custom_seed>]
```

### Arguments
--path, -p: Path to the ZIP file, KTR file, or directory containing ZIP and KTR files (default: current directory).\
--output, -o: Path to the output CSV file (default: None, prints to terminal).\
--seed, -s: Custom seed for decryption (default: None).

### Example 1: Decrypt with default key
```
python3 ktr_parse.py --path ./ktr_files --output output.csv
```
### Example 2: Decrypt with user-supplied key
```
python3 ktr_parse.py --path ./ktr_files --output output.csv --seed 1234567890123456789012345678901234567890
```

### Functionality
--Parses connection elements and step elements from KTR files.\
--Decrypts passwords using a custom seed if provided.\
--Counts unique connection strings, user:pass pairs, and 'sa' user:pass@server pairs.\
--Outputs the results to a CSV file or prints them to the terminal.\
--Key Recovery\
--key_recovery.py is a script to recover the seed used for encryption by XORing the plaintext and ciphertext.\

## Key Recovery
`key_recovery.py` is a script to recover the seed used for encryption by XORing the plaintext and ciphertext.

### Usage
```
python3 key_recovery.py --plaintext <plaintext> --ciphertext <ciphertext>
```

### Arguments
--plaintext, -p: The plaintext password you know or have set, corresponding 
    with ciphertext from a ktr file.\
--ciphertext, -c: The ciphertext aka 'Encrypted ' password value from a ktr 
    file whose plaintext password you already know.

### Example
```
python3 key_recovery.py -p password -c 2be98afc86aa7f2e4bb18bd63c99dbdde
Recovered seed: 933910847463829827159347601486730416058
```

### Functionality
Recovers the seed value used in the encryption process by XORing the plaintext and ciphertext.

# Thanks
Thanks to [Haicen](https://blog.haicen.me/) for pointing out how simple it would be to recover the 'seed' for anyone who already knew a valid plaintext/ciphertext combo and saving us all a lot of time as a result. 

# References
1. Pentaho Kettle source code that includes the `decryptPasswordInternal` function, used for decrypting the 'Encrypted' values and the default `envSeed` value: [Pentaho Kettle: KettleTwoWayPasswordEncoder.java](https://github.com/pentaho/pentaho-kettle/blob/master/core/src/main/java/org/pentaho/di/core/encryption/KettleTwoWayPasswordEncoder.java#L123). 
2. Pentaho's official documentation for class: [`KettleTwoWayPasswordEncoder`](https://javadoc.pentaho.com/kettle800/kettle-core-8.0.0.0-6-javadoc/org/pentaho/di/core/encryption/KettleTwoWayPasswordEncoder.html). 
3. Riktastic's KTF that executes the (now deprecated) `decryptPassword` function: [DecryptPassword.ktr](https://github.com/Riktastic/Pentaho-Kettle-Password-Decrypt/blob/master/Decrypt_password.ktr)
4. A nice writeup by zinea llc (aka [serialenabler(???)](https://github.com/serialenabler)) on the process of preparing and using `DecryptPassword.ktr`: [Pentest Guide to Pentaho Business Analytics](https://zineausa.com/blog/2020/07/pen-test-guide-to-pentaho-business-analytics/)
5. Another reference to some of the encrypt/decrypt functions and how they are used in existing one-off utilities within the larger Pentaho Data Integration toolkit: [PDI Password Encryption](https://diethardsteiner.github.io/pdi/2017/03/03/PDI-Password-Encryption.html)
