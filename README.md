# HMAC Hasher

This project includes source code and example Jupyter notebooks for a configurable HMAC Hasher, a class that uses the HMAC encryption algorithm to distribute the information from a secret uniformly through a value that is being obfuscated, rather than combining a salt with each value based on some algorithm, and the hashing.  The end result is the same, however - a given value will get the same resulting obfuscated value each time it is run through the HMAC Hasher with the same secret.

The HMAC hasher itself has been written to support either Python 2 or Python 3.  The example code for generating secrets (or salts, in the terminology of hashing) uses the Python 3.6 "secrets" package, and so  does not support Python 2 or versions of Python 3 earlier than 3.6.  The basic algorithm laid out in this notebook could be implemented with other libraries in other versions of Python, however.

## Repository Contents

- `README.md` - this file - overview of contents of repository and setup instructions.
- `requirements.txt` - list of Python packages needed to run the code included in this  repository, for pip (it is just `six` at the moment).
- `Hashing-CSV-to-CSV.ipynb` - example file that shows process of hashing a set of data files in CSV format once salt/secrets have been generated and stored in configuration files.
- `/examples` - directory that includes sample code and example data files used in some examples.

    - `create_salt.py`  - plain Python 3.6 example code for generating a cryptographically sound salt/secret.
    - `create_salt.ipynb` - the same code, in a Jupyter notebook, in case you prefer that.
    - `Fake_Data_Test_001.csv` - first file of fake data used in `Hashing-CSV-to-CSV.ipynb`.
    - `Fake_Data_Test_002.csv` - second file of fake data used in `Hashing-CSV-to-CSV.ipynb`.

- `/hmac_hasher` - contains actual source code for HMAC Hasher, plus testing scripts and an example of running HMAC Hasher from the command line (a very tightly constrained use case).

## Creating a secret/salt

To create salts/secrets, you can use the code in either "`examples/create_salt.ipynb`" or "`examples/create_salt.py`" (the code itself is identical).

The string that is printed in the last statement in the code is the secret.  You can use it as-is, or add in a delimiter to make it easier to share verbally (hyphen every 5 characters, for example).


## Using the HMAC hasher

There are two ways to use the HMAC hasher in this repository:

- 1) as a standalone program that takes a CSV file and a single configuration (so a single secret/salt) and writes results of hashing all column values using the single shared secret to an output CSV, each column value in the same row as in the input file.  This is a basic use-case.
- 2) For more complex use cases (say, multiple files where a subset of columns need to be hashed, potentially with different secrets/salts per column or per type of information), one or more instances of the Python HMACHasher class can be created, initialized either programmatically or from INI files, and then used in a separate Python program to simply hash values.

## configuration INI file

The HMAC hasher configuration INI file that is used to configure either the standalone hashing program or a HMACHasher class instance has three sections:

- `secret` - for now, just contains the salt or secret.  Supported properties:
	- `passphrase` - string passphrase used to encrypt values with HMAC algorithm.
- `file_paths` - file paths used if program is run at command line.  If HMACHasher class is used in a Python program that handles input and output, these are not needed.  Supported properties:

    - `input_file_path` - path to file whose values we want hashed.
    - `output_file_path` - path to file where we want hashed values stored.

- `configuration` - other configuration options.  Supported properties:

    - `has_header_row` - boolean, "true" results in first row being output in clear text to output file, "false" results in values in first row being treated like all other rows, so hashed and output.

If you are using the standalone program, you'll want to properly configure all properties.  If you are just using the HMACHasher class to hash values in a program of your own design, you'll likely just need to set a `passphrase` in the `secret` section of the file (or forego the file entirely and configure in your Python code).

_Note: Having the secret in a separate file is useful should you ever want to share or version your code files - You are less likely to accidentally commit or share a secret if it is separate from the code that uses it._

## Testing

To run unit tests:

- make sure you have installed pytest (using pip, it is `pip install pytest`).
- in a command shell:

    - cd into the `hmac_hasher` folder.
    - run `pytest`

- if successful, you should see something like:

        ============================= test session starts ==============================
        platform darwin -- Python 3.6.4, pytest-3.2.1, py-1.4.34, pluggy-0.4.0
        rootdir: ./hmac_hasher, inifile:
        collected 9 items                                                               
        
        test_HMACHasher.py .........
        
        =========================== 9 passed in 0.05 seconds ===========================

To run the end-to-end test program:

- in a command shell:

    - cd into the `emac_hasher` folder.
    - run `python hash_tester.py`

- If successful, you should see something like:

        
        ==> Processing file: ./Fake_Data_Test.csv @ 2018-02-15 13:29:36.410136
        
        ==> Processing complete @ 2018-02-15 13:29:36.410998
        
        No status messages - SUCCESS!

## Example: Running standalone program

To run the standalone hashing program that hashes all values in all columns in a given file using a shared secret:

- in a command shell:

    - cd into the `hmac_hasher` folder.
    - run `python hash_program.py <ini_file_path>`

        - WHERE `<ini_file_path>` is the path to your INI file.

    - Example (can be run as-is in repository):

            python hash_program.py ./hashing_configuration.ini 


## Example: Using HMACHasher class instances in separate program

To see an example of the HMACHasher class being used in a standalone program, see the Jupyter notebook `Hashing-CSV-to-CSV.ipynb` in the root folder of this repository.

This jupyter notebook contains a more nuanced example where a CSV file is read in, some values are hashed, and then each row is written to a separate output file (if you need jupyter, consider installing Anaconda: [https://www.anaconda.com/download/](https://www.anaconda.com/download/)).

Notes:

- for each separate salt you want to use to hash a set of values (so, if separate salts for first name, last name, and SSN), you'll need to generate a salt value using "`create_salt.ipynb`", then store it in an INI file bsaed on the file "`hmac_hasher/hashing_configuration.ini`".
- In your INI file, if you will be only using the HMACHasher class for actually hashing values, not processing a file, then you will only need to correctly populate your passphrase in the secret section of these INI files.  The other configuration properties can be omitted.