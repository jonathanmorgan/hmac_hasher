#==============================================================================#
# imports
#==============================================================================#

# imports
import csv
import os
import six
import sys

# HMACHasher
from hmac_hasher import HMACHasher

#==============================================================================#
# CONSTANTS-ish
#==============================================================================#


TEST_PASSPHRASE = "fakedata"
TEST_INPUT_FILE_PATH = "./Fake_Data_Test.csv"
TEST_OUTPUT_FILE_PATH = "./Fake_Data_Test_Output.csv"

# expected results names
NAME_EXPECTED_SSN = "SSN"
NAME_EXPECTED_FNAME = "FNAME"
NAME_EXPECTED_MNAME = "MNAME"
NAME_EXPECTED_LNAME = "LNAME"


#==============================================================================#
# declare variables
#==============================================================================#

# declare variables
status_message_list = []
status_message = ""
command_line_arguments = None
ini_file_path = None

# declare variables - hashing
hmac_hasher = None
load_config_status_list = None
hashing_status_list = None

# declare variables - testing
expected_results = {}
current_results_map = {}
test_result_csv_file = None
test_result_csv_reader = None
current_record = None
PK = ""
SSN = ""
FNAME = ""
MNAME = ""
LNAME = ""
expected_SSN = ""
expected_FNAME = ""
expected_MNAME = ""
expected_LNAME = ""


#==============================================================================#
# Build expected results
#==============================================================================#


# ==> PK 555555
current_results_map = {}
current_results_map[ NAME_EXPECTED_SSN ] = "a69ecf70cab21fdc100165faceaf87f04d0b9fb50d4dc627b04d7e5554a38bc0"
current_results_map[ NAME_EXPECTED_FNAME ] = "a0c82465bc168bfc72b7e4aab39bfa74debfa4b785f16976eb0248455be03d14"
current_results_map[ NAME_EXPECTED_MNAME ] = "e60d8aa3a723832d2b298fd2e415d75c8d1ec1c273573d0480b7233ef8021310"
current_results_map[ NAME_EXPECTED_LNAME ] = "70dba5087a8ab6789d53bc26b02e598c31e2701fe5d8b450a9e4fcbe5eaf296b"

# add to expected results, associated with PK
expected_results[ "555555" ] = current_results_map

# ==> PK 10101010
current_results_map = {}
current_results_map[ NAME_EXPECTED_SSN ] = "5a823abdcc524029e5497e29d65486cf69befc714758b60edf5113748afd79e3"
current_results_map[ NAME_EXPECTED_FNAME ] = "f315ed89f0cb43c52b96aae0003b4adfd5cbd61f3fc1a3e72075533eb73332af"
current_results_map[ NAME_EXPECTED_MNAME ] = "4c4768fb4c07d15651adb24f9dbd7f036c226cbf0c26cc5232a1738d59a5337f"
current_results_map[ NAME_EXPECTED_LNAME ] = "12cfb1171ef0103a81afa8c37414e232e0931e544d6c4ecc599b995312597f38"

# add to expected results, associated with PK
expected_results[ "10101010" ] = current_results_map

# ==> PK 346712
current_results_map = {}
current_results_map[ NAME_EXPECTED_SSN ] = "5f552e4659d4604b44049cc4a70d82b86c4453a0f4a88d7af2df03e8596ac4ad"
current_results_map[ NAME_EXPECTED_FNAME ] = "15a70ba92649d971a4c4b2c68aa98f52527cc29399e25e57e5aa6ae4df41bbad"
current_results_map[ NAME_EXPECTED_MNAME ] = "5218afe466a5aedd298e84c8a60a0293f7407cb46ce64f9cc1fe2fd591a35cff"
current_results_map[ NAME_EXPECTED_LNAME ] = "8a8afb5eaaa282f6132f88562a4502272c8bfa3514e0327e85d4f76a2b271ced"

# add to expected results, associated with PK
expected_results[ "346712" ] = current_results_map

# ==> PK 987654
current_results_map = {}
current_results_map[ NAME_EXPECTED_SSN ] = "27becbaca10ec9cf7f2bbb4c0bece17999cad56d2d14fa5282ac2bbc5f7a82ec"
current_results_map[ NAME_EXPECTED_FNAME ] = "c4cda429751d60bebdb9624ea19c195bb4111af011524128e30b4854d5104baa"
current_results_map[ NAME_EXPECTED_MNAME ] = "c41d324c94ab58469f00c85564fe444d5dc18c3b8c8a83cef9883a37c8889485"
current_results_map[ NAME_EXPECTED_LNAME ] = "722b8277d9828ba4537d130ec31611d9104f740c1bdc8311a2086dbdbc78178a"

# add to expected results, associated with PK
expected_results[ "987654" ] = current_results_map

# ==> PK 23232323
current_results_map = {}
current_results_map[ NAME_EXPECTED_SSN ] = "cc559eb94e32af592d37a9b631a22d7ee320620d24020d59bc56b6019a593ee4"
current_results_map[ NAME_EXPECTED_FNAME ] = "2ccae105615b7a58714b580f3d6320b9f7fe7b11463e3a773981a0fb2fdd44b5"
current_results_map[ NAME_EXPECTED_MNAME ] = "11acfc917b5b8a25608085a9a9781b60b0ed8ded17fafd73d294a151c364ed81"
current_results_map[ NAME_EXPECTED_LNAME ] = "96ccc9b53ef91dc48a6ef634c5d73394b82ea4dbe2d950ea13f6395ad2c2f6b1"

# add to expected results, associated with PK
expected_results[ "23232323" ] = current_results_map


#==============================================================================#
# Hard-code configuration and process test file
#==============================================================================#

# create HMACHasher instance
hmac_hasher = HMACHasher()

# configure
hmac_hasher.set_passphrase( TEST_PASSPHRASE )
hmac_hasher.input_file_path = TEST_INPUT_FILE_PATH
hmac_hasher.output_file_path = TEST_OUTPUT_FILE_PATH
hmac_hasher.has_header_row = True

# no errors loading config - process file.
hashing_status_list = hmac_hasher.process_file()

# errors?
if ( len( hashing_status_list ) > 0 ):

    # add list of errors to master list, do not process file.
    status_message_list.extend( hashing_status_list )

else:

    # open output file in a CSV reader.
    # Python 3 only - with open( TEST_OUTPUT_FILE_PATH, encoding = hmac_hasher.output_file_encoding ) as test_result_csv_file:
    with open( TEST_OUTPUT_FILE_PATH ) as test_result_csv_file:

        # get a CSV reader
        test_result_csv_reader = csv.reader( test_result_csv_file )

        # skip header row
        current_record = six.next( test_result_csv_reader )

        # loop over records
        line_counter = 0
        for current_record in test_result_csv_reader:

            # initialize values
            PK = ""
            SSN = ""
            FNAME = ""
            MNAME = ""
            LNAME = ""

            # increment line counter
            line_counter += 1

            # get values (check if positions are correct)
            PK = current_record[ hmac_hasher.CSV_INDEX_PK ]
            SSN = current_record[ hmac_hasher.CSV_INDEX_SSN ]
            FNAME = current_record[ hmac_hasher.CSV_INDEX_FIRST_NAME ]
            MNAME = current_record[ hmac_hasher.CSV_INDEX_MIDDLE_NAME ]
            LNAME = current_record[ hmac_hasher.CSV_INDEX_LAST_NAME ]

            # retrieve results for the PK.
            if ( PK in expected_results ):

                # get results
                current_results_map = expected_results.get( PK, None )

                # retrieve expected values.
                expected_SSN = current_results_map[ NAME_EXPECTED_SSN ]
                expected_FNAME = current_results_map[ NAME_EXPECTED_FNAME ]
                expected_MNAME = current_results_map[ NAME_EXPECTED_MNAME ]
                expected_LNAME = current_results_map[ NAME_EXPECTED_LNAME ]

                # The moment of truth

                # ==> SSN
                if ( SSN != expected_SSN ):
                    status_message = "ERROR - PK " + str( PK ) + " - SSN \"" + str( SSN ) + "\" != \"" + str( expected_SSN ) + "\""
                    status_message_list.append( status_message )
                #-- END check of SSN --#

                # ==> FNAME
                if ( FNAME != expected_FNAME ):
                    status_message = "ERROR - PK " + str( PK ) + " - FNAME \"" + str( FNAME ) + "\" != \"" + str( expected_FNAME ) + "\""
                    status_message_list.append( status_message )
                #-- END check of FNAME. --#

                # ==> MNAME
                if ( MNAME != expected_MNAME):
                    status_message = "ERROR - PK " + str( PK ) + " - MNAME \"" + str( MNAME ) + "\" != \"" + str( expected_MNAME ) + "\""
                    status_message_list.append( status_message )
                #-- END check of MNAME. --#

                # ==> LNAME
                if ( LNAME != expected_LNAME ):
                    status_message = "ERROR - PK " + str( PK ) + " - LNAME \"" + str( LNAME ) + "\" != \"" + str( expected_LNAME ) + "\""
                    status_message_list.append( status_message )
                #-- END check of LNAME. --#

            else:

                # No PK match - big trouble
                status_message = "ERROR - No PK match for PK " + str( PK ) + " - wrong input file?"
                status_message_list.append( status_message )

            #-- END check to see if PK match. --#

        #-- END loop over input lines.

    #-- END with ... test_result_csv_file --#

#-- END check to see if errors. --#

# status messages?
if ( len( status_message_list ) > 0 ):

    print( "\nstatus messages:" )
    for status_message in status_message_list:

        print( "- " + status_message )

    #-- END loop over status messages --#

else:

    print( "\nNo status messages - SUCCESS!" )

#-- END check for status messages. --#

print( "\n" )
