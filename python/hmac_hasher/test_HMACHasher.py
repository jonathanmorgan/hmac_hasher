# imports
import os
from hmac_hasher import HMACHasher

# test SSN cleaning.
def test_standardize_ssn():

    # initialize
    hmac_hasher = HMACHasher()

    input = "123456789"
    expected_output = "123456789"
    actual_output = hmac_hasher.standardize_ssn( input )
    assert expected_output == actual_output

    input = "123-45-6789"
    expected_output = "123456789"
    actual_output = hmac_hasher.standardize_ssn( input )
    assert expected_output == actual_output

    input = " 1234-56789  "
    expected_output = "123456789"
    actual_output = hmac_hasher.standardize_ssn( input )
    assert expected_output == actual_output

    input = "1234-56789  "
    expected_output = "123456789"
    actual_output = hmac_hasher.standardize_ssn( input )
    assert expected_output == actual_output

    input = "   1234-56789"
    expected_output = "123456789"
    actual_output = hmac_hasher.standardize_ssn( input )
    assert expected_output == actual_output

    input = "1234-^?56789"
    expected_output = "123456789"
    actual_output = hmac_hasher.standardize_ssn( input )
    assert expected_output == actual_output

    input = "   1234-5     6789  "
    expected_output = "12345 6789"
    actual_output = hmac_hasher.standardize_ssn( input )
    assert expected_output == actual_output

    input = "   1234-^?567    89 "
    expected_output = "1234567 89"
    actual_output = hmac_hasher.standardize_ssn( input )
    assert expected_output == actual_output

#-- END function test_standardize_ssn() --#


# test Name cleaning.
def test_standardize_name():

    # initialize
    hmac_hasher = HMACHasher()

    input = "MORGAN"
    expected_output = "MORGAN"
    actual_output = hmac_hasher.standardize_name( input )
    assert expected_output == actual_output

    input = "Morgan"
    expected_output = "MORGAN"
    actual_output = hmac_hasher.standardize_name( input )
    assert expected_output == actual_output

    input = " Morgan "
    expected_output = "MORGAN"
    actual_output = hmac_hasher.standardize_name( input )
    assert expected_output == actual_output

    input = "  Morgan"
    expected_output = "MORGAN"
    actual_output = hmac_hasher.standardize_name( input )
    assert expected_output == actual_output

    input = "Morgan "
    expected_output = "MORGAN"
    actual_output = hmac_hasher.standardize_name( input )
    assert expected_output == actual_output

    input = "  Mo    rgan  "
    expected_output = "MO    RGAN"
    actual_output = hmac_hasher.standardize_name( input )
    assert expected_output == actual_output

    input = "Morga='n"
    expected_output = "MORGA='N"
    actual_output = hmac_hasher.standardize_name( input )
    assert expected_output == actual_output

    input = "  Mo    rga='n  "
    expected_output = "MO    RGA='N"
    actual_output = hmac_hasher.standardize_name( input )
    assert expected_output == actual_output

    # test additional formatting options
    
    # compact white space
    input = "  Mo    rgan  "
    expected_output = "MO RGAN"
    actual_output = hmac_hasher.standardize_name( input, do_compact_white_space_IN = True )
    assert expected_output == actual_output

    # remove punctuation
    input = "Morga='n"
    expected_output = "MORGAN"
    actual_output = hmac_hasher.standardize_name( input, do_remove_punctuation_IN = True )
    assert expected_output == actual_output

    # lower instead of upper
    input = "Morgan"
    expected_output = "morgan"
    actual_output = hmac_hasher.standardize_name( input, convert_to_case_IN = hmac_hasher.STRING_LOWER_CASE )
    assert expected_output == actual_output    

    # all at once.
    input = "  Mo    rga='n  "
    expected_output = "mo rgan"
    actual_output = hmac_hasher.standardize_name( input, do_compact_white_space_IN = True, do_remove_punctuation_IN = True, convert_to_case_IN = hmac_hasher.STRING_LOWER_CASE )
    assert expected_output == actual_output

#-- END function test_standardize_name() --#


# test string standardization.
def test_standardize_string():

    # initialize
    hmac_hasher = HMACHasher()

    input = "MORGAN"
    expected_output = "MORGAN"
    actual_output = hmac_hasher.standardize_string( input )
    assert expected_output == actual_output

    input = "Morgan"
    expected_output = "MORGAN"
    actual_output = hmac_hasher.standardize_string( input )
    assert expected_output == actual_output

    input = " Morgan "
    expected_output = "MORGAN"
    actual_output = hmac_hasher.standardize_string( input )
    assert expected_output == actual_output

    input = "  Morgan"
    expected_output = "MORGAN"
    actual_output = hmac_hasher.standardize_string( input )
    assert expected_output == actual_output

    input = "Morgan "
    expected_output = "MORGAN"
    actual_output = hmac_hasher.standardize_string( input )
    assert expected_output == actual_output

    input = "  Mo    rgan  "
    expected_output = "MO    RGAN"
    actual_output = hmac_hasher.standardize_string( input )
    assert expected_output == actual_output

    input = "Morga='n"
    expected_output = "MORGA='N"
    actual_output = hmac_hasher.standardize_string( input )
    assert expected_output == actual_output

    input = "  Mo    rga='n  "
    expected_output = "MO    RGA='N"
    actual_output = hmac_hasher.standardize_string( input )
    assert expected_output == actual_output

    # test additional formatting options
    
    # compact white space
    input = "  Mo    rgan  "
    expected_output = "MO RGAN"
    actual_output = hmac_hasher.standardize_string( input, do_compact_white_space_IN = True )
    assert expected_output == actual_output

    # remove punctuation
    input = "Morga='n"
    expected_output = "MORGAN"
    actual_output = hmac_hasher.standardize_string( input, do_remove_punctuation_IN = True )
    assert expected_output == actual_output

    # lower instead of upper
    input = "Morgan"
    expected_output = "morgan"
    actual_output = hmac_hasher.standardize_string( input, convert_to_case_IN = hmac_hasher.STRING_LOWER_CASE )
    assert expected_output == actual_output    

    # all at once.
    input = "  Mo    rga='n  "
    expected_output = "mo rgan"
    actual_output = hmac_hasher.standardize_string( input, do_compact_white_space_IN = True, do_remove_punctuation_IN = True, convert_to_case_IN = hmac_hasher.STRING_LOWER_CASE )
    assert expected_output == actual_output

#-- END function test_standardize_string() --#


# test setting passphrase (and so the hash key)
def test_set_passphrase():

    # initialize
    hmac_hasher = HMACHasher()

    # set passphrase
    input = "fakedata"
    hmac_hasher.set_passphrase( input )

    # test that passphrase stored
    expected_output = "fakedata"
    actual_output = hmac_hasher.passphrase
    assert expected_output == actual_output

    # test key value
    expected_output = "8f50a1b24abc24aebb1b4b67745f4d8776ffeb5183ad1ebc6296def10e8f3150"
    actual_output = hmac_hasher.hmac_key_hash_instance.hexdigest()
    assert expected_output == actual_output

#-- END test_set_passphrase() --#


# test setting passphrase (and so the hash key)
def test_hash_value():

    # initialize
    hmac_hasher = HMACHasher()

    # set passphrase
    hmac_hasher.set_passphrase( "fakedata" )

    # test hashing
    input = "Calliope"
    expected_output = "ffa3be8150b4c6aa6c6939411daf1419310f3851a285e27536fd2070aadd7900"
    actual_output = hmac_hasher.hash_value( input )
    assert expected_output == actual_output

    input = "CalLIOpe"
    expected_output = "0fd783a8226cf946b2825673ec0c2cb88e2b115c48491bbddf47f99ff510c05d"
    actual_output = hmac_hasher.hash_value( input )
    assert expected_output == actual_output

    input = "CALLIOPE"
    expected_output = "170c422bf7af219bdd28c876e50359e6fecc0234b790e25e89c59ef65b29277a"
    actual_output = hmac_hasher.hash_value( input )
    assert expected_output == actual_output

#-- END test_set_passphrase() --#


def test_hash_value_plus_standardize_ssn():

    # initialize
    hmac_hasher = HMACHasher()
    expected_output = "a69ecf70cab21fdc100165faceaf87f04d0b9fb50d4dc627b04d7e5554a38bc0"

    # set passphrase
    hmac_hasher.set_passphrase( "fakedata" )

    input = "123456789"
    input = hmac_hasher.standardize_ssn( input )
    actual_output = hmac_hasher.hash_value( input )
    assert expected_output == actual_output

    input = "123-45-6789"
    input = hmac_hasher.standardize_ssn( input )
    actual_output = hmac_hasher.hash_value( input )
    assert expected_output == actual_output

    input = " 1234-56789  "
    input = hmac_hasher.standardize_ssn( input )
    actual_output = hmac_hasher.hash_value( input )
    assert expected_output == actual_output

    input = "1234-56789  "
    input = hmac_hasher.standardize_ssn( input )
    actual_output = hmac_hasher.hash_value( input )
    assert expected_output == actual_output

    input = "   1234-56789"
    input = hmac_hasher.standardize_ssn( input )
    actual_output = hmac_hasher.hash_value( input )
    assert expected_output == actual_output

#-- END function test_hash_value_plus_standardize_ssn() --#


def test_hash_value_plus_standardize_name():

    # initialize
    hmac_hasher = HMACHasher()
    expected_output = "170c422bf7af219bdd28c876e50359e6fecc0234b790e25e89c59ef65b29277a"

    # set passphrase
    hmac_hasher.set_passphrase( "fakedata" )

    # test hashing plus standardize_name()
    input = "CalLIOpe"
    input = hmac_hasher.standardize_name( input )
    actual_output = hmac_hasher.hash_value( input )
    assert expected_output == actual_output

    input = "  CALLIOPE  "
    input = hmac_hasher.standardize_name( input )
    actual_output = hmac_hasher.hash_value( input )
    assert expected_output == actual_output

    input = "Calliope "
    input = hmac_hasher.standardize_name( input )
    actual_output = hmac_hasher.hash_value( input )
    assert expected_output == actual_output

#-- END test_hash_value_plus_standardize_name() --#


def test_load_configuration_from_ini_file():

    '''
    Assumes that there is an ini file named "hashing_configuration.ini" in the
        current directory that contains:

    [secret]

    passphrase=fakedata

    [file_paths]

    input_file_path=./Fake_Data_Test.csv
    ;output_file_path=./hashed_output.csv
    '''

    # initialize
    hmac_hasher = HMACHasher()
    ini_file_path = "./hashing_configuration.ini"
    load_message_list = None

    # ==> first, test loading by passing path into method.
    load_message_list = hmac_hasher.load_configuration_from_ini_file( ini_file_path, require_input_file_path_IN = True )
    assert len( load_message_list ) == 0

    # test that passphrase stored
    expected_output = "fakedata"
    actual_output = hmac_hasher.passphrase
    assert expected_output == actual_output

    # test key value
    expected_output = "8f50a1b24abc24aebb1b4b67745f4d8776ffeb5183ad1ebc6296def10e8f3150"
    actual_output = hmac_hasher.hmac_key_hash_instance.hexdigest()
    assert expected_output == actual_output

    # test that input file path stored
    expected_output = "./Fake_Data_Test.csv"
    actual_output = hmac_hasher.input_file_path
    assert expected_output == actual_output

    # test that output file path derived correctly
    expected_output = "HASHED-Fake_Data_Test.csv"
    actual_output = hmac_hasher.output_file_path
    assert expected_output == actual_output

    # test that output file path derived correctly
    expected_output = True
    actual_output = hmac_hasher.has_header_row
    assert expected_output == actual_output

    # ==> next, test by storing ini file path in instance.
    hmac_hasher.configuration_ini_file_path = ini_file_path
    load_message_list = hmac_hasher.load_configuration_from_ini_file( require_input_file_path_IN = True )
    assert len( load_message_list ) == 0

    # test that passphrase stored
    expected_output = "fakedata"
    actual_output = hmac_hasher.passphrase
    assert expected_output == actual_output

    # test key value
    expected_output = "8f50a1b24abc24aebb1b4b67745f4d8776ffeb5183ad1ebc6296def10e8f3150"
    actual_output = hmac_hasher.hmac_key_hash_instance.hexdigest()
    assert expected_output == actual_output

    # test that input file path stored
    expected_output = "./Fake_Data_Test.csv"
    actual_output = hmac_hasher.input_file_path
    assert expected_output == actual_output

    # test that output file path derived correctly
    expected_output = "HASHED-Fake_Data_Test.csv"
    actual_output = hmac_hasher.output_file_path
    assert expected_output == actual_output

    # test missing file
    ini_file_path = "./this_file_is_almost_certainly_not_here.ini"
    load_message_list = hmac_hasher.load_configuration_from_ini_file( ini_file_path, require_input_file_path_IN = True )
    assert len( load_message_list ) > 0


#-- END function test_load_configuration_from_ini_file() --#


def test_process_file():

    '''
    Assumes that there is an ini file named "hashing_configuration.ini" in the
        current directory that contains:

        [secret]

        passphrase=fakedata

        [file_paths]

        input_file_path=./Fake_Data_Test.csv
        ;output_file_path=./hashed_output.csv

        [configuration]
        has_header_row=true

    And assumes that "Fake_Data_Test.csv" is in the current directory, as well.
    '''

    # initialize
    hmac_hasher = HMACHasher()
    ini_file_path = "./hashing_configuration.ini"
    load_message_list = hmac_hasher.load_configuration_from_ini_file( ini_file_path, require_input_file_path_IN = True )
    assert len( load_message_list ) == 0

    # test process_file
    process_file_message_list = hmac_hasher.process_file()
    assert len( process_file_message_list ) == 0
    assert os.path.exists( hmac_hasher.output_file_path ) == True

    # test missing file
    csv_file_path = "./this_file_is_almost_certainly_not_here.ini"
    hmac_hasher.input_file_path = csv_file_path
    process_file_message_list = hmac_hasher.process_file()
    assert len( process_file_message_list ) > 0

#-- END function test_load_configuration_from_ini_file() --#