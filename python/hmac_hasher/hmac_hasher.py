'''
This class implments HMAC hashing of CSV files.
'''

#==============================================================================#
# imports
#==============================================================================#


# Python imports
import copy
import csv
import datetime
import hashlib
import hmac
import os
import re
import string

# six imports
import six
from six.moves import configparser


#==============================================================================#
# class HMACHasher
#==============================================================================#


class HMACHasher( object ):

    #--------------------------------------------------------------------------#
    # CONSTANTs-ish
    #--------------------------------------------------------------------------#


    # DEBUG
    DEBUG = False

    # INI file configuration
    DEFAULT_INI_FILE_PATH = "./hashing_configuration.ini"

    # secret INI group
    INI_GROUP_SECRET = "secret"
    INI_VALUE_PASSPHRASE = "passphrase"

    # file paths INI group
    INI_GROUP_FILE_PATHS = "file_paths"
    INI_VALUE_INPUT_FILE_PATH = "input_file_path"
    INI_VALUE_OUTPUT_FILE_PATH = "output_file_path"
    DEFAULT_OUTPUT_FILE_PATH_PREFIX = "HASHED-"

    # configuration INI group
    INI_GROUP_CONFIGURATION = "configuration"
    INI_VALUE_HAS_HEADER_ROW = "has_header_row"

    # file details
    CSV_INDEX_PK = 0
    CSV_INDEX_SSN = 1
    CSV_INDEX_FIRST_NAME = 2
    CSV_INDEX_MIDDLE_NAME = 3
    CSV_INDEX_LAST_NAME = 4

    # encoding
    DEFAULT_FILE_ENCODING = "utf-8"

    # string case
    STRING_UPPER_CASE = "upper"
    STRING_LOWER_CASE = "lower"
    STRING_CASE_DEFAULT = STRING_UPPER_CASE


    #--------------------------------------------------------------------------#
    # init
    #--------------------------------------------------------------------------#


    def __init__( self ):

        # initialize instance variables.
        self.passphrase = None
        self.input_file_path = None
        self.output_file_path = None

        # configuration file path
        self.configuration_ini_file_path = self.DEFAULT_INI_FILE_PATH

        # file encoding
        self.input_file_encoding = self.DEFAULT_FILE_ENCODING
        self.output_file_encoding = self.DEFAULT_FILE_ENCODING

        # first row = column names?
        self.has_header_row = False

        # processing auditing
        self.message_every_x_lines = 10000

        # keys and hashing
        self.hmac_key_hash_function = hashlib.sha256
        self.hmac_hash_function = hashlib.sha256
        self.hmac_key_hash_instance = None
        self.hmac_key = None

        # debug
        self.debug_flag = self.DEBUG

    #-- END __init__() method --#


    #--------------------------------------------------------------------------#
    # class methods (in alphabetical order)
    #--------------------------------------------------------------------------#


    @classmethod
    def remove_extra_space( cls, string_IN ):
        
        '''given a string replace all multiple spaces with only one space'''
        
        # return reference
        value_OUT = None
        
        # got a string?
        if ( string_IN is not None ):
            
            # yup - sub in single space for multiple contiguous spaces.
            value_OUT = re.sub( ' +', ' ', string_IN )
            
        else:
            
            # nothing passed in - return None.
            value_OUT = None
            
        #-- END check to see if string passed in. --#
        
        return value_OUT

    #-- END class method remove_extra_space() --#


    @classmethod
    def strip_punctuation( cls, string_IN ):

        '''given a string, only return characters not in the list of punctuation'''
        
        # return reference
        value_OUT = None
        
        # declare variables.
        current_character = None
        character_list = None
        
        # got a string?
        if ( string_IN is not None ):
        
            # ''.join(c for c in s if c not in punctuation)
            character_list = []

            # loop over characters in string_IN
            for current_character in string_IN:

                # check to see if in punctuation
                if ( current_character not in string.punctuation ):
                    
                    # not punctuation - append to list of characters.
                    character_list.append( current_character )
                    
                #-- END check to see if current character is punctuation. --#
                
            #-- END loop over all characters in input string. --#
            
            # convert back to string
            value_OUT = "".join( character_list )
            
        else:
            
            # no string.  Return None.
            value_OUT = None
            
        #-- END check to see if string passed in. --#
            
        return value_OUT

    #-- END class method strip_punctuation() --#


    #--------------------------------------------------------------------------#
    # instance methods (in alphabetical order)
    #--------------------------------------------------------------------------#


    def hash_name_value( self, message_IN ):

        '''
        Accepts name value we want to hash. Standardizes the value, then calls
            hash_value() to do the actual hashing.
        '''

        # return reference
        value_OUT = None

        # declare variables
        standardized_value = ""

        # anything passed in?
        if ( ( message_IN is not None ) and ( message_IN != "" ) ):

            # standardize
            standardized_value = self.standardize_name( message_IN )

            # hash
            value_OUT =self.hash_value( standardized_value )

        else:

            # empty in, empty out
            value_OUT = "";

        #-- END check to see if message passed in. --#

        return value_OUT

    #-- END method hash_name_value() --#


    def hash_ssn_value( self, message_IN ):

        '''
        Accepts SSN value we want to hash. Standardizes the value, then calls
            hash_value() to do the actual hashing.
        '''

        # return reference
        value_OUT = None

        # declare variables
        standardized_value = ""

        # anything passed in?
        if ( ( message_IN is not None ) and ( message_IN != "" ) ):

            # standardize
            standardized_value = self.standardize_ssn( message_IN )

            # hash
            value_OUT =self.hash_value( standardized_value )

        else:

            # empty in, empty out
            value_OUT = "";

        #-- END check to see if message passed in. --#

        return value_OUT

    #-- END method hash_ssn_value() --#


    def hash_value( self, message_IN, allow_empty_string_IN = False ):

        '''
        Accepts value we want to hash.  Uses HMAC instance nested in this object
            to hash the value with the key/passphrase also nested here, returns
            the hashed value, else None if error.
        '''

        # return reference
        value_OUT = None

        # declare variables
        encoded_message = None
        hmac_instance = None
        hmac_key = None

        # anything passed in?
        if ( ( message_IN is not None ) and ( ( allow_empty_string_IN == True ) or ( message_IN != "" ) ) ):

            # encode
            encoded_message = message_IN.encode( "utf-8" )

            # get key.
            #hmac_instance = self.hmac_key_hash_instance
            #hmac_key = hmac_instance.digest()
            hmac_key = self.hmac_key

            # make hmac_instance
            hmac_instance = hmac.new( hmac_key, encoded_message, digestmod = self.hmac_hash_function )

            value_OUT = hmac_instance.hexdigest()

        else:

            # empty in, empty out
            value_OUT = "";

        #-- END check to see if message passed in. --#

        return value_OUT

    #-- END method hash_value() --#


    def load_configuration_from_ini_file( self, ini_file_path_IN = None, require_input_file_path_IN = False ):

        '''
        Accepts ini file path.  Checks to make sure there is something at that
            path, then opens the file and parses it using ConfigParser.  Tries
            to read properties that relate to instance variables in this object.
            Returns list of status messages, empty list if success.
        '''

        # return reference
        status_message_list_OUT = []

        # declare variables
        ini_file_path = None
        status_message_list = []
        status_message = ""
        config_file = None
        config_props = None

        # declare variables - configuration properties
        secret_section = None
        current_value = None
        passphrase = None
        file_paths_section = None
        input_file_path = None
        output_file_path = None
        absolute_path = None
        path_part_list = None
        configuration_section = None
        has_header_row = None

        # set ini file path.
        ini_file_path = ini_file_path_IN

        # anything passed in?
        if ( ( ini_file_path is None ) or ( ini_file_path == "" ) ):

            # no - use the value in instance.
            ini_file_path = self.configuration_ini_file_path

        #-- END check if anything passed in --#

        # got an INI file path?
        if ( ( ini_file_path is not None ) and ( ini_file_path != "" ) ):

            # load ini file.
            print( "\n==> Loading configuration from: " + str( ini_file_path ) + "\n" )

            # Create ConfigParser instance.
            config_props = configparser.ConfigParser()

            # does ini file exist?
            if ( os.path.exists( ini_file_path ) == True ):

                # load file
                with open( ini_file_path ) as config_file:

                    # read file.
                    config_props.readfp( config_file )

                    # retrieve configuration properties

                    if ( six.PY3 == True ):

                        # secret section
                        secret_section = config_props[ self.INI_GROUP_SECRET ]
                        passphrase = secret_section.get( self.INI_VALUE_PASSPHRASE, None )

                        # do we have file_paths section?
                        if ( self.INI_GROUP_FILE_PATHS in config_props ):
                        
                            # file_paths configuration properties
                            file_paths_section = config_props[ self.INI_GROUP_FILE_PATHS ]
                            input_file_path = file_paths_section.get( self.INI_VALUE_INPUT_FILE_PATH, None )
                            output_file_path = file_paths_section.get( self.INI_VALUE_OUTPUT_FILE_PATH, None )

                        #-- END check to see if "file_paths" section present. --#

                        # do we have file_paths section?
                        if ( self.INI_GROUP_CONFIGURATION in config_props ):
                        
                            # configuration config properties
                            configuration_section = config_props[ self.INI_GROUP_CONFIGURATION ]
                            has_header_row = configuration_section.get( self.INI_VALUE_HAS_HEADER_ROW, "false" )
                            has_header_row = ( has_header_row.lower() == "true" )

                        #-- END check to see if "configuration" section present. --#
                        
                    else:

                        # Use Legacy Python 2 API.
                        # secret section
                        #secret_section = config_props[ self.INI_GROUP_SECRET ]
                        #passphrase = secret_section.get( self.INI_VALUE_PASSPHRASE, None )
                        section = self.INI_GROUP_SECRET
                        option = self.INI_VALUE_PASSPHRASE
                        current_value = None
                        if ( config_props.has_option( section, option ) == True ):

                            # in file, get value.
                            current_value = config_props.get( section, option )

                        else:

                            # not in file, set to None.
                            current_value = None

                        #-- END check to see if option is present in section in file. --#
                        passphrase = current_value

                        # file_paths section
                        #file_paths_section = config_props[ self.INI_GROUP_FILE_PATHS ]
                        #input_file_path = file_paths_section.get( self.INI_VALUE_INPUT_FILE_PATH, None )
                        #output_file_path = file_paths_section.get( self.INI_VALUE_OUTPUT_FILE_PATH, None )
                        
                        section = self.INI_GROUP_FILE_PATHS
                        option = self.INI_VALUE_INPUT_FILE_PATH
                        current_value = None
                        if ( config_props.has_option( section, option ) == True ):

                            # in file, get value.
                            current_value = config_props.get( section, option )

                        else:

                            # not in file, set to None.
                            current_value = None

                        #-- END check to see if option is present in section in file. --#
                        input_file_path = current_value

                        section = self.INI_GROUP_FILE_PATHS
                        option = self.INI_VALUE_OUTPUT_FILE_PATH
                        current_value = None
                        if ( config_props.has_option( section, option ) == True ):

                            # in file, get value.
                            current_value = config_props.get( section, option )

                        else:

                            # not in file, set to None.
                            current_value = None

                        #-- END check to see if option is present in section in file. --#
                        output_file_path = current_value

                        # configuration
                        section = self.INI_GROUP_CONFIGURATION
                        option = self.INI_VALUE_HAS_HEADER_ROW
                        current_value = None
                        if ( config_props.has_option( section, option ) == True ):

                            # in file, get value.
                            current_value = config_props.get( section, option )

                        else:

                            # not in file, set to None.
                            current_value = "false"

                        #-- END check to see if option is present in section in file. --#
                        
                        # convert to boolean and store.
                        has_header_row = ( current_value.lower() == "true" )

                    #-- END check for Python 3 --#

                #-- END with open( ini_file_path ) as config_file --#

            else:

                # ERROR - no ini file.
                status_message = "ERROR - file " + str( ini_file_path ) + " does not exist."
                status_message_list.append( status_message )

            #-- END check to see if ini_file_path exists. --#

            # check required configuration properties

            # passphrase - always REQUIRED.
            if ( ( passphrase is not None ) and ( passphrase != "" ) ):

                # store it in instance
                self.set_passphrase( passphrase )

            else:

                # no passphrase - ERROR.
                status_message = "ERROR - you must specify a \"" + self.INI_VALUE_PASSPHRASE + "\" in the \"" + self.INI_GROUP_SECRET + "\" section of your INI file."
                status_message_list.append( status_message )

            #-- END check to see if passphrase --#

            # got a passphrase - input file path?
            if ( ( input_file_path is not None ) and ( input_file_path != "" ) ):

                # store it in instance
                self.input_file_path = input_file_path

                # we have input file path - do we have output_file_path?
                if ( ( output_file_path is None ) or ( output_file_path == "" ) ):

                    # no output file path.  Get file name part of input path,
                    #     prepend "HASHED_" to the front, and store in current
                    #     directory.
                    absolute_path = os.path.abspath( input_file_path )
                    path_part_list = os.path.split( absolute_path )
                    output_file_path = path_part_list[ -1 ]
                    output_file_path = self.DEFAULT_OUTPUT_FILE_PATH_PREFIX + output_file_path

                #-- END check to see if output_file_path --#

            else:

                # are we requiring input file path?
                if ( require_input_file_path_IN == True ):

                    # no input file path.  ERROR.
                    status_message = "ERROR - you must specify an \"" + self.INI_VALUE_INPUT_FILE_PATH + "\" in the \"" + self.INI_GROUP_FILE_PATHS + "\" section of your INI file."
                    status_message_list.append( status_message )

                #-- END check to see if we require input file path. --#

            #-- END check to see if input file path. --#

            # store output file path.
            self.output_file_path = output_file_path

            # DEBUG - output configuration
            if ( self.DEBUG == True ):

                print( "passphrase = " + str( self.passphrase ) )
                print( "input_file_path = " + str( self.input_file_path ) )
                print( "output_file_path = " + str( self.output_file_path ) )

            #-- END DEBUG check. --#

            # store optional properties
            self.has_header_row = has_header_row

        else:

            # No ini file path - print that fact, will fall out of program ahead when
            #     no parameters are set.
            status_message = "ERROR - no ini file path set."
            status_message_list.append( status_message )

        #-- END check to see if ini file path --#

        status_message_list_OUT = status_message_list
        return status_message_list_OUT

    #-- END method load_configuration_from_ini_file() --#


    def process_file( self ):

        '''
        Uses nested passphrase, input file path, and output file path, all
            required.  Opens input file path for reading, then passes that to a
            CSV reader.  Then, opens output file path for writing, passes that
            to a CSV writer.  For each line in the input file:
            - copies the current row's values.
            - does light transformation appropriate to the type of value:
                - SSN - removes any hyphens.
                - name part - converts to all capitals.
            -

        Returns list of status messages, empty list if success.
        '''

        # return reference
        status_list_OUT = []

        # declare variables - input variables
        input_file_path_IN = None
        output_file_path_IN = None

        # declare variables - processing
        status_message = ""
        my_hmac_key = None
        line_counter = -1
        hash_output_file = None
        to_hash_csv_file = None
        input_csv_reader = None
        output_csv_writer = None
        current_record = None
        INDEX = ""
        SSN = ""
        FNAME = ""
        MNAME = ""
        LNAME = ""
        hashed_SSN = ""
        hashed_FNAME = ""
        hashed_MNAME = ""
        hashed_LNAME = ""
        row_value_list = []

        # get INPUT variables from instance
        input_file_path_IN = self.input_file_path
        output_file_path_IN = self.output_file_path

        print( "\n==> Processing file: " + str( input_file_path_IN ) + " @ " + str( datetime.datetime.now() ) )

        # make sure there is a key.
        my_hmac_key = self.hmac_key
        if ( ( my_hmac_key is not None ) and ( my_hmac_key != "" ) ):

            # does the input file exist?
            if ( os.path.exists( input_file_path_IN ) == True ):

                # initialize
                line_counter = 0

                # open the output file for writing.
                with open( output_file_path_IN, "w" ) as hash_output_file:

                    # init CSV writer.
                    output_csv_writer = csv.writer( hash_output_file, delimiter = "," )

                    # open the input file for reading
                    # Only Python 3 - with open( input_file_path_IN, encoding = self.input_file_encoding ) as to_hash_csv_file:
                    with open( input_file_path_IN ) as to_hash_csv_file:

                        # get a CSV reader
                        input_csv_reader = csv.reader( to_hash_csv_file )

                        # do we have a header row?
                        if ( self.has_header_row == True ):

                            # first row is column names - no need to hash - output header row
                            row_value_list = six.next( input_csv_reader )
                            output_csv_writer.writerow( row_value_list )

                        #-- END check to see if first row is column names --#

                        # loop over records
                        for current_record in input_csv_reader:

                            # initialize values
                            SSN = ""
                            FNAME = ""
                            MNAME = ""
                            LNAME = ""
                            hashed_SSN = ""
                            hashed_FNAME = ""
                            hashed_MNAME = ""
                            hashed_LNAME = ""

                            # initialize output list with copy of input list
                            row_value_list = copy.copy( current_record )

                            # increment line counter
                            line_counter += 1

                            # get and standardize values:
                            # - SSN - remove hyphens, leading or trailing white space.
                            # - names - upcase, remove leading or trailing white space.
                            SSN = current_record[ self.CSV_INDEX_SSN ]
                            SSN = self.standardize_ssn( SSN )
                            FNAME = current_record[ self.CSV_INDEX_FIRST_NAME ]
                            FNAME = self.standardize_name( FNAME )
                            MNAME = current_record[ self.CSV_INDEX_MIDDLE_NAME ]
                            MNAME = self.standardize_name( MNAME )
                            LNAME = current_record[ self.CSV_INDEX_LAST_NAME ]
                            LNAME = self.standardize_name( LNAME )

                            # hash.
                            hashed_SSN = self.hash_value( SSN )
                            hashed_FNAME = self.hash_value( FNAME )
                            hashed_MNAME = self.hash_value( MNAME )
                            hashed_LNAME = self.hash_value( LNAME )

                            # create list of values for current row.
                            row_value_list[ self.CSV_INDEX_SSN ] = hashed_SSN
                            row_value_list[ self.CSV_INDEX_FIRST_NAME ] = hashed_FNAME
                            row_value_list[ self.CSV_INDEX_MIDDLE_NAME ] = hashed_MNAME
                            row_value_list[ self.CSV_INDEX_LAST_NAME ] = hashed_LNAME

                            # write to output file.
                            output_csv_writer.writerow( row_value_list )

                            if ( ( line_counter % self.message_every_x_lines ) == 0 ):
                                print( "- Hashed " + str( line_counter ) + " lines at " + str( datetime.datetime.now() ) )
                            #-- END check to see if we've done x records. --#

                        #-- END loop over input lines.

                    #-- END with ... to_hash_csv_file --#

                #-- END with ... hash_output_file --#

            else:

                # ERROR - no input file.
                status_message = "ERROR - file " + str( input_file_path_IN ) + " does not exist."
                status_list_OUT.append( status_message )

            #-- END check to see if ini_file_path exists. --#

        else:

            # no key.  ERROR.
            status_message = "ERROR - no key present when trying to process_file().  Full stop."
            status_list_OUT.append( status_message )

        print( "\n==> Processing complete @ " + str( datetime.datetime.now() ) )

        return status_list_OUT

    #-- END method process_file() --#


    def set_passphrase( self, value_IN ):

        '''
        Accepts passphrase value.  Hashes it, then stores the hash as a key
            inside this instance.  Stores passphrase in instance as well.
        '''

        # declare variables
        encoded_passphrase = None
        sha256_instance = None
        passphrase_hash = None

        # store the value
        self.passphrase = value_IN

        # is it non-empty?
        if ( ( value_IN is not None ) and ( value_IN != "" ) ):

            # get hasher
            sha256_instance = self.hmac_key_hash_function()

            # update it with the message
            encoded_passphrase = value_IN.encode( "utf-8" )
            sha256_instance.update( encoded_passphrase )

            # get digest
            passphrase_hash = sha256_instance.digest()

            # store as key
            self.hmac_key_hash_instance = sha256_instance
            self.hmac_key = passphrase_hash

        #-- END check to make sure we have a value --#

    #-- END method set_passphrase


    def standardize_name( self,
                          value_IN,
                          do_remove_punctuation_IN = False,
                          do_compact_white_space_IN = False,
                          convert_to_case_IN = STRING_CASE_DEFAULT ):

        '''
        Accepts name or name part (first name, middle name, last name).  Does
        the following:

        - converts to upper case (you can adjust this in convert_to_case_IN).
        - strips leading and trailing white space.
        - has optional additional cleaning, not done by default.

        then returns the result.
        '''

        # return reference
        value_OUT = None

        # use standard standardization function.
        value_OUT = self.standardize_string( value_IN,
                                             do_remove_punctuation_IN = do_remove_punctuation_IN,
                                             do_compact_white_space_IN = do_compact_white_space_IN,
                                             convert_to_case_IN = convert_to_case_IN )

        return value_OUT

    #-- END method standardize_name() --#


    def standardize_ssn( self,
                         value_IN,
                         do_remove_punctuation_IN = True,
                         do_compact_white_space_IN = True,
                         convert_to_case_IN = None ):

        '''
        Accepts SSN value.  Does the following:

        - removes any hyphens
        - strips leading and trailing white space.

        then returns the result.
        '''

        # return reference
        value_OUT = None

        # use standard standardization function.
        value_OUT = self.standardize_string( value_IN,
                                             do_remove_punctuation_IN = do_remove_punctuation_IN,
                                             do_compact_white_space_IN = do_compact_white_space_IN,
                                             convert_to_case_IN = convert_to_case_IN )

        return value_OUT

    #-- END method standardize_ssn() --#


    def standardize_string( self,
                            value_IN,
                            do_remove_punctuation_IN = False,
                            do_compact_white_space_IN = False,
                            convert_to_case_IN = STRING_CASE_DEFAULT ):

        '''
        Accepts name or name part (first name, middle name, last name).  Does
        the following:

        - converts to upper case.
        - strips leading and trailing white space.

        then returns the result.
        '''

        # return reference
        value_OUT = None

        # got a string passed in?
        if ( value_IN is not None ):

            # start with value passed in.
            value_OUT = value_IN

            # remove punctuation?
            if ( do_remove_punctuation_IN == True ):
            
                # remove punctuation if any present.
                value_OUT = self.strip_punctuation( value_OUT )

            #-- END check to see if we remove punctuation --#

            # convert string case?
            if ( convert_to_case_IN is not None ):

                # --> upper?
                if ( convert_to_case_IN == self.STRING_UPPER_CASE ):
                
                    # convert to upper case.
                    value_OUT = value_OUT.upper()

                # --> lower?
                elif ( convert_to_case_IN == self.STRING_LOWER_CASE ):

                    # convert to lower case.
                    value_OUT = value_OUT.lower()

                else:

                    # unknown
                    print( "ERROR - case type {} is unknown - did not convert.".format( convert_to_case_IN ) )

                #-- END check to see how to convert. --#

            #-- END check to see if we convert case. --#

            # convert any stretches of more than one contiguous space to a single space.
            if ( do_compact_white_space_IN == True ):

                # remove extra white space.
                value_OUT = self.remove_extra_space( value_OUT )

            #-- END check to see if we compact white space. --#

            # always strip any white space from the ends of the string.
            value_OUT = value_OUT.strip()

        else:

            # nothing passed in, None returned.
            value_OUT = None

        #-- END check to see if string passed in. --#

        return value_OUT

    #-- END method standardize_string() --#


#-- END class HMACHasher --#
