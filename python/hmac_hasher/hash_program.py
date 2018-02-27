#==============================================================================#
# imports
#==============================================================================#

# imports
import os
import sys

# HMACHasher
from hmac_hasher import HMACHasher

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

#==============================================================================#
# Command line arguments
#==============================================================================#

# store command line arguments
command_line_arguments = sys.argv

# check to see if two (and only two - Python file path + INI file path) arguments
if (  len( command_line_arguments ) == 2 ):

    # there is a single argument other than Python file path.  Get it.
    ini_file_path = command_line_arguments[ 1 ]

elif ( len( command_line_arguments ) > 2 ):

    # ERROR - only want 2 arguments, no more.
    status_message = "ERROR - you should only pass either a single argument, the path to your INI file, or no arguments to this program."
    status_message_list.append( status_message )
    ini_file_path = None

else:

    # No argument.  Use default.
    ini_file_path = HMACHasher.DEFAULT_INI_FILE_PATH

#-- END check to see if two (and only two) arguments --#

#==============================================================================#
# Read configuration and process file
#==============================================================================#

# got an INI file path?
if ( ( ini_file_path is not None ) and ( ini_file_path != "" ) ):

    # create HMACHasher instance
    hmac_hasher = HMACHasher()

    # load configuration
    load_config_status_list = hmac_hasher.load_configuration_from_ini_file( ini_file_path )

    # errors?
    if ( len( load_config_status_list ) > 0 ):

        # add list of errors to master list, do not process file.
        status_message_list.extend( load_config_status_list )

    else:

        # no errors loading config - process file.
        hashing_status_list = hmac_hasher.process_file()

        # errors?
        if ( len( hashing_status_list ) > 0 ):

            # add list of errors to master list, do not process file.
            status_message_list.extend( hashing_status_list )

        #-- END check to see if errors. --#

    #-- END check to see if config load errors. --#

#-- END check to see if config file path. --#

# status messages?
if ( len( status_message_list ) > 0 ):

    print( "status messages:" )
    for status_message in status_message_list:

        print( "- " + status_message )

    #-- END loop over status messages --#

#-- END check for status messages. --#

print( "\n" )
