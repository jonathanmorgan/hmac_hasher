using System;
using System.Security.Cryptography;
using System.Text;

namespace c_sharp
{
    class Program
    {
        static void Main( string[] args )
        {

            // declare variables
            string secret = "";
            string to_hash = "";
            string hex_hash = "";

            // set up hash test.
            secret = "fakedata";
            //secret = "8f50a1b24abc24aebb1b4b67745f4d8776ffeb5183ad1ebc6296def10e8f3150";
            to_hash = "123456789";

            // hash
            hex_hash = HMACHashIntoHexString( to_hash, secret );

            // output result.
            Console.WriteLine( "hex: " + hex_hash );

        }


        private static string HMACHashIntoHexString( string value_IN, string secret_IN )
        {
            // return reference
            string value_OUT = null;

            // declare variables
            string secret = "";
            string to_hash = "";
            string hex_hash = "";
            System.Text.UTF8Encoding encoding = null;

            // declare variables - making HMAC hash
            byte[] key = null;
            System.Security.Cryptography.HMACSHA256 myhmacsha256 = null;
            byte[] value_bytes = null;
            byte[] hashValue = null;
            //string resultSTR = null;

            // do we have a value?
            if ( ( value_IN != null ) && ( value_IN != "" ) )
            {
                
                // set up hash test.
                secret = secret_IN;
                to_hash = value_IN;

                // set encoding
                encoding = new System.Text.UTF8Encoding();
                
                // Hash secret using SHA256, use that as the key.
                key = SHA256HashByteArray( secret );

                // not just converting to byte array
                // key = encoding.GetBytes( secret );

                // initialize HMAC hasher.
                myhmacsha256 = new System.Security.Cryptography.HMACSHA256( key );
                
                // hash the value.
                value_bytes = encoding.GetBytes( to_hash );

                // compute hash on bytes
                hashValue = myhmacsha256.ComputeHash( value_bytes );
                
                // clear out the hasher - wouldn't need to do this if you just
                //    initialized it once with a secret, then kept it around in a
                //    variable.
                myhmacsha256.Clear();

                // convert to base-64 string.
                // resultSTR = Convert.ToBase64String( hashValue );
                // Console.WriteLine( "base 64: " + resultSTR );
                
                // output as base-64

                // output as hex, lower-case...
                hex_hash = BitConverter.ToString( hashValue ).Replace( "-", string.Empty );
                hex_hash = hex_hash.ToLower();
                //Console.WriteLine( "hex: " + hex_hash );

                value_OUT = hex_hash;

            }
            else
            {
                
                // nothing passed in.  Return "".
                value_OUT = "";

            }

            return value_OUT;

        } //-- END private static method HMACHashIntoHexString --//


        private static string ToHex( byte[] bytes, bool upperCase )
        {
            // return reference
            string value_OUT = null;

            // declare variables
            System.Text.StringBuilder result = null;
            
            // get string builder to hold output.
            result = new System.Text.StringBuilder( bytes.Length * 2 );

            // loop.
            for (int i = 0; i < bytes.Length; i++)
            {
                result.Append(bytes[i].ToString(upperCase ? "X2" : "x2"));
            }

            value_OUT = result.ToString();

            return value_OUT;

        } //-- END private static method ToHex() --//


        private static byte[] SHA256HashByteArray( string StringIn )
        {
            byte[] value_OUT = null;
            using ( var sha256 = SHA256Managed.Create() )
            {
                var hash = sha256.ComputeHash(Encoding.Default.GetBytes(StringIn));
                value_OUT = hash;
            }

            return value_OUT;
        } //-- END private static method SHA256HashByteArray --//


        private static string SHA256HexHashString(string StringIn)
        {
            string hashString;
            using ( var sha256 = SHA256Managed.Create() )
            {
                var hash = sha256.ComputeHash( Encoding.Default.GetBytes( StringIn ) );
                hashString = ToHex(hash, false);
            }

            return hashString;
        } //-- END private static method SHA256HexHashString --//

    } //-- END class Program --//

} //-- END name space c_sharp --//
