KeystoreBrute
=============
A program that uses a brute-force attack to find the password for a given Keystore (Java KeyStore).

Please note
-----------
Please note that this program will only try to find the password to the Keystore,
not to any of the keys inside.

Usage
-----
If you are using the binary found in the directory with the same name:
java -jar Breaker.jar <keystore file> <startdepth> <number of threads>

If you are compiling the program yourself and want to use those classfiles:
java se.bes.br.BruteMain <keystore file> <startdepth> <number of threads>