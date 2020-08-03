# FMP - Find Matching Patterns
The purpose of this script is:
* To scan for hex magic numbers in binary files.
* Find all the strings in a binary file.
* Find repeating byte above a user given threshold.
## Usage
`fmp.py <binary file path> [map of hex strings or list of regex [-s]] [-r byte_threshold]`

## Mandatory Arguments
* `<Path to a binary file.>`

## Optional Arguments (Choose only one)
* `<a map of hex string>`: Entering a map of hex strings without any flags will start a scan that will search in the binary file for the hex phrases the user entered and will return a list of the offset of the phrases found and the phrases themselves.

**Example:** `python3 fmp.py ./file "{ '5D00008000': 'lzma', '18286F01': 'zImage', '1F8B0800': 'gzip' }"`

* `-s`: using the `-s` flag argument will search and count all the string in the file that their length is bigger than 4.

**Example:** `python3 fmp.py ./file -s`

* `-r <byte_threshold>`: The argument will scan the binary file for all the the repeating bytes sequences and will return a list of dictionaries that will contain the range of every sequence (in hex), the size of the sequence and the repeating byte.

**Example:** `python3 fmp.py ./file -r 1000`
