import os
import sys
import re
from ast import literal_eval
from functools import partial

FILE_PATH_ARG = 1
SECOND_ARG = 2
THIRD_ARG = 3
BYTE_THRESHOLD_ARG = 3

MIN_AMOUNT_OF_ARGS = 3
FLAG_INDEX = 3
MAX_AMOUNT_OF_ARGS = 6

DEFAULT_CHUNK_SIZE = 10000


class Scanner:
    @staticmethod
    def scan_file_for_hex_patterns(file_path, search_terms):
        """
        The function scans a binary file for hex phrases that the user entered as an argument to the script
        and prints a dictionary with a list that contains the offset of every phrase found and the phrase itself.
        :param file_path: represents the file path of the target binary file.
        :param search_terms: a dictionary that contains all the hex phrases to search in the binary file.
        :return: None.
        """
        if isinstance(search_terms, dict):
            print("[~] This action may take a few seconds.")
            results = {"results": []}

            with open(file_path, 'rb') as file:
                previous = b''
                longest_term = max(search_terms, key=len)
                chunk_size = DEFAULT_CHUNK_SIZE
                if os.path.getsize(file_path) < DEFAULT_CHUNK_SIZE:
                    # If the file size is smaller than the default chunk size, change the chunk size to the file size.
                    chunk_size = os.path.getsize(file_path)
                for chunk in iter(partial(file.read, chunk_size), b''):
                    file_position = file.tell()
                    for term in search_terms:
                        chunk_with_prev = previous + chunk
                        bytes_term = bytearray.fromhex(term)
                        term_len = len(bytes_term)
                        if 0 < term_len < len(previous):
                            # Creating a chunk that contains the end bytes of the previous chunk so the script
                            # won't miss phrases between chunks
                            chunk_with_prev = chunk_with_prev[int(term_len / 2):]
                        if bytes_term in chunk_with_prev:
                            findings_indexes = [i for i in range(len(chunk_with_prev)) if
                                                chunk_with_prev.startswith(bytes_term, i)]
                            for index in findings_indexes:
                                start_offset = file_position - len(chunk_with_prev) + index
                                results["results"].append({"range": (hex(start_offset), hex(start_offset + term_len)) ,
                                                           "phrase": search_terms[term]})
                    previous = chunk[-len(longest_term):]
                print("[+] Number of matches found:\n", results)
        else:
            print("[!] The search terms entered are not in a dictionary format.")
            exit(1)

    @staticmethod
    def find_repeating_sequences(file_path, bytes_threshold):
        """
        The function scans a binary file for ALL the repeating byte sequences and prints the range, size and the
        repeating byte of every sequence.
        :param file_path: represents the file path of the target binary file.
        :param bytes_threshold: the minimum sequence size to be included in the results.
        :return: None.
        """
        print("[~] This action may take a few seconds or minutes (depending on the file size and the number of results).")
        results = {"results": []}
        with open(file_path, 'rb') as file:
            repeating_byte = b''
            start_offset = 0
            chunk_size = DEFAULT_CHUNK_SIZE
            if os.path.getsize(file_path) < DEFAULT_CHUNK_SIZE:
                # If the file size is smaller than the default chunk size, change the chunk size to the file size.
                chunk_size = os.path.getsize(file_path)
            for chunk in iter(partial(file.read, chunk_size), b''):
                file_offset = file.tell()
                for i in range(0, len(chunk) - 2, 2):
                    # Checking if the current three bytes are equal to each other.
                    # The checks are held in variables for optimization reasons.
                    three_bytes_check = chunk[i] == chunk[i + 1] == chunk[i + 2]
                    if repeating_byte != b'' and chunk[i] != chunk[i + 1]:
                        finish_offset = file_offset - chunk_size + i
                        if (finish_offset - start_offset) > bytes_threshold:
                            results["results"].append({'range': (hex(start_offset), hex(finish_offset)),
                                                       'size': finish_offset - start_offset,
                                                       'repeating_byte': hex(repeating_byte)})
                        repeating_byte = b''
                    elif three_bytes_check or i == 0 and chunk[0] == repeating_byte:
                        # If the current three bytes are equal to each other and there is no current repeating byte
                        # start tracking the sequence.
                        if repeating_byte == b'':
                            start_offset = file.tell() - chunk_size + i
                            repeating_byte = chunk[i]
        print(results)

    @staticmethod
    def search_strings(file_path):
        """
        The function searches for all the string in a binary file that are 4 characters and more and counts the
        number of appearances of every string.
        :param file_path: represents the file path of the target binary file.
        :return: None
        """
        print("[~] This action may take a few seconds or minutes (depending on file size and number of results).")
        results = {}
        with open(file_path, "rb") as file:
            previous = b''
            chunk_size = DEFAULT_CHUNK_SIZE
            if os.path.getsize(file_path) < DEFAULT_CHUNK_SIZE:
                # If the file size is smaller than the default chunk size, change the chunk size to the file size.
                chunk_size = os.path.getsize(file_path)
            for chunk in iter(partial(file.read, chunk_size), b''):
                chunk_with_prev = previous + chunk
                # Using regex to extract all the strings from the binary
                strings_found = re.findall(b'([a-zA-Z0-9!,/-]{4,})', chunk_with_prev)
                for string in strings_found:
                    if string in results:
                        results[string] += 1
                    else:
                        results[string] = 1

                if len(strings_found) > 0:
                    previous = chunk[-len(strings_found[-1]):]
        print(results)

def help():
    print("Usage: fmp.py <binary file path> [map of hex strings or list of regex [-s]] [-r byte_threshold]\n\n"
          "Mandatory arguments:\n"
          "    Path to a binary file.\n\n"
          "Optional arguments (choose only one):\n\n"
          "    <a map of hex string>: Entering a map of hex strings without any flags will scan the binary file and\n"
          "                           count the number of appearances of every hex string in the map and will return\n"
          "                           a json object with the output.\n"
          "    Example: python3 fmp.py ./file \"{ '5D00008000': 'lzma', '18286F01': 'zImage', '1F8B0800': 'gzip' }\"\n\n\n"
          "    -s: Adding the -s flag to the previous argument will search and count all the\n"
          "                              string in the file that their length is bigger than 4.\n"
          "    Example: python3 fmp.py ./file  -s\n\n\n"
          "    -r <byte_threshold>: The argument will scan the binary file for all the the repeating bytes sequences\n"
          "                         and will return a list of dictionaries that will contain the range of every\n"
          "                         sequence (in hex), the size of the sequence and the repeating byte.\n"
          "    Example: python3 fmp.py ./file -r 1000")

def usage():
    print("Usage: fmp.py <binary file path> [map of hex strings or list of regex [-s]] [-r byte_threshold]\n"
          "Enter \"fmp.py -help\" for more information.")
    exit(1)

def main():
    scanner = Scanner()
    if sys.argv[FILE_PATH_ARG] == '-help':
        help()
    elif len(sys.argv) < MIN_AMOUNT_OF_ARGS or len(sys.argv) > MAX_AMOUNT_OF_ARGS \
            or os.path.isfile(sys.argv[FILE_PATH_ARG]) is False:
        usage()
    elif len(sys.argv) == MIN_AMOUNT_OF_ARGS and sys.argv[SECOND_ARG] != '-r' and sys.argv[SECOND_ARG] != '-s':
        try:
            scanner.scan_file_for_hex_patterns(sys.argv[FILE_PATH_ARG], literal_eval(sys.argv[SECOND_ARG]))
        except SyntaxError or ValueError:
            print("[!] Error: the search terms entered are not in a correct dictionary format.")
            exit(1)
    elif len(sys.argv) == 3 and sys.argv[SECOND_ARG] == '-s':
        scanner.search_strings(sys.argv[FILE_PATH_ARG])
    elif len(sys.argv) == 4 and sys.argv[SECOND_ARG] == '-r' and sys.argv[BYTE_THRESHOLD_ARG].isdigit() > 0:
        scanner.find_repeating_sequences(sys.argv[FILE_PATH_ARG], int(sys.argv[BYTE_THRESHOLD_ARG]))
    else:
        usage()


if __name__ == "__main__":
    main()

