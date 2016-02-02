#native python libraries
import os
import zlib
import hmac
import json
import time
import base64
import hashlib
import getpass
import logging
import binascii
import argparse
import datetime

#pip-installed libraries
import pyaes
import requests



"""
    logging initialization
"""
logging.basicConfig(level=logging.INFO, format='[%(levelname)s]\t%(asctime)s: %(message)s')



"""
    decrypt_candidate
performs the decryption, decompression, and hmac verification.
it's possible to "decrypt" but not decompress correctly.
it's also possible to "decrypt and decompress", but it will not pass HMAC
only if the hmac is verified is anything passed back to the 
"""
def decrypt_candidate(candidate_data, key, candidate_iv, candidate_hmac):
    decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key, candidate_iv))
    plaintext = decrypter.feed(candidate_data)
    try:
        plaintext+= decrypter.feed(None) #same as encryption ; must flush buffs and strip padding
    except:
        logging.error('Unable to Decrypt Candidate Message')
        return None

    logging.debug('Decrypted data (%d bytes)' % (len(plaintext)))

    try:
        decompressed_data = zlib.decompress(plaintext)
    except:
        logging.error('Unable to Decompress Candidate Message')
        return None
    logging.debug('Decompressed data (%d bytes)' % (len(decompressed_data)))

    hmac_data = hmac.new(key)
    hmac_data.update(decompressed_data)
    if not hmac.compare_digest(candidate_hmac, hmac_data.digest()):
        logging.error('Decompressed data does not have matching HMAC')
        print binascii.hexlify(candidate_hmac), hmac_data.hexdigest()
        return None

    return decompressed_data


"""
    decrypt_message
walks through all files in a message.
essentially a wrapper to decrypt_candidate, which performs the actual decryption and verification
"""
def decrypt_message(package, enc_derived_key):
    logging.info('Decrypting Message')
    candidate_messages = package['files']
    logging.debug('Candidates for Decryption: %d' % len(candidate_messages))

    success = False
    final_decrypt = None
    for i, candidate_message_id in enumerate(candidate_messages.keys()):
        logging.debug('Attempting Decryption on Candidate %d of %d' % (i+1, len(candidate_messages.keys())))
        candidate_enc_data = base64.b64decode(candidate_messages[candidate_message_id]['content'])
        logging.debug('Message Length: %d (bin: %d)' % (len(candidate_messages[candidate_message_id]), len(candidate_enc_data)))
        candidate_enc_hmac = candidate_enc_data[-16:]
        candidate_enc_data = candidate_enc_data[0:-16]
        candidate_enc_iv   = binascii.unhexlify(candidate_message_id[0:32])
        decrypted = decrypt_candidate(candidate_enc_data, enc_derived_key, candidate_enc_iv, candidate_enc_hmac)
        if not decrypted:
            logging.debug('Did Not Decrypt Candidate Message')
            continue
        else:
        	final_decrypt = decrypted
        	success = True

    if not success:
        logging.error('Unable to decrypt any entries in the message')
        return None

    logging.info('Successfully decrypted message. Len: %d' % len(final_decrypt))
    return final_decrypt




"""
    retrieve_all_files_from_message
walks through a gist entries files and gathers all the data
in the case that a file is truncated (10mb and more), it will retrieve the full data
"""
def retrieve_all_files_from_message(files):
    output = {}
    for file_entry in files.keys():
        #file was truncated, must make additional request
        if(files[file_entry]['truncated']):
            logging.debug('File was truncated ; making additional request')
            r = requests.get(files[file_entry]['raw_url'], verify='cacert.pem.txt')
            file_data = r.text
        else:
            file_data = files[file_entry]['content']
        output[file_entry] = {'content': file_data}
    return output



"""
    retrieve_message
pulls the message blob from the GITHUB server via the GIST API
verifies against offline CA_BUNDLE downloaded from curl library (http://curl.haxx.se/docs/caextract.html)
"""
def retrieve_message(gist_id, domain='api.github.com'):
    print 'https://%s/gists/%s' % (domain, gist_id)
    r = requests.get('https://%s/gists/%s' % (domain, gist_id), verify='cacert.pem.txt')
    if(r.status_code != 200):
        logging.error('GIST Status Code Not 200')
        return None
    response = json.loads(r.text)
    if('id' not in response.keys()):
        logging.error('GIST did not return an id')
        return None
    if(response['id'] != gist_id):
        logging.error('GIST did not return requested id')
        return None
    
    #check files
    if('files' not in response.keys()):
        logging.error('GIST did not return any files')
        return None
    if(len(response['files'].keys()) == 0):
        logging.error('GIST returned no messages')
        return None

    #retrieve all of the files
    uploaded_message_data = retrieve_all_files_from_message(response['files'])
    if(not uploaded_message_data):
        logging.error('Unable to grab all message data')
        return None

    #put back into the original format for consistency
    output_package = {}
    output_package['descrption'] = response['description']
    output_package['public'] = response['public']
    output_package['files'] = uploaded_message_data

    return output_package


"""
    gen_derived_key
used for generating the message key based on the pre-shared key and received salt
"""
def gen_derived_key(pre_shared_key, message_salt):
    enc_derived_key = hashlib.pbkdf2_hmac('sha256', pre_shared_key, message_salt, 5000000)
    return enc_derived_key




"""
    main
mostly argument parsing
"""
def main():
    #argparsing
    parser = argparse.ArgumentParser()
    parser.description = 'GISTER - RECEIVER'
    parser.epilog = 'NYU Poly - CS-GY-6903 - Fall 2015'
    parser.epilog+= 'Andre Protas (ADP369) & Nate Rogers (NJR5)'
    parser.epilog+= 'GISTER: Abusing GIST.GITHUB.com for encrypted comms'
    parser.add_argument('gist_id', help='Gist ID to retrieve.', type=str)
    parser.add_argument('message_salt_b64', help='Message-Specific Encryption Salt To Use', type=str)
    args = parser.parse_args()

    #gather the pre-shared key from the user
    pre_shared_key = getpass.getpass('Please Enter Pre-Shared Key: ')
    if(len(pre_shared_key) < 0):
        logging.error('Pre-Shared Key must be more than 10 characters')

    #generate key
    message_salt = base64.b64decode(args.message_salt_b64)
    enc_derived_key = gen_derived_key(pre_shared_key, message_salt)

    #download encrypted package from gist
    downloaded_package = retrieve_message(args.gist_id)
    if not downloaded_package:
        logging.error('Unable to download package from GIST ; Exiting')
        return False

    #decrypt package
    decrypted_message = decrypt_message(downloaded_package, enc_derived_key)
    if not decrypted_message:
        logging.error('Unable to decrypt the message successfully ; Exiting')
        return False

    #write output
    output_filename = time.strftime('%Y%b%d-%H%M%S').upper() + '.decrypted.bin'
    f = open(output_filename, 'wb')
    f.write(decrypted_message)
    f.close()
    logging.info('Final Package Decrypted: %s' % output_filename)




if __name__ == '__main__':
    main()