#native python libraries
import io
import os
import json
import uuid
import hmac
import zlib
import time
import string
import base64
import random
import getpass
import hashlib
import logging
import argparse
import webbrowser

#pip-installed libraries
import pyaes
import requests
import pyqrcode


"""
    logging initialization
"""
logging.basicConfig(level=logging.INFO, format='[%(levelname)s]\t%(asctime)s: %(message)s')



"""
    open_qr_code
opens the qr code with the default browser
"""
def open_report(filename):
    if(not os.path.exists(filename)):
        logging.error('QR code file doesnt exist: %s' % filename)
        return False
    webbrowser.open(filename, new=1, autoraise=True)
    return True


"""
    create_qr_code
creates a qr code from the supplied data
writes it to the designated filename
"""
def create_qr_code(data):
    buffer = io.BytesIO()
    qr_code = pyqrcode.create(data)
    qr_code.svg(buffer, scale=10)
    logging.info('QR code created')
    return buffer


"""
    generate_and_display_report
generates the report for the user to pass on to the receiver using a different channel
"""
def generate_and_display_report(gist_id, enc_salt, report_file='report.html'):
    gist_id_qr  = create_qr_code(gist_id)
    enc_salt_qr = create_qr_code(enc_salt)

    report = r'<html><div align="center">'
    #ID
    report+= r'<font size="6"><b>MESSAGE ID:</b><br> <pre>%s</pre></font>' % gist_id
    report+= r'<img src="data:image/svg+xml;base64,%s"/><br><hr>' % base64.b64encode(gist_id_qr.getvalue())
    #SALT
    report+= r'<font size="6"><b>MESSAGE SALT:</b><br> <pre>%s</pre></font>' % enc_salt
    report+= r'<img src="data:image/svg+xml;base64,%s"/><br>' % base64.b64encode(enc_salt_qr.getvalue())

    report+='</div></html>'

    f = open(report_file,'w')
    f.write(report)
    f.close()
    open_report('report.html')

    time.sleep(5)

    #secure delete the file
    f = open(report_file,'wb')
    f.write(''.join(chr(random.SystemRandom().randint(0,255)) for _ in range(len(report))))
    f.close()
    f = open(report_file,'wb')
    f.write('\x00')
    f.close()
    os.remove(report_file)
    return True



"""
    upload_package_to_gist
shoves the upload package up to the GIST server
verifies against offline CA_BUNDLE downloaded from curl library (http://curl.haxx.se/docs/caextract.html)
"""
def upload_package_to_gist(package, domain='api.github.com'):
    r = requests.post('https://%s/gists' % domain, data=json.dumps(package), verify='cacert.pem.txt')
    if(r.status_code != 201):
        logging.error('GIST Status Code Not 201 ; Did Not Create')
        return None
    response = json.loads(r.text)
    if('id' not in response.keys()):
        logging.error('GIST did not return an id')
        return None
    logging.info('GIST ID: %s' % response['id'])
    return response['id']





"""
    gen_post_parameters
creates the upload package per the API
"""
def gen_post_parameters(uploads):
    post_data = {}
    post_data['description'] = ''.join( random.SystemRandom().\
                                        choice(string.ascii_letters + string.digits + ' ') \
                                        for _ in range(random.SystemRandom().randint(10,60)))
    post_data['public'] = bool(random.SystemRandom().randint(0,1))
    post_data['files'] = uploads
    return post_data



"""
    gen_red_herrings
generates a random amount of 'files' for uploading as well
uses the same size as the real message, and just random data
"""
def gen_red_herrings(length):
    output = {}
    red_herring_count = random.SystemRandom().randrange(2, 8)
    while(len(output.keys()) < red_herring_count):
        red_herring_data = ''.join(chr(random.SystemRandom().randint(0,255)) for _ in range(length))
        output[gen_gist_file_name()] = {"content": base64.b64encode(red_herring_data)}
    return output



"""
    encrypt_blob
encrypts the blob using aes-256 in cbc mode
"""
def encrypt_blob(blob, key, iv):
    logging.debug('Encrypting Data')
    encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv))
    ciphertext = encrypter.feed(blob)
    ciphertext+= encrypter.feed(None)   #performs flush
    logging.debug('Encrypted Data: %d bytes (input: %d)' % (len(ciphertext), len(blob)))
    return ciphertext



"""
    compress_blob
performs zlib compression on the binary
uses level 9 for the slowest and most compression
python does not add headers or footers, so there is nothing to strip
"""
def compress_blob(input):
    logging.debug('Compressing Data')
    compressed_data = zlib.compress(input, 9)
    logging.info('Compressed data from %d -> %d bytes' % (len(input), len(compressed_data)))
    return compressed_data


"""
    gen_hmac
simply wraps the hmac function to generate an hmac for the file data and filename
"""
def gen_hmac(key, msg):
    logging.debug('Generating HMAC')
    hmac_data = hmac.new(key)
    hmac_data.update(msg)
    logging.debug('HMAC for data: %s' % hmac_data.hexdigest())
    return hmac_data.digest()


"""
    gen_gist_file_name
creates a file name to post to GIST
structure:
- first 32 characters are random hex values for the IV
- next characters are a random choice of other characters with a range in size
"""
def gen_gist_file_name(iv_length=32, chars=string.ascii_letters + string.digits):
    logging.debug('Generating File Name')
    file_name_length = random.SystemRandom().randrange(10, 50)
    file_name = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(iv_length))
    file_name+= ''.join(random.SystemRandom().choice(chars) for _ in range(file_name_length))
    logging.debug('GIST File Name: %s' % file_name)
    return file_name


"""
    gen_message_salt
creates an ascii key that can be easily typed
Uses SystemRandom to use cryptographically secure PRNG
  - http://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits-in-python/23728630#23728630
"""
def gen_message_salt(key_length=32):
    logging.debug('Generating Key')
    key = ''.join(chr(random.SystemRandom().randint(0,255)) for _ in range(key_length))
    logging.info('Generated Salt: %s' % base64.b64encode(key))
    return key



"""
    read_file
simple file reader, returns the data (or None if there was an error)
"""
def read_file(filename, mode='rb'):
    #verify the file exists
    if(not os.path.isfile(filename)):
        logging.error('Input File Not Found: %s; Exiting' % filename)
        return None
    #read the file data
    f = open(filename, mode)
    data = f.read()
    f.close()
    logging.debug('Read %d bytes from input file %s' % (len(data), filename))
    return data


"""
    generate_upload_package
wrapper for all of the message encryption data.
returns a package ready for uploading.
"""
def generate_upload_package(binary_blob, enc_derived_key, enc_iv, real_gist_file_name):
    #generate the hmac
    hmac_data = gen_hmac(enc_derived_key, binary_blob)
    if not hmac_data:
        logging.error('Unable to generate HMAC ; Exiting')
        return False

    #compress the blob
    compressed_blob = compress_blob(binary_blob)
    if not compress_blob:
        logging.error('Unable to compress blob ; Exiting')
        return False

    #encrypt the compressed blob
    encrypted_blob = encrypt_blob(compressed_blob, enc_derived_key, enc_iv)
    if not encrypt_blob:
        logging.error('Unable to encrypt blob ; Exiting')
        return False

    #encode as base64 for upload
    upload_data = base64.b64encode(encrypted_blob + hmac_data)
    print 'uploaded', len(upload_data), len(encrypted_blob + hmac_data)
    logging.info('Final file size for upload: %d' % len(upload_data))

    #generate red herrings to challenge cryptanalysis
    upload_files = gen_red_herrings(len(encrypted_blob + hmac_data))
    if not upload_files:
        logging.error('Unable to generate red herrings ; Exiting')
        return False

    #append the real message
    upload_files[real_gist_file_name] = {"content":upload_data}

    #generate upload package
    upload_package = gen_post_parameters(upload_files)

    return upload_package


"""
    generate_key_material
using the pre-shared key, generates a random salt (sent out-of-band) and iv (sent as part of file name)
"""
def generate_key_material(pre_shared_key):
    #generate symmetric key
    enc_salt = gen_message_salt()
    if not enc_salt:
        logging.error('Unable to generate message salt ; Exiting')
        return False

    enc_derived_key = hashlib.pbkdf2_hmac('sha256', pre_shared_key, enc_salt, 5000000)

    #get the filename
    real_gist_file_name = gen_gist_file_name()
    if not real_gist_file_name:
        logging.error('Unable to generate filename for GIST upload ; Exiting')
        return False
    #the first 32-charcters are the iv bytes
    enc_iv = real_gist_file_name[0:32].decode("hex")

    return enc_derived_key, enc_salt, enc_iv, real_gist_file_name





"""
    main
mostly argument parsing
"""
def main():
    #argparsing
    parser = argparse.ArgumentParser()
    parser.description = 'GISTER - TRANSMITTER'
    parser.epilog = 'NYU Poly - CS-GY-6903 - Fall 2015'
    parser.epilog+= 'Andre Protas (ADP369) & Nate Rogers (NJR5)'
    parser.epilog+= 'GISTER: Abusing GIST.GITHUB.com for encrypted comms'
    parser.add_argument('input_file', help='File to post', type=str)
    args = parser.parse_args()

    #gather the pre-shared key from the user
    pre_shared_key = getpass.getpass('Please Enter Pre-Shared Key: ')
    if(len(pre_shared_key) < 0):
        logging.error('Pre-Shared Key must be more than 10 characters')

    #verify the file exists
    input_file_data = read_file(args.input_file)
    if not input_file_data:
        logging.error('No Input File Data ; Exiting')
        return False

    #generate the key material for the upload
    enc_derived_key, enc_salt, enc_iv, real_gist_file_name = generate_key_material(pre_shared_key)
    enc_salt_b64 = base64.b64encode(enc_salt)

    #generate the upload package
    upload_package = generate_upload_package(input_file_data, enc_derived_key, enc_iv, real_gist_file_name)
    if(not upload_package):
        logging.error('Unable to generate the upload package ; exiting')
        return False

    #post the package up to gist
    gist_id = upload_package_to_gist(upload_package)
    if(not gist_id):
        logging.error('Unable to upload the package to Gist')
        return False

    #generate the report and display to user (we're finished transmitting)
    generate_and_display_report(gist_id, enc_salt_b64)
    return True


if __name__ == '__main__':
    main()