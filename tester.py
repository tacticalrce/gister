import time
import random
import unittest

import gister_receive
import gister_transmit


class TestOfflineWithMessages(unittest.TestCase):
    def test_string_encryption_100x(self):
        for i in range(0,100):
            message = "Lorem ipsum dolor sit amet, justo tortor praesent a dui at. Amet leo. Accumsan nec venenatis eget, imperdiet vitae pellentesque maecenas ut. Aut ac eleifend at nonummy nec, litora quam hymenaeos vehicula sed diam, blandit duis fermentum lacus ante, accumsan velit nonummy eleifend, id ante. Ultrices elit ipsum. Integer est, posuere sed duis odio. Praesent per ante eligendi etiam, integer convallis vestibulum et ultricies, porta mauris, ab dui a nulla vitae ac aliquet, erat sem integer. Fermentum risus nulla, risus eget mi. Taciti dui justo feugiat malesuada adipiscing arcu, ac sapien sed phasellus vitae porta, vel quisque mattis nunc ultricies fames, volutpat ipsum et. Mauris vestibulum justo augue phasellus lacinia, consectetuer urna ut, est consectetuer enim porta nulla. Viverra amet sodales nam duis maecenas, vitae quis ornare officia integer non, placeat tristique placerat at wisi sit, ut urna enim fusce sit et, amet libero pharetra. Morbi nascetur ipsum malesuada neque, mollis justo ipsum neque accumsan eget, nullam proin aliquam elementum."
            pre_shared_key = '0123456789qazWSXedcRFV'

            #generate the encrypted package
            enc_derived_key, enc_salt, enc_iv, real_gist_file_name = gister_transmit.generate_key_material(pre_shared_key)
            encrypted_package = gister_transmit.generate_upload_package(message, enc_derived_key, enc_iv, real_gist_file_name)
            
            #pass the encrypted package, key, and iv to the decrypter
            derived_key = gister_receive.gen_derived_key(pre_shared_key, enc_salt)
            decrypted_message = gister_receive.decrypt_message(encrypted_package, derived_key)

            self.assertTrue(decrypted_message == message)


    def test_encryption_large_blob_10x(self):
        blob_size = 100000
        for i in range(0,10):
            message = ''.join(chr(random.SystemRandom().randint(0,255)) for _ in range(random.SystemRandom().randint(blob_size,blob_size*10)))
            pre_shared_key = '0192837465OKMijnUHBygv'

            #generate the encrypted package
            enc_derived_key, enc_salt, enc_iv, real_gist_file_name = gister_transmit.generate_key_material(pre_shared_key)
            encrypted_package = gister_transmit.generate_upload_package(message, enc_derived_key, enc_iv, real_gist_file_name)
            
            #pass the encrypted package, key, and iv to the decrypter
            decrypted_message = gister_receive.decrypt_message(encrypted_package, enc_derived_key)

            self.assertTrue(decrypted_message == message)



class TestOnlineWithGist(unittest.TestCase):
    def test_post_small_message(self):
        for i in range(0,5):
            message = "Lorem ipsum dolor sit amet, justo tortor praesent a dui at. Amet leo. Accumsan nec venenatis eget, imperdiet vitae pellentesque maecenas ut. Aut ac eleifend at nonummy nec, litora quam hymenaeos vehicula sed diam, blandit duis fermentum lacus ante, accumsan velit nonummy eleifend, id ante. Ultrices elit ipsum. Integer est, posuere sed duis odio. Praesent per ante eligendi etiam, integer convallis vestibulum et ultricies, porta mauris, ab dui a nulla vitae ac aliquet, erat sem integer. Fermentum risus nulla, risus eget mi. Taciti dui justo feugiat malesuada adipiscing arcu, ac sapien sed phasellus vitae porta, vel quisque mattis nunc ultricies fames, volutpat ipsum et. Mauris vestibulum justo augue phasellus lacinia, consectetuer urna ut, est consectetuer enim porta nulla. Viverra amet sodales nam duis maecenas, vitae quis ornare officia integer non, placeat tristique placerat at wisi sit, ut urna enim fusce sit et, amet libero pharetra. Morbi nascetur ipsum malesuada neque, mollis justo ipsum neque accumsan eget, nullam proin aliquam elementum."
            pre_shared_key = '0123456789qazWSXedcRFV'

            #generate the encrypted package
            enc_derived_key, enc_salt, enc_iv, real_gist_file_name = gister_transmit.generate_key_material(pre_shared_key)
            encrypted_package = gister_transmit.generate_upload_package(message, enc_derived_key, enc_iv, real_gist_file_name)
            gist_id = gister_transmit.upload_package_to_gist(encrypted_package)

            #just as it will be used, only pass the gist_id and the 
            
            #pass the encrypted package, key, and iv to the decrypter
            time.sleep(5)
            derived_key = gister_receive.gen_derived_key(pre_shared_key, enc_salt)
            encrypted_package = gister_receive.retrieve_message(gist_id)
            decrypted_message = gister_receive.decrypt_message(encrypted_package, derived_key)

            self.assertTrue(decrypted_message == message)

    def test_post_large_message(self):
        blob_size = 100000
        for i in range(0,2):
            message = ''.join(chr(random.SystemRandom().randint(0,255)) for _ in range(random.SystemRandom().randint(blob_size,blob_size*10)))
            pre_shared_key = '0192837465OKMijnUHBygv'

            #generate the encrypted package
            enc_derived_key, enc_salt, enc_iv, real_gist_file_name = gister_transmit.generate_key_material(pre_shared_key)
            encrypted_package = gister_transmit.generate_upload_package(message, enc_derived_key, enc_iv, real_gist_file_name)
            gist_id = gister_transmit.upload_package_to_gist(encrypted_package)
            
            #pass the encrypted package, key, and iv to the decrypter
            time.sleep(5)
            encrypted_package = gister_receive.retrieve_message(gist_id)
            decrypted_message = gister_receive.decrypt_message(encrypted_package, enc_derived_key)

            self.assertTrue(decrypted_message == message)


class TestQRCodeRendering(unittest.TestCase):
    def TestQRCodeGeneration(self):
        gist_id = r'4941b2934929dcccfea9'
        salt_enc= r't}"1DC~Axg*;T93X01+8%qnMSh?)sZ}9'
        gister_transmit.generate_and_display_report(gist_id, salt_enc)


if __name__ == '__main__':
    unittest.main()