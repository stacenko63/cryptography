import argparse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import os


parser = argparse.ArgumentParser(description="CryptoSystem")
#parser.add_argument("--gen", dest="gen_option", help="Запускает режим генерации ключей. Обязательные параметры: -encode_symmetric_key_in_file, -encode_public_key_in_file, encode_private_key_in_file")
#parser.add_argument("--enc", dest="enc_option", help="Запускает режим шифрования. Обязательный параметры: -text_for_encrypt, -file_with_private_key_for_encrypt, -file_with_encrypt_symmetric_key, -file_for_encrypt_text")
#parser.add_argument("--dec", dest="dec_option", help="Запускает режим дешифрования. Обязательные параметры: -file_with_encrypt_text, -file_with_private_key_for_encrypt, -file_with_encrypt_symmetric_key, -file_for_decrypt_text")
parser.add_argument("--work_option", dest="work_option", help="gen: Запускает режим генерации ключей. Обязательные параметры: -encode_symmetric_key_in_file, -encode_public_key_in_file, encode_private_key_in_file; enc: Запускает режим шифрования. Обязательный параметры: -text_for_encrypt, -file_with_private_key_for_encrypt, -file_with_encrypt_symmetric_key, -file_for_encrypt_text; "
                                                              "dec: Запускает режим дешифрования. Обязательные параметры: -file_with_encrypt_text, -file_with_private_key_for_encrypt, "
                                                              "-file_with_encrypt_symmetric_key, -file_for_decrypt_text")

parser.add_argument("--encode_symmetric_key_in_file", dest="encode_symmetric_key_in_file", help="Путь, по которому сериализовать зашифрованный симметричный ключ")
parser.add_argument("--encode_public_key_in_file", dest="encode_public_key_in_file", help="Путь, по которому сериализовать открытый ключ")
parser.add_argument("--encode_private_key_in_file", dest="encode_private_key_in_file", help="Путь, по которому сериализовать закрытый ключ")
##########
parser.add_argument("--text_for_encrypt", dest="text_for_encrypt", help="Путь к шифруемому текстовому файлу")
parser.add_argument("--file_with_private_key_for_encrypt", dest="file_with_private_key_for_encrypt", help="Путь к закрытому ключу ассиметричного алгоритма")
parser.add_argument("--file_with_encrypt_symmetric_key", dest="file_with_encrypt_symmetric_key", help="Путь к зашифрованному ключу симметричного алгоритма")
parser.add_argument("--file_for_encrypt_text", dest="file_for_encrypt_text", help="Путь, по которому сохранить зашифрованный текстовый файл")
##########
parser.add_argument("--file_with_encrypt_text", dest="file_with_encrypt_text", help="Путь к зашифрованному текстовому файлу")
parser.add_argument("--file_for_decrypt_text", dest="file_for_decrypt_text", help="Путь, по которому сохранить расшифрованный текстовый файл")
args = parser.parse_args()
iv = os.urandom(8)
if args.work_option == "gen":
    if args.encode_symmetric_key_in_file is None or args.encode_public_key_in_file is None or args.encode_private_key_in_file is None:
        print("Ошибка! Были введены не все параметры")
    else:
        key = os.urandom(16)
        print(key)
        keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key = keys
        print(type(private_key))
        public_key = keys.public_key()
        symmetric_key = public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        with open(args.encode_symmetric_key_in_file, 'wb') as key_file:
            key_file.write(symmetric_key)
        with open(args.encode_public_key_in_file, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
        with open(args.encode_private_key_in_file, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()))
# python CryptoSystem.py --work_option gen --encode_symmetric_key_in_file symmetric_keys.txt --encode_public_key_in_file public.pem --encode_private_key_in_file private.pem
elif args.work_option == "enc":
# python CryptoSystem.py --work_option enc --text_for_encrypt E:\\3.txt --file_with_private_key_for_encrypt private.pem --file_with_encrypt_symmetric_key symmetric_keys.txt --file_for_encrypt_text E:\\result.txt
    if args.text_for_encrypt is None or args.file_with_private_key_for_encrypt is None or args.file_with_encrypt_symmetric_key is None or args.file_for_encrypt_text is None:
        print("Ошибка! Были введены не все параметры")
    else:
        if not os.path.exists(args.text_for_encrypt):
            print("Ошибка! Некорректный путь к шифруемому текстовому файлу")
        elif not os.path.exists(args.file_with_private_key_for_encrypt):
            print("Ошибка! Некорректный путь к закрытому ключу ассиметричного алгоритма")
        elif not os.path.exists(args.file_with_encrypt_symmetric_key):
            print("Ошибка! Некорректный путь к зашифрованному ключу симметричного алгоритма")
        else:
            with open(args.file_with_encrypt_symmetric_key, 'rb') as key_file:
                encrypt_symmetric_key = key_file.read()
            with open(args.file_with_private_key_for_encrypt, 'rb') as private_file:
                private_k = serialization.load_pem_private_key(private_file.read(), password=None)
            with open(args.text_for_encrypt, 'rb') as text_file:
                text_for_encrypt = text_file.read()
            symmetric_key = private_k.decrypt(encrypt_symmetric_key,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            print(symmetric_key)
            from cryptography.hazmat.primitives import padding
            padder = padding.ANSIX923(64).padder()
            text = text_for_encrypt
            padded_text = padder.update(text)+padder.finalize()
            cipher = Cipher(algorithms.IDEA(symmetric_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            c_text = encryptor.update(padded_text) + encryptor.finalize()
            print(c_text)
            with open(args.file_for_encrypt_text, 'wb') as file_result:
                file_result.write(c_text)
elif args.work_option == "dec":
    #python CryptoSystem.py --work_option dec --file_with_encrypt_text E:\\result.txt --file_with_private_key_for_encrypt private.pem --file_with_encrypt_symmetric_key symmetric_keys.txt --file_for_decrypt_text E:\\result2.txt
    if args.file_with_encrypt_text is None or args.file_with_private_key_for_encrypt is None or args.file_with_encrypt_symmetric_key is None or args.file_for_decrypt_text is None:
        print("Ошибка! Были введены не все параметры")
    else:
        if not os.path.exists(args.file_with_encrypt_text):
            print("Ошибка! Некорректный путь к зашифрованному текстовому файлу")
        elif not os.path.exists(args.file_with_private_key_for_encrypt):
            print("Ошибка! Некорректный путь к закрытому ключу ассиметричного алгоритма")
        elif not os.path.exists(args.file_with_encrypt_symmetric_key):
            print("Ошибка! Некорректный путь к зашифрованному ключу симметричного алгоритма")
        else:
            with open(args.file_with_encrypt_symmetric_key, 'rb') as key_file:
                encrypt_symmetric_key = key_file.read()
            with open(args.file_with_private_key_for_encrypt, 'rb') as private_file:
                private_k = serialization.load_pem_private_key(private_file.read(), password=None)
            with open(args.file_with_encrypt_text, 'rb') as text_file:
                text_for_decrypt = text_file.read()
            print(type(encrypt_symmetric_key))
            print(type(private_k))
            print(type(text_for_decrypt))
            print(iv)
            print(type(iv))
            symmetric_key = private_k.decrypt(encrypt_symmetric_key,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            print(symmetric_key)
            from cryptography.hazmat.primitives import padding
            cipher = Cipher(algorithms.IDEA(symmetric_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            dc_text = decryptor.update(text_for_decrypt) + decryptor.finalize()
            print(dc_text)
            unpadder = padding.ANSIX923(64).unpadder()
            unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
            with open(args.file_for_decrypt_text, 'wb') as file_result:
                file_result.write(unpadded_dc_text)
else:
    print("Ошибка! Указанной вами опции работы программы не существует")


