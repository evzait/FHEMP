from .core import (
    generate_k_vector, generate_k_poly, generate_evaluation_key, generate_m_matrix,
    encrypt_message, decrypt_ciphertext,
    add_ciphertexts, multiply_ciphertexts,
    save_json, load_json, matrix_list_to_numpy, matrix_to_numpy
)
import os

DEFAULT_DATA_DIR = os.path.abspath("FHEMP_data")
DEFAULT_KEY_DIR = os.path.join(DEFAULT_DATA_DIR, "key")
DEFAULT_CIPHER_DIR = os.path.join(DEFAULT_DATA_DIR, "cipher")

json_end = ".json"

def ensure_directories():
    os.makedirs(DEFAULT_KEY_DIR, exist_ok=True)
    os.makedirs(DEFAULT_CIPHER_DIR, exist_ok=True)

def generate_keys(n, p, lam, omega, delta, sk_name = "sk", k_name = "vec", evk_name = "evk", save_dir = DEFAULT_KEY_DIR):
    ensure_directories()

    if not sk_name.endswith(json_end):
        sk_name += json_end
    if not k_name.endswith(json_end):
        k_name += json_end
    if not evk_name.endswith(json_end):
        evk_name += json_end

    k_poly = generate_k_poly(n, p, lam, omega)
    k_vec = generate_k_vector(n, p)
    evk = generate_evaluation_key(k_poly, n, p, delta, lam)

    save_json(k_poly, os.path.join(save_dir, sk_name))
    save_json(k_vec, os.path.join(save_dir, k_name))
    save_json(evk, os.path.join(save_dir, evk_name))

    return True

def encrypt(message, filename, n, p, lam, psi, secret_key_file, vector_file):
    ensure_directories()
    if not filename.endswith(json_end):
        filename += json_end
    if not secret_key_file.endswith(json_end):
        secret_key_file += json_end
    if not vector_file.endswith(json_end):
        vector_file += json_end

    secret_key_file = os.path.join(DEFAULT_KEY_DIR, secret_key_file)
    vector_file = os.path.join(DEFAULT_KEY_DIR, vector_file)

    k_poly = matrix_list_to_numpy(load_json(secret_key_file))
    k_vec = matrix_to_numpy(load_json(vector_file))

    M = generate_m_matrix(k_poly, k_vec, message, p)

    ciphertext = encrypt_message(k_poly, M, n, p, lam, psi)
    save_json(ciphertext, os.path.join(DEFAULT_CIPHER_DIR, filename))
    return ciphertext

def decrypt(ciphertext_file, secret_key_file, vector_file, p):
    if not ciphertext_file.endswith(json_end):
        ciphertext_file += json_end
    if not secret_key_file.endswith(json_end):
        secret_key_file += json_end
    if not vector_file.endswith(json_end):
        vector_file += json_end

    ciphertext_file = os.path.join(DEFAULT_CIPHER_DIR, ciphertext_file)
    secret_key_file = os.path.join(DEFAULT_KEY_DIR, secret_key_file)
    vector_file = os.path.join(DEFAULT_KEY_DIR, vector_file)

    c_poly = matrix_list_to_numpy(load_json(ciphertext_file))
    k_poly = matrix_list_to_numpy(load_json(secret_key_file))
    k_vec = matrix_to_numpy(load_json(vector_file))

    result = decrypt_ciphertext(c_poly, k_poly, k_vec, p)
    return result

def operate_add(ciphertext_file1, ciphertext_file2, p, filename):
    if not ciphertext_file1.endswith(json_end):
        ciphertext_file1 += json_end
    if not ciphertext_file2.endswith(json_end):
        ciphertext_file2 += json_end
    if not filename.endswith(json_end):
        filename += json_end

    ciphertext_file1 = os.path.join(DEFAULT_CIPHER_DIR, ciphertext_file1)
    C1 = matrix_list_to_numpy(load_json(ciphertext_file1))

    ciphertext_file2 = os.path.join(DEFAULT_CIPHER_DIR, ciphertext_file2)
    C2 = matrix_list_to_numpy(load_json(ciphertext_file2))

    result = add_ciphertexts(C1, C2, p)

    save_json(result, os.path.join(DEFAULT_CIPHER_DIR, filename))
    return result

def operate_multi(ciphertext_file1, ciphertext_file2, p, name_evaluation_key_file, filename):
    if not ciphertext_file1.endswith(json_end):
        ciphertext_file1 += json_end
    if not ciphertext_file2.endswith(json_end):
        ciphertext_file2 += json_end
    if not filename.endswith(json_end):
        filename += json_end
    if not name_evaluation_key_file.endswith(json_end):
        name_evaluation_key_file += json_end

    ciphertext_file1 = os.path.join(DEFAULT_CIPHER_DIR, ciphertext_file1)
    C1 = matrix_list_to_numpy(load_json(ciphertext_file1))

    ciphertext_file2 = os.path.join(DEFAULT_CIPHER_DIR, ciphertext_file2)
    C2 = matrix_list_to_numpy(load_json(ciphertext_file2))

    evaluation_key_file = os.path.join(DEFAULT_KEY_DIR, name_evaluation_key_file)
    evk = matrix_list_to_numpy(load_json(evaluation_key_file))

    result = multiply_ciphertexts(C1, C2, evk, p)

    save_json(result, os.path.join(DEFAULT_CIPHER_DIR, filename))
    return result


generate_keys(5, 65537, 3, 3, 3, "sk", "kvec", "evk")
