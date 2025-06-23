import json
import numpy as np
import os
import time


# ====== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ КРИПТОГРАФИЧЕСКИ СТОЙКОЙ ГЕНЕРАЦИИ ======
def _generate_secure_random_int(p):
    if p <= 0:
        raise ValueError("Верхняя граница диапазона должна быть положительной.")
    byte_length = (p.bit_length() + 7) // 8
    max_valid_val = (2 ** (8 * byte_length) // p) * p
    while True:
        random_bytes = os.urandom(byte_length)
        random_int = int.from_bytes(random_bytes, 'big')
        if random_int < max_valid_val:
            return random_int % p

def _generate_secure_random_matrix(n, p):
    flat_size = n * n
    matrix_flat = np.array([_generate_secure_random_int(p) for _ in range(flat_size)], dtype=int)
    return matrix_flat.reshape((n, n))

def _generate_secure_random_vector(n, p):
    return np.array([_generate_secure_random_int(p) for _ in range(n)], dtype=int)


# ====== ГЛАВА 1: ГЕНЕРАЦИЯ СЕКРЕТНОГО КЛЮЧА ======
def generate_k_poly(n, p, lam, omega):
    degree = omega * lam
    k_poly = [_generate_secure_random_matrix(n, p) for _ in range(degree)]
    k_poly.append(np.identity(n, dtype=int))
    return k_poly

def generate_k_vector(n, p):
    while True:
        k_vec = _generate_secure_random_vector(n, p)
        if np.any(k_vec != 0):
            has_invertible = False
            for element in k_vec:
                if element != 0:
                    try:
                        pow(int(element), -1, p)
                        has_invertible = True
                        break
                    except ValueError:
                        continue
            if has_invertible:
                return k_vec

# ====== ГЛАВА 2: КЛЮЧ ВЫЧИСЛЕНИЯ ======
def generate_random_matrix_poly(delta, lam, n, p):
    degree = delta * lam
    r_poly = [_generate_secure_random_matrix(n, p) for _ in range(degree + 1)]
    return r_poly

def multiply_matrix_polynominals(a, b, p):
    if not a or not b:
        return []
    deg_a, deg_b = len(a) - 1, len(b) - 1
    n_a_rows, n_a_cols = a[0].shape if a else (0, 0)
    n_b_rows, n_b_cols = b[0].shape if b else (0, 0)

    if n_a_cols != n_b_rows:
        raise ValueError("Матричные полиномы несовместимы для умножения.")

    result_rows, result_cols = n_a_rows, n_b_cols
    result = [np.zeros((result_rows, result_cols), dtype=int) for _ in range(deg_a + deg_b + 1)]

    for i in range(deg_a + 1):
        for j in range(deg_b + 1):
            result[i + j] = (result[i + j] + a[i] @ b[j]) % p
    while len(result) > 1 and np.all(result[-1] == 0):
        result.pop()
    return result

def generate_evaluation_key(k_poly, n, p, delta, lam):
    r_poly = generate_random_matrix_poly(delta, lam, n, p)
    evk = multiply_matrix_polynominals(r_poly, k_poly, p)
    return evk


# ====== ГЛАВА 3: ШИФРОВАНИЕ ======
def commutes_with_poly(m, k_poly, p):
    return all(np.array_equal((m @ Ki) % p, (Ki @ m) % p) for Ki in k_poly)

def is_eigenvector(mat, k, m, p):
    k_col = k.reshape(-1, 1)
    mat_k = (mat @ k_col) % p
    mk = (m * k_col) % p
    return np.array_equal(mat_k, mk)

def generate_m_matrix(k_poly, k, m, p):
    N = k.shape[0]
    identity = np.identity(N, dtype=int)
    base = m * identity % p
    i = 0
    total_elements = N * N
    attempt = 0
    while True:
        b_flat = []
        remainder = attempt
        for _ in range(total_elements):
            b_flat.append(remainder % p)
            remainder //= p
        B = np.array(b_flat).reshape(N, N)

        M = (base + B) % p
        i = i + 1

        if commutes_with_poly(M, k_poly, p) and is_eigenvector(M, k, m, p):
            return M

def generate_r_poly(n, p, lam, psi):
    degree = psi * lam
    r_poly = [_generate_secure_random_matrix(n, p) for _ in range(degree + 1)]
    return r_poly

def encrypt_message(k_poly, m, n, p, lam, psi):
    start_time = time.time()

    r_poly = generate_r_poly(n, p, lam, psi)
    RK = multiply_matrix_polynominals(r_poly, k_poly, p)
    if not RK:
        RK = [np.zeros_like(m)]
    if len(RK) == 0:
        RK.append(np.zeros_like(m))
    RK[0] = (RK[0] + m) % p
    while len(RK) > 1 and np.all(RK[-1] == 0):
        RK.pop()

    end_time = time.time()
    print(f"[*] Шифрование выполнено за {end_time - start_time:.6f} секунд.")

    return RK


# ====== ГЛАВА 4: ОПЕРАЦИИ ======
def add_ciphertexts(c1, c2, p):
    start_time = time.time()
    len1, len2 = len(c1), len(c2)
    max_len = max(len1, len2)
    if c1 and len(c1[0].shape) == 2:
        N = c1[0].shape[0]
    elif c2 and len(c2[0].shape) == 2:
        N = c2[0].shape[0]
    elif c1 or c2:
        raise ValueError("Некорректный формат шифртекста")
    else:
        return []
    result = []
    for i in range(max_len):
        A = c1[i] if i < len1 else np.zeros((N, N), dtype=int)
        B = c2[i] if i < len2 else np.zeros((N, N), dtype=int)
        result.append((A + B) % p)
    while len(result) > 1 and np.all(result[-1] == 0):
        result.pop()
    end_time = time.time()
    print(f"[*] Гомоморфное сложение выполнено за {end_time - start_time:.6f} секунд.")
    return result

def multiply_ciphertexts(c1, c2, evk, p):
    start_time=time.time()

    multi = multiply_matrix_polynominals(c1, c2, p)
    multi = poly_divmod(multi, evk, p)

    end_time = time.time()
    print(f"[*] Гомоморфное умножение выполнено за {end_time - start_time:.6f} секунда")
    return multi


# ====== ГЛАВА 5: РАСШИФРОВКА ======

def poly_divmod(dividend_poly, divisor_poly, p):
    if not divisor_poly:
        raise ZeroDivisionError("Деление на нулевой полином")
    N = dividend_poly[0].shape[0]
    zero_matrix = np.zeros((N, N), dtype=int)
    remainder = [m.copy() for m in dividend_poly]
    divisor_deg = len(divisor_poly) - 1
    while len(remainder) - 1 >= divisor_deg:
        remainder_deg = len(remainder) - 1
        remainder_leading_coeff = remainder[-1]
        if np.all(remainder_leading_coeff == 0):
            remainder.pop()
            if not remainder:
                remainder = [zero_matrix.copy()]
            continue
        deg_diff = remainder_deg - divisor_deg
        term_coeff = remainder_leading_coeff
        for i in range(divisor_deg + 1):
            idx_to_subtract = i + deg_diff
            if idx_to_subtract < len(remainder):
                product = (term_coeff @ divisor_poly[i]) % p
                remainder[idx_to_subtract] = (remainder[idx_to_subtract] - product) % p
        if len(remainder) > 1 and np.all(remainder[-1] == 0):
            remainder.pop()
        if not remainder:
            remainder = [zero_matrix.copy()]
        if remainder_deg == len(remainder) - 1 and not np.all(remainder[-1] == 0):
            break
    while len(remainder) > 1 and np.all(remainder[-1] == 0):
        remainder.pop()
    if not remainder:
        remainder = [zero_matrix.copy()]
    return remainder

def decrypt_ciphertext(c_poly, k_poly, k, p):
    start_time = time.time()
    if not c_poly:
        raise ValueError("Нельзя расшифровать пустой шифртекст")
    if not k_poly:
        raise ValueError("Секретный полином K(X) не может быть пустым")
    N = k.shape[0]
    if c_poly[0].shape != (N, N):
        raise ValueError(f"Размер матрицы C0 {c_poly[0].shape} не соответствует N={N}")
    if k_poly[0].shape != (N, N):
        raise ValueError(f"Размер матрицы K0 {k_poly[0].shape} не соответствует N={N}")
    try:
        m_poly = poly_divmod(c_poly, k_poly, p)
    except Exception as e:
        raise ValueError(f"Ошибка при делении полиномов: {e}")
    if not m_poly:
        raise ValueError("Результат деления полиномов пуст.")
    M0 = m_poly[0]

    k_col = k.reshape(-1, 1)
    y = (M0 @ k_col) % p

    decrypted_message = None
    for i in range(N):
        if k[i] != 0:
            try:
                inv_ki = pow(int(k[i]), -1, p)
                m = (y[i, 0] * inv_ki) % p
                decrypted_message = m
                break
            except ValueError:
                continue

    if decrypted_message is None:
        raise ValueError("Невозможно расшифровать: нет обратимых элементов в векторе k")

    end_time = time.time()
    print(f"[*] Расшифровка выполнена за {end_time - start_time:.6f} секунд.")

    return decrypted_message

# === ГЛАВА 5. Сохранение и загрузка ===
def save_json(data, filename):
    def convert_to_list(item):
        if isinstance(item, np.ndarray):
            return item.tolist()
        if isinstance(item, (list, tuple)):
            return [convert_to_list(sub_item) for sub_item in item]
        if isinstance(item, dict):
            return {key: convert_to_list(value) for key, value in item.items()}
        if isinstance(item, (np.int_, np.intc, np.intp, np.int8, np.int16, np.int32, np.int64,
                             np.uint8, np.uint16, np.uint32, np.uint64)):
            return int(item)
        if isinstance(item, (np.float_, np.float16, np.float32, np.float64)):
            return float(item)
        if isinstance(item, (np.complex_, np.complex64, np.complex128)):
            return {'real': item.real, 'imag': item.imag}
        if isinstance(item, np.bool_):
            return bool(item)
        if isinstance(item, np.void):
            return None
        return item

    serializable_data = convert_to_list(data)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(serializable_data, f, indent=2, ensure_ascii=False)

def load_json(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return json.load(f)

def matrix_list_to_numpy(data):
    if isinstance(data, list):
        try:
            return [np.array(m, dtype=int) for m in data]
        except Exception as e:
            print(f"Ошибка при преобразовании списка матриц в numpy: {e}")
            raise ValueError("Некорректный формат данных для списка матриц") from e
    else:
        raise ValueError("Ожидался список матриц")

def matrix_to_numpy(data):
    try:
        return np.array(data, dtype=int)
    except Exception as e:
        print(f"Ошибка при преобразовании матрицы в numpy: {e}")
        raise ValueError("Некорректный формат данных для матрицы") from e

