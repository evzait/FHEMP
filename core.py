import json
import numpy as np
import os
import time


# ====== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ КРИПТОГРАФИЧЕСКИ СТОЙКОЙ ГЕНЕРАЦИИ ======
def generate_random(p):
    if p <= 0:
        raise ValueError("Верхняя граница диапазона должна быть положительной.")
    byte_length = (p.bit_length() + 7) // 8
    max_valid_val = (2 ** (8 * byte_length) // p) * p
    while True:
        random_bytes = os.urandom(byte_length)
        random_int = int.from_bytes(random_bytes, 'big')
        if random_int < max_valid_val:
            return random_int % p

def generate_random_matrix(N, p):
    flat_size = N * N
    matrix_flat = np.array([generate_random(p) for _ in range(flat_size)], dtype=int)
    return matrix_flat.reshape((N, N))

def generate_random_vector(N, p):
    return np.array([generate_random(p) for _ in range(N)], dtype=int)


# ====== ГЛАВА 1: ГЕНЕРАЦИЯ СЕКРЕТНОГО КЛЮЧА ======
def generate_K_poly(N, p, lam, omega):
    degree = omega * lam
    K_poly = [generate_random_matrix(N, p) for _ in range(degree)]
    K_poly.append(np.identity(N, dtype=int))
    return K_poly

def generate_k_vector(N, p):
    while True:
        k_vec = generate_random_vector(N, p)
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
def generate_random_matrix_poly(delta, lam, N, p):
    degree = delta * lam
    R_poly = [generate_random_matrix(N, p) for _ in range(degree + 1)]
    return R_poly

def multiply_matrix_polynominals(A, B, p):
    if not A or not B:
        return []
    deg_A, deg_B = len(A) - 1, len(B) - 1
    N_A_rows, N_A_cols = A[0].shape if A else (0, 0)
    N_B_rows, N_B_cols = B[0].shape if B else (0, 0)

    if N_A_cols != N_B_rows:
        raise ValueError("Матричные полиномы несовместимы для умножения.")

    result_rows, result_cols = N_A_rows, N_B_cols
    result = [np.zeros((result_rows, result_cols), dtype=int) for _ in range(deg_A + deg_B + 1)]

    for i in range(deg_A + 1):
        for j in range(deg_B + 1):
            result[i + j] = (result[i + j] + A[i] @ B[j]) % p
    while len(result) > 1 and np.all(result[-1] == 0):
        result.pop()
    return result

def generate_evaluation_key(K_poly, N, p, delta, lam):
    R_poly = generate_random_matrix_poly(delta, lam, N, p)
    evk = multiply_matrix_polynominals(R_poly, K_poly, p)
    return evk


# ====== ГЛАВА 3: ШИФРОВАНИЕ ======
def commutes_with_poly(M, K_poly, p):
    return all(np.array_equal((M @ Ki) % p, (Ki @ M) % p) for Ki in K_poly)

def is_eigenvector(M, k, m, p):
    k_col = k.reshape(-1, 1)
    Mk = (M @ k_col) % p
    mk = (m * k_col) % p
    return np.array_equal(Mk, mk)

def generate_M_matrix(K_poly, k, m, p):
    N = k.shape[0]
    identity = np.identity(N, dtype=int)
    base = m * identity % p
    i = 0
    total_elements = N * N
    attempt = 0
    while True:
        B_flat = []
        remainder = attempt
        for _ in range(total_elements):
            B_flat.append(remainder % p)
            remainder //= p
        B = np.array(B_flat).reshape(N, N)

        M = (base + B) % p
        i = i + 1

        if commutes_with_poly(M, K_poly, p) and is_eigenvector(M, k, m, p):
            return M

def generate_R_poly(N, p, lam, psi):
    degree = psi * lam
    R_poly = [generate_random_matrix(N, p) for _ in range(degree + 1)]
    return R_poly

def encrypt_message(K_poly, M, N, p, lam, psi):
    R_poly = generate_R_poly(N, p, lam, psi)
    RK = multiply_matrix_polynominals(R_poly, K_poly, p)
    RK[0] = (RK[0] + M) % p
    while len(RK) > 1 and np.all(RK[-1] == 0):
        RK.pop()
    return RK


# ====== ГЛАВА 4: ОПЕРАЦИИ ======
def add_ciphertexts(C1, C2, p):
    start_time = time.time()
    len1, len2 = len(C1), len(C2)
    max_len = max(len1, len2)
    if C1 and len(C1[0].shape) == 2:
        N = C1[0].shape[0]
    elif C2 and len(C2[0].shape) == 2:
        N = C2[0].shape[0]
    elif C1 or C2:
        raise ValueError("Некорректный формат шифртекста")
    else:
        return []
    result = []
    for i in range(max_len):
        A = C1[i] if i < len1 else np.zeros((N, N), dtype=int)
        B = C2[i] if i < len2 else np.zeros((N, N), dtype=int)
        result.append((A + B) % p)
    while len(result) > 1 and np.all(result[-1] == 0):
        result.pop()
    end_time = time.time()
    #print(f"[*] Гомоморфное сложение выполнено за {end_time - start_time:.6f} секунд.")
    return result

def multiply_ciphertexts(C1, C2, evk, p):
    start_time=time.time()

    multi = multiply_matrix_polynominals(C1, C2, p)
    multi = poly_divmod(multi, evk, p)

    end_time = time.time()
    #print(f"[*] Гомоморфное умножение выполнено за {end_time - start_time:.6f} секунда")
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

def decrypt_ciphertext(C_poly, K_poly, k, p):
    if not C_poly:
        raise ValueError("Нельзя расшифровать пустой шифртекст")
    if not K_poly:
        raise ValueError("Секретный полином K(X) не может быть пустым")
    N = k.shape[0]
    if C_poly[0].shape != (N, N):
        raise ValueError(f"Размер матрицы C0 {C_poly[0].shape} не соответствует N={N}")
    if K_poly[0].shape != (N, N):
        raise ValueError(f"Размер матрицы K0 {K_poly[0].shape} не соответствует N={N}")
    try:
        M_poly = poly_divmod(C_poly, K_poly, p)
    except Exception as e:
        raise ValueError(f"Ошибка при делении полиномов: {e}")
    if not M_poly:
        raise ValueError("Результат деления полиномов пуст.")
    M0 = M_poly[0]

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
    #print(f"[*] Расшифровка выполнена за {end_time - start_time:.6f} секунд.")

    return decrypted_message

# === ГЛАВА 5. Сохранение и загрузка ===
def save_json(data, filename):
    def convert_to_list(item):
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

