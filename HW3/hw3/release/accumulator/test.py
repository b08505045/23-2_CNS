def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm: Computes gcd(a, b) and coefficients x, y
    such that ax + by = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def extended_gcd(a, b):
    """return (x, y) such that a*x + b*y = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return x0, y0

def modular_inverse(number, modulus):
    """
    Calculates the modular inverse of a number in modulus N.
    """
    x, _ = extended_gcd(number, modulus)
    return x % modulus
    # if gcd == 1:
    #     return x % modulus
    # else:
    #     raise ValueError("Modular inverse does not exist.")

# Example usage
number = 7
modulus = 26

inverse = modular_inverse(number, modulus)
print(inverse)
print(pow(7, -1, 26))