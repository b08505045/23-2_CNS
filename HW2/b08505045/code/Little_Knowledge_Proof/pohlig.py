def discrete_log(p, g, h):
    """
    Computes the discrete logarithm of h in base g modulo p using the Pohlig-Hellman algorithm.
    """
    factors = factorize(p - 1)
    x = 0
    for prime, exp in factors:
        m = (p - 1) // prime**exp
        # compute discrete logarithm modulo prime**exp
        y = pow(pow(g, x, p), m, p)
        z = pow(h, m, p)
        q = pow(g, m * (prime**(exp - 1)), p)
        # print(f'y = {y}')
        # print(f'z = {z}')
        # print(f'q = {q}')
        for j in range(1, exp):
            # compute discrete logarithm modulo prime**j
            y = pow(y, prime, p)
            z = z * pow(q, -1, p) % p
            q = pow(q, prime, p)
            l = 0
            while pow(q, l, p) != z:
                l += 1
            x += l * prime**(j - 1)
    return x

def factorize(n):
    """
    Returns a list of prime factors of n with their multiplicities.
    """
    factors = []
    i = 2
    while i * i <= n:
        exp = 0
        while n % i == 0:
            n //= i
            exp += 1
        if exp > 0:
            factors.append((i, exp))
        i += 1
    if n > 1:
        factors.append((n, 1))
    return factors

p = 14441638348624213626083118173029616034636236203323405960283519413957104355762238013154233838351528737517308038661176687865191516418733778513644060317253479
q = p - 1   # group order
g = 11
y = 9561649903826401194424429829087038008994189104830088932155338858706813419184358908819778209856931077467756994935446807814714436047612742953865073558777496
factors = factorize(q)
print(factors)
# x = discrete_log(p, g, y)
# print(x)