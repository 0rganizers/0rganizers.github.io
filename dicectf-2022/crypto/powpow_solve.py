from gmpy2 import mpz, is_prime, to_binary
from hashlib import shake_128

n = mpz(20074101780713298951367849314432888633773623313581383958340657712957528608477224442447399304097982275265964617977606201420081032385652568115725040380313222774171370125703969133604447919703501504195888334206768326954381888791131225892711285554500110819805341162853758749175453772245517325336595415720377917329666450107985559621304660076416581922028713790707525012913070125689846995284918584915707916379799155552809425539923382805068274756229445925422423454529793137902298882217687068140134176878260114155151600296131482555007946797335161587991634886136340126626884686247248183040026945030563390945544619566286476584591)
T = mpz(2**64)

def is_valid(x):
    return type(x) == int and 0 < x < n

def encode(x):
    if type(x) == int:
        return x.to_bytes(256, 'big')
    else:
        return int(x).to_bytes(256, 'big')

def H(g, h):
    return int.from_bytes(shake_128(encode(g) + encode(h)).digest(16), 'big')

def verify(g, h, pi):
    assert is_valid(g)
    assert is_valid(h)
    assert is_valid(pi)
    assert g != 1 and g != n - 1
    m = H(g, h)
    r = pow(2, T, m)
    # change assert to return bool for testing
    return h == pow(pi, m, n) * pow(g, r, n) % n

def gen_smooth(upper_bound):
    M = mpz(1)
    for i in range(1, upper_bound):
        if is_prime(i):
            M *= i
    return M

def gen_solution(M):
    g = pow(2, M, n)
    h = 1
    for i in range(10**6):
        m = mpz(H(g, h))
        if M % m == 0:
            r = pow(2, T, m)
            k = -r*M // m
            pi = pow(2, k, n)
            return int(g), int(h), int(pi) 
        M = M << 1
        g = pow(g,2,n)

print(f"Generating smooth value M")
M = gen_smooth(10**6)

print(f"Searching for valid m")
g, h, pi = gen_solution(M)
    
print(f"g  = {hex(g)}")
print(f"h  = {hex(h)}")
print(f"pi = {hex(pi)}")

assert verify(g, h, pi)
