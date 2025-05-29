b = [
    "Call: bn_wexpand(FakeRet(BN_CTX_get), 1 + FakeRet(bn_get_top))",
    "Call: bn_wexpand(FakeRet(T), 1 + FakeRet(bn_get_top))",
    "Call: bn_wexpand(FakeRet(BN_CTX_get), 1 + FakeRet(T))",
    "Call: bn_wexpand(FakeRet(BN_CTX_get), FakeRet(bn_get_top) + T)",
    "Call: bn_wexpand(T, 1 + FakeRet(bn_get_top))",
    "Call: bn_wexpand(FakeRet(T), 1 + FakeRet(T))",
    "Call: bn_wexpand(FakeRet(T), FakeRet(bn_get_top) + T)",
    "Call: bn_wexpand(FakeRet(BN_CTX_get), 1 + T)",
    "Call: bn_wexpand(FakeRet(BN_CTX_get), FakeRet(T) + T)",
    "Call: bn_wexpand(T, 1 + FakeRet(T))",
    "Call: bn_wexpand(T, FakeRet(bn_get_top) + T)",
    "Call: bn_wexpand(FakeRet(T), 1 + T)",
    "Call: bn_wexpand(FakeRet(T), FakeRet(T) + T)",
    "Call: bn_wexpand(FakeRet(BN_CTX_get), 2*T)",
    "Call: bn_wexpand(T, 1 + T)",
    "Call: bn_wexpand(T, FakeRet(T) + T)",
    "Call: bn_wexpand(FakeRet(T), 2*T)",
    "Call: bn_wexpand(FakeRet(BN_CTX_get), T)",
    "Call: bn_wexpand(T, 2*T)",
    "Call: bn_wexpand(FakeRet(T), T)",
    "Call: bn_wexpand(T, T)"
]

b.reverse()
# print(b)
for i, item in enumerate(b):
    print(f"{i+1}: {item}")

# [Put: 64 = T, Put: 64 = 2*T, Put: 64 = 1 + T, Put: 64 = FakeRet(T) + T, Put: 64 = 1 + FakeRet(T), Put: 64 = FakeRet(bn_get_top) + T, Put: 64 = 1 + FakeRet(bn_get_top)], [Put: 32 = T, Put: 32 = 2*T, Put: 32 = 1 + T, Put: 32 = FakeRet(T) + T, Put: 32 = 1 + FakeRet(T), Put: 32 = FakeRet(bn_get_top) + T, Put: 32 = 1 + FakeRet(bn_get_top)]