##################
# Challenge Data #
##################

N  = 0xba8cb3257c0c83edf4f56f5b7e139d3d6ac8adf71618b5f16a02d61b63426c2c275ce631a0927b2725c6cc7bdbe30cd8a8494bc7c7f6601bcee5d005b86016e79919e22da4c431cec16be1ee72c056723fbbec1543c70bff8042630c5a9c23f390e2221bed075be6a6ac71ad89a3905f6c706b4fb6605c08f154ff8b8e28445a7be24cb184cb0f648db5c70dc3581419b165414395ae4282285c04d6a00a0ce8c06a678181c3a3c37b426824a5a5528ee532bdd90f1f28b7ec65e6658cb463e867eb5280bda80cbdb066cbdb4019a6a2305a03fd29825158ce32487651d9bfa675f2a6b31b7d05e7bd74d0f366cbfb0eb711a57e56e6db6d6f1969d52bf1b27b
e  = 0xd4088c345ced64cbbf8444321ef2af8b
c1 = 0x75240fcc256f1e2fc347f75bba11a271514dd6c4e58814e1cb20913195db3bd0440c2ca47a72efee41b0f9a2674f6f46a335fd7e54ba8cd1625daeaaaa45cc9550c566f6f302b7c4c3a4694c0f5bb05cd461b5ca9017f2eb0e5f60fb0c65e0a67f3a1674d74990fd594de692951d4eed32eac543f193b70777b14e86cf8fa1927fe27535e727613f9e4cd00acb8fab336894caa43ad40a99b222236afc219397620ca766cef2fe47d53b07e302410063eae3d0bf0a9d67793237281e0bfdd48255b58b2c1f8674a21754cf62fab0ba56557fa276241ce99140473483f3e5772fcb75b206b3e7dfb756005cec2c19a3cb7fa17a4d17f5edd10a8673607047a0d1
c2 = 0xdb8f645b98f71b93f248442cfc871f9410be7efee5cff548f2626d12a81ee58c1a65096a042db31a051904d7746a56147cc02958480f3b5d5234b738a1fb01dc8bf1dffad7f045cac803fa44f51cbf8abc74a17ee3d0b9ed59c844a23274345c16ba56d43f17d16d303bb1541ee1c15b9c984708a4a002d10188ccc5829940dd7f76107760550fac5c8ab532ff9f034f4fc6aab5ecc15d5512a84288d6fbe4b2d58ab6e326500c046580420d0a1b474deca052ebd93aaa2ef972aceba7e6fa75b3234463a68db78fff85c3a1673881dcb7452390a538dfa92e7ff61f57edf48662991b8dd251c0474b59c6f73d4a23fe9191ac8e52c8c409cf4902eeaa71714

##################
#    Solution    #
##################

R.<X> = PolynomialRing(Zmod(N))
R.<X> = R.quo(X^5 - c2)

f1 = (c1 - X)^e
f2 = f1^2
f3 = f1^3
f4 = f1^4
f5 = f1^5

M = Matrix(Zmod(N), 
    [f1.lift().coefficients(sparse=False),
    f2.lift().coefficients(sparse=False),
    f3.lift().coefficients(sparse=False),
    f4.lift().coefficients(sparse=False),
    f5.lift().coefficients(sparse=False)]).transpose()

v = vector(Zmod(N), [1,0,0,0,0])

sol = list(M.solve_right(v))

K.<m> = PolynomialRing(Zmod(N), implementation='NTL')
g = -1
for i,v in enumerate(sol):
    g += v*m^(i+1)

flag = g.monic().small_roots(X=2**(31*8), beta=1, epsilon=0.05)[0]
print(int(flag).to_bytes(31, 'big'))
