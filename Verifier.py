import json
import hashlib

file_path = input('Enter absolute path to file: ')

with open(file_path) as f:
    data = json.load(f)


def fast_powmod(n, m):
    pow2 = 2
    result = 1
    while n > 0:
        if n % 2 == 1:
            result = (result * pow2) % m
        pow2 = (pow2 * pow2) % m
        n >>= 1

    return result


def modulo_multiplicative_inverse(A, M):
    return fast_power(A, M - 2, M)


def fast_power(base, power, MOD):
    result = 1
    while power > 0:
        if power % 2 == 1:
            result = (result * base) % MOD

        power = power // 2
        base = (base * base) % MOD
    return result


# Initialize values for p, q, r, g, g_

q = 2 ** 256 - 189
p = 2 ** 4096 - 69 * q - 2650872664557734482243044168410288960
r = (p - 1) // q

# g = fast_powmod(r, p)
g = pow(2, r, p)
g_ = modulo_multiplicative_inverse(g, p)
joint_public_key_K = int(data['joint_public_key'])
ballot_status_flag = True
valid_public_key_list = []
for trustee_key_list in data['trustee_public_keys']:
    for trustee_key_info in trustee_key_list:
        valid_public_key_list.append(int(trustee_key_info['public_key']))
        break


def function_modular_product(contest_index, selection_index):
    A, B = 1, 1
    for cast_ballot in data['cast_ballots']:
        A = A * int(cast_ballot['contests'][contest_index]['selections'][selection_index]['message']['public_key'])
        B = B * int(cast_ballot['contests'][contest_index]['selections'][selection_index]['message']['ciphertext'])
    return pow(A, 1, p), pow(B, 1, p)


i = 0
for trustee_key_list in data['trustee_public_keys']:
    print('Trustee :', i)
    for trustee_key_info in trustee_key_list:
        lhs = pow(g, int(trustee_key_info['proof']['response']), p)
        rhs = pow(pow(int(trustee_key_info['proof']['commitment']), 1, p) * pow(int(trustee_key_info['public_key']),
                                                                                int(trustee_key_info['proof'][
                                                                                        'challenge']), p), 1, p)
        if lhs != rhs:
            print("Verification failed for: ")
            print(trustee_key_info)
            ballot_status_flag = False

    i = i + 1

i = 0
for cast_ballot in data['cast_ballots']:
    print('Computing ',i, 'of', len(data['cast_ballots']), ' ballot')
    for contest in cast_ballot["contests"]:
        A, B = 1, 1
        for selection in contest['selections']:
            # Ensure alpha,beta, a0, b0, a1, b1 are in set p and Z_p* and x^q mod p == 1

            if not (int(selection['message']['public_key']) < p):
                print('Public Key (Alpha): ', int(selection['message']['public_key']), ' not a part of subgroup p')
                ballot_status_flag = False

            if not (pow(int(selection['message']['public_key']), q, p) == 1):
                print('Public Key(Alpha): ', int(selection['message']['public_key']), ' not a part of subgroup Z_p*')
                ballot_status_flag = False

            if not (int(selection['message']['ciphertext']) < p):
                print('Ciphertext(Beta): ', int(selection['message']['ciphertext']), ' not a part of subgroup p')
                ballot_status_flag = False

            if not (pow(int(selection['message']['ciphertext']), q, p) == 1):
                print('Ciphertext(Beta): ', int(selection['message']['public_key']), ' not a part of subgroup Z_p*')
                ballot_status_flag = False

            # Zero proof public key in set p
            if not (int(selection['zero_proof']['commitment']['public_key']) < p):
                print('Public Key(a_0): ', int(selection['zero_proof']['commitment']['public_key']),
                      ' not a part of subgroup p')
                ballot_status_flag = False
            # Zero proof public key in Z_p*
            if not (pow(int(selection['zero_proof']['commitment']['public_key']), q, p) == 1):
                print('Public Key(a_0): ', int(selection['zero_proof']['commitment']['public_key']),
                      ' not a part of subgroup Z_p*')
                ballot_status_flag = False

            # Zero proof ciphertext in set p
            if not (int(selection['zero_proof']['commitment']['ciphertext']) < p):
                print('Ciphertext(b_0): ', int(selection['zero_proof']['commitment']['ciphertext']),
                      ' not part of subgroup p ')
                ballot_status_flag = False
            #Zero proof in ciphertext in set Z_p*
            if not (pow(int(selection['zero_proof']['commitment']['ciphertext']), q, p) == 1):
                print('Ciphertext(b_0): ', int(selection['zero_proof']['commitment']['ciphertext']),
                      ' not a part of subgroup Z_p*')
                ballot_status_flag = False

            # One proof public key in set p
            if not (int(selection['one_proof']['commitment']['public_key']) < p):
                print('Public Key(a_1): ', int(selection['one_proof']['commitment']['public_key']),
                      ' not a part of subgroup p')
                ballot_status_flag = False
            # One proof public key in set Z_p*
            if not (pow(int(selection['one_proof']['commitment']['public_key']), q, p) == 1):
                print('Public Key (a_1):', int(selection['one_proof']['commitment']['public_key']),
                      'not a part of subgroup Z_p*')
                ballot_status_flag = False

            # One proof ciphertext in set p

            if not (int(selection['one_proof']['commitment']['ciphertext']) < p):
                print('Ciphertext (b_1): ', int(selection['one_proof']['commitment']['ciphertext']),
                      ' not a part of subgroup p')
                ballot_status_flag = False
            # One proof ciphertext in set Z_p*
            if not (pow(int(selection['one_proof']['commitment']['ciphertext']), q, p) == 1):
                print('Ciphertext (b_1):', int(selection['one_proof']['commitment']['ciphertext']),
                      'not a part of subgroup Z_p*')
                ballot_status_flag = False

            # Ensure c0, c1, v0, v1 are in set Z_q
            if not (int(selection['zero_proof']['challenge']) < q):
                print('Challenge (c_0): ', int(selection['zero_proof']['challenge']), ' not a part of subgroup Z_q')
                ballot_status_flag = False
            if not (int(selection['zero_proof']['response']) < q):
                print('Challenge (c_0): ', int(selection['zero_proof']['challenge']), ' not a part of subgroup Z_q')
                ballot_status_flag = False
            if not (int(selection['one_proof']['challenge']) < q):
                print('Challenge (c_0): ', int(selection['zero_proof']['challenge']), ' not a part of subgroup Z_q')
                ballot_status_flag = False
            if not (int(selection['one_proof']['response']) < q):
                print('Challenge (c_0): ', int(selection['zero_proof']['challenge']), ' not a part of subgroup Z_q')
                ballot_status_flag = False

            # Compute c = SHA-256(extended_hash = 0, alpha, beta, a0, b0, a1, b1)
            # print('c: ',int(fn_compute_c(selection['message']['public_key'],
            # selection['message']['ciphertext'],
            # selection['zero_proof']['commitment']['public_key'],
            # selection['zero_proof']['commitment']['ciphertext'],
            # selection['one_proof']['commitment']['public_key'],
            # selection['one_proof']['commitment']['ciphertext']),0))

            # c0+c1 mod q
            # Corresponding C not computed
            c = pow(int(selection['zero_proof']['challenge']) + int(selection['one_proof']['challenge']), 1, q)

            #General Equation: g^(v_0) = (a_0)*(alpha)^(c_0) mod p. Don't use this with FULTON dataset!
            #lhs1 = pow(g, int(selection['zero_proof']['response']), p)
            #rhs1 = pow(pow(int(selection['zero_proof']['commitment']['public_key']), 1, p)*pow(int(selection['message']['public_key']),int(selection['zero_proof']['challenge']),p,1),1,p)

            # Modified equation for Fulton Verifier: g^(v_0) = a_0*K^(c_0) mod p

            lhs1 = pow(g, int(selection['zero_proof']['response']), p)
            rhs1 = pow(
                pow(int(selection['zero_proof']['commitment']['public_key']), 1, p) * pow(int(joint_public_key_K), int(
                    selection['zero_proof']['challenge']), p), 1, p)

            if lhs1 != rhs1:
                #print('g^(v_0) = (a_0)*(alpha)^(c_0) mod p verification falied for: ')
                print('g^(v_0) = (a_0)*K^(c_0) mod p verification failed for: ')
                print(selection)
                ballot_status_flag = False
            # General Equation: g^(v_1) = (a_1)*(alpha)^(c_1) mod p. Don't use this with FULTON dataset!
            # lhs2 = pow(g, int(selection['one_proof']['response']), p)
            # rhs2 = pow(pow(int(selection['one_proof']['commitment']['public_key']), 1, p)*pow(int(selection['message']['public_key']),int(selection['one_proof']['challenge']),p,1),1,p)

            # Modified equation for Fulton Verifier: g^(v_1) = a_1*K^(c_1) mod p
            lhs2 = pow(g, int(selection['one_proof']['response']), p)
            rhs2 = pow(pow(int(selection['one_proof']['commitment']['public_key']), 1, p) * pow(int(joint_public_key_K),
                                                                                                int(selection[
                                                                                                        'one_proof'][
                                                                                                        'challenge']),
                                                                                                p), 1, p)
            if lhs2 != rhs2:
                #print('g^(v_1) = (a_1)*(alpha)^(c_1) mod p verification failed for: ')
                print('g^(v_1) = a_1*K^(c_1) mod p verification failed for: ')
                print(selection)
                ballot_status_flag = False

            #General equation: K^v_0 = b_0*(beta)^(c_0) mod p
            #lhs3 = pow(int(joint_public_key_K), int(selection['zero_proof']['response']), p)
            #rhs3 = pow(pow(int(selection['zero_proof']['commitment']['ciphertext']), 1, p) * pow(int(selection['message']['ciphertext']), int(selection['zero_proof']['challenge']), p), 1, p)

            # Modified equation for Fulton Verifier: alpha^v_0 = b_0*(beta)^(c_0) mod p
            lhs3 = pow(int(selection['message']['public_key']), int(selection['zero_proof']['response']), p)
            rhs3 = pow(pow(int(selection['zero_proof']['commitment']['ciphertext']), 1, p) * pow(
                int(selection['message']['ciphertext']), int(selection['zero_proof']['challenge']), p), 1, p)
            if lhs3 != rhs3:
                #print('K^v_0 = b_0*(beta)^(c_0) mod p verification failed for: ')
                print('alpha^v_0 = b_0*(beta)^(c_0) mod p verification failed for: ')
                print(selection)
                ballot_status_flag = False

            #General equation: g^(c_1)*(K)^(v_1) = (b_1)*(beta)^(c_1) mod p
            #lhs4 = pow(pow(g, int(selection['one_proof']['challenge']), p) * pow(int(joint_public_key_K),int(selection['one_proof']['response']), p),1, p)
            #rhs4 = pow(pow(int(selection['one_proof']['commitment']['ciphertext']), 1, p) * pow(int(selection['message']['ciphertext']), int(selection['one_proof']['challenge']), p), 1, p)

            # Modified equation for Fulton Verifier: g^(c_1)*(alpha)^(v_1) = (b_1)*(beta)^(c_1) mod p
            lhs4 = pow(
                pow(g, int(selection['one_proof']['challenge']), p) * pow(int(selection['message']['public_key']),
                                                                          int(selection['one_proof']['response']), p),
                1, p)
            rhs4 = pow(pow(int(selection['one_proof']['commitment']['ciphertext']), 1, p) * pow(
                int(selection['message']['ciphertext']), int(selection['one_proof']['challenge']), p), 1, p)
            if lhs4 != rhs4:
                #print('g^(c_1)*(K)^(v_1) = (b_1)*(beta)^(c_1) mod p veriification failed for: ')
                print('g^(c_1)*(alpha)^(v_1) = (b_1)*(beta)^(c_1) mod p verification failed for: ')
                print(selection)
                ballot_status_flag = False

            # Compute A = modular_product(a_i)
            A = A * int(selection['message']['public_key'])

            # Compute B = modular_product(b_i)
            B = B * int(selection['message']['ciphertext'])

        # a,b in Zp^r
        if not (pow(int(contest["num_selections_proof"]['commitment']["public_key"]), q, p) == 1):
            print('Contest Selection Public Key (a): ',
                  int(contest["num_selections_proof"]['commitment']["public_key"]), ' not in Z_p^r')
            ballot_status_flag = False
        if not (pow(int(contest["num_selections_proof"]['commitment']["ciphertext"]), q, p) == 1):
            print('Contest Selection Ciphertext (b): ',
                  int(contest["num_selections_proof"]['commitment']["ciphertext"]), ' not in Z_p^r')
            ballot_status_flag = False
        # V in Zq
        if not (int(contest["num_selections_proof"]["response"]) < q):
            print('Contest selection response (V): ', int(contest["num_selections_proof"]["response"]),
                  ' not in set Z_q')
            ballot_status_flag = False

        A = pow(A, 1, p)
        B = pow(B, 1, p)
        #General equation: g^v = a*A^c mod p
        #lhs = pow(g, int(contest["num_selections_proof"]["response"]), p)
        #rhs = pow(pow(int(contest["num_selections_proof"]['commitment']["public_key"]), 1, p) * pow(A, int(contest["num_selections_proof"]['challenge']), p), 1, p)


        # Modified equation for Fulton Verifier: g^v = a*K^c mod p
        lhs = pow(g, int(contest["num_selections_proof"]["response"]), p)
        rhs = pow(pow(int(contest["num_selections_proof"]['commitment']["public_key"]), 1, p) * pow(
            joint_public_key_K, int(contest["num_selections_proof"]['challenge']), p), 1, p)
        if lhs != rhs:
            #print('Equation g^v = a*A^c mod p not satisfied for contest')
            print('Equation g^v = a*K^c mod p not satisfied for contest: ')
            print(contest)
            ballot_status_flag = False

        #General equation: (g^LC)*(K^v) = b*B^c mod p
        #lhs = pow(pow(g, int(contest["max_selections"])*int(contest['num_selections_proof']['challenge']), p) * pow(int(joint_public_key_K), int(contest["num_selections_proof"]["response"]), p), 1, p)
        #rhs = pow(pow(int(contest["num_selections_proof"]['commitment']["ciphertext"]), 1, p) * pow(B, int(contest["num_selections_proof"]['challenge']), p), 1, p)

        # Modified equation for Fulton Verifier: (g^LC)*(A^v) = b*B^c mod p
        lhs = pow(pow(g, int(contest["max_selections"])*int(contest['num_selections_proof']['challenge']), p) * pow(A, int(contest["num_selections_proof"]["response"]), p), 1, p)

        rhs = pow(
            pow(int(contest["num_selections_proof"]['commitment']["ciphertext"]), 1, p) * pow(B, int(
                contest["num_selections_proof"]['challenge']), p), 1, p)


        if lhs != rhs:
            #print('Equation (g^LC)*(K^v) = b*B^c mod p not satisfied for contest')
            print('Equation (g^LC)*(A^v) = b*B^c mod p not satisfied for:')
            print(contest)
            ballot_status_flag = False
    i = i+1



j = 0
for index, contest_tally in enumerate(data['contest_tallies']):
    print('Computing contest tally', j, 'of ', len(data['contest_tallies']))
    for index1, contest_tally_value in enumerate(contest_tally):
        i = 0
        share_val = 1
        for contest_share_val in contest_tally_value['shares']:
            # v_i is in Z_q
            if not (int(contest_share_val['proof']['response']) < q):
                print('Response (v) not a part of set Z_q for:')
                print(contest_share_val)
                ballot_status_flag = False

            # a_i in Z_q^r
            if not (pow(int(contest_share_val['proof']['commitment']['public_key']), q, p) == 1):
                print('Public key a_i not a part of set Z_p^r for:')
                print(contest_share_val)
                ballot_status_flag = False

            # b_i in Z_q^r
            if not (pow(int(contest_share_val['proof']['commitment']['ciphertext']), q, p) == 1):
                print('Ciphertext not a part of set Z_p^r for:')
                print(contest_share_val)
                ballot_status_flag = False

            # g^(v_i) = (a_i)*(K_i)^(c_i) mod p
            lhs1 = pow(g, int(contest_share_val['proof']['response']), p)
            rhs1 = pow(
                pow(int(contest_share_val['proof']['commitment']['public_key']), 1, p) * pow(valid_public_key_list[i],
                                                                                             int(contest_share_val[
                                                                                                     'proof'][
                                                                                                     'challenge']), p),
                1, p)
            if lhs1 != rhs1:
                print('Equation: g^(v_i) = (a_i)*(K_i)^(c_i) mod p could not be verified for:')
                print(contest_share_val)
                ballot_status_flag = False
            i = i + 1
            # A^(v_i) = (b_i)*(M_i)^(c_i) mod p
            lhs1 = pow(int(contest_tally_value['encrypted_tally']['public_key']), int(contest_share_val['proof']['response']), p)
            rhs1 = pow(pow(int(contest_share_val['proof']['commitment']['ciphertext']), 1, p) * pow(
                int(contest_share_val['share']), int(contest_share_val['proof']['challenge']), p), 1, p)
            if lhs1 != rhs1:
                print('Equation: A^(v_i) = (b_i)*(M_i)^(c_i) mod p could not be verified for:')
                print(contest_share_val)
                ballot_status_flag = False
            share_val = share_val * int(contest_share_val['share'])

        A, B = function_modular_product(index, index1)
        # Compare A = modular_Product(a_i) mod p
        if not (A == int(contest_tally_value['encrypted_tally']['public_key'])):
            print('Public Key (A) does not tally up for:')
            print(contest_tally_value)
            ballot_status_flag = False
        # Compare B = modular_product(b_i) mod p
        if not (B == int(contest_tally_value['encrypted_tally']['ciphertext'])):
            print('Ciphertext (B) does not tally up for:')
            print(contest_tally_value)
            ballot_status_flag = False
        # Compute B = M*modular_product(M_i) mod p
        lhs = int(contest_tally_value['encrypted_tally']['ciphertext'])
        rhs = pow(pow(int(contest_tally_value['decrypted_tally']), 1, p) * pow(share_val, 1, p), 1, p)
        if lhs != rhs:
            print('Equation B = M*modular_product(M_i) mod p does not compute for:')
            print(contest_tally_value)
            ballot_status_flag = False
        # Compute M = g^t mod p
        lhs = int(contest_tally_value['decrypted_tally'])
        rhs = pow(g, int(contest_tally_value['cleartext']), p)
        if lhs != rhs:
            print('Equation M = g^t mod p does not compute for:')
            print(contest_tally_value)
            ballot_status_flag = False
    j = j+1
if ballot_status_flag:
    print('Success! Ballot passed all checks')
if not ballot_status_flag:
    print("Failure! Ballot had errors. Check output log for more information")
