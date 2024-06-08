import hashlib
from multiprocessing import Pool

def read_file(file_path):
    with open(file_path, 'r', encoding='utf-8-sig') as input:  
        words = [line.strip() for line in input.readlines()]
        return words
    
def sha1_hash(string):
    return hashlib.sha1(string.encode()).hexdigest()

# to perform a attack only on number sequences
def numerical_attack(start, end, hash_set):
    cracked_passwords = {}

    zero=['0','00','000','0000','00000','000000','0000000', '00000000', '000000000']
    for x in range(len(zero)):
        hash_value = sha1_hash(zero[x])
        if hash_value in hash_set:
            cracked_passwords[hash_value] = zero[x]
            
        for d in range(10):
                digits = f"{zero[x]}{d}"
                hash_value = sha1_hash(digits)
                if hash_value in hash_set:
                    cracked_passwords[hash_value] = digits
                    
    for x in range(int(start), int(end)): 
        hash_value = sha1_hash(str(x))
        if hash_value in hash_set:
            cracked_passwords[hash_value] = str(x)
            
    return cracked_passwords
            

def dictionary_attack(arguments):
    subset, wordlist, hashed_pwds = arguments
    cracked_passwords = {}
    hash_set = set(hashed_pwds)  
    
    # Attack on words combination
    for w1 in subset:
        hash_value = sha1_hash(w1)
        if hash_value in hash_set:
            cracked_passwords[hash_value] = w1
            
        #word and digit combination
        num=['0','00','000','0000','00000','000000','0000000', '00000000', '000000000','0000000000','00000000000']
        for x in range(len(num)):
            combined = f"{w1}{num[x]}"
            hash_value = sha1_hash(combined)
            if hash_value in hash_set:
                cracked_passwords[hash_value] = combined       
        for d in range(100000):  
            combined = f"{w1}{d}"
            hash_value = sha1_hash(combined)
            if hash_value in hash_set:
               cracked_passwords[hash_value] = combined     

        #two words combination
        for w2 in subset:
            two_words = f"{w1}{w2}"
            hash_value = sha1_hash(two_words)
            if hash_value in hash_set:
                cracked_passwords[hash_value] = two_words
                
            #three words combination
            for w3 in subset:
                three_words = f"{w1}{w2}{w3}"
                hash_value = sha1_hash(three_words)
                if hash_value in hash_set:
                    cracked_passwords[hash_value] = three_words

    #Two words with digits
    for w1 in subset:
        for w2 in wordlist:
                for d in range(10):
                    two_words = f"{w1}{w2}{d}"
                    hash_value = sha1_hash(two_words)
                    if hash_value in hash_set:
                        cracked_passwords[hash_value] = two_words
                    
    return cracked_passwords




def main():
    dictionary = read_file('dictionary.txt')
    passwords = read_file('passwords.txt')

    password_hashes = {line.split()[1]: line.split()[0] for line in passwords}

    num_processes = 10  
    
    #numerical_attack calling
    max = 5020000000
    subset_size = max // num_processes
    ranges = [(i * subset_size, (i + 1) * subset_size) for i in range(num_processes)]
    ranges[-1] = (ranges[-1][0], max)    
    
    #dictionary_attack calling
    subset_size = len(dictionary) // num_processes
    subsets = [dictionary[i:i + subset_size] for i in range(0, len(dictionary), subset_size)]
    
    multi_processing = Pool(processes=num_processes) 
    numerical_pwds = multi_processing.starmap(numerical_attack, [(start, end, password_hashes) for start, end in ranges])
    passwords = multi_processing.map(dictionary_attack, [(subset, dictionary, list(password_hashes.keys())) for subset in subsets])
    multi_processing.close()
    multi_processing.join()
    
    cracked_pwds = {}

    for pwd in numerical_pwds:
        cracked_pwds.update(pwd) 

    for password in passwords:
        cracked_pwds.update(password) 

    sorted_passwords = sorted(
        ((password_hashes[hash], hash, pwd) for hash, pwd in cracked_pwds.items()),
        key=lambda l: int(l[0]) 
    )
    
   
    # Output results
    with open('output.txt', 'w') as file:
        for user_id, hash, pwd in sorted_passwords:
            output_string = f"{user_id} {hash} : {pwd}\n"
            file.write(output_string)
            print(f"UserID {password_hashes[hash]}: {hash} - {pwd}")


if __name__ == "__main__":
    main()

