#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <unistd.h>

constexpr int AES_KEY_LENGTH = 32;
constexpr int AES_IV_LENGTH = 16;
constexpr int SALT_LENGTH = 16;
constexpr int ITERATIONS = 10000;

std::vector<unsigned char> generateRandomBytes(int numBytes) {
    std::vector<unsigned char> bytes(numBytes);
    if (!RAND_bytes(bytes.data(), numBytes)) {
        throw std::runtime_error("Error generating random bytes");
    }
    return bytes;
}

std::vector<unsigned char> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Error opening file");
    }
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(file), {});
}

void writeFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Error writing to file");
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

std::vector<unsigned char> deriveKeyFromPassword(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(AES_KEY_LENGTH);
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), ITERATIONS, EVP_sha256(), key.size(), key.data())) {
        throw std::runtime_error("Error generating key from password");
    }
    return key;
}


std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Error creating encryption context");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error initializing encryption");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error encrypting data");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error finalizing encryption");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Error creating decryption context");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error initializing decryption");
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error decrypting data");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error finalizing decryption");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return plaintext;
}

void encryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    auto data = readFile(inputFile);
    auto salt = generateRandomBytes(SALT_LENGTH);
    auto iv = generateRandomBytes(AES_IV_LENGTH);
    auto key = deriveKeyFromPassword(password, salt);
    auto encryptedData = encrypt(data, key, iv);

    std::vector<unsigned char> outputData;
    outputData.reserve(salt.size() + iv.size() + encryptedData.size());
    outputData.insert(outputData.end(), salt.begin(), salt.end());
    outputData.insert(outputData.end(), iv.begin(), iv.end());
    outputData.insert(outputData.end(), encryptedData.begin(), encryptedData.end());

    writeFile(outputFile, outputData);
}

void decryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    auto inputData = readFile(inputFile);
    if (inputData.size() < SALT_LENGTH + AES_IV_LENGTH) {
        throw std::runtime_error("Error: insufficient input data size");
    }
    std::vector<unsigned char> salt(inputData.begin(), inputData.begin() + SALT_LENGTH);
    std::vector<unsigned char> iv(inputData.begin() + SALT_LENGTH, inputData.begin() + SALT_LENGTH + AES_IV_LENGTH);
    std::vector<unsigned char> encryptedData(inputData.begin() + SALT_LENGTH + AES_IV_LENGTH, inputData.end());
    auto key = deriveKeyFromPassword(password, salt);
    auto decryptedData = decrypt(encryptedData, key, iv);

    writeFile(outputFile, decryptedData);
}

void printUsage(const char* progName) {
    std::cerr << "Usage: " << progName << " <encrypt|decrypt> <input file> <output file>" << std::endl;
}

void processCommandLine(int argc, char* argv[]) {
    std::cout << R"(	         
	              	   		___
				     .-'   `'.
				    /         \
				    |         ;
				    |         |           ___.--,
			   _.._     |*) ~ (*) |    _.---'`__.-( (_.
		    __.--'`_.. '.__.\    '--. \_.-' ,.--'`     `""`
		   ( ,.--'`   ',__ /./;   ;, '.__.'`    __
		   _`) )  .---.__.' / |   |\   \__..--""  """--.,_
		  `---' .'.''-._.-'`_./  /\ '.  \ _.-~~~````~~~-._`-.__.'
			| |  .' _.-' |  |  \  \  '.               `~---`
			 \ \/ .'     \  \   '. '-._)
			  \/ /        \  \    `=.__`~-.
		          / /\         `) )    / / `"".`\
		    , _.-'.'\ \        / /    ( (     / /
		     `--~`   ) )    .-'.'      '.'.  | (
			    (/`    ( (`          ) )  '-;
			     `      '-;         (-'
       
  sSSs_sSSs      sSSs  sdSS_SSSSSSbs    sSSs_sSSs     .S_sSSs     .S       S.     sSSs  
 d%%SP~YS%%b    d%%SP  YSSS~S%SSSSSP   d%%SP~YS%%b   .SS~YS%%b   .SS       SS.   d%%SP  
d%S'     `S%b  d%S'         S%S       d%S'     `S%b  S%S   `S%b  S%S       S%S  d%S'    
S%S       S%S  S%S          S%S       S%S       S%S  S%S    S%S  S%S       S%S  S%|     
S&S       S&S  S&S          S&S       S&S       S&S  S%S    d*S  S&S       S&S  S&S     
S&S       S&S  S&S          S&S       S&S       S&S  S&S   .S*S  S&S       S&S  Y&Ss    
S&S       S&S  S&S          S&S       S&S       S&S  S&S_sdSSS   S&S       S&S  `S&&S   
S&S       S&S  S&S          S&S       S&S       S&S  S&S~YSSY    S&S       S&S    `S*S  
S*b       d*S  S*b          S*S       S*b       d*S  S*S         S*b       d*S     l*S  
S*S.     .S*S  S*S.         S*S       S*S.     .S*S  S*S         S*S.     .S*S    .S*P  
 SSSbs_sdSSS    SSSbs       S*S        SSSbs_sdSSS   S*S          SSSbs_sdSSS   sSS*S   
  YSSP~YSSY      YSSP       S*S         YSSP~YSSY    S*S           YSSP~YSSY    YSS'    
                            SP                       SP                                 
                            Y                        Y                                  
                            
                                                                                             
                                           )" << std::endl;

    if (argc < 2) {
        std::cout << "Welcome to Octopus!" << std::endl;
        std::cout << "Usage: octopus <encrypt|decrypt> <input file> <output file>" << std::endl;
        return;
    }

    std::string mode = argv[1];
    if (mode == "encrypt" || mode == "decrypt") {
        if (argc != 4) {
            std::cerr << "Incorrect number of parameters. Use 'octopus encrypt/decrypt <input file> <output file>'." << std::endl;
            return;
        }

        std::string inputFile = argv[2];
        std::string outputFile = argv[3];

        // Securely get password without showing it in terminal history
        std::cout << "Enter password: ";
        std::string password = getpass("");

        try {
            if (mode == "encrypt") {
                encryptFile(inputFile, outputFile, password);
            } else if (mode == "decrypt") {
                decryptFile(inputFile, outputFile, password);
            }
            std::cout << mode << " operation completed successfully." << std::endl;
        } catch (const std::exception& e) {
            std::cerr << e.what() << std::endl;
        }
    } else {
        std::cerr << "Invalid command. Use 'encrypt' or 'decrypt'." << std::endl;
    }
}

int main(int argc, char* argv[]) {
    processCommandLine(argc, argv);
    return 0;
}

