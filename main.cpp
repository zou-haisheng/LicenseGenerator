#include <iostream>
#include <string>
#include <vector>
#include <fstream>  // 引入标准文件流
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

// 32字节的 AES 密钥 和 16字节的 IV（必须与客户端一致）
const std::vector<unsigned char> AES_KEY = { 'M','y','S','e','c','r','e','t','A','E','S','K','e','y','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8' };
const std::vector<unsigned char> AES_IV = { 'I','n','i','t','V','e','c','t','o','r','1','2','3','4','5','6' };

// ==========================================
// 2. 辅助函数：Base64 编码
// ==========================================
std::string Base64Encode(const std::vector<unsigned char>& buffer) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // 不换行
    BIO_write(bio, buffer.data(), static_cast<int>(buffer.size()));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

// ==========================================
// 3. AES-256-CBC 加密
// ==========================================
bool AesEncrypt(const std::string& plainText, std::vector<unsigned char>& cipherText) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY.data(), AES_IV.data())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    cipherText.resize(plainText.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int ciphertext_len = 0;

    if (1 != EVP_EncryptUpdate(ctx, cipherText.data(), &len, (const unsigned char*)plainText.c_str(), static_cast<int>(plainText.size()))) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, cipherText.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;
    cipherText.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// ==========================================
// 4. 重构：从外部文件读取私钥并进行 RSA 私钥签名 (SHA-256)
// ==========================================
bool RsaSignWithFile(const std::vector<unsigned char>& data, std::vector<unsigned char>& signature, const std::string& keyPath) {
    // 1. 使用 OpenSSL 原生的文件 BIO 直接读取外部文件，比标准 C++ 文件流效率更高更安全
    BIO* bio = BIO_new_file(keyPath.c_str(), "r");
    if (!bio) {
        std::cerr << "[-] 错误：无法打开私钥文件，请检查路径: " << keyPath << std::endl;
        return false;
    }

    // 2. 从文件 BIO 中解析 PEM 格式的私钥
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio); // 读完立刻释放文件句柄

    if (!pkey) {
        std::cerr << "[-] 错误：私钥解析失败，请确保文件是标准 PEM 格式！" << std::endl;
        return false;
    }

    // 3. 经典的 EVP 签名流程
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (1 != EVP_SignInit_ex(md_ctx, EVP_sha256(), NULL)) {
        EVP_PKEY_free(pkey);
        return false;
    }

    if (1 != EVP_SignUpdate(md_ctx, data.data(), data.size())) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    unsigned int sig_len = EVP_PKEY_size(pkey);
    signature.resize(sig_len);

    if (1 != EVP_SignFinal(md_ctx, signature.data(), &sig_len, pkey)) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    signature.resize(sig_len);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey); // 强制安全清除内存中的敏感私钥
    return true;
}

// ==========================================
// 5. 主生成逻辑
// ==========================================
int main(int argc, char* argv[]) {
    if (argc = 3) {
        std::cout << "=== 离线许可证生成器 (Linux 稳健版) ===" << std::endl;

        // 定义外部私钥文件路径（默认读取可执行文件同目录下的 private.key）
        const std::string PRIVATE_KEY_PATH = "private.key";

        // 1. 模拟输入的授权信息
        std::string hardware_id = argv[1]; // 客户给你的硬件指纹
        std::string expire_date = argv[2];       // 截止日期
        std::string features = argv[3];   // 开启的功能模块

        // 拼接原始授权明文
        std::string raw_license_data = hardware_id + "," + expire_date + "," + features;
        std::cout << "[1] 授权明文: " << raw_license_data << std::endl;

        // 2. AES 加密
        std::vector<unsigned char> cipher_text;
        if (!AesEncrypt(raw_license_data, cipher_text)) {
            std::cerr << "AES 加密失败！" << std::endl;
            return -1;
        }
        std::string b64_cipher = Base64Encode(cipher_text);
        std::cout << "[2] AES 密文(Base64): " << b64_cipher << std::endl;

        // 3. RSA 签名 (传入私钥文件路径)
        std::vector<unsigned char> signature;
        if (!RsaSignWithFile(cipher_text, signature, PRIVATE_KEY_PATH)) {
            std::cerr << "RSA 签名失败！中断退出。" << std::endl;
            ERR_print_errors_fp(stderr); // 打印 OpenSSL 底层错误栈
            return -1;
        }
        std::string b64_signature = Base64Encode(signature);
        std::cout << "[3] RSA 签名(Base64): " << b64_signature << std::endl;

        // 4. 组合最终的 License 文件内容
        std::string final_license = b64_cipher + "." + b64_signature;

        std::cout << "\n================ 最终 LICENSE 文件内容 ================\n";
        std::cout << final_license << "\n";
        std::cout << "=======================================================\n";

        // 顺手做个自动化：直接把 License 内容写入到同目录的 license.lic 文件中
        std::ofstream lic_file("license.lic");
        if (lic_file.is_open()) {
            lic_file << final_license;
            lic_file.close();
            std::cout << "[+] 自动化成功：已自动将授权证书导出至同目录下的 license.lic" << std::endl;
        }
    }
    else {
        std::cerr << "须传入三个参数！\nThree parameters are needed!\n"；
    }
    return 0;
}