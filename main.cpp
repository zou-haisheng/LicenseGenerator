#include <iostream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

// ==========================================
// 1. 硬编码的服务端私钥（绝对不能泄露给客户端！）
// ==========================================
const std::string PRIVATE_KEY =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7...\n" // 替换为你的真实RSA私钥
"-----END PRIVATE KEY-----\n";

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
// 4. RSA 私钥签名 (SHA-256)
// ==========================================
bool RsaSign(const std::vector<unsigned char>& data, std::vector<unsigned char>& signature) {
    BIO* bio = BIO_new_mem_buf(PRIVATE_KEY.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) return false;

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
    // 强制清除内存中的敏感私钥信息
    EVP_PKEY_free(pkey);
    return true;
}

// ==========================================
// 5. 主生成逻辑
// ==========================================
int main() {
    std::cout << "=== 离线许可证生成器 ===" << std::endl;

    // 1. 模拟输入的授权信息（实际可以从命令行参数或前端输入获取）
    std::string hardware_id = "516c90bc89451a2e"; // 客户给你的硬件指纹
    std::string expire_date = "2027-12-31";       // 截止日期
    std::string features = "Module_A|Module_B"; // 开启的功能模块

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

    // 3. RSA 签名 (对 AES 密文内容进行签名)
    std::vector<unsigned char> signature;
    if (!RsaSign(cipher_text, signature)) {
        std::cerr << "RSA 签名失败！请检查私钥是否正确。" << std::endl;
        return -1;
    }
    std::string b64_signature = Base64Encode(signature);
    std::cout << "[3] RSA 签名(Base64): " << b64_signature << std::endl;

    // 4. 组合最终的 License 文件内容
    // 格式定义：密文Base64 + "." + 签名Base64
    std::string final_license = b64_cipher + "." + b64_signature;

    std::cout << "\n================ 最终 LICENSE 文件内容 ================\n";
    std::cout << final_license << "\n";
    std::cout << "=======================================================\n";
    std::cout << "(请将上方完整字符串保存为 license.lic 发放给客户)" << std::endl;

    return 0;
}