#include <iostream>
#include <string>
#include <vector>
#include <fstream>  // 引入标准文件流
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <cstdlib>
#include <cstring>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

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

// 辅助函数，防止 Base64 编码中出现 '+' 和 '/'，并去掉末尾的 '='，以便在命令行中安全输入
std::string makeB64Safe(std::string b64) {
    std::replace(b64.begin(), b64.end(), '+', '-'); // '+' 换成 '-'
    std::replace(b64.begin(), b64.end(), '/', '_'); // '/' 换成 '_'
    b64.erase(std::remove(b64.begin(), b64.end(), '='), b64.end()); // 删掉末尾的 '='
    return b64;
}

// 辅助函数：计算 SHA-256 并返回十六进制字符串
std::string getSHA256(const std::string& input) {
    // 1. 创建并初始化上下文环境
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) return "";

    // 2. 指定使用 SHA-256 算法
    if (EVP_DigestInit_ex(mdCtx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdCtx);
        return "";
    }

    // 3. 传入要计算的数据
    if (EVP_DigestUpdate(mdCtx, input.c_str(), input.length()) != 1) {
        EVP_MD_CTX_free(mdCtx);
        return "";
    }

    // 4. 获取哈希结果（SHA-256 结果固定为 32 字节）
    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int hashLen = 0;

    if (EVP_DigestFinal_ex(mdCtx, hash.data(), &hashLen) != 1) {
        EVP_MD_CTX_free(mdCtx);
        return "";
    }

    // 5. 释放上下文内存
    EVP_MD_CTX_free(mdCtx);

    // 6. 将 32 字节的二进制数据转换为 64 位的十六进制可见字符串
    std::stringstream ss;
    for (unsigned int i = 0; i < hashLen; ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)hash[i];
    }
    return ss.str();
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
    if (!md_ctx) {   // 检查内存分配是否成功
        EVP_PKEY_free(pkey);
        return false;
    }

    bool is_success = false; // 引入状态flag，确保任何分支退出都能进入底部统一释放资源

    if (1 != EVP_SignInit_ex(md_ctx, EVP_sha256(), NULL)) {
        if (1 != EVP_SignUpdate(md_ctx, data.data(), data.size())) {
            unsigned int sig_len = EVP_PKEY_size(pkey);
            signature.resize(sig_len);

            if (1 != EVP_SignFinal(md_ctx, signature.data(), &sig_len, pkey)) {
                signature.resize(sig_len);
                is_success = true;    // 全部成功才设置为true
            }
        }
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey); // 强制安全清除内存中的敏感私钥
    return is_success;
}

// 激活码生成
std::string ActivateKeyGenerate(std::string expire_date, std::string features, std::string PRIVATE_KEY_PATH, int num) {
    // 初始化激活码原始数据
    std::string activate_key;
    std::string tmp_string = getSHA256(expire_date + "-" + features  + "-" + std::to_string(num));
    int autoIncrementId = num;
    // 2. AES 加密
    std::vector<unsigned char> cipher_text;
    if (!AesEncrypt(tmp_string, cipher_text)) {
        std::cerr << "AES 加密失败！" << std::endl;
        return "AES Failed!";
    }
    std::string b64_cipher = Base64Encode(cipher_text);
    std::cout << "[2] AES 密文(Base64): " << b64_cipher << std::endl;

    // 3. RSA 签名 (传入私钥文件路径)
    std::vector<unsigned char> signature;
    if (!RsaSignWithFile(cipher_text, signature, PRIVATE_KEY_PATH)) {
        std::cerr << "RSA 签名失败！中断退出。" << std::endl;
        ERR_print_errors_fp(stderr); // 打印 OpenSSL 底层错误栈
        return "RSA Failed";
    }
    std::string b64_signature = Base64Encode(signature);
    std::cout << "[3] RSA 签名(Base64): " << b64_signature << std::endl;

    // 4. 切出前 6 位作为激活码后段
    if (signature.size() < 6) {      // 检查签名长度是否足够
        std::cerr << "错误：RSA 签名长度不足 6 字节！" << std::endl;
        return "Signature Too Short";
    }
    std::vector<unsigned char> buffer(10);

    // 【核心操作】：把 4 字节的 int 拆开塞进 vector 的前 4 个位置
    // 这里使用位移操作（Shift），不仅比 memcpy 更安全，而且能自动统一大小端问题
    buffer[0] = (autoIncrementId >> 24) & 0xFF;
    buffer[1] = (autoIncrementId >> 16) & 0xFF;
    buffer[2] = (autoIncrementId >> 8) & 0xFF;
    buffer[3] = autoIncrementId & 0xFF;

    // 把 6 字节的短签名塞进 vector 的后 6 个位置
    for (int i = 0; i < 6; ++i) {
        buffer[4 + i] = static_cast<unsigned char>(signature[i]);
    }
    activate_key = makeB64Safe(Base64Encode(buffer));
    return activate_key;
}

// ==========================================
// 5. 主生成逻辑
// ==========================================
int main(int argc, char* argv[]) {
    if (argc == 4 and argv[1] == "-c") {
        // 生成指定数量的激活码并写入~/database/ + features（即argv[2]）+ /actuvate.json
        std::cout << "=== 批量激活码生成器 ===" << std::endl;
        // 获取 Linux 家目录环境变量
        const char* homeDir = std::getenv("HOME");
        if (!homeDir) {
            std::cerr << "[-] 错误：无法获取 Linux 家目录环境变量！" << std::endl;
            return -1;
        }
        std::string databasePath = std::string(homeDir) + "/database/" + std::string(argv[2]) + "/activate.json";
        std::string activate_key;
        json tmp_data;
        // 加载数据库，并将其导入到可操作的对象中
        {
            std::ifstream json_load(databasePath);
            if (!json_load.is_open()) {
                std::cerr << "[-] 错误：无法读取文件，请检查路径权限！\nError: Unable to load files, please check permission of the address!" << std::endl;
                return -1;
            }
            json_load >> tmp_data;
        }
        // 输入的生成信息
        std::string expire_date = argv[2];       // 截止日期
        std::string features = argv[3];   // 开启的功能模块
        // 向可操作对象中添加指定数量的激活码字典
        int start_index = tmp_data.size(); // 获取当前数据库中已有的激活码数量，作为自增 ID 的起始值
        int end_index = start_index + std::stoi(argv[4]); // 计算结束索引，用stoi将argv[3]由字符串指针转换为整型
        for (int i = start_index; i < end_index; i++) {
            activate_key = ActivateKeyGenerate(expire_date, features, std::string(homeDir) + "/private.key", i);
            tmp_data[activate_key] = { {"status", false}, {"expire_date", expire_date}, {"features", features} };
        }
        // 将生成的激活码追加写入数据库中
        {
            std::ofstream json_write(databasePath);
            if (!json_write.is_open()) {
                std::cerr << "[-] 错误：无法写入文件，请检查路径权限！\nError: Unable to write in files, please check permission of the address!" << std::endl;
                return -1;
            }
            json_write << tmp_data.dump(4);
        }
        std::cout << "[+] 批量激活码已生成并写入 ~/database/" << argv[2] << "/activate.json" << std::endl;
    }
    else if (argc = 3) {
        // 获取 Linux 家目录环境变量
        const char* homeDir = std::getenv("HOME");
        if (!homeDir) {
            std::cerr << "[-] 错误：无法获取 Linux 家目录环境变量！" << std::endl;
            return -1;
        }
        // 定义外部私钥文件路径（指定绝对路径）
        const std::string PRIVATE_KEY_PATH = std::string(homeDir) + "/private.key";

        // 1. 输入的授权信息
        std::string hardware_id = argv[1]; // 客户给你的硬件指纹
        std::string expire_date = argv[2];       // 截止日期
        std::string features = argv[3];   // 开启的功能模块

        // 拼接原始授权明文
        std::string raw_license_data = hardware_id + "," + expire_date + "," + features;
        //std::cout << "[1] 授权明文: " << raw_license_data << std::endl;

        // 2. AES 加密
        std::vector<unsigned char> cipher_text;
        if (!AesEncrypt(raw_license_data, cipher_text)) {
            std::cerr << "AES 加密失败！" << std::endl;
            return -1;
        }
        std::string b64_cipher = Base64Encode(cipher_text);
        //std::cout << "[2] AES 密文(Base64): " << b64_cipher << std::endl;

        // 3. RSA 签名 (传入私钥文件路径)
        std::vector<unsigned char> signature;
        if (!RsaSignWithFile(cipher_text, signature, PRIVATE_KEY_PATH)) {
            std::cerr << "RSA 签名失败！中断退出。" << std::endl;
            ERR_print_errors_fp(stderr); // 打印 OpenSSL 底层错误栈
            return -1;
        }
        std::string b64_signature = Base64Encode(signature);
        //std::cout << "[3] RSA 签名(Base64): " << b64_signature << std::endl;

        // 4. 组合最终的 License 文件内容
        std::string final_license = b64_cipher + "." + b64_signature;

        std::cout << final_license << "\n";
    }
    else {
        std::cerr << "非法传参！\nInvalid parameters!\n";
    }
    return 0;
}