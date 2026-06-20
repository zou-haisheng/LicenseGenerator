from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/api/activate', methods=['POST'])
def activate():
    # 1. 接收客户端发来的 JSON 数据
    data = request.json
    hardware_id = data.get("hardware_id")
    expire_date = "2027-12-31"  # 授权时间（实际可查数据库或写死）
    features = "Module_A|Module_B"

    if not hardware_id:
        return jsonify({"status": "error", "message": "Missing hardware ID"}), 400

    try:
        # 2. 核心联动：直接调用你编译好的 C++ 静态大炮
        # 假设你的 C++ 传参优化成了接受命令行参数：./LicenseGenerator <hardware_id>
        result = subprocess.run(
            ['./LicenseGenerator', hardware_id, expire_date, features],
            capture_output=True, text=True, check=True
        )

        # 3. 读取你 C++ 写入的 license.lic 文件内容（或者直接从标准输出抓取）
        with open("license.lic", "r") as f:
            license_content = f.read()

        # 4. 把生成的 License 吐回给 Windows 客户端
        return jsonify({"status": "success", "license": license_content})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # 监听全局 80 端口（或者自定义端口）
    app.run(host='0.0.0.0', port=80)