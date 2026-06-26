from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/api/activate', methods=['POST'])
def activate():
    # 1. 接收客户端发来的 JSON 数据
    data = request.json
    hardware_id = data.get("hardware_id")
    activate_key = data.get("activate_key") 
    try:
        with open("~/database/activate.json", "r") as f:
            activate_data = json.read(f)
            if activate_key not in activate_data:
                return jsonify({"status": "error", "message": "Invalid activation key"}), 400
    except Exception as e:
        print(f"Error reading activation data: {e}")
        return jsonify({"status": "error", "message": "Server error"}), 400
    expire_date = activate_data.get("activate_key").get("expire_date")  # 授权时间（查数据库）
    features = activate_data.get("activate_key").get("features")  # 功能列表（查数据库）

    if not hardware_id:
        return jsonify({"status": "error", "message": "Missing hardware ID"}), 400

    try:
        # 2. 核心联动：直接调用你编译好的 C++ 静态大炮
        # 假设你的 C++ 传参优化成了接受命令行参数：./LicenseGenerator <hardware_id>
        result = subprocess.run(
            ['./LicenseGenerator', hardware_id, expire_date, features],
            capture_output=True, text=True, check=True
        )

        # 3. 直接从标准输出抓取c++输出license
        license_content = result.stdout.strip()

        # 4. 把生成的 License 吐回给 Windows 客户端
        return jsonify({"status": "success", "license": license_content})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # 监听全局 80 端口（或者自定义端口）
    app.run(host='0.0.0.0', port=80)