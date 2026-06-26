from flask import Flask, request, jsonify
from pathlib import Path
import subprocess
import json

app = Flask(__name__)

@app.route('/api/activate', methods=['POST'])
def activate():
    # 1. 接收客户端发来的 JSON 数据
    data = request.json
    hardware_id = data.get("hardware_id")
    activate_key = data.get("activate_key") 
    features = data.get("features")
    # 准备数据库路径
    database_path = Path.home() / "database" / "activate.json"
    database_path.parent.mkdir(parents=True, exist_ok=True) # 如果路径不存在，自动创建
    # 读取数据库
    try:
        with open("~/database/activate.json", "r") as f:
            activate_data = json.read(f)
            if activate_key not in activate_data:
                return jsonify({"status": "error", "message": "Invalid activation key"}), 400
            if activate_data[activate_key].get("features") != features:
                return jsonify({"status": "error", "message": "Feature mismatch"}), 400
    except Exception as e:
        print(f"Error reading activation data: {e}")
        return jsonify({"status": "error", "message": "Server error"}), 400
    expire_date = activate_data.get("activate_key").get("expire_date")  # 授权时间（查数据库）
    status = activate_data.get("activate_key").get("status")  # 状态（查数据库）

    if not hardware_id:
        return jsonify({"status": "error", "message": "Missing hardware ID"}), 400

    if status == False:
        try:
            # 2. 核心联动：直接调用你编译好的 C++ 静态大炮
            # C++ 传参优化成了接受命令行参数：./LicenseGenerator <hardware_id> <expire_date> <features>
            result = subprocess.run(
                ['./LicenseGenerator', hardware_id, expire_date, features],
                capture_output=True, text=True, check=True
            )

            # 3. 直接从标准输出抓取c++输出license
            license_content = result.stdout.strip()
            # 将生成的License写入数据库
            with open("~/database/activate.json", "r") as f:
                active_data = json.load(f)
                active_data[activate_key]["license"] = license_content
                active_data[activate_key]["status"] = True  # 更新状态为已激活
                active_data[activate_key]["hardware_id"] = hardware_id  # 保存硬件ID
            with open("~/database/activate.json", "w", encoding="utf-8") as f:
                json.dump(active_data, f, indent=4, ensure_ascii=False)

            # 4. 把生成的 License 吐回给 Windows 客户端
            return jsonify({"status": "success", "license": license_content})

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    else:
        try:
           license_content = activate_data.get("activate_key").get("license")  # 直接从数据库获取 license

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # 监听全局 80 端口（或者自定义端口）
    app.run(host='0.0.0.0', port=80)