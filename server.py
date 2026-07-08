from flask import Flask, request, jsonify
from pathlib import Path
import subprocess
import json
import os

app = Flask(__name__)

@app.route('/api/activate', methods=['POST'])
def activate():
    # 1. 接收客户端发来的 JSON 数据
    data = request.json
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400
    hardware_id = data.get("hardware_id")
    activate_key = data.get("activate_key") 
    features = data.get("features")

    if not hardware_id or not activate_key or not features:
        return jsonify({"status": "error", "message": "Missing required fields"}), 400

    # 安全防御：防止路径穿越，只取文件名部分
    safe_features = os.path.basename(features)

    # 准备数据库路径
    databasePath = Path.home() / "database" / safe_features / "activate.json"
    databasePath.parent.mkdir(parents=True, exist_ok=True) # 如果路径不存在，自动创建
    # 读取数据库
    try:
        # 如果文件不存在，先做个防御
        if not databasePath.exists():
            return jsonify({"status": "error", "message": "Database not initialized"}), 404

        with open(databasePath, "r", encoding="utf-8") as f:
            activate_data = json.load(f)
            if activate_key not in activate_data:
                return jsonify({"status": "error", "message": "Invalid activation key"}), 400
#            if activate_data[activate_key].get("features") != features:
#                return jsonify({"status": "error", "message": "Feature mismatch"}), 400
    except Exception as e:
        print(f"Error reading activation data: {e}")
        return jsonify({"status": "error", "message": "Server error"}), 400
    key_info = activate_data.get(activate_key)
    expire_date = key_info.get("expire_date")  # 授权时间（查数据库）
    status = key_info.get("status")  # 状态（查数据库）

    if not hardware_id:
        return jsonify({"status": "error", "message": "Missing hardware ID"}), 400

    if status == False:
        try:
            # 2. 核心联动：直接调用编译好的 C++ 静态大炮
            # C++ 传参优化成了接受命令行参数：./LicenseGenerator <hardware_id> <expire_date> <features>
            result = subprocess.run(
                ['./build/LicenseGenerator', hardware_id, expire_date, features],
                capture_output=True, text=True, check=True
            )

            # 3. 直接从标准输出抓取c++输出license
            license_content = result.stdout.strip()
            # 将生成的License写入数据库
            key_info[activate_key]["license"] = license_content
            key_info[activate_key]["status"] = True  # 更新状态为已激活
            key_info[activate_key]["hardware_id"] = hardware_id  # 保存硬件ID
            
            databasePath.parent.mkdir(parents=True, exist_ok=True)
            with open(databasePath, "w", encoding="utf-8") as f:
                json.dump(activate_data, f, indent=4, ensure_ascii=False)

            # 4. 把生成的 License 吐回给 Windows 客户端
            return jsonify({"status": "success", "license": license_content})

        except Exception as e:
            return jsonify({"status": "error", "message": f"Execute generator failed: {str(e)}"}), 500
    else:
        try:
           license_content = key_info.get("license")  # 直接从数据库获取 license
           return jsonify({"status": "success", "license": license_content})

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # 监听全局 80 端口（或者自定义端口）
    app.run(host='0.0.0.0', port=80)