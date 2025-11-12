from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import jwt

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import RemoveFriend_Req_pb2
except ImportError:
    print("Warning: RemoveFriend_Req_pb2 not found. Please generate it using protoc for remove functionality.")

app = Flask(__name__)

def get_region_from_token(token):
    """
    Decode the JWT token (without verifying signature) to extract region code.
    Tries common claim keys in order, normalizes the value, and returns uppercase region.
    """
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        keys = [
            "region", "region_code", "rd", "server", "regionId",
            "country", "locale", "noti_region", "lock_region", "country_code"
        ]
        for k in keys:
            val = decoded.get(k)
            if isinstance(val, str) and val.strip():
                region = val.strip().upper()
                if region == "IND":
                    return "IN"
                elif region == "USA":
                    return "US"
                elif region in ["BRA", "BRZ", "BR"]:
                    return "BR"
                elif region in ["SA", "SAC"]:
                    return "SAC"
                return region
        return None
    except Exception as e:
        print(f"Token decode error: {e}")
        return None

def get_base_url(region):
    """
    Choose the backend base URL based on the extracted region.
    Defaults to blueshark if unknown.
    """
    if region == "IN":
        return "https://client.ind.freefiremobile.com"
    elif region in ["BR", "US", "SAC", "NA"]:
        return "https://client.us.freefiremobile.com"
    else:
        return "https://clientbp.ggblueshark.com"

def get_jwt_token_from_api(uid, password):
    """
    Fetch JWT token from the API using uid and password.
    """
    try:
        url = f"https://jwt-new-khaki.vercel.app/token?uid={uid}&password={password}"
        r = requests.get(url, verify=False, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if "token" in data:
                return data["token"]
        return None
    except Exception as e:
        print("JWT fetch error:", e)
        return None

def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    xxx[0] = '00'  # Fix apparent copy-paste error for hex consistency
    original_x = x
    x = x / 128.0
    if x > 128:
        x = x / 128.0
        if x > 128:
            x = x / 128.0
            if x > 128:
                x = x / 128.0
                strx = int(x)
                y = (x - strx) * 128
                stry = int(y)
                z = (y - stry) * 128
                strz = int(z)
                n = (z - strz) * 128
                strn = int(n)
                m = (n - strn) * 128
                strm = int(m)
                return dec[int(strm)] + dec[int(strn)] + dec[int(strz)] + dec[int(stry)] + xxx[int(strx)]
            else:
                strx = int(x)
                y = (x - strx) * 128
                stry = int(y)
                z = (y - stry) * 128
                strz = int(z)
                n = (z - strz) * 128
                strn = int(n)
                return dec[int(strn)] + dec[int(strz)] + dec[int(stry)] + xxx[int(strx)]
        else:
            strx = int(x)
            y = (x - strx) * 128
            stry = int(y)
            z = (y - stry) * 128
            strz = int(z)
            return dec[int(strz)] + dec[int(stry)] + xxx[int(strx)]
    else:
        strx = int(x)
        y = (x - strx) * 128
        stry = int(y)
        return dec[int(stry)] + xxx[int(strx)]
    return xxx[int(original_x)]

def encrypt_message(data_bytes):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data_bytes, AES.block_size))
    return encrypted

def decode_author_uid(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded.get("account_id") or decoded.get("sub")
    except Exception as e:
        print(f"Decode error: {e}")
        return None

def validate_and_get_token(token, uid, password):
    """
    Validate input and fetch token if uid and password are provided.
    """
    if not token:
        if uid and password:
            token = get_jwt_token_from_api(uid, password)
            if not token:
                return None, {"error": "Failed to fetch JWT token from API"}
        else:
            return None, {"error": "token or (uid and password) is required"}
    return token, None

@app.route('/add-friend', methods=['GET'])
def add_friend():
    token = request.args.get('token')
    uid = request.args.get('uid')
    password = request.args.get('password')
    target_uid = request.args.get('target-uid')
    if not target_uid:
        return jsonify({"error": "target-uid is required"}), 400

    token, error = validate_and_get_token(token, uid, password)
    if error:
        return jsonify(error), 400

    region = get_region_from_token(token)
    base_url = get_base_url(region) if region else get_base_url(None)
    host = base_url.split('://')[1].rpartition('/')[0]
    url = base_url + "/RequestAddingFriend"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB51",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "User-Agent": "Free%20Fire/2019117061 CFNetwork/1399 Darwin/22.1.0",
        "Connection": "keep-alive",
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "Accept": "*/*",
        "Host": host
    }

    try:
        id_encrypted = Encrypt_ID(target_uid)
        data0 = "08c8b5cfea1810" + id_encrypted + "18012008"
        plain_bytes = bytes.fromhex(data0)
        encrypted_data = encrypt_message(plain_bytes)

        response = requests.post(url, headers=headers, data=encrypted_data, verify=False)
        if response.status_code == 200:
            return jsonify({"message": "Request add friend sent successfully", "backend": base_url}), 200
        else:
            return jsonify({"error": f"Request failed, status {response.status_code}: {response.text}", "backend": base_url}), 500
    except Exception as e:
        return jsonify({"error": f"Request exception: {str(e)}", "backend": base_url}), 500

@app.route('/remove-friend', methods=['GET'])
def remove_friend_api():
    token = request.args.get('token')
    uid = request.args.get('uid')
    password = request.args.get('password')
    target_uid = request.args.get('target-uid')
    if not target_uid:
        return jsonify({"status": "fail", "message": "target-uid is required"}), 400

    token, error = validate_and_get_token(token, uid, password)
    if error:
        return jsonify(error), 400

    author_uid = decode_author_uid(token)
    if not author_uid:
        return jsonify({"status": "fail", "message": "Unable to decode author UID from token", "backend": None}), 400

    region = get_region_from_token(token)
    base_url = get_base_url(region) if region else get_base_url(None)
    host = base_url.split('://')[1].rpartition('/')[0]
    url = base_url + "/RemoveFriend"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB51",
        'Host': host
    }

    try:
        if not hasattr(RemoveFriend_Req_pb2, 'RemoveFriend'):
            return jsonify({"status": "error", "message": "Protobuf RemoveFriend class not available", "backend": base_url}), 500

        message = RemoveFriend_Req_pb2.RemoveFriend()
        message.AuthorUid = int(author_uid)
        message.TargetUid = int(target_uid)
        serialized = message.SerializeToString()
        encrypted_bytes = encrypt_message(serialized)

        response = requests.post(url, data=encrypted_bytes, headers=headers, verify=False)

        if response.status_code == 200:
            return jsonify({"status": "success", "message": "Friend removed successfully", "backend": base_url}), 200
        else:
            return jsonify({"status": "fail", "code": response.status_code, "response": response.text, "backend": base_url}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "backend": base_url}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
