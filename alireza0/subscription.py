import base64
import json
import time

import requests
from flask import Flask, Response

import conf

app = Flask(__name__)

cookies = {}

@app.get("/<user_id>")
def get_links(user_id):
    try:
        all_users = get_all_users_from_server(conf.server)
        processed_users = extract_info_from_users(all_users)
        user = processed_users[user_id]
        if not user:
            return "User not found!", 404

        if not user['enabled']:
            return "User disabled!", 403

        links_txt = ''
        for link, link_info in conf.links.items():
            links_txt += f'{user["protocol"]}://{user_id}@{link_info["address"]}:{user["port"]}?type=tcp&security=none#{user["remark"]}{link_info["suffix"]}{user["days"]}days-{user["traffic"]}GB'
            links_txt += '\n'
        encoded = links_txt.encode()
        base64_bytes = base64.b64encode(encoded)
        return Response(base64_bytes.decode(), mimetype='text/plain', headers={'Profile-Update-Interval': 12, 'Subscription-Userinfo': '; '.join([f'upload={user["upload"]}', f'download={user["download"]}', f'total={user["total"]}', f'expire={user["expire"]}'])})
    except Exception as e:
        print(e)
        return "Unexpected error occurred!", 499

def get_all_users_from_server(server):
    if server["host"] not in cookies:
        login(server)

    response = requests.post(f'{server["host"]}/xui/inbound/list', verify=False, cookies=cookies[server["host"]])
    if response.status_code == 200 and response.json()['success']:
        return response.json()['obj']
    elif response.status_code == 404 or response.text == '404 page not found':
        login(server)
    else:
        raise Exception(f"Error occurred on getting all users from server. {response.text}")


def extract_info_from_users(all_users: dict):
    extracted = {}
    for user in all_users:
        for client in json.loads(user["settings"])["clients"]:
            for client_stat in user["clientStats"]:
                if client_stat["email"] == client["email"]:
                    extracted[client["id"]] = {
                        "port": user["port"],
                        "protocol": user["protocol"],
                        "remark": client["email"],
                        "enabled": client_stat["enable"],
                        "traffic": f'{((client_stat["total"] - client_stat["down"] - client_stat["up"]) / (2 ** 30)):.2f}' if client_stat["total"] != 0 else '♾️',
                        "upload": client_stat["up"],
                        "download": client_stat["down"],
                        "total": client_stat["total"],
                        "expire": client_stat["expiryTime"]/1000,
                        "days": round((client_stat["expiryTime"] - int(time.time() * 1000)) / (24 * 60 * 60 * 1000)) if client_stat["expiryTime"] != 0 else '♾️',
                    }
    return extracted

def login(server):
    login_response = requests.post(f'{server["host"]}/login', data={
        "username": server['username'],
        "password": server['password'],
    }, verify=False)
    if login_response.status_code == 200 and login_response.json()['success']:
        cookies[server["host"]] = login_response.cookies
    else:
        raise Exception(f"Error occurred on getting new token from server {server}. {login_response.text}")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5500)
