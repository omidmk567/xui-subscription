import base64
import json
import time

import requests
from flask import Flask, Response

import conf

app = Flask(__name__)

cookies = {}

@app.get("/<server>/<user_id>")
def get_links(server, user_id):
    if server not in conf.server_urls.keys():
        return "Server not found!", 400

    try:
        user_info = get_user_from_server(user_id, server)
    except Exception as e:
        print(e)
        return "Unexpected error occurred!", 499

    if not user_info:
        return "User not found!", 400

    if not user_info["enabled"]:
        return "Access denied.", 403

    final_link = '\n'.join(
        [f'{user_info["protocol"]}://{user_id}@{link_info["address"].format(server)}?type=ws&security=tls&' +
         f'sni={link_info["sni"].format(server)}&host={link_info["host"].format(server)}&' +
         f'path=%2F{user_info["port"]}'
         f'#{user_info["remark"]}-{link_info["suffix"]}-{user_info["days"]}days-{user_info["traffic"]}GB'
         for link_id, link_info in conf.links.items()])
    encoded = final_link.encode()
    base64_bytes = base64.b64encode(encoded)
    return Response(base64_bytes.decode(), mimetype='text/plain')


def get_user_from_server(user_id, server):
    return extract_info_from_users(get_all_users_from_server(server))[user_id]


def get_all_users_from_server(server):
    host = conf.server_urls[server]
    if server not in cookies:
        login(server)

    response = requests.post(f'{host}/xui/inbound/list', verify=False, cookies=cookies[server])
    if response.status_code == 200 and response.json()['success']:
        return response.json()['obj']
    elif response.status_code == 404 or response.text == '404 page not found':
        login(server)
    else:
        raise Exception(f"Error occurred on getting all users from server {server}. {response.text}")


def login(server):
    host = conf.server_urls[server]
    login_response = requests.post(f'{host}/login', data={
        "username": conf.server_credentials['username'],
        "password": conf.server_credentials['password'],
    }, verify=False)
    if login_response.status_code == 200 and login_response.json()['success']:
        cookies[server] = login_response.cookies
    else:
        raise Exception(f"Error occurred on getting new token from server {server}. {login_response.text}")


def extract_info_from_users(all_users: dict):
    extracted = {}
    for user in all_users:
        for client in json.loads(user["settings"])["clients"]:
            if user["protocol"] == "trojan":
                identifier = "password"
            else:
                identifier = "id"

            extracted[client[identifier]] = {
                "port": user["port"],
                "protocol": user["protocol"],
                "remark": user["remark"],
                "enabled": user["enable"],
                "traffic": f'{((user["total"] - user["down"] - user["up"]) / (2 ** 30)):.2f}' if user["total"] != 0 else '♾️',
                "days": round((user["expiryTime"] - int(time.time() * 1000)) / (24 * 60 * 60 * 1000)) if user["expiryTime"] != 0 else '♾️',
            }
    return extracted


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5500)
