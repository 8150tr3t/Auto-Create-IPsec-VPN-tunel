import json
from datetime import datetime
from debugpy import log_to
import pandas as pd
import netmiko
from ipaddress import IPv4Address
from getpass import getpass
import sys
from pprint import pprint


def wildcardmask(prelix):
    return str(IPv4Address(int(IPv4Address._make_netmask(prelix)[0]) ^ (2 ** 32 - 1)))


def subnetmask(prelix):
    return IPv4Address._make_netmask(prelix)[0]


def loadConfigFile(filename):
    try:
        if filename.endswith('.csv'):
            raw_config_data = pd.read_csv(filename, index_col=0)
            # Bỏ cột trống ra khỏi dữ liệu excel đọc được
            config_data = raw_config_data.dropna(axis='columns', how='all')
            # CHuyển định dạng về dạng Dictionary
            config_data = config_data.to_json()
            return json.loads(config_data)
        elif filename.endswith('.json'):
            # Đọc dữ liệu từ file json
            with open(filename, 'r') as file:
                devices = json.loads(file.read())[0]
            #
            config_data = dict()
            for device in devices:
                new_device = dict()
                for key, value in devices[device].items():
                    if not isinstance(value, dict):
                        new_device[key] = value
                    else:
                        for k, v in value.items():
                            new_device[key + "_" + k] = v
                config_data[device] = new_device
            # config_data = json.dumps(config_data)
            return config_data
        else:
            print("- Không thể đọc file. Kiểm tra lại đường dẫn !")
            # print("- Định dạng file không được hỗ trợ !")
    except Exception as e:
        print("- Không thể đọc file. Kiểm tra lại đường dẫn !")
        pass


def saveLogToFile(filename,text):
    with open(filename, "a") as file:
        file.writelines(text)
    file.close()


def sendConfig(config, commands):
    try:
        device = {
            "host": config['ssh_ip'],
            "username": config['ssh_user'],
            "password": str(config['ssh_pass']),
            "device_type": config['ssh_device_type']
        }
        
        print(f"[HOST {device['host']}]")
        
        if device['password'] == 'None' or device['password'] == '':
            device['password'] = getpass(prompt=f"Password {device['host']}: ")

        print(f"- Đang kết nối đến {device['host']} ...")
        net_connect = netmiko.ConnectHandler(**device)
        print("- Kết nối thành công !")
        print("- Đang gửi cấu hình...")
        result = net_connect.send_config_set(commands, strip_command=True)
        # net_connect.save_config()
        # print(result)
        net_connect.disconnect() # Close the connection
        return result
    except Exception as e:
        print("- Kết nối thất bại, vui lòng thử lại !")
        # In ra lỗi
        print("=> Lỗi: "+str(e))
        pass


def ConfigIpSec(devices):
    print("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    print("┃   THỰC HIỆN CẤU HÌNH TUNNEL IPSEC    ┃")
    print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")

    log = ""
    for device in devices:
        config_data = devices[device]
        commands = [
            f"crypto isakmp policy {config_data['isakmp_policy_number']}",
            f"hash {config_data['isakmp_hash']}",
            f"encryption {config_data['isakmp_encryption']}",
            f"group {config_data['isakmp_group']}",
            f"authentication {config_data['isakmp_authentication']}",
            f"crypto isakmp key {config_data['isakmp_key']} {config_data['isakmp_pass']} address {config_data['isakmp_peer']}",
            f"crypto ipsec transform-set {config_data['ipsec_transform_set_name']} {config_data['ipsec_transform_set_1']} {config_data['ipsec_transform_set_2']}",
            f"access-list {config_data['acl_permit']} permit ip {config_data['vpn_ip_site']} {wildcardmask(config_data['vpn_prefix_site'])} {config_data['vpn_ip_peer']} {wildcardmask(config_data['vpn_prefix_peer'])}",
            f"crypto map {config_data['ipsec_transform_set_name']} {config_data['isakmp_policy_number']} ipsec-isakmp",
            f"set peer {config_data['isakmp_peer']}",
            f"set transform-set {config_data['ipsec_transform_set_name']}",
            f"match address {config_data['acl_permit']}",
            f"interface {config_data['public_int']}",
            f"crypto map {config_data['ipsec_transform_set_name']}",
            f"ip route 0.0.0.0 0.0.0.0 {config_data['ip_route']}",
            f"access-list {config_data['nat_acl_number']} deny ip {config_data['vpn_ip_site']} {wildcardmask(config_data['vpn_prefix_site'])} {config_data['vpn_ip_peer']} {wildcardmask(config_data['vpn_prefix_peer'])}",
            f"access-list {config_data['nat_acl_number']} permit ip {config_data['vpn_ip_site']} {wildcardmask(config_data['vpn_prefix_site'])} any",
            f"ip nat inside source list {config_data['nat_acl_number']} interface {config_data['nat_int_outside']} overload",
            f"interface {config_data['nat_int_outside']}",
            f"ip nat outside",
            f"interface {config_data['nat_int_inside']}",
            f"ip nat inside"
        ]
        # commands = commands(devices[device])
        result = sendConfig(config_data, commands)
        if result is not None:
            print("==> Gởi cấu hình thành công !")
            print("━━━━━━━━")
        else:
            result = "Kết nối thất bại"
        log += f"[{datetime.now()}] {device}:{config_data['ssh_ip']}\n"
        log += f"{result}"+"\n"*2
        log += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    saveLogToFile("log_config.txt", text=log)
    print("File log đã được lưu vào file log_config.txt")
    choice = input("- Xem lại log (y/n): ")
    if choice == 'y':
        print("\n"+log)
    else:
        pass
            


def deleteConfigIpSec(devices):
    print("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    print("┃       XOÁ CẤU HÌNH TUNNEL IPSEC      ┃")
    print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")

    log = ""
    for device in devices:
        config_data = devices[device]
        commands = [
            f"interface {config_data['public_int']}",
            f"no crypto map {config_data['ipsec_transform_set_name']} {config_data['isakmp_policy_number']} ipsec-isakmp",
            f"no crypto map {config_data['ipsec_transform_set_name']}",
            f"no crypto isakmp policy {config_data['isakmp_policy_number']}",
            f"no crypto isakmp key {config_data['isakmp_key']} {config_data['isakmp_pass']} address {config_data['isakmp_peer']}",
            f"no crypto ipsec transform-set {config_data['ipsec_transform_set_name']} {config_data['ipsec_transform_set_1']} {config_data['ipsec_transform_set_2']}",
            f"no access-list {config_data['acl_permit']} permit ip {config_data['vpn_ip_site']} {wildcardmask(config_data['vpn_prefix_site'])} {config_data['vpn_ip_peer']} {wildcardmask(config_data['vpn_prefix_peer'])}",
            f"no ip route 0.0.0.0 0.0.0.0 {config_data['ip_route']}",
            f"no access-list {config_data['nat_acl_number']} deny ip {config_data['vpn_ip_site']} {wildcardmask(config_data['vpn_prefix_site'])} {config_data['vpn_ip_peer']} {wildcardmask(config_data['vpn_prefix_peer'])}",
            f"no access-list {config_data['nat_acl_number']} permit ip {config_data['vpn_ip_site']} {wildcardmask(config_data['vpn_prefix_site'])} any",
            f"no ip nat inside source list {config_data['nat_acl_number']} interface {config_data['nat_int_outside']} overload",
            f"interface {config_data['nat_int_outside']}",
            f"no ip nat outside",
            f"interface {config_data['nat_int_inside']}",
            f"no ip nat inside"
        ]
        # commands = ["no " + s for s in commands]
        result = sendConfig(config_data, commands)
        if result is not None:
            # print(result)
            print("==> Xoá cấu hình IPsec thành công !")
            print("━━━━━━━━")
        else:
            result = "Kết nối thất bại"
        log += f"[{datetime.now()}] {device}:{config_data['ssh_ip']}\n"
        log += f"{result}"+"\n"*2
        log += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    saveLogToFile("log_delete.txt",text = log)
    print("File log đã được lưu vào file log_delete.txt")
    choice = input("- Xem lại log (y/n): ")
    if choice == 'y':
        print("\n"+log)
    else:
        pass


def sendCommand(ssh_info, commands):
    try:
        device = {
            "host": ssh_info['ssh_ip'],
            "username": ssh_info['ssh_user'],
            "password": str(ssh_info['ssh_pass']),
            "device_type": ssh_info['ssh_device_type']
        }
        if device['password'] == 'None' or device['password'] == '':
            device['password'] = getpass(prompt=f"Password {device['host']}: ")
        net_connect = netmiko.ConnectHandler(**device)
        for command in commands:
            # print(f"\t==> {command}")
            print(net_connect.find_prompt()+command)
            print("-------")
            result = net_connect.send_command(command)
            if result is not None:
                print(result)
                print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            else:
                break
            # print(net_connect.find_prompt()+command)
            # result = net_connect.send_command(command)
            # return result
        net_connect.disconnect()
    except Exception as e:
        print("- Kết nối thất bại, vui lòng thử lại !")
        # In ra lỗi
        print("=> Lỗi: "+str(e))
        pass

def checkTunnel(device):
    print("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    print("┃    KIỂM TRA KẾT NỖI CỦA TUNNEL       ┃")
    print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")

    # kiểm tra phase 1 isakmp
    commands = ["show crypto isakmp sa", # kiểm tra phase 1 isakmp
                "show crypto ipsec sa", # kiểm tra phase 2 isakmp
                f"ping {device['vpn_ip_peer'][:-1]+'10'} source {device['vpn_ip_site'][:-1]+'10'} repeat 3" # kiểm tra ping
    ]
    result = sendCommand(device, commands)


def main(devices):   
    print("\n========================================"*2)
    print("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    print("┃       CHỌN CHỨC NĂNG CẤU HÌNH        ┃")
    print("┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫")
    print("┃ 1. Tạo Tunnel IPSEC VPN              ┃")
    print("┃ 2. Xoá cấu hình IPSEC                ┃")
    print("┃ 3. Kiểm tra kết nối Tunnel           ┃")
    # print("┃ 4. Chọn lại đường dẫn file cấu hình  ┃")    
    print("┃ 0. Thoát                             ┃")
    print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    choice = input("Nhập lựa chọn của bạn: ")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━")
  # Đọc file config
    if choice == '1':
        ConfigIpSec(devices)
    elif choice == '2':
        deleteConfigIpSec(devices)
    elif choice == '3':
        for device in devices:
            checkTunnel(devices[device])
        # pprint(devices['SITE A'])
        # checkTunnel(devices['SITE A'])
    # elif choice == '4':
    #     devices = None
    #     while devices is None:
    #         config_file_path = input("Nhập đường dẫn file cấu hình: ")
    #         devices = loadConfigFile(config_file_path)
    elif choice == "0":
        print("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
        print("┃        KẾT THÚC CHƯƠNG TRÌNH         ┃")
        print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
        sys.exit()
    else:
        print("✖ KHÔNG CÓ CHỨC NĂNG NÀY ✖")
        print("✖    VUI LÒNG CHỌN LẠI   ✖")
    

if __name__ == "__main__":
    global devices
    devices = None
    while devices is None:
        config_file_path = input("Nhập đường dẫn file cấu hình: ")
        devices = loadConfigFile(config_file_path)
    while True:
        # print(devices)
        main(devices)
        
# show crypto isakmp sa
# show crypto ipsec sa

