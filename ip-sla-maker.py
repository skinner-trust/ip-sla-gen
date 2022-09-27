import yaml
import os
from jinja2 import Environment, FileSystemLoader
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException
from pprint import pprint
from napalm import get_network_driver
from ciscoconfparse import CiscoConfParse

driver = get_network_driver("ios")
# -----------------------------------------------------
#tuns_to_explore = ['20100', '20200', '21100', '21200']
#tuns_to_explore = ['35100', '35200', '36100', '36200', '37100']
tuns_to_explore = ['17100', '17200', '18100', '18200']
#tuns_to_explore = ['188100', '188200', '189100', '189200']
# -----------------------------------------------------

import logging
logging.basicConfig(filename='netmiko.log', level=logging.DEBUG)
logger = logging.getLogger("netmiko")

generator_dic = {}
hubs = yaml.safe_load(open('hubs.yml'))
cur_dir = os.path.abspath(os.getcwd())
env = Environment(loader=FileSystemLoader(cur_dir), trim_blocks=True, lstrip_blocks=True)
sla_template = env.get_template('sla-tpl.txt')
ROUTER = '10.1.164.1'


def info_getter(ip):
    f_result = {}
    print('connecting infogetter to to ', ip)
    try:
        device = driver(ip, 'prime', 'KDVMC6wOlEK_',
                        optional_args={'secret': 'Universal', 'global_delay_factor': 2, 'auto_file_prompt': True})
        device.open()
        f_result2 = device.get_interfaces_ip()
        f_result1 = device.get_facts()
        return f_result1['hostname'], f_result2
    except:
        return ip, {'xynta': 'xynta'}

def info_getter2(ip):
    f_result = {}
    print('connecting infogetter to to ', ip)

    device = driver(ip, 'prime', 'KDVMC6wOlEK_', optional_args={'secret': 'Universal', 'global_delay_factor': 2, 'auto_file_prompt': True})
    device.open()
    print(device.get_interfaces_ip())
    print(device.get_facts())


def MODELCHECK(ip):
    from napalm import get_network_driver
    try:
        driver = get_network_driver("ios")
        device = driver(ip, 'prime', 'KDVMC6wOlEK_',
                        optional_args={'secret': 'Universal', 'global_delay_factor': 0, 'auto_file_prompt': True})
        device.open()
        tmp = device.get_facts()
        return tmp['model']
    except:
        return 'unknown'


def UP_CFGMERGER(ip, cfg):
    USER = 'adm_shav'
    PASSWORD = 'ab12rvalgforKDVM'
    ENABLE_PASS = 'Universal'
    DEVICE_PARAMS = {'device_type': 'cisco_ios',
                     'ip': ip,
                     'username': USER,
                     'password': PASSWORD,
                     'secret': ENABLE_PASS,
                     }
    from napalm import get_network_driver
    try:
        with ConnectHandler(**DEVICE_PARAMS) as ssh:
            ssh.enable()
            result = ssh.send_config_set(['ip scp server enable'])
            print(result)

        driver = get_network_driver("ios")
        device = driver(ip, USER, PASSWORD,
                        optional_args={'secret': 'Universal', 'global_delay_factor': 2, 'auto_file_prompt': True})
        device.open()
        device.load_merge_candidate(config=cfg)
        print(device.compare_config())

        if len(device.compare_config()) > 0:
            choice = input("\n would you like to commit these changes [yN]: ")
            if choice == 'y':
                device.commit_config()
                print('commiting ...')
            else:
                print('Discarding ...')
                #        device.close()
                device.discard_config()
        return 'ok'
    except:
        return 'unknown'


def up_ssh_cfg(ip, cfg):
    USER = 'prime'
    PASSWORD = 'KDVMC6wOlEK_'
    ENABLE_PASS = 'Universal'
    DEVICE_PARAMS = {'device_type': 'cisco_ios',
                     'ip': ip,
                     'username': USER,
                     'password': PASSWORD,
                     'secret': ENABLE_PASS,
                     }
    print('connecting to ', ip)
    with ConnectHandler(**DEVICE_PARAMS) as ssh:
        ssh.enable()
        result = ssh.send_command('sh access-list 105')
        return result


def CFG_DOWNLOAD(ip):
    USER = 'prime'
    PASSWORD = 'KDVMC6wOlEK_'
    ENABLE_PASS = 'Universal'
    DEVICE_PARAMS = {'device_type': 'cisco_ios',
                     'ip': ip,
                     'username': USER,
                     'password': PASSWORD,
                     'secret': ENABLE_PASS,
                     }
    try:
        with ConnectHandler(**DEVICE_PARAMS) as ssh:
            ssh.enable()
            print('connecting to ', ip)
            result = ssh.send_command('sh run')
            with open(f'temp.cfg', 'w') as f:
                f.write(result)
    except (NetMikoTimeoutException):
        print('ip {} - timeout '.format(ip))
    return 'temp.cfg'


hostname, interfaces_ip_result = info_getter(ROUTER)
# pprint(interfaces_ip_result)
# pprint(list(interfaces_ip_result['Dialer1']['ipv4'].keys()))

filename = CFG_DOWNLOAD(ROUTER)
cisco_cfg = CiscoConfParse(filename)

for tunnels in tuns_to_explore:
    for obj in cisco_cfg.find_objects_w_child(parentspec=r"^interface Tunnel" + tunnels,
                                              childspec=r"^ ip nhrp map multicast"):
        generator_dic.update({tunnels: {}})
        #        interface = obj.text.split()[1]
        generator_dic[tunnels]['hostname'] = hostname
        if obj.re_match_iter_typed(r'ip nhrp map multicast\s(.*)', default=''):
            generator_dic[tunnels]['dest'] = obj.re_match_iter_typed(r'ip nhrp map multicast\s(.*)', default='')
        if obj.re_match_iter_typed(r'tunnel vrf\s(.*)', default=''):
            generator_dic[tunnels]['vrf'] = obj.re_match_iter_typed(r'tunnel vrf\s(.*)', default='')
        if obj.re_match_iter_typed(r'tunnel source\s(.*)', default=''):
            tun_src = obj.re_match_iter_typed(r'tunnel source\s(.*)', default='')
            generator_dic[tunnels]['src_interface'] = tun_src
            #print(list(interfaces_ip_result[tun_src]['ipv4'].keys())[0])
            generator_dic[tunnels]['source'] = list(interfaces_ip_result[tun_src]['ipv4'].keys())[0]
            for isp_int in cisco_cfg.find_objects_w_child(parentspec=r"^interface " + tun_src,
                                                          childspec=r"^ description"):
                isp_name = isp_int.re_match_iter_typed(
                    r'^ description .*ISP[\S,\s]*?[\d,\-][\s,\-]*?([\w,\-,\.,_]{2,})\s')
                generator_dic[tunnels]['isp_local'] = isp_name
        generator_dic[tunnels]['isp_target'] = hubs[int(tunnels)]['tun_city']

router_dic = {'router': generator_dic}
print(router_dic)

result_cfg = sla_template.render(router_dic)
print(result_cfg)


UP_CFGMERGER(ROUTER, result_cfg)
