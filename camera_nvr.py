import argparse
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import socket
import nmap 
import ipaddress
import time

scanner = nmap.PortScanner()                   #camera ip for scanning
live_arr=[]

def get_local_ip():                          #get my local ip_address and remove my local ip adress and router ip[192.168.5.1]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        ip_network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        ip_network.network_address=str(ip_network.network_address)+str("/24")
        ip_list=check_ip_is_live(ip_network.network_address)
        s.close()
    except socket.error as e:
        print(f"Error: {e}")
        local_ip = None
    filtered_ips = [ip for ip in ip_list if not (ipaddress.IPv4Address(ip).is_private and ipaddress.IPv4Address(ip).packed[-1] == 1) and ip != local_ip]
    return filtered_ips


def check_ip_is_live(ip_scan):
    scanner.scan(hosts=ip_scan, arguments='-sn')
    print("-------------Live Ip address-------------")
    for ip in scanner.all_hosts():
        live_arr.append(ip)
        print(f"IP: {ip}")
    return live_arr

def open_new_tab(driver):
    driver.execute_script("window.open('', '_blank');")

def tab_navgation(driver,filtered_ips):    #open the all tab for camera ip address
    count=0
    for i,k in enumerate(filtered_ips):
        open_new_tab(driver)
        driver.switch_to.window(driver.window_handles[i+1])
        count=i
        try:
            driver.get(f"http://{k}")
        except:
            time.sleep(1)
            driver.switch_to.window(driver.window_handles[count+1])
            driver.get(f"https://about.google/pagenotfound")

def change_the_tab(driver,filtered_ips):
    print("-------------URL PAGE TITLE-------------")
    for z in range(len(filtered_ips)+1):
        driver.switch_to.window(driver.window_handles[z])
        if driver.title:
            print(f"Page Title: {driver.title}")
        else:
            print("Page Title: Unknow")
        time.sleep(5)

def change_the_password(driver,ip_network):
    pass

    
    
def main(password, new_password, gui_mode):
    firefox_options = Options()
    ok=False
    if gui_mode:
        firefox_options.add_argument('--headless')
    driver = webdriver.Firefox(options=firefox_options)
    #my_ip = get_local_ip()
    #driver.maximize_window()
    print(password, new_password)
    driver.get(f"http://192.168.5.210/")
    #tab_navgation(driver,my_ip)
    #change_the_tab(driver,my_ip)
    #change_the_password(driver,122)
    admin_login= driver.find_element(By.ID,"txtPassword")
    time.sleep(3)
    admin_login.send_keys('magdyn')
    time.sleep(3)
    admin_login.send_keys(Keys.ENTER)
    time.sleep(3)
    check_login=driver.find_element(By.ID,"mu_cfgHome")
    check_login.click()
    time.sleep(3)
    # button=driver.find_element(By.ID,"mu_cfgHome")  user  btnModify
    user_link = driver.find_element(By.LINK_TEXT, "User")
    user_link.click()
    time.sleep(3)
    edit_click=driver.find_element(By.ID,"btnModify")
    edit_click()
    time.sleep(3)
    #vaa da poda

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automatic change the camera password using Selenium')
    parser.add_argument('-op', '--password', help='Current Password of Camera', required=True)
    parser.add_argument('-np', '--new_password', help='New password of Camera', required=True)
    parser.add_argument('-no_gui', '--set_gui', action='store_true', help='Set GUI interface in browser')
    args = parser.parse_args()

    main(args.password, args.new_password, args.set_gui)
