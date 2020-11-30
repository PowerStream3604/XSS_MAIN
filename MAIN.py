import sys
sys.path.append("../")
import requests
import os
from bs4 import BeautifulSoup
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from seleniumwire import webdriver
from webdriver_manager.opera import OperaDriverManager

attack_file = sys.argv[1:]
attack_file = ''.join(attack_file)

final = None
flag = False


class IP_info:

    def __init__(self, IP, PORT, NATION):
        self.IP = IP
        self.PORT = PORT
        self.NATION = NATION

    def get_ip(self):
        return self.IP

    def set_ip(self, IP):
        self.IP = IP

    def get_port(self):
        return self.PORT

    def set_port(self, PORT):
        self.PORT = PORT

    def get_nation(self):
        return self.NATION

    def set_nation(self, NATION):
        self.NATION = NATION



def select_Webdriver(num):
    driver = ""
    num = int(num)
    if num == 1:
        from webdriver_manager.chrome import ChromeDriverManager
        driver = webdriver.Chrome(executable_path=ChromeDriverManager().install())
        print("You have chosen the ChromeDriver")
    elif num == 2:
        from webdriver_manager.firefox import GeckoDriverManager
        driver = webdriver.Firefox(executable_path=GeckoDriverManager().install())
        print("You have chosen the GeckoDriver")
    elif num == 3:
        from webdriver_manager.microsoft import IEDriverManager
        driver = webdriver.Ie(executable_path=IEDriverManager().install())
        print("You have chosen the IEDriver")
    elif num == 4:
        from webdriver_manager.opera import OperaDriverManager
        driver = webdriver.Opera(executable_path=OperaDriverManager().install())
        print("You have chosen the OperaDriver")
    return driver

def find_http():
    info_IP_ETC=[]
    url = "https://free-proxy-list.net/anonymous-proxy.html"
    source_code = requests.get(url)


    soup = BeautifulSoup(source_code.content,'html.parser')
    for link in soup.findAll('div',class_='container'):

        if link.find('div',class_='table-responsive'):
            div_table_responsive = link.find('div',class_='table-responsive')
            if div_table_responsive.find('table', id='proxylisttable'):
                table_cell = div_table_responsive.find('table', id='proxylisttable')
                IP_A_S = table_cell.findAll('td')
                index = 0
                index_1 = 0
                information = []
                for hello in IP_A_S:

                    if index % 8 == 0:
                        information.append(hello.string)
                    elif index % 8 == 1:
                        information.append(hello.string)
                    elif index % 8 == 3:
                        information.append(hello.string)
                        info_IP_ETC.append(IP_info(information[0], information[1], information[2]))
                        index_1 += 1
                        information.clear()
                    if index_1 == 9:
                        break
                    index += 1

    #prints the IP and the information of port and nation
    count = 0
    print("Choose the number of ssl proxy to use......")
    for info in info_IP_ETC:

        print("[*]----------["+str(count+1)+"]")
        print("[*]IP : "+info.get_ip())
        print("[*]PORT : " + info.get_port())
        print("[*]NATION : " + info.get_nation())

        count += 1
    choosed = input(": ")


    if 1 <= int(choosed) <= 9:
        list_j = info_IP_ETC[int(choosed)-1:int(choosed)]
        print("you have selected:")
        print(list_j[0].get_ip())
        print(list_j[0].get_port())
        print(list_j[0].get_nation())
    else:
        print("input number in range of 1 to 10")
    return list_j


def get_last_n_lines(file_name):
    # Create an empty list to keep the track of last N lines
    list_of_lines = []
    # Open file for reading in binary mode
    with open(file_name, 'rb') as read_obj:
        # Move the cursor to the end of the file
        read_obj.seek(0, os.SEEK_END)
        # Create a buffer to keep the last read line
        buffer = bytearray()
        # Get the current position of pointer i.e eof
        pointer_location = read_obj.tell()
        # Loop till pointer reaches the top of the file

        while pointer_location >= 0:
            # Move the file pointer to the location pointed by pointer_location
            read_obj.seek(pointer_location)
            # Shift pointer location by -1
            pointer_location = pointer_location -1
            # read that byte / character
            new_byte = read_obj.read(1)
            # If the read byte is new line character then it means one line is read
            if new_byte != b'\n':
                # If last read character is not eol then add it in buffer
                buffer.extend(new_byte)

            elif new_byte == b'\n':
                list_of_lines.append(buffer.decode()[::-1])
                return list(reversed(list_of_lines))


def dict(f):
    file = open(f,"r")
    if file.mode == "r":
        #line means the number of line and variable content means the actual line of the file ********** content variable must be the global variable to count it from every function
        xss_list = []

        for line,file_content in enumerate(file):
            xss_list.append(file_content)
            if file_content  == str(get_last_n_lines(f)[0]):
                return xss_list
            #if line is int(100):
            #    return xss_list


def get_cookie():
    cookie_dict = None
    with open(attack_file, 'r') as f_txt:
        f_txt = f_txt.read()
        real_t = f_txt.splitlines()
        for i in range(len(real_t)):
            if "Cookie:" in real_t[i]:
                global flag
                flag = True
                break
        if (flag == True):
            final = real_t[i].replace('Cookie:', '')
            final = final.split()
            for i_1 in range(len(final)):
                if (i_1 == 0):
                    cookie_dict = {final[i_1].split('=')[0]: final[i_1].split('=')[1]}
                else:
                    cookie_dict[final[i_1].split('=')[0]] = final[i_1].split('=')[1]
    return cookie_dict


def get_referer():
    global final
    with open(attack_file, 'r') as f_txt:
        f_txt = f_txt.read()
        real_t = f_txt.splitlines()

        for i in range(len(real_t)):
            # print(real_t[i])
            if "Referer:" in real_t[i]:
                global flag
                flag = True
                break

        if (flag == True):
            final = real_t[i].replace('Referer:', '',)
            final = final.replace(' ','',)

    # print(final) -- cookie
    return final, 'http://'


def get_host_and_path():
    global flag

    flag = None
    final_GE=None
    with open(attack_file, 'r') as f_txt:
        f_txt = f_txt.read()
        real_t = f_txt.splitlines()

        for i in range(len(real_t)):
            # print(real_t[i])
            if "Host:" in real_t[i]:
                flag = True
                print("hello")
                print(i)
                break

            elif "GET " in real_t[i]:
                fla_GE = True
                In_Ge = i

        if (flag == True):
            final_Ho = real_t[i].replace('Host:', '')
            if (' ' in final_Ho):
                final_Ho = final_Ho.replace(' ', '')

        if (fla_GE == True):
            final_GE = real_t[In_Ge].replace('GET', '')
            final_GE = final_GE.replace('HTTP/2', '')
            final_GE = final_GE.replace('HTTP/1.1', '')
            final_GE = final_GE.replace('HTTP/1.0', '')
            final_GE = final_GE.replace(' ', '')

        return final_Ho, ''.join([final_Ho,final_GE])
    #print(final_Ho)  # -- host
    #print(final_GE)  # -- GET_PATH
    # print(urls)

print("""xxx       xxx
 xxx     xxx
  xxx   xxx
   xxx xxx
    xxxxx  
     xxx
    xxxxx
   xxx xxx                             This is an open source XSS scanning tools.
  xxx	xxx                            This tool is intended to help researchers who genuinely desire safe internet world.
 xxx     xxx                                                                                                     --By PowerStream
xxx       xxx
 xxx     xxx
  xxx   xxx
   xxx xxx
    xxxxx  
     xxx
    xxxxx
   xxx xxx
  xxx	xxx
 xxx     xxx
xxx       xxx
 xxxxxxxxxxxx
xxxxxxxxxxxxx
 xx
  xx
   xx
    xxxxxxxxx
   xxxxxxxxxx
          xx
     	 xx
        xx
 xxxxxxxxxx
xxxxxxxxxx
""")
proxies=""
sele_web_d = input("In order to handle alert(pop up) of the website the program uses webdriver\nSo choose the web driver installed in your system\nPress 1 for ChromeDriver\nPress 2 for GeckoDriver\nPress 3 for IEDriver\nPress 4 for OperaDriver\n:")
print("----------------------------------------------------------------------------------------------------")
print(sele_web_d)
drive = select_Webdriver(sele_web_d)# -- this function selects the wendriver to use
#print("This is a XSS vulnerability scanning(brute-forcing) tool")
deci = input("Press 1 to scan using encrypted proxy(Hide(conceal) your IP address)\nPress 2 to scan with your current IP address\n:")
if deci == 1:
    print("You chose to scan the target using encrypted proxy")
    list_j = find_http()
elif deci == 2:
    print("You chose to scan the target with current IP")
try:
    proxies={
        "http":str(list_j[0].get_ip()+":"+str(list_j[0].get_port())),
        "https":str(list_j[0].get_ip()+":"+str(list_j[0].get_port()))
    }
    print("list_j[0]:       " + str(list_j[0].get_ip() + ":" + str(list_j[0].get_port())))
except:
    pass
#print("URL_______________")
#print(URL)
cookie = get_cookie()
referer,protocol = get_referer()
HOST_g,PATH_g = get_host_and_path()


print("cookie_______________")
print(cookie)
print("referer_______________")
print(referer)
print("#_________________")
print(PATH_g)
print("hello-----------")
print(protocol)
print("*********")
print(HOST_g)
print(")))))))))")
print(PATH_g)

print("-------------------------------------------------------------((((((((((((((((")
try:
    print(list_j[0].get_ip())
except:
    pass

URL = "https://httpbin.org/ip"
#URL = """http://testphp.vulnweb.com/listproducts.php?cat=<script>alert("Kimyongjun")</script>"""
#The xss dictionary reader will go right below

#URL = ""

#res = requests.get((protocol+PATH_g).strip(), headers={'Referer': referer}, cookies=cookie, proxies=proxies)
#res = driver.get(URL, headers={'Referer': referer}, cookies=cookie, proxies=proxies)
#options = {
#    "proxy": {
#        "http": str(list_j[0].get_ip() + ":" + str(list_j[0].get_port())),
#        "https": str(list_j[0].get_ip() + ":" + str(list_j[0].get_port()))
#    }
#}
drive.header_overrides = {
    'Referer': str(referer),
    'Cookie': str(cookie)
}

#res = drive.get(URL)
#try:
#    WebDriverWait(drive, 5).until(EC.alert_is_present(), 'Timed out waiting for alerts to appear')
#   alert = drive.switch_to.alert
#    alert.accept()
#    print(alert.text)
#except TimeoutException:
#    print("no alert")

#print(res.json())




