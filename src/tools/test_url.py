
import socket
import thread
import time


SERVER_ADDR = ("163.177.79.174", 80)

HTTP_REQ = \
"""\
GET /search.php?keyword=%E6%B3%95%E8%BD%AE%E5%8A%9F HTTP/1.1
Host: search.kankan.com
Connection: keep-alive
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36
Referer: http://search.kankan.com/search.php?keyword=boxun
Accept-Encoding: gzip, deflate, sdch
Accept-Language: en,zh-CN;q=0.8,zh;q=0.6,zh-TW;q=0.4
Cookie: KANKANWEBUID=b20f8b15ac55e07d37d126903a281a2f; KANKANWEBSESSIONID=69f65f043497e595595a8ff9a1ad7740; vjuids=1a0b27559.1531a185929.0.48b31197; f_refer=http%253A%252F%252Fwww.kankan.com%252F; fa2c=1; SEARCHUNFINISHEDRECORD=91342_18%2C; gid=; blockid=; WWW_GUANGGAO_1924=8; WWW_GUANGGAO_1925=7; adFilter_ck=1.0; vjlast=1456431717.1459281493.11; KANKANSEARCHSID=c940c2a3a47db400f3fbb04d4b19a6ee; KANKANSEARCHRECORD=boxun%2Cultrasurf%2C%25E6%25B3%2595%25E8%25BD%25AE%25E5%258A%259F%2Csafeweb%2Cde%2Cfreetibet%2Cnine%2520commentaries%2Cjasmine%2520revolution; Hm_lvt_f85580b78ebb540403fe1f04da080cfd=1459281612; Hm_lpvt_f85580b78ebb540403fe1f04da080cfd=1459968975


"""


TIMES = 1



def send_request():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(SERVER_ADDR)
    sock.sendall(HTTP_REQ)
    time.sleep(5)
    sock.close()


for i in range(TIMES):
    thread.start_new_thread(send_request, ())
    time.sleep(0.1)


print("Sent %d HTTP requests." % TIMES)
print("Wait for 10 seconds before exit.")

time.sleep(10)


