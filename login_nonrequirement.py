# login_with_nothing.py
import json, re, os, sys, math, hashlib, hmac, http.client, ssl
import urllib.parse, urllib.request

_PADCHAR = "="
_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
host = '10.8.8.8'
port = 443
enc = 's' + 'run' + '_bx1'
n = 200
type_num = 1
header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36'}
ac_id = ''
ip = ''
username = ''


def readConfig():
    global loginInfo, header, device, os, host, port ,username
    configFile = open(os.path.join(os.path.dirname(sys.argv[0]), 'config.json'))
    configInfo = json.loads(str(configFile.read()))
    loginInfo = configInfo['userInfo']
    username = configInfo['userInfo']['username']
    host = host
    port = port
    device = 'Windows'
    os = 'Windows'


def getAc_id():
    global ac_id
    # 打开URL
    response = urllib.request.urlopen('http://' + host)

    # 读取并解码为字符串
    html = response.read().decode('utf-8')

    # 使用正则表达式提取ac_id
    match = re.search(r"ac_id=(\d+)", html)
    ac_id = match.group(1)
    print(ac_id)


def getIp():
    global ip
    response = urllib.request.urlopen(
        'http://' + host
        + "/cgi-bin/get_challenge?callback="
        + "jQuery112400496191401220758_1730443914031"
        + "&username="
        + username
    )
    html = response.read()
    html_str = html.decode('utf-8')

    match = re.search(r'"client_ip":"([^"]+)"', html_str)
    if match:
        ip = match.group(1)
        print(ip)
        return ip
    else:
        print("IP not found.")
        return None


def getInfo():
    context = ssl._create_unverified_context()
    # 创建 HTTP 连接对象
    conn = http.client.HTTPSConnection(host, port, context=context, timeout=5)

    # 发送 GET 请求
    conn.request("GET", "/", headers=header)

    # 获取响应
    resp = conn.getresponse()
    resp_data = resp.read().decode("utf-8")

    # 获取当前的 URL
    current_url = resp.getheader("Location") if resp.status == 301 or resp.status == 302 else resp.getheader(
        "Content-Location") or resp.getheader("Location")

    # 解析 URL 查询参数
    if current_url:
        query_string = urllib.parse.urlsplit(current_url).query
        resp_info = dict(urllib.parse.parse_qsl(query_string))

    # 填充 loginInfo 字典
    loginInfo['ac_id'] = resp_info.get('ac_id', '')
    loginInfo['double_stack'] = 0
    loginInfo['otp'] = False

    # 查找隐藏的 user_ip 输入字段值
    fpos = resp_data.find('<input type=\"hidden\" name=\"user_ip\" id=\"user_ip\" value=\"') + 56
    segment = resp_data[fpos:fpos + 15]

    # 关闭连接
    conn.close()


def getChallenge(data):
    # 设置回调参数
    data['callback'] = 'jsonp1583251661367'

    # 构建查询字符串
    query_string = urllib.parse.urlencode(data)

    # 创建 HTTP 连接对象
    context = ssl._create_unverified_context()
    # 创建 HTTP 连接对象
    conn = http.client.HTTPSConnection(host, port, context=context, timeout=5)

    # 发送 GET 请求
    conn.request("GET", "/cgi-bin/get_challenge?" + query_string, headers=header)

    # 获取响应
    resp = conn.getresponse()
    resp_data = resp.read().decode("utf-8")

    # 关闭连接
    conn.close()

    return resp_data


def getPortal(data):
    # 构建查询字符串
    query_string = urllib.parse.urlencode(data)

    # 创建 HTTP 连接对象
    context = ssl._create_unverified_context()
    # 创建 HTTP 连接对象
    conn = http.client.HTTPSConnection(host, port, context=context, timeout=5)

    # 发送 GET 请求
    conn.request("GET", "/cgi-bin/srun_portal?" + query_string, headers=header)

    # 获取响应
    resp = conn.getresponse()
    resp_data = resp.read().decode("utf-8")

    # 关闭连接
    conn.close()

    return resp_data


def force(msg):
    ret = []
    for w in msg:
        ret.append(ord(w))
    return bytes(ret)


def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24)
    if key:
        pwd.append(l)
    return pwd


def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(0, l):
        msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
            msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
    if key:
        return "".join(msg)[0:ll]
    return "".join(msg)


def _getbyte(s, i):
    x = ord(s[i])
    if (x > 255):
        print("INVALID_CHARACTER_ERR: DOM Exception 5")
        exit(0)
    return x


def get_base64(s):
    i = 0
    b10 = 0
    x = []
    imax = len(s) - len(s) % 3
    if len(s) == 0:
        return s
    for i in range(0, imax, 3):
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) | _getbyte(s, i + 2)
        x.append(_ALPHA[(b10 >> 18)])
        x.append(_ALPHA[((b10 >> 12) & 63)])
        x.append(_ALPHA[((b10 >> 6) & 63)])
        x.append(_ALPHA[(b10 & 63)])
    i = imax
    if len(s) - imax == 1:
        b10 = _getbyte(s, i) << 16
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _PADCHAR + _PADCHAR)
    elif len(s) - imax == 2:
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8)
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _ALPHA[((b10 >> 6) & 63)] + _PADCHAR)
    else:
        # do nothing
        pass
    return "".join(x)


def get_xencode(msg, key):
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)


def info(d, k):
    return '{SRBX1}' + get_base64(get_xencode(json.dumps(d), k))


def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()


def get_md5(password, token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


def login():
    try:
        # 创建一个连接到百度的 HTTP 连接
        conn = http.client.HTTPSConnection("baidu.com", timeout=5)

        # 发送 GET 请求
        conn.request("GET", "/")

        # 获取响应
        response = conn.getresponse()

        # 检查响应状态码是否为 200
        if response.status == 200:
            print('Network available. Exited.')
            return
    except:
        print('Network unavailable. Connecting...')
    username = loginInfo['username']
    params = {'username': username, 'ip': ip}
    # 假设 getChallenge 返回的是 HTTPResponse 对象
    resp = getChallenge(params)

    # 如果响应是字节数据，解码为文本
    if isinstance(resp, http.client.HTTPResponse):
        resp_text = resp.read().decode('utf-8')  # 解码字节数据为字符串
    else:
        resp_text = resp  # 如果是其他类型的对象（例如 requests.Response），直接使用 text 属性

    token = re.search('"challenge":"(.*?)"', resp_text).group(1)
    payload = {
        'username': username,
        'password': loginInfo['password'],
        'ip': ip,
        'acid': ac_id,
        'enc_ver': enc
    }
    encoded_payload = info(payload, token)
    hmd5 = get_md5(loginInfo['password'], token)
    chkstr = token + username
    chkstr += token + str(hmd5)
    chkstr += token + ac_id
    chkstr += token + ip
    chkstr += token + str(n)
    chkstr += token + str(type_num)
    chkstr += token + encoded_payload
    loginInfo['password'] = '{MD5}' + hmd5

    params = {
        'callback': 'jQuery112400496191401220758_1730443914031',
        'action': 'login',
        'username': username,
        'password': loginInfo['password'],
        'ac_id': ac_id,
        'ip': ip,
        'chksum': get_sha1(chkstr),
        'info': encoded_payload,
        'n': n,
        'type': type_num,
        'os': os,
        'name': device,
        'double_stack': 0
    }
    resp = getPortal(params)
    print(resp)


def main():
    readConfig()
    getAc_id()
    getIp()
    getInfo()
    login()


if __name__ == '__main__':
    main()
