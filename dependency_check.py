import requests
from bs4 import BeautifulSoup

def get_pom_xml():
    all_dependencys = []
    soup = BeautifulSoup(open("pom.xml", mode='r', encoding='utf-8'), 'lxml')
    dependencys = soup.select("dependency")
    for depen in dependencys:
        try:
            result = {}
            result['groupid'] = depen.select('dependency > groupid')[0].string
            result['artifactId'] = depen.select('dependency > artifactId')[0].string
            result['version'] = depen.select('dependency > version')[0].string
            all_dependencys.append(result)
        except:
            continue

    print(all_dependencys)
    return all_dependencys

def Is_vuln(group_id,artifact_id,version):

    BASEURL = "https://mvnrepository.com/"
    session = requests.session()
    headers = {"Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"96\", \"Google Chrome\";v=\"96\"",
               "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"macOS\"", "Upgrade-Insecure-Requests": "1",
               "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
               "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
               "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate",
               "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7", "Connection": "close"}

    all_cve = []
    url = f"{BASEURL}artifact/{artifact_id}/{group_id}/{version}"
    response = session.get(url=url, headers=headers)
    # print(response.status_code)
    soup = BeautifulSoup(response.text,'lxml')
    tableclass = soup.select(".grid")[0]
    cvelist = tableclass.select(".vuln:nth-child(1)")
    for cve in cvelist:
        all_cve.append(cve.string)
    if all_cve !=[]:
        print(artifact_id+"   "+group_id  + "   " + version+" 存在漏洞"  + "   " + str(all_cve))

def check():

    for a in get_pom_xml():
        artifactId = a.get('artifactId')
        groupid = a.get('groupid')
        version = a.get('version')
        try:
            Is_vuln(artifactId, groupid, version)
        except:
            continue

def main():
    check()

if __name__ == '__main__':
    main()

# Is_vuln("org.apache.logging.log4j","log4j-core","2.13.1")
#
# Is_vuln("commons-collections","commons-collections","3.2.1")
#
# Is_vuln("commons-collections","commons-collections","3.2.2")

# Is_vuln("com.alibaba","fastjson","1.2.24")