from urllib.parse import urlparse
import whois, sys
from tld import get_tld
import requests
from bs4 import BeautifulSoup, SoupStrainer
import re
import pandas as pd
import numpy as np
import datetime
import tldextract

#URL에 - 유무
def Prefix_suffix(url):
    if '-' in url :
        return "비정상"
    else :
        return "정상"

def having_Sub_Domain(url):
    try:
        if 'www.' in url[:12]:
            url = url.replace("www.", "")
        domain = get_tld(url, as_object=True)
        #최상위 도메인 반환, 서브 도메인 조회 가능
        if domain.subdomain == "":
            return "정상"
        dot = domain.subdomain.count('.')
        # dot = 0일때 의심사이트로 분류하는게 더 좋긴 함.
        if dot >= 1:
            return "비정상"
        else:
            return "정상"
        
    except:
        return "비정상"

def Alexa_Ranking(url):
    try:
        res = requests.get("http://data.alexa.com/data?cli=10&dat=s&url="+url, timeout = 5)
        html = res.text
        rank = BeautifulSoup(html, 'xml').find("REACH")['RANK']
        if not rank:
            return "비정상"
        else:
            return "정상"
    except:
        return "비정상"

def abnormalUrl(url):
    try:
        domain = whois.whois(url)
    except :
        return "비정상"
    return "정상"

def count_Redirection(url):
    try:
        count = 0
        res = requests.head(url, allow_redirects=True, timeout = 5)
        #request
        for resp in res.history:
            if resp.status_code == 301 or resp.status_code == 302:
                count += 1
        if count >= 3:
            return "비정상"
        else:
            return "정상"
    except:
        return "비정상"

def getLinksInTags(url):
    try :
        retVal = 0
        parsed_url = urlparse(url)
        domain = '{url.netloc}'.format(url = parsed_url)
        res = requests.get(url, timeout = 5)
        html = res.text
        metaTags = BeautifulSoup(html, 'html.parser', parse_only=SoupStrainer(['meta','script','link']))
        matchedDomains =0
        unMatchedDomains =0
        for tag in metaTags:
            content=""
            if tag.has_attr('content'):
                content += (tag['content'])
            if tag.has_attr('src'):
                content += (tag['src'])
            if tag.has_attr('link'):
                content += (tag['link'])
            matchObj = re.match(r"([^a-zA-Z\d]+|http[s]?://)?([a-z0-9|-]+)\.?([a-z0-9|-]+)\.([a-z0-9|-]+)",content, re.M|re.I)
            #정규식으로 사이트 주소 찾기
            if matchObj:
                subdomain = matchObj.group(2)
                midDomain = matchObj.group(3)
                topDomain = matchObj.group(4)
                if domain.find(midDomain) != -1:  #리다이렉트사이트 도메인이 도메인과 같은경우
                    matchedDomains +=1
                else:
                    unMatchedDomains +=1

        percentUnmatched = unMatchedDomains/(matchedDomains+unMatchedDomains)
        if percentUnmatched > 0.5:
            retVal = "비정상"
        else:
            retVal = "정상"
        return  retVal
    except requests.ConnectionError:
        retVal = "비정상"
    except Exception:
            retVal = "정상"
            pass
    return retVal

def Disabling_Right_Click(url):
    try:
        res = requests.get(url, timeout = 5)
        if "event.button==2" in res.text:
            return "비정상"
        else :
            return "정상"
    except :
        return "비정상"

def checkAnchorTag(url):
    try:
        posiAnc = 0
        negaAnc = 1
        # URL domain 추출
        domain = tldextract.extract(url).domain
        # HTTP GET Request
        req = requests.get(url, timeout = 5)
        # HTML 소스 추출
        html = req.text
        # HTML 소스 -> Python 객체로 변환, <a>태그 추출
        anchorTag = BeautifulSoup(html, "html.parser", parse_only=SoupStrainer('a'))

        # <a> 태그 내의 href 속성 검사
        for anchor in anchorTag:
            if 'href' in anchor.attrs:
                # tldextract를 사용해서 sub-domain, domain, TLD 추출
                tldResult = tldextract.extract(anchor.attrs['href'])           
                # 빈 태그
                if ((tldResult.domain == "") | (tldResult.domain == " ") | (tldResult.domain == None)):
                    continue
                # domain과 일치하는 경우 -> Positive
                if (tldResult.domain == domain):
                    posiAnc += 1
                # domain과 일치하지 않는 경우나 # 혹은 javascript:void(0)이 나오는 경우 -> Negative
                else:
                    negaAnc += 1
        # Percentage of phishing site
        pctOfPhishing = negaAnc / (posiAnc + negaAnc)
        # 논문에 따라 Percentage 기준 설정
        if pctOfPhishing > 0.67:
            return "비정상"
        else:
            return "정상"
    except:
        return "비정상"

# HTML 소스 내의 form action 내에 about:blank나 공백이 있는지 검사
def checkFormTag(url):
    try:
        # HTTP GET Request
        req = requests.get(url, timeout = 5)
        # HTML 소스 추출
        html = req.text
         # HTML 소스 -> Python 객체로 변환, <form>태그 추출
        formTag = BeautifulSoup(html, "html.parser", parse_only=SoupStrainer('form'))
        # <form> 태그 내의 action 속성 검사
        for form in formTag:
            if 'action' in form.attrs:
                # about:blank나 공백이 있는 경우 -> Phishing site 처리
                if form.get('action') == "" or form.get('action') == "about:blank":
                    return "비정상"
        # 정상
        return "정상"
    except:
        return "비정상"

def favicon(url):
    try:
        if(fav_ico(url) == 1):
            return "정상"
        # HTTP GET Request
        req = requests.get(url, timeout = 5)
        # HTML 소스 추출
        html = req.text
        # HTML 소스 -> Python 객체로 변환, <link>태그 추출
        linkTag = BeautifulSoup(html, "html.parser", parse_only=SoupStrainer('link'))
        # rel 속성에서 favicon을 불러오는 경우가 있음.
        for link in linkTag:
            if 'rel' in link.attrs:
                # shortcut icon
                if 'shortcut' and 'icon' in link.get('rel'):
                    return "정상"
                # icon
                if 'icon' in link.get('rel'):
                    return "정상"
        return "비정상"
    except:
        return "비정상"

# URL (/favicon.ico) 내에 존재하는지
def fav_ico(url):
    try:
        # http ~ domain. 까지 split
        prev = url.split(get_tld(url))
        # URL 최상위 도메인까지 + /favicon.ico
        result = prev[0]+get_tld(url)+'/favicon.ico'
        # HTTP GET Request
        req = requests.get(result, timeout = 5)
        # status code
        res = req.status_code
        # 200 OK 시에는 정상사이트일 확률이 높음.
        if res == 200:
            return "정상"
        else:
            return "비정상"
    except:
        return "비정상"

# Domain_registration_length
# Domain 남은 기간 check
def Domain_registration_length(url):
    try :
        total_date = get_total_date(url)
        if total_date > 365:
            return "정상"
        else:
            return "비정상"
    except whois.parser.PywhoisError:
        return "비정상"
def get_total_date(url):
    try:
        domain = whois.whois(url)
        if type(domain.expiration_date) is list :
            expiration_date = domain.expiration_date[0]
        else :
            expiration_date = domain.expiration_date
        if type(domain.updated_date) is list :
            updated_date = domain.updated_date[0]
        else :
            updated_date = domain.updated_date
        
        total_date = (expiration_date - updated_date).days
    
        return total_date
    except :
        return "비정상"


# Prompt_in_Popup
# prompt와 같이 입력을 요구하는 창이 뜨는 경우
def textFieldInPopup(url):
    try:
        # HTTP GET Request
        req = requests.get(url, timeout = 5)
        # HTML 소스 추출
        html = req.text
         # HTML 소스 -> Python 객체로 변환, <script>태그 추출
        scriptTag = BeautifulSoup(html, "html.parser", parse_only=SoupStrainer('script'))
        for script in scriptTag:
            prompt = str(script)
            # prompt Popup이 존재 시 -> Phishing site
            if 'prompt' in prompt:
                return "비정상"
        return "정상"
    except:
        return "비정상"

def Length_of_Source(url):
    try:
        res = requests.get(url, timeout = 5)
        if len(res.text)> 30000:
            return "정상"
        else:
            return "비정상"
    except :
        return "비정상"


def makefeature(url):
    url_feature = []
    url_feature.append(Domain_registration_length(url))
    url_feature.append(Length_of_Source(url))
    url_feature.append(getLinksInTags(url))
    url_feature.append(checkAnchorTag(url))
    url_feature.append(favicon(url))
    url_feature.append(Alexa_Ranking(url))
    url_feature.append(abnormalUrl(url))
    url_feature.append(Prefix_suffix(url))
    url_feature.append(count_Redirection(url))
    url_feature.append(checkFormTag(url))
    url_feature.append(textFieldInPopup(url))
    url_feature.append(Disabling_Right_Click(url))
    url_feature.append(fav_ico(url))
    url_feature.append(having_Sub_Domain(url))
    return url_feature

def returntitle():
    tmp_list=["Domain_registration_length", "Length_of_Source", "getLinksInTags", "checkAnchorTag", "favicon", "alexaRanking", "abnormalUrl", "Prefix_suffix",
     "count_Redirection", "checkFormTag", "textFieldInPopup", "Disabling_Right_Click", "fav_ico", "having_Sub_Domain"]
    return tmp_list
    
def returncontent():
    tmp_list2=[
        
        "피싱 사이트의 경우 단기간만 활동하는 경우가 많기 때문에, 도메인 가입 기간이 짧다.",
        "HTML 소스코드의 길이가 지나치게 짧은 경우 피싱 사이트일 확률이 높다.",
        "HTML 문서의 특성을 담고 있는 <meta> 태그나 자바 스크립트를 실행하는 <script> 태그, 외부 문서를 연결하는 <link> 태그가 많다면 외부와 연결된 것이 많다고 예상되므로 피싱 사이트일 확률이 높다.",
        "<a> 태그의 대부분이 웹 페이지에 연결되어 있지 않거나 웹 사이트와 다른 도메인 이름을 가진다면 피싱 사이트일 확률이 높다.",
        "웹 사이트를 대표하는 아이콘인 favicon이 존재하지 않거나 외부 도메인에서 로드 되었다면 피싱 사이트일 확률이 높다.",
        "Alexa 데이터 베이스에는 방문자 수와 그들이 방문한 페이지 수를 기반으로 웹 사이트의 순위가 존재한다. 피싱 사이트는 비교적 짧은 기간 존재하기 때문에 데이터 베이스에 조회되지 않는다면 피싱 사이트로 의심할 수 있다.",
        "WHOIS 데이터 베이스에 도메인이 존재하지 않다면 피싱 사이트일 확률이 높다",
        "정상 URL에서는 ‘-‘가 거의 사용되지 않는다. 보통 피싱 사이트에서 정상 사이트로 위장하기 위해 ‘-‘ 기호를 사용한다.",
        "사이트 접속 시 리다이렉션 횟수가 많다면 피싱으로 의심할 수 있다.",
        "<form action>을 통해 사용자가 입력한 정보를 서버에서 처리해줘야 한다. 따라서 action 속성에 공백이나 ‘about:blank’가 존재한다면 정보에 대한 처리가 없다는 의미이므로 피싱 사이트일 확률이 높다.",
        "대부분의 정상 사이트에는 사용자에게 입력을 요구하는 팝업창이 존재하지 않는다. 따라서 정보 입력 창이 존재하는 팝업이 있다면 피싱 사이트일 확률이 높다.",
        "피셔는 피싱 사이트의 소스코드를 숨기기 위해서 우 클릭을 막을 수 있다.",
        "url에서 직접적으로 favicon 을 보는게 아닌 소스코드에서 favicon이 존재할 경우 도 favicon이 있는 것으로 취급한다.",
        "대부분 피싱 사이트는 2개 이상의 서브 도메인을 갖는다.",
        
        ]
    return tmp_list2
