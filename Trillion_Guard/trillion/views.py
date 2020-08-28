from django.shortcuts import render, get_object_or_404, redirect
from .models import NEW_URL, ORIGINAL_URL, DAILY_HIT,POST
from django.views import View
from django.http import HttpResponse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from datetime import datetime
from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators.csrf import csrf_exempt
from django.utils.dateparse import parse_date
from datetime import timedelta
from django.template import loader, RequestContext
import pickle
import joblib
import re
from .feature import check
from .detailfeature import makefeature
from .detailfeature import returntitle
from .detailfeature import returncontent
from collections import OrderedDict
from .fusioncharts import FusionCharts
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from .forms import CustomUserCreationForm
#from django.contrib.auth import get_user_model
from django.contrib.auth.views import LoginView
from django.contrib.auth.models import User
# Create your views here.

#회원가입
def register(request):
    if request.method == 'POST':
        f = CustomUserCreationForm(request.POST)
        if f.is_valid():
            f.save()
            return render(request, 'index.html',{'messages' : '회원가입에 성공했습니다.'})

    else:
        f = CustomUserCreationForm()

    return render(request, 'register.html', {'form': f})
    
# 로그인
class UserLoginView(LoginView):           
    template_name = 'login.html'

    def form_invalid(self, form):
        messages.error(self.request, '로그인에 실패하였습니다.', extra_tags='danger')
        return super().form_invalid(form)
    

# 주의 위험 경고 이런거 처리하는 chart - /chart - chart.html
class chart_VIEW(View):
    def get(self, request):
        
        #기계학습에 사용된 original url과 검색을 통해 들어온 new url을 hits기준으로 불러온다
        #그래서 bar 그래프로 정상과 피싱 사이트 보유 수를 보여줌
        NEW_phishing_urls = NEW_URL.objects.filter(LABEL=0).order_by('-HITS')
        NEW_legitimate_urls = NEW_URL.objects.filter(LABEL=1).order_by('-HITS')
        
        Original_phishing_urls = ORIGINAL_URL.objects.filter(LABEL=0).order_by('-HITS')
        Original_legitimate_urls = ORIGINAL_URL.objects.filter(LABEL=1).order_by('-HITS')
        
        # Chart data is passed to the `dataSource` parameter, as dictionary in the form of key-value pairs.
        Bar_dataSource = OrderedDict()
        
        Bar_dataSource["data"] = []
                
        Bar_chartConfig = OrderedDict()
    
        #Bar_chart설정
        Bar_chartConfig["caption"] = "Phishing & legitimate site 보유 수"
        Bar_chartConfig["subCaption"] = ""
        Bar_chartConfig["xAxisName"] = "site"
        Bar_chartConfig["yAxisName"] = "number of site"
        Bar_chartConfig["formatnumberscale"] = "0"
        Bar_chartConfig["thousandSeparator"] = ","
        Bar_chartConfig["theme"] = "fusion"
        Bar_chartConfig["plottooltext"]= "$label:  $dataValue"
        #Bar_chartConfig["showvalues"] = "1"

        #phishing 수 체크
        new_phishing_count = NEW_phishing_urls.count()
        original_phishing_count = Original_phishing_urls.count()
        phishing_count = new_phishing_count + original_phishing_count
        
        #Legitimate 수 체크
        new_legitimate_count = NEW_legitimate_urls.count()
        original_legitimate_count = Original_legitimate_urls.count()
        legitimate_count = new_legitimate_count + original_legitimate_count
        
        Bar_chartData = OrderedDict()
        
        Bar_chartData["Phishing"] = phishing_count
        Bar_chartData["Legitimate"] = legitimate_count
        
        Bar_dataSource["chart"] = Bar_chartConfig
       
        Bar_dataSource["data"].append({"label": 'Phishing', "value": phishing_count})
        Bar_dataSource["data"].append({"label": 'Legitimate', "value": legitimate_count})
        
      
        # Create an object for the column 2D chart using the FusionCharts class constructor
        # The chart data is passed to the `dataSource` parameter.
        Bar_column2D = FusionCharts(
            "column2d", "Bar_Chart", "450", "400", "Bar_chart", "json", Bar_dataSource)
            #"chart 형태", "잘모르겠고", "width", "height", "id명", "데이터타입", "datasource"
                
        #일일 검색 url 정상비율 나타내는 그래프
        Legitimate_ratio_dataSource = OrderedDict()
        Legitimate_ratio_chartConfig = OrderedDict()
        
        Daily_Phishing_hit = int(DAILY_HIT.objects.filter(PHISHING=0).first().DAY_HITS)
        Daily_Legitimate_hit = int(DAILY_HIT.objects.filter(PHISHING=1).first().DAY_HITS)

        
        Legitimate_ratio_dials = OrderedDict()
        Legitimate_ratio_dials['dial'] = []

        #비율 대입
        #아무런 hit이 없으면 50% 처리
        if Daily_Legitimate_hit + Daily_Phishing_hit == 0:
            Legitimate_ratio_value = [50]
        else:
            Legitimate_ratio_value = [(Daily_Legitimate_hit / (Daily_Legitimate_hit + Daily_Phishing_hit)) * 100]
   
        Legitimate_ratioValues = [Legitimate_ratio_value]
    
        

        #chart 설정
        # Legitimate_ratio_chartConfig["caption"] = "Daily 검색 URL의 Legitimate URL 비율 "
        Legitimate_ratio_chartConfig["caption"] = "Daily 보안 안전율 "
        Legitimate_ratio_chartConfig["subCaption"] = ""
        Legitimate_ratio_chartConfig["lowerLimit"] = "0"
        Legitimate_ratio_chartConfig["upperLimit"] = "100"
        Legitimate_ratio_chartConfig["numbersuffix"] ="%"
        Legitimate_ratio_chartConfig["showValue"] = "1"
        Legitimate_ratio_chartConfig["theme"] = "fusion"
        Legitimate_ratio_chartConfig["showTollTip"] = "0"
        Legitimate_ratio_chartConfig["chartBottomMargin"] = "50"
        
        #annotaion 설정
        Legitimate_ratio_annotations = OrderedDict()
        
        Legitimate_ratio_annotations['origw'] = "450"
        Legitimate_ratio_annotations['origh'] = "300"
        Legitimate_ratio_annotations['autoscale'] = "1"
        Legitimate_ratio_annotations['showBelow'] = "0"
        

        if 0 <= Legitimate_ratio_value[0] and Legitimate_ratio_value[0] <= 50:
            ratio_string = '보안 수준이 위험합니다.'
            ratio_color = '#e44a00'
        elif 50 < Legitimate_ratio_value[0] and Legitimate_ratio_value[0] <= 75:
            ratio_string = '보안 수준을 경고합니다.'
            ratio_color = '#f8bd19'
        elif 75 < Legitimate_ratio_value[0] and Legitimate_ratio_value[0] <= 100:
            ratio_string = '보안 수준이 안전합니다.'
            ratio_color = '#6baa01'

 
        Legitimate_ratio_annotations['groups'] = [
                {
                    "id": "arcs",
                    "items": [
                        {
                            "id": "store-cs-bg",
                            "type": "rectangle",
                            "x": "$chartCenterX-140",
                            "y": "$chartEndY - 22",
                            "tox": "$chartCenterX + 150",
                            "toy": "$chartEndY - 2",
                            "fillcolor": "#FFFFFF"
                        },
                        {
                            "id": "state-cs-text",
                            "type": "Text",
                            "color": ratio_color,
                            "label": ratio_string,
                            "fontSize": "18",
                            "font-weight": "600",
                            "align": "center",
                            "x": "$chartCenterX + 10",
                            "y": "$chartEndY - 12"
                        }
                    ]
                }
            ]
        
        #chart color 설정        
        Legitimate_ratio_colorRange = OrderedDict()
        Legitimate_ratio_colorRange['color'] = [
            {
                "minValue": "0",
                "maxValue": "50",
                "code": "#e44a00"
            },
            {
                "minValue": "50",
                "maxValue": "75",
                "code": "#f8bd19"
            },
            {
                "minValue": "75",
                "maxValue": "100",
                "code": "#6baa01"
                
            }
        ]
        
        Legitimate_ratio_dataSource['annotations'] = Legitimate_ratio_annotations      
        Legitimate_ratio_dataSource['colorRange'] = Legitimate_ratio_colorRange
        

        #실제 값 대입
        for i in range(len(Legitimate_ratioValues)):
            Legitimate_ratio_dials["dial"].append(
                {"value": Legitimate_ratioValues[i]})
        #chart 구성
        Legitimate_ratio_dataSource['chart'] = Legitimate_ratio_chartConfig
        Legitimate_ratio_dataSource['colorRange'] = Legitimate_ratio_colorRange
        Legitimate_ratio_dataSource['dials'] = Legitimate_ratio_dials

        Legitimate_ratio_gauge = FusionCharts(
            "angulargauge", "Legitimate_ratio_Chart", "50%", "400", "Legitimate_ratio_chart", "json", Legitimate_ratio_dataSource)
            #"chart형태", "잘 모르겠고", "width", "height", "id명", "데이터 타입", "data source"
        return render(request, 'chart.html', {
            'Bar_chart': Bar_column2D.render(),
            'Legitimate_ratio_chart': Legitimate_ratio_gauge.render(),
                                                       })
        



#기존 일별 피싱 사이트 검색 순위 - /board- urlList.html
class board_VIEW(View):
    def get(self, request):
        board_list = NEW_URL.objects.all()
        page_count=10
        page = request.GET.get('page', 1)
        paginator = Paginator(board_list, page_count)
        try:
            lines = paginator.page(page)
            max_index = len(paginator.page_range)
        except PageNotAnInteger:
            lines = paginator.page(1)
            max_index = len(paginator.page_range)
        except EmptyPage:
            lines = paginator.page(paginator.num_pages)
            max_index = len(paginator.page_range)

        context = {'board_list': lines,'max_index': max_index, 'mul': (lines.number-1)*page_count}
        return render(request, 'urlList.html', context)

    def post(self, request):
        domain_input=request.POST['domain_input']
        fromDate=request.POST['fromDate']
        toDate=request.POST['toDate']
        if fromDate==toDate and fromDate!='':
            date = parse_date(fromDate)
            board_list = NEW_URL.objects.all().filter(DATE__range=[date, date+ timedelta(days=1)]).order_by('-DATE')
        elif fromDate=='' or toDate=='':
            board_list = NEW_URL.objects.all().filter(URL__icontains=domain_input).order_by('-DATE')
        else:
            board_list = NEW_URL.objects.all().filter(DATE__range=[fromDate,toDate]).filter(URL__icontains=domain_input).order_by('-DATE')
            
        page_count=10
        page = request.GET.get('page', 1)
        paginator = Paginator(board_list, page_count)
        try:
            lines = paginator.page(page)
            max_index = len(paginator.page_range)
        except PageNotAnInteger:
            lines = paginator.page(1)
            max_index = len(paginator.page_range)
        except EmptyPage:
            lines = paginator.page(paginator.num_pages)
            max_index = len(paginator.page_range)

        context = {'board_list': lines,'domain_input':domain_input,'fromDate': fromDate,'toDate':toDate,'max_index': max_index, 'mul': (lines.number-1)*page_count}
        return render(request, 'urlList.html', context)

#메인 페이지 - / - index.html
def search(request):
    board_list = NEW_URL.objects.all().order_by('-DATE')    
    return render(request, 'index.html', {'urllist': board_list})

#검색 시 상세 링크 - /detail - urlInfo.html
def detail(request):
    entry_url = request.GET['url']
    content_save=returncontent()
    title_save=returntitle()
    feature_save=makefeature(entry_url)
    context={'content':content_save,'title':title_save,'makefeature':feature_save}
    return render(request, 'urlInfo.html',context)

def append(request):
    entry_url = request.GET['url_catch']
    flag=0
    tflag=0
    if 'www.' in entry_url[0:13]:
        a = entry_url[0:13].replace('www.','')
        entry_url = a + entry_url[13:]
    #label=1 -> 정상 label=0 -> 피싱
    #if(queryset) -> original db에 있는지 확인
    try:
        queryset = ORIGINAL_URL.objects.get(URL=entry_url)
        tflag=1
    except ObjectDoesNotExist:
        tflag=0

    if(tflag):
        queryset.HITS = queryset.HITS+1
        queryset.DAILY_HITS = queryset.DAILY_HITS+1
        queryset.save()
        #정상인지 확인
        if( queryset.LABEL=='1'):
            queryset2 = DAILY_HIT.objects.get(PHISHING=1)
            queryset2.DAY_HITS = queryset2.DAY_HITS+1
            flag=1
        else:
            queryset2 = DAILY_HIT.objects.get(PHISHING=0)
            queryset2.DAY_HITS = queryset2.DAY_HITS+1
            flag=0
        queryset2.save()
        return render(request, 'append.html', {'flag':flag,'url':entry_url})
    else:
        #new_url에 있는지 확인
        try:
            queryset = NEW_URL.objects.get(URL=entry_url)
            tflag=1
        except ObjectDoesNotExist:
            tflag=0
        if(tflag):
            queryset.HITS = queryset.HITS+1
            queryset.DAILY_HITS = queryset.DAILY_HITS+1
            queryset.save()
            #정상인지 확인
            if( queryset.LABEL=='1'):
                queryset2 = DAILY_HIT.objects.get(PHISHING=1)
                queryset2.DAY_HITS = queryset2.DAY_HITS+1
                flag=-1
            else:
                queryset2 = DAILY_HIT.objects.get(PHISHING=0)
                queryset2.DAY_HITS = queryset2.DAY_HITS+1
                flag=0
            queryset2.save()
            return render(request, 'append.html', {'flag':flag,'url':entry_url})
        else:
            #기계학습 돌려서 확인
            New_pre=check(entry_url)
            fb = NEW_URL(URL=entry_url, DATE=datetime.now(),  HITS=1,DAILY_HITS=1,LABEL=New_pre)
            fb.save()
            queryset2 = DAILY_HIT.objects.get(PHISHING=New_pre)
            queryset2.DAY_HITS = queryset2.DAY_HITS+1
            queryset2.save()
            if(New_pre==1):
                New_pre=-1
            return render(request, 'append.html', {'flag':New_pre,'url':entry_url})


#밑쪽부터 post
@login_required
def shareInfo_index(request):
    post_list = POST.objects.all()#.order_by('created_date')
    page = request.GET.get('page', 1)
    paginator = Paginator(post_list, 5)
    try:
        posts = paginator.page(page)
        max_index = len(paginator.page_range)
    except PageNotAnInteger:
        posts = paginator.page(1)
        max_index = len(paginator.page_range)
    except EmptyPage:
        posts = paginator.page(paginator.num_pages)
        max_index = len(paginator.page_range)
    
    context = {'posts': posts,
                'max_index': max_index, 'mul': (posts.number-1)*5 }
    
    return render(request, 'shareInfo_index.html', context)
                 
def shareInfo_show(request,pk):
    post = get_object_or_404(POST,pk=pk)
    return render(request, 'shareInfo_show.html',{'post' :post})

def shareInfo_new(request):
    return render(request, 'shareInfo_new.html')

def shareInfo_create(request):
    if(request.method == 'POST'):
        post = POST()
        post.title = request.POST['title']
        post.content = request.POST['content']
        post.author = request.user
        post.save()
    return redirect('shareInfo_index')

def shareInfo_delete(request,pk):
    post = POST.objects.get(pk=pk)
    if post.author == request.user:
        post.delete()
        return redirect('shareInfo_index')
    else:
        return render(request, 'shareInfo_show.html',{'post' :post, 'messages' :'권한이 없습니다.'})
   
def contact(request):
    return render(request, 'contact.html')