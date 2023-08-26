import json,os,sys,time,subprocess,random,hashlib,re,glob
from os.path import exists
import tldextract
import urllib.parse
from urllib.parse import urlparse
from subprocess import PIPE

###auxiliary function--network dump analysis---------

def find_identifiers(string):
	identifiers=[]
	start=string.find("code")
	end=string.find("state")
	if(start == -1):
		print("Code not present inspect dump file!!!!!!")
	identifiers.append(string[start+5:end-1])
	identifiers.append(string[end+6:-4])
	identifiers.append(string[:-4])

	return identifiers


def FB_find_accessToken_in_content(received):
	bcut=received.find("access_token=")
	if(bcut== -1):
		print("unable to find access_token")
		return["-1"]
	else:
		ecut=received.find("&",bcut)
		if(ecut==-1):
			print("unable to find end of parameter")
			return ["-1"]
		else:
			token=received[bcut:ecut]
	
	return token

def FB_find_redirectLink_in_content(received):
	#try to remove everything before url param and get identifiers from there
	bcut=received.find("window.location.href")
	ecut=received.find("#_=_")
	if(bcut== -1 or ecut== -1):
		print("unable to slice redirect url")
		return["-1"]
	else:
		link=received[bcut+22:ecut]
		link= link.replace("\\","")	
	
	return link

def TW_find_redirectLink_in_content(received):
	
	#try to remove everything before url param and get identifiers from there
	bcut=received.find("0;url=")
	ecut=received.rfind("<script",bcut)

	if(bcut== -1 or ecut== -1):
		print("unable to slice redirect url")
		return[-1]
	else:
		link=received[bcut+6:ecut]

	look=link.find(">")
	link=link[:look-1]
	link= link.replace("amp;","")

	return link


def Orcid_find_redirectLink_in_content(received):
	
	#try to remove everything before url param and get identifiers from there
	bcut=received.find("redirectUrl")
	ecut=received.rfind("responseType",bcut)

	if(bcut== -1 or ecut== -1):
		print("Orcid unable to slice redirect url")
		return["-1"]
	else:
		link=received[bcut+14:ecut-3]
	if("code="not in link):
		return["-1"]
	return link

def Yan_find_redirectLink_in_content(received):
	
	#try to remove everything before url param and get identifiers from there
	bcut=received.find("URL='")
	ecut=received.rfind("'\">",bcut)

	if(bcut== -1 or ecut== -1):
		print("unable to slice redirect url")
		return[-1]
	else:
		link=received[bcut+5:ecut]

	return link

def findOauthredirect(Networkdump,idp,site,pathconfusion):
	print(f'Findoauthredirect received len network log: {len(Networkdump)}\nidp: {idp}\nsite: {site}')
	marker=[]
	if(idp =="github.com"):
		marker=findOauthredirect_gh(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="facebook.com"):
		marker=findOauthredirect_fb2(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="atlassian.com"):
		marker=findOauthredirect_at(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="linkedin.com"):
		marker=findOauthredirect_lk(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="microsoftonline.com"):
		marker=findOauthredirect_mic(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="live.com"):
		marker=findOauthredirect_mic(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="line.me"):
		marker=findOauthredirect_line(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="kakao.com"):
		marker=findOauthredirect_kakao(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="twitter.com"):
		marker=findOauthredirect_tw(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="yandex.ru"):
		marker=findOauthredirect_yan(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="orcid.org"):
		marker=findOauthredirect_orcid(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="slack.com"):
		marker=findOauthredirect_slack(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="ok.ru"):
		marker=findOauthredirect_ok(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="reddit.com"):
		marker=findOauthredirect_reddit(Networkdump,idp,site,pathconfusion)
		return marker
	if(idp=="vk.com"):
		marker=findOauthredirect_vk(Networkdump,idp,site,pathconfusion)
		return marker
	print(f'idp:{idp} NOT SUPPORTED!!')
	return ["-1","Eror in exctracting redirect url"]


def FindPathconfusioninRequest(request,pathconfusion):
	inrequest=False
	inresponse=False
	inredirect_uri=False
	error=False
	accesstoken=False
	botblock=False
	botmessage=["We limit how often you can post, comment or do other things in a given amount of time in order to help protect the community from spam. You can try again later."]
	login_deact=False
	logindisabled=["attualmente disponibile per questa app."]
	errors=["The+redirect_uri+MUST+match+the+registered+callback+URL","redirect_uri_mismatch","The provided value for the input parameter &#39;redirect_uri&#39; is not valid. The expected value is a URI which matches a redirect URI registered for this client application.",
	"This integration is misconfigured. Contact the vendor for assistance.","Assicurati che l'accesso OAuth client e quello web siano attivi e aggiungi tutti i domini dell'app come URI di reindirizzamento OAuth validi."]
	for key in request["request"].keys():
		if(key=="url" or key=="Referer"):
			print(f'use key={key}request url to analyze: {request["request"]["url"]}')
			if("redirect_uri" in str(request["request"][key])):
				print(f'url request has redirecrt uri')
				#here extract redirect_uri and inspect if pathconfusion in redirect uri
				#string find redirect uri and search for & or %3F and cut string 
				#search for marker in this string and it true very vulnerable!!!!
				indices_object = re.finditer(pattern='redirect_uri', string=str(request["request"][key]))
				indices = [index.start() for index in indices_object]
				if(len(indices)<=1):
					cut=""
					a=str(request["request"][key]).find("redirect_uri")
					b=str(request["request"][key]).find("&",a)
					b2=str(request["request"][key]).find('%26',a)
					c=str(request["request"][key]).find('%3F',a)
					c2=str(request["request"][key]).find("?",a)
					#se encoded ma non normale allora encoded
					if((b==-1 and b2>0) or (b>0 and b2>0 and b2<b)):
						#if the encoded char is present but not normal use encoded position or both but encoded before 
						b=b2
					if((c==-1 and c2>0) or(c>0 and c2>0 and c2<c) ):
						#if the encoded char is present but not normal use encoded position or both but encoded before 
						c=c2
					print(f'position parameters:{a},{b},{c}')
					if((b>0 and b<c and c>0) or (b>0 and (c==-1))):
						cut=str(request["request"][key])[a+13:b]
						print(f'cut string with & final:{cut}')
					elif((c>0 and c<b and b>0) or(c>0 and (b==-1)) ):
						cut=str(request["request"][key])[a+13:c]
						print(f'cut string with ? final:{cut}')
					elif(b<0 and c<0):
						print(f'end of the string no parameters or ?')
						cut=str(request["request"][key])[a+13:]
					if(pathconfusion in cut):
						print(f'cut string in url is this one:{cut}')
						print(f'This one is REALLY vulnerable!!!!')
						inredirect_uri=True
					else:
						print(f'cut string in url is this one:{cut}')
						print(f'confusion in something else')
				else:
					print(f'multi redirect uri parameters where to search it?')
			else:
				print(f'url request does not contains redirecrt uri')
			
	for key in request["request"].keys():
		if(pathconfusion in str(request["request"][key])):
			#print(f'path confusion in request field {key}:{request["request"][key]}')
			inrequest=True
	for key in request["response"].keys():
		if(pathconfusion in str(request["response"][key])):
			#print(f'path confusion in response field {key}:{request["response"][key]}')
			inresponse=True
	for key in request["response"].keys():
		for e in errors:
			if(e in str(request["response"][key])):
				#print(f'path confusion in response field {key}:{request["response"][key]}')
				error=True
				print(f'error detected from IDP')
	for key in request["response"].keys():
		for e in botmessage:
			if(e in str(request["response"][key])):
				botblock=True
				print(f'Bot detection triggered by IDP')
	for key in request["response"].keys():
		for e in logindisabled:
			if(e in str(request["response"][key])):
				login_deact=True
				print(f'Login deactivated!!!')
	for key in request["response"].keys():
		if("access_token" in str(request["response"][key])):
			accesstoken=True
			print(f'access token in response not a usefull oauthflow!!')

	print(f'before evaluating the poisoned cases:\ninredirect_uri:{inredirect_uri}\ninrequest:{inrequest}\ninresponse:{inresponse}\nerror:{error}\naccesstoken:{accesstoken}\nBot protection:{botblock}\nlogin deactivated:{login_deact}')
	if(inredirect_uri and not inresponse and not error and not accesstoken and not botblock and not login_deact):
		print(f'REDIRECT_URI poisoned in final request')
		return "redirect uri request only poisoned"
	if(inredirect_uri and inresponse and not error and not accesstoken and not botblock and not login_deact):
		print(f'REDIRECT_URI and response poisoned')
		return "redirect uri and response poisoned"
	if(inresponse and not inredirect_uri and not error and not accesstoken and not botblock and not login_deact):
		print(f'Response poisoned but not in request redirect_uri!!!')
		return "only Response poisoned"	
	if(inrequest and not inresponse and not error and not accesstoken and not botblock and not login_deact):
		print(f'this is an idp melt not in redirect uri of req but in request')
		return "idp melt"
	if(inrequest and not inresponse and not error and accesstoken and not botblock and not login_deact):
		print(f'Access token as response not a usefull oauthflow')
		return "not usable oauthflow"
	if(not inrequest and not inresponse and not error and not accesstoken and not botblock and not login_deact):
		print(f'request sanitized')
		return "idp sanitized"
	if(inresponse and inrequest and not error and not botblock and not login_deact):
		print(f'in response and in request PathConfusion')
		return "both poisoned"
	if(error and not botblock and not login_deact):
		return "idp blocked attack"
	if(botblock and not login_deact):
		return "Bot defence triggered"
	if(login_deact):
		return "Login deactivated"
	return "end of FUNCTION"

def findOauthredirect_reddit(Networkdump,idp,site,pathconfusion):
	marker=[]
	if(marker):return link
	for request in Networkdump:
		if(request["response"]["status_code"]==302 and request["response"]["status_text"]=="Found"):
			print("look for right reddit request")
			if("https://ssl.reddit.com/api/v1/authorize" in request["request"]["url"]):
				print(f'right request extract from location url look for capitol and not capitol location')
				try:
					url=request["response"]["headers"]["Location"]
					if(not("code=" in url)):continue
					marker.append(url)
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					return marker
				except KeyError:
					try:
						url=request["response"]["headers"]["location"]
						if(not("code=" in url)):continue
						marker.append(url)
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						return marker
					except KeyError:
						print("unable to extract identifier check this file!!")
	error=["invalid redirect_uri parameter."]
	#search for error in login process
	for request in Networkdump:
		if(request["response"]["status_code"]==400 and request["response"]["status_text"]=="Bad Request"):
			print("look for error or bot detection in reddit response")
			if("https://ssl.reddit.com/api/v1/authorize" in request["request"]["url"]):
				for key in request["response"].keys():
					for e in error:
						if(e in str(request["response"][key])):
							print(f'error in response')
							marker.append("-1")
							marker.append("idp blocked attack")
							return marker
	print(f'[{idp}-error]if here error in finding the right request manually check it')
	return ["-1","Eror in exctracting redirect url"]

def findOauthredirect_ok(Networkdump,idp,site,pathconfusion):
	marker=[]
	if(marker):return link
	for request in Networkdump:
		if(request["response"]["status_code"]==302):
			print("look for right ok.ru request")
			if("https://connect.ok.ru/dk?st.cmd=OAuth2Permissions" in request["request"]["url"]):
				print(f'right request extract from location url look for capitol and not capitol location')
				try:
					url=request["response"]["headers"]["Location"]
					if(not("code=" in url)):continue
					marker.append(url)
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					return marker
				except KeyError:
					try:
						url=request["response"]["headers"]["location"]
						if(not("code=" in url)):continue
						marker.append(url)
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						return marker
					except KeyError:
						print("unable to extract identifier check this file!!")
	error=["Indicated redirect_uri is not registered in App settings."]
	for request in Networkdump:
		if(request["response"]["status_code"]==200):
			print("look for error or bot detection in slack response")
			if("https://connect.ok.ru/dk?st.cmd=OAuth2Permissions" in request["request"]["url"]):
				for key in request["response"].keys():
					for e in error:
						if(e in str(request["response"][key])):
							print(f'error in response')
							marker.append("-1")
							marker.append("idp blocked attack")
							return marker
	print(f'[{idp}-error]if here error in finding the right request manually check it')
	return ["-1","Eror in exctracting redirect url"]

def findOauthredirect_slack(Networkdump,idp,site,pathconfusion):
	marker=[]
	if(marker):return link
	for request in Networkdump:
		if(request["response"]["status_code"]==302 and request["response"]["status_text"]=="Found"):
			print("look for right slack.com request")
			if(request['request']['method']=="POST" and "https://tommycalltext.slack.com/oauth/" in request["request"]["url"]):
				print(f'right request extract from location url look for capitol and not capitol location')
				try:
					url=request["response"]["headers"]["Location"]
					if(not("code=" in url)):continue
					marker.append(url)
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					return marker
				except KeyError:
					try:
						url=request["response"]["headers"]["location"]
						if(not("code=" in url)):continue
						marker.append(url)
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						return marker
					except KeyError:
						print("unable to extract identifier check this file!!")

	#search for bot protection and errors
	error=["Enter your authentication code"]
	#search for error in login process
	for request in Networkdump:
		if(request["response"]["status_code"]==200 and request["response"]["status_text"]=="OK"):
			print("look for error or bot detection in slack response")
			if("https://tommycalltext.slack.com/" in request["request"]["url"]):
				for key in request["response"].keys():
					for e in error:
						if(e in str(request["response"][key])):
							print(f'error in response')
							marker.append("-1")
							marker.append("Bot defence triggered")
							return marker
	print(f'[{idp}-error]if here error in finding the right request manually check it')
	return ["-1","Eror in exctracting redirect url"]

def findOauthredirect_orcid(Networkdump,idp,site,pathconfusion):
	marker=[]
	if(marker):return link
	for request in Networkdump:
		if(request['request']['method']=="POST" and "https://orcid.org/oauth/custom/init.json?" in request['request']['url'] or "https://orcid.org/oauth/custom/authorize.json"== request['request']['url']):
			print("look for right orcid.id request")
			try:
				if(request["response"]['content']):
					temp=Orcid_find_redirectLink_in_content(request["response"]['content'])					
					print(f'received this from search in content:{temp} len:{len(temp)} temp[0]:{temp[0]}')
					if(not(len(temp)==1)):
						marker.append(temp)
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
					else:
						print(f'received an error from extracting url check it')
			except Exception as e:
				print(f'exception e :{e}')
				print("SEARCHING FOR CODE/STATE PARAMETERS IN CONTENT ERROR------>LOOK AT THIS FILE AND UNDERSTAND WHY")		
	if(marker):
		return marker
	["-1","Eror in exctracting redirect url"]

def findOauthredirect_yan(Networkdump,idp,site,pathconfusion):
	marker=[]
	if(marker):return link
	for request in Networkdump:
		if(request["response"]["status_code"]==200 and request["response"]["status_text"]=="OK"):
			if(request['request']['method']=="GET" and "https://oauth.yandex.ru/authorize?client_id=" in request['request']['url'] or request['request']['method']=="POST" and "https://oauth.yandex.ru/authorize/allow" in request['request']['url']):
				print("look for right yandex.ru request")
				try:
					if(request["response"]['content']):
						print(f'search in content yandex')
						temp=Yan_find_redirectLink_in_content(request["response"]['content'])
						marker.append(temp)
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						return marker
				except Exception as e:
					print("SEARCHING FOR CODE/STATE PARAMETERS IN CONTENT ERROR------>LOOK AT THIS FILE AND UNDERSTAND WHY")
	#search for error in login and blocked requests
	error=["Callback URL,"]
	print(f'look for error in login yandex')
	for request in Networkdump:
		if(request["response"]["status_code"]==400 and request["response"]["status_text"]=="Bad Request"):
			if(request['request']['method']=="GET" and "https://oauth.yandex.ru/authorize?client_id=" in request['request']['url']):
				print("look for right yandex.ru request")
				for key in request["response"].keys():
					for e in error:
						if(e in str(request["response"][key])):
							print(f'error in response')
							marker.append("-1")
							marker.append("idp blocked attack")
							return marker
	print(f'return from search in content marker:{marker}')

	print(f'[{idp}-error]if here error in finding the right request manually check it')
	return ["-1","Error extraction redirect url"]

def findOauthredirect_tw(Networkdump,idp,site,pathconfusion):
	marker=[]
	if(marker):return link
	for request in Networkdump:
		if(request['request']['method']=="POST" and "https://api.twitter.com/oauth/authenticate"==request['request']['url'] or "https://api.twitter.com/oauth/authorize"==request['request']['url']):
			print("look for right twitter request")
			try:
				if(request["response"]['content']):
					temp=TW_find_redirectLink_in_content(request["response"]['content'])
					marker.append(temp)
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					
			except Exception as e:
				print("SEARCHING FOR CODE/STATE PARAMETERS IN CONTENT ERROR------>LOOK AT THIS FILE AND UNDERSTAND WHY")
	print("return from search in contentTW")		
	if(marker):
		return marker
	["-1","Eror in exctracting redirect url"]



def findAccess_token_fb2(Networkdump,idp,site,pathconfusion):
	marker=[]
	#search for access token in request
	for request in Networkdump:
		if(request["response"]["status_code"]==200 and request["response"]["status_text"]=="OK"):
			if(request['request']['method']=="POST" and "/dialog/oauth/read" in request['request']['url'] and "https://www.facebook.com/" in request['request']['url'] or\
				request['request']['method']=="POST" and "https://www.facebook.com/login/device-based/regular/login/" in request['request']['url'] or\
				request['request']['method']=="POST" and "/dialog/oauth/confirm/" in request['request']['url'] and "https://www.facebook.com/" in request['request']['url'] or\
				request['request']['method']=="GET" and "/dialog/oauth?"in request['request']['url'] and "https://www.facebook.com/" in request['request']['url']):
				try:
					print("search for access_token in content Facebook")
					if(request["response"]['content']):
						temp=FB_find_accessToken_in_content(request["response"]['content'])
						print(f'return from Access_token in content:{temp}')
						if(len(temp)==2):
							print("len temp==2")
							if(not int(temp)==-1):
								print("int temp==-1")
								marker.append(temp)
								print(f'provide this request:{request["request"]["timestamp_start"]}')
								add=FindPathconfusioninRequest(request,pathconfusion)
								marker.append(add)
						print("THE REST")
						marker.append(temp)
						print(f'provide this request:{request["request"]["timestamp_start"]}')
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						
				except Exception as e:
					print(f'exception e:{e}')
					print("SEARCHING FOR CODE/STATE PARAMETERS IN CONTENT ERROR------>LOOK AT THIS FILE AND UNDERSTAND WHY")
	print(f'return from Access_token facebook marker:{marker}')
	if(marker):
		return marker
	["-1","Eror in exctracting redirect url"]

def findOauthredirect_fb2(Networkdump,idp,site,pathconfusion):
	marker=[]
	for request in Networkdump:
		if(request['request']['method']=="POST" and "/dialog/oauth/" in request['request']['url'] and "https://www.facebook.com/" in request['request']['url']):
			try:
				if(request["response"]['content']):
					print(f'provide this request:{request["request"]["timestamp_start"]}')
					temp=FB_find_redirectLink_in_content(request["response"]['content'])
					print(f'returned from search in content:{temp}')
					
					if(not len(temp)==2):	
						#this is a link extracted from content
						marker.append(temp)
						print(f'provide this request:{request["request"]["timestamp_start"]}')
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
					
					else:
						print(f'Facebook return content problem:{temp}')


			except Exception as e:
				print(f'exception e:{e}')
				print("SEARCHING FOR CODE/STATE PARAMETERS IN CONTENT ERROR------>LOOK AT THIS FILE AND UNDERSTAND WHY")
	print("return from search in contentFB")
	
	if(marker):
		if(not len(marker[0])==2):
			return marker
	else:
		marker=findAccess_token_fb2(Networkdump,idp,site,pathconfusion)
		

	if(marker):
		return marker
	else:
		marker=[]

		#identify redirection response and extract link
		print(f'search in location of response')
		for request in Networkdump:
			if(request["response"]["status_code"]==302 and request["response"]["status_text"]=="Found"):
				print(f'look for right facebook.com request timestamp request start:{request["request"]["timestamp_start"]}')
				if(request["response"]["status_code"]==302 and request["response"]["status_text"]=="Found" and \
					"https://www.facebook.com/" in request['request']['url'] and "/dialog/oauth" in request['request']['url'] and\
					request['request']['method']=="GET"):
					print(f'right request extract from location url look for capitol and not capitol location')
					url=""
					#also include the access_token= case in location
					try:

						url=request["response"]["headers"]["Location"]
						if("access_token=" in url):
							b=url.find("access_token=")
							marker.append(url[b:])
							print(f'provide this request:{request["request"]["timestamp_start"]}')
							add=FindPathconfusioninRequest(request,pathconfusion)
							marker.append(add)
							return marker
						else:
							if(not("code=" in url)):continue
							marker.append(url)
							add=FindPathconfusioninRequest(request,pathconfusion)
							marker.append(add)
							return marker
					except KeyError:
						try:
							url=request["response"]["headers"]["location"]
							if("access_token=" in url):
								b=url.find("access_token=")
								marker.append(url[b:])
								print(f'povide this request:{request["request"]["timestamp_start"]}')
								add=FindPathconfusioninRequest(request,pathconfusion)
								marker.append(add)
								return marker
							else:
								if(not("code=" in url)):continue
								marker.append(url)
								add=FindPathconfusioninRequest(request,pathconfusion)
								marker.append(add)
								return marker
						except KeyError:
							print("unable to extract identifier check this file!!")
		
		#look for RP site misconfigured
		error=["To be able to load this URL, add all domains and subdomains of your app to the App Domains field in your app settings",
		"attualmente disponibile per questa app."]
		for request in Networkdump:
			if(request["response"]["status_code"]==200 and request["response"]["status_text"]=="OK"):
				print(f'look for right facebook.com request timestamp request start:{request["request"]["timestamp_start"]}')
				if("https://www.facebook.com/login.php?" in request['request']['url'] and\
					request['request']['method']=="GET"):
					print(f'check if misconfigured RP site')
					for key in request["response"].keys():
						for e in error:
							if(e in str(request["response"][key])):
								print(f'error detected from IDP RP site misconfigured')
								marker.append("-1")
								marker.append("RP misconfigured")
								return marker

		print(f'[{idp}-error]if here error in finding the right request manually check it')

	return ["-1","Error extraction redirect url"]

def findOauthredirect_kakao(Networkdump,idp,site,pathconfusion):

	#identify redirection response and extract link
	marker=[]
	for request in Networkdump:
		if(request["response"]["status_code"]==302 and request["response"]["status_text"]=="Found"):
			print("look for right kakao.com request")
			if("https://kauth.kakao.com/oauth/authorize?" in request["request"]["url"]):
				print(f'right request extract from location url look for capitol and not capitol location:{request["request"]["timestamp_start"]}')
				try:
					url=request["response"]["headers"]["Location"]
					if(not("code=" in url)):continue
					marker.append(url)
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					return marker
				except KeyError:
					print("use lowecase location")
					try:
						url=request["response"]["headers"]["location"]
						if(not("code=" in url)):continue
						marker.append(url)
						add=FindPathconfusioninRequest(request,pathconfusion)
						return marker
					except KeyError:
						print("unable to extract identifier check this file!!")
	#seach for eventual error
	error=["Admin Settings Issue (KOE006)"]
	for request in Networkdump:
		if(request["response"]["status_code"]==400 and request["response"]["status_text"]=="Bad Request"):
			print("look for error in kakao.com response")
			if("https://kauth.kakao.com/oauth/authorize?" in request["request"]["url"]):
				print(f'right request extract from location url look for capitol and not capitol location:{request["request"]["timestamp_start"]}')
				for key in request["response"].keys():
					for e in error:
						if(e in str(request["response"][key])):
							print(f'error in response')
							marker.append("-1")
							marker.append("idp blocked attack")
							return marker
	print(f'[{idp}-error]if here error in finding the right request manually check it')
	return ["-1","Eror in exctracting redirect url"]


def findOauthredirect_line(Networkdump,idp,site,pathconfusion):

	#identify redirection response and extract link
	marker=[]
	for request in Networkdump:
		if(request["response"]["status_code"]==302 and request["response"]["status_text"]=="Moved Temporarily"):
			print("look for right line.me request")
			if("https://access.line.me/dialog/oauth/approve?" in request["request"]["url"] or "https://access.line.me/oauth2/v2.1/authorize/consent" in request["request"]["url"] or\
				"https://access.line.me/dialog/oauth/authenticate" in request["request"]["url"]):
				print(f'right request extract from location url look for capitol and not capitol location')
				try:
					url=request["response"]["headers"]["Location"]
					marker.append(url)
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					return marker
				except KeyError:
					try:
						url=request["response"]["headers"]["location"]
						marker.append(url)
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						return marker
					except KeyError:
						print("unable to extract identifier check this file!!")
	error=["Invalid request path"]
	#search for error in login process
	for request in Networkdump:
		if(request["response"]["status_code"]==400 and request["response"]["status_text"]=="Bad Request"):
			print("look for right line.me request")
			if("https://access.line.me/oauth" in request["request"]["url"] or "/authorize?" in request["request"]["url"]):
				for key in request["response"].keys():
					for e in error:
						if(e in str(request["response"][key])):
							print(f'error in response')
							marker.append("-1")
							marker.append("idp blocked attack")
							return marker
	print(f'[{idp}-error]if here error in finding the right request manually check it')
	return ["-1","Eror in exctracting redirect url"]


def findincontentMic(text):
	b=text.find("action=\"")
	f=text.find("><",b)
	if(b==-1):
		print("not found return link")
	else:
		f=text.find("><",b)
		if(f==-1):
			print("not found the cut")
		else:
			temp=text[b+8:f]

	return temp


def findOauthredirect_mic(Networkdump,idp,site,pathconfusion):

	marker=[]
	for request in Networkdump:
		if(request["response"]["status_code"]==200 and request["response"]["status_text"]=="OK"):
			print(f'look for right microsoftonline.com/live.com request request timestamp_start: {request["request"]["timestamp_start"]}')
			if("https://login.microsoftonline.com/common/federation" in request["request"]["url"]):
				print(f'right request extract from location url look for capitol and not capitol location')
				#abort if code not in request
				if("code=" not in request["request"]["content"]):break
				#extract from content url microsoft
				add=findincontentMic(request["response"]["content"])
				print(f'returned this url:{add}')
				marker.append(add)
				add=FindPathconfusioninRequest(request,pathconfusion)
				marker.append(add)
				return marker


	#identify redirection response and extract link
	marker=[]
	for request in Networkdump:
		if(request["response"]["status_code"]==302 and request["response"]["status_text"]=="Found" or request["response"]["status_code"]==200 and request["response"]["status_text"]=="OK"):
			print(f'look for right microsoftonline.com/live.com request request timestamp_start: {request["request"]["timestamp_start"]}')
			if("https://login.live.com/ppsecure/post.srf" in request["request"]["url"] or "https://login.live.com/oauth20_authorize.srf?" in request["request"]["url"]):
				print(f'right request extract from location url look for capitol and not capitol location')
				try:
					url=request["response"]["headers"]["Location"]
					marker.append(url)
					print("inspect for pathconfusion effect like errors")
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					return marker
				except KeyError:
					try:
						url=request["response"]["headers"]["location"]
						marker.append(url)
						print("inspect for pathconfusion effect like errors")
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						return marker
					except KeyError:
						#case of login stuck in idp with error message
						print("final exception inspect for pathconfusion effect like errors")
						marker.append("-1")
						add=FindPathconfusioninRequest(request,pathconfusion)
						if(add!="end of FUNCTION"):
							marker.append(add)
							return marker
						print("unable to extract identifier check this file!!")
	print(f'[{idp}-error]if here error in finding the right request manually check it')
	return ["-1","Eror in exctracting redirect url"]


def findOauthredirect_lk(Networkdump,idp,site,pathconfusion):

	#identify redirection response and extract link
	marker=[]
	for request in Networkdump:
		if(request["response"]["status_code"]==303 and request["response"]["status_text"]=="See Other"):
			print("look for right linkedin request")
			if("linkedin.com/oauth/v2/login-success" in request["request"]["url"] or "linkedin.com/oauth/v2/authorization-submit" in request["request"]["url"]):
				print(f'right request extract from location url look for capitol and not capitol location')
				try:
					url=request["response"]["headers"]["Location"]
					marker.append(url)
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					return marker
				except KeyError:
					try:
						url=request["response"]["headers"]["location"]
						marker.append(url)
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						return marker
					except KeyError:
						print("unable to extract identifier check this file!!")
	print("if here error in finding the right request manually check it")
	return ["-1","Eror in exctracting redirect url"]


def findOauthredirect_vk(Networkdump,idp,site,pathconfusion):

	#identify redirection response and extract link
	marker=[]
	for request in Networkdump:
		if(request["response"]["status_code"]==302 and request["response"]["status_text"]=="Found"):
			print("look for right vk request")
			if("login.vk.com/?act=grant_access"in request["request"]["url"]):
				print(f'right request extract from location url look for capitol and not capitol location')
				try:
					url=request["response"]["headers"]["Location"]
					marker.append(url)
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					return marker
				except KeyError:
					try:
						url=request["response"]["headers"]["location"]
						marker.append(url)
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						return marker
					except KeyError:
						print("unable to extract identifier check this file!!")
	print("if here error in finding the right request manually check it")
	return ["-1","Eror in exctracting redirect url"]

def findOauthredirect_at(Networkdump,idp,site,pathconfusion):

	#identify redirection response and extract link
	marker=[]
	for request in Networkdump:
		if(request["response"]["status_code"]==200 and request["response"]["status_text"]=="OK"):
			if("data-redirect" in request["response"]["content"]):
				print("identified the right request for atlassian with the right content")
				temp=request["response"]["content"]
				cut=temp.find("data-redirect")
				if(cut<0):
					print("error in cutting content")
				else:
					remain=temp[cut:]
					end=remain.find(">")
					temp=remain[:end]
					print(f'temp:{temp}')
					temp=temp.replace('data-redirect=',"")
					temp=temp.replace('\\',"")
					temp=temp.replace('&amp;',"&")
					temp=temp.replace('"',"")
					marker.append(temp)
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					return marker

	for request in Networkdump:
		if(request["response"]["status_code"]==302 and request["response"]["status_text"]=="Found"):
			print("look for right atlassian request")
			if("https://bitbucket.org/site/oauth" in request["request"]["url"]):
				print(f'right request extract from location url look for capitol and not capitol location')
				try:
					url=request["response"]["headers"]["Location"]
					if(site not in urlparse(url).netloc):continue
					marker.append(url)
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					return marker
				except KeyError:
					try:
						url=request["response"]["headers"]["location"]
						if(site not in urlparse(url).netloc):continue
						marker.append(url)
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						return marker
					except KeyError:
						print("unable to extract identifier check this file!!")

	for request in Networkdump:
		if(request["response"]["status_code"]==200 and request["response"]["status_text"]=="OK"):
			print("look for right atlassian request")
			if("https://bitbucket.org/site/oauth" in request["request"]["url"]):
				print(f'right request extract from location url look for capitol and not capitol location')
				try:
					url=request["response"]["headers"]["Location"]
					if(site not in urlparse(url).netloc):continue
					marker.append(url)
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					return marker
				except KeyError:
					try:
						url=request["response"]["headers"]["location"]
						if(site not in urlparse(url).netloc):continue
						marker.append(url)
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						return marker
					except KeyError:
						print(f'inspect for idp block')
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						return marker
						print("unable to extract identifier check this file!!")
	
	print("if here error in finding the right request manually check it")
	return ["-1","Eror in exctracting redirect url"]



def findOauthredirect_gh(Networkdump,idp,site,pathconfusion):
	
	#identify redirection response and extract link
	marker=[]
	for request in Networkdump:
		if("github.com/login/oauth/authorize" in request["request"]["url"]):
			print("found the right request now look at the content")
			if("js-manual-authorize-redirect" in request["response"]["content"] and "code=" in request["response"]["content"]):
				print("identified the right request with the right content")
				temp=request["response"]["content"]
				cut=temp.find("js-manual-authorize-redirect")
				if(cut<0):
					print("error in cutting content")
				else:
					remain=temp[cut:]
					f=remain.find("href")
					end=remain.find(">",f)
					temp=remain[f:end]
					print(f'temp:{temp}')
					temp=temp.replace('\\',"")
					temp=temp.replace('&amp;',"&")
					temp=temp.replace('href=',"")
					temp=temp.replace('"',"")
					marker.append(temp)
					add=FindPathconfusioninRequest(request,pathconfusion)
					marker.append(add)
					return marker
	if(marker):
		return marker
	else:
		print(f'github second round code not identified search for blocked url')
		for request in Networkdump:
			if("github.com/login/oauth/authorize" in request["request"]["url"]):
				print("found the right request now look at the content")
				if("js-manual-authorize-redirect" in request["response"]["content"]):
					print("identified the right request with the right content")
					temp=request["response"]["content"]
					cut=temp.find("js-manual-authorize-redirect")
					if(cut<0):
						print("error in cutting content")
					else:
						remain=temp[cut:]
						f=remain.find("href")
						end=remain.find(">",f)
						temp=remain[f:end]
						print(f'temp:{temp}')
						temp=temp.replace('\\',"")
						temp=temp.replace('&amp;',"&")
						temp=temp.replace('href=',"")
						temp=temp.replace('"',"")
						marker.append(temp)
						add=FindPathconfusioninRequest(request,pathconfusion)
						marker.append(add)
						return marker

	print(f'[{idp}-error]if here error in finding the right request manually check it')
	return ["-1","Eror in exctracting redirect url"]

def Find_OauthLekage(output,idp,site,identifiers,redirect_domain):
	
	#reserved domain excluded from leakages
	#excluded_domains=["cdn"]
	
	#search identifiers in request that are not directed to site or idp-->leakages
	site=site
	result=tldextract.extract(site)
	domainsite=result.domain
	idp=idp.split(".")[0]
	print(f'oauthleakage received site:{site}, domainsite:{domainsite}, redirect_domain:{redirect_domain}, idp: {idp}, identifiers: {identifiers}')

	Leakages=dict()

	### if no redirect domain consider domainsite as redirect domain
	if(redirect_domain==""):
		#print(f'SITE WITH NO REDIRECT domain!!!check it')
		redirect_domain=domainsite

	for n in output:
		netloc=urlparse(n["request"]["url"]).netloc
		print(f'this is networkloc to check:{netloc}')
		'''
		#exclude reserved domains as CDN if you wants to consider them as a trusted party
		for l in excluded_domains:
			if(l in netloc):
				break
		'''
		if(domainsite not in netloc and idp not in netloc and redirect_domain not in netloc):
			#search for identifiers in all the request fields and report leakage
			for elem in n["request"]:
				for i in identifiers:
					#print(f'analyze req: {n["request"][elem]}')
					if(i in str(n["request"][elem])):
						#build structure for leakage content
						req_info=str(n["request"]["timestamp_start"])+"##"+str(netloc)+"##"+str(n["request"]["method"])+"##"+str(n["request"]["url"])
						if(req_info not in Leakages.keys()):
							Leakages[req_info]=dict()
							Leakages[req_info][i]=[]
							Leakages[req_info][i].append(elem)
						else:
							if(i not in Leakages[req_info].keys()):
								Leakages[req_info][i]=[]
								Leakages[req_info][i].append(elem)
								print(f'This is a double location different identifier')
							else:
								print(f'This is a double location in the same request same identifier')
								Leakages[req_info][i].append(elem)
						continue


	return Leakages


###auxiliary function----crawler result analusis

def GetCrawlerResult(target):
	print(f'analysis crawler log look in: {target}')

	if not exists(target+"-crawlerlog.txt"):
		print("Crawler log not present stop here!")
		return 0
	
	with open(target+"-crawlerlog.txt") as crawler_log:
		lines=crawler_log.readlines()

	#first search for proxy connection error
	for line in lines:
		if("ERR_PROXY_CONNECTION_FAILED" in line):
			print("proxy crashed fix MITMproxy")
	#condition of success in crawler log
	for line in lines:
		if("RESULT-EXPERIMENT:1" in line):
			print("crawler log analysis succesful!(id in return page)")
			return 2
		if("RESULT-EXPERIMENT:0" in line):
			print("crawler log analysis succesful!(no id)")
			return 1
		if("found identifier in page but error in redirect url-->visual check!!!"in line):
			print("crawler log analysis succesful(visual check)!")
			return 1
		if("no identifiers in page redirect to a different page with error in redirect url"in line):
			print("error in redirect url try process it and see if leaking or not")
			return 1
		if("redirect to different domain and no identifiers in page not succesful login!!"in line):
			print("redirect to different domain still check it")
			return 1
		if("error in surfing to the login page!ABORT-EXPERIMENT:YES"in line):
			print("error in surfing to the login page")
			return -1
		if("login procedure stopped in IDP!!!"in line):
			print("login procedure error")
			return 1 #Potentially error use findpathconfusion request to identify IdP blocked or other error
		if("new windows still open no identifiers in initial window and no redirection in initial page error in login procedure!!"in line):
			print("login procedure stuck.")
			return 1 #Potentially error use findpathconfusion request to identify IdP blocked or other error
		if("unable to trigger IDP login ABORT-EXPERIMENT:YES"in line):
			print("unable to trigger sso login!!")
			return -4
		if("fill form unsucessful stop ABORT-EXPERIMENT:YES"in line):
			print("error in filling forms!!")
			return -5 #linkedin block initially the flow
		if("Open a new tab but not with the idp domain check xpath! ABORT-EXPERIMENT:YES"in line):
			print("error in xpath!!")
			return -6

	#last check if crawler reaches the last step or not
	for line in lines:
		if("analyze result measurement:"in line):
			print("different error check it")
			return 0
		
			
	print("if here crawling incomplete(timeout/error in login!!")
	for line in lines:
		if("No node found for selector: div[aria-label*='ontinua']"in line):
			print("potential facebook block after too many attempts")
			return 3 #use the error check to find facebook bot protection
		if("domain return:null" in line):
			print("error in connection")
			return 1 ##crawling and proxy ok only a network error check for vulnerability
	return -7


def GetProxyResult(target):
	print(f'analysis proxylog look in: {target}')

	if not exists(target+"-proxylog.txt"):
		print("Crawler log not present stop here!")
		return 0
	
	with open(target+"-proxylog.txt") as crawler_log:
		lines=crawler_log.readlines()

	#condition of success in proxy log
	for line in lines:
		if("temp string modified with replace:" in line):
			print("proxy injected the path confusion")
			return 1
			
	print("proxy not able to inject the path confusion")
	return -1

#####auxiliary function----process network dump
def ProcessStreamfile(target):
	#process the stream and read it

	if(exists(target+"_processed.json")):
		#open the file and not reprocess it
		jsonFile = open(target+"_processed.json", "r")
		new=[]
		new=json.load(jsonFile)
		jsonFile.close()
		return new


	print(f'received this target to analyze: {target}')
	cmd=["mitmdump","-q","-ns","dump_http.py"]
	cmd.append("-r")
	cmd.append(target+"-stream")

	Proxy_subproc = subprocess.Popen(cmd, stdout=subprocess.PIPE,universal_newlines=True)
	
	#wait for the subprocess to complete task
	time.sleep(10)
	Proxy_subproc.terminate()

	outs=Proxy_subproc.stdout
	buff=outs.read()
	
	buff=buff.replace("},\n","}\n")
	buff=buff.replace('\"','"')
	save= buff.split("\n")
	new=[]
	save.pop()
	test=[]
	for s in save:
		if("Addon error: Traceback (most recent call last):"not in s):
			try:
				test.append(json.loads(s))
			except Exception as e:
				#print(f'string with error len:{len(s)}\n{s}')
				#print(f'exception e:{e}')
				pass
			

	#save file
	jsonFile = open(target+"_processed.json", "w+")
	jsonFile.write(json.dumps(test, indent=2))
	jsonFile.close()

	jsonFile = open(target+"_processed.json", "r")
	new=[]
	new=json.load(jsonFile)
	jsonFile.close()

	return new

###auxiliary function------save output analysis

def SaveLeakageReport(destination,site,report):
	print(f'Save Lekage report:{destination+"_processed.json"}')

	if(not exists(destination+'/'+site+"_LeakageReport.json")):
		#create the leakage report
		acc=[]
		acc.append(report)
		jsonFile = open(destination+'/'+site+"_LeakageReport.json", "w+")
		jsonFile.write(json.dumps(acc))
		jsonFile.close()
	else:
		#leakage report already there update file and override same idp
		content=json.load(open(destination+'/'+site+"_LeakageReport.json", "r"))
		print(f'len report:{len(content)}, type:{type(content)}')

		
		#check if idp already there override
		acc=[]
		updated=False
		for c in content:
			if(c["idp"]==report["idp"]):
				acc.append(report)
				updated=True
			else:
				acc.append(c)
		#if not an update of idp add the report to leakage report
		if(not updated):acc.append(report)

		jsonFile = open(destination+'/'+site+"_LeakageReport.json", "w+")
		jsonFile.write(json.dumps(acc))
		jsonFile.close()

def AddToRedoMeasurement(t,m,Redo_measurement,Dict_sites):
	
	m_info=GetInfoMeasuremnt(m)
	if(t.split("/")[-1] not in Redo_measurement.keys()):
		Redo_measurement[t.split("/")[-1]]={}
		#check idp and get login page
		if(m_info[1] in Dict_sites[t.split("/")[-1]].keys()):
			#obtain login page
			pagehash=m_info[2]
			for e in Dict_sites[t.split("/")[-1]][m_info[1]]:
				if(pagehash==hashlib.md5((e.split("##")[0]+e.split("##")[1]).encode('utf-8')).hexdigest()):
					Redo_measurement[t.split("/")[-1]][e.split("##")[0]]=[]
					Redo_measurement[t.split("/")[-1]][e.split("##")[0]].append(m_info[1])
		else:
			print(f'idp not present in a database? check it!!!!!')
	else:
		print(f'site already included for redo add idp to right login page')

		if(m_info[1] in Dict_sites[t.split("/")[-1]].keys()):
			#obtain login page
			pagehash=m_info[2]
			for e in Dict_sites[t.split("/")[-1]][m_info[1]]:
				if(pagehash==hashlib.md5((e.split("##")[0]+e.split("##")[1]).encode('utf-8')).hexdigest()):
					if(e.split("##")[0] not in Redo_measurement[t.split("/")[-1]].keys()):
						Redo_measurement[t.split("/")[-1]][e.split("##")[0]]=[]
						Redo_measurement[t.split("/")[-1]][e.split("##")[0]].append(m_info[1])
					else:
						Redo_measurement[t.split("/")[-1]][e.split("##")[0]].append(m_info[1])
		else:
			print(f'idp not present in a database? check it!!!!!')


#####auxiliary function-----get info result folder
def GetMeasurements(target):
	with open(target+"/"+target.split("/")[-1]+"-Target.txt") as f:
		Files=f.readlines()
	
	#remove \n at the end of string 
	output=[]
	for f in Files:
		output.append(f[:-1])

	return output

def GetInfoMeasuremnt(measurements):
	result=[]
	if(len(measurements.split("-"))<2):
		#site witthout - in name
		result=measurements.split("-")
		return result
	else:
		#one or multiple - in site name
		temp=measurements.split("-")
		cut=measurements.find(temp[-2])
		result.append(measurements[:cut-1])
		result.append(temp[-2])
		result.append(temp[-1])
		return result

def checktrgetfile(Path_File):
	targets=[]
	print(f'search for file in this folder:{Path_File}')
	for files in glob.glob(Path_File + '/*proxylog*'):
		targets.append(files)

	final=[]
	for f in targets:
		final.append(os.path.basename(os.path.normpath(f.replace("-proxylog.txt",""))))

	print(f'this are the file found len:{len(final)}')
	if not exists(Path_File+"/"+Path_File.split("/")[-1]+"-Target.txt"):
		print("target file not present creat one")
		save = ["{}\n".format(i) for i in final]
		with open(Path_File+"/"+Path_File.split("/")[-1]+"-Target.txt", 'w+') as fp:
			fp.writelines(save)
	else:
		print("update target file with new sites")
		with open(Path_File+"/"+Path_File.split("/")[-1]+"-Target.txt") as f:
			Files=f.readlines()
		if(len(Files)<len(final)):
			print("increase number of site update file")
			save = ["{}\n".format(i) for i in final]
			with open(Path_File+"/"+Path_File.split("/")[-1]+"-Target.txt", 'w') as fp:
				fp.writelines(save)
		else:
			print("skip update")

def Gen_stat(Savestat,Crawlerresult,m):
	'''
	{"okprocedure":[],
	"failoauthleakanalysis":[],
	"sitewithleak":[],
	"notsuccesscrawling":{"login_error":[]
		,"login_stuck":[]
		,"untriggered_sso_login":[]
		,"error_fill_forms":[]
		,"xpath_error":[]
		,"incomplete_crawling":[]
		,"different_error":[]
		,"empty_stream":[]},,
	"measurementfail":[]}
	'''
	m_info=GetInfoMeasuremnt(m)
	idp=m_info[1]
	if(idp not in Savestat.keys()):
		print(f'idp:{idp} not present in dictionary statistics!!!')
	else:
		if(Crawlerresult==1):
			Savestat[idp]["okprocedure"].append(m)
			return
		if(Crawlerresult==-9):
			Savestat[idp]["failoauthleakanalysis"].append(m)
			return
		if(Crawlerresult==2):
			Savestat[idp]["sitewithleak"].append(m)
			return
		if(Crawlerresult==-1):
			Savestat[idp]["measurementfail"].append(m)
			return
		if(Crawlerresult==-2):
			Savestat[idp]["notsuccesscrawling"]["login_error"].append(m)
			return
		if(Crawlerresult==-3):
			Savestat[idp]["notsuccesscrawling"]["login_stuck"].append(m)
			return
		if(Crawlerresult==-4):
			Savestat[idp]["notsuccesscrawling"]["untriggered_sso_login"].append(m)
			return
		if(Crawlerresult==-5):
			Savestat[idp]["notsuccesscrawling"]["error_fill_forms"].append(m)
			return
		if(Crawlerresult==-6):
			Savestat[idp]["notsuccesscrawling"]["xpath_error"].append(m)
			return
		if(Crawlerresult==-7):
			Savestat[idp]["notsuccesscrawling"]["incomplete_crawling"].append(m)
			return
		if(Crawlerresult==-8):
			Savestat[idp]["notsuccesscrawling"]["empty_stream"].append(m)
			return
		if(Crawlerresult==0):
			Savestat[idp]["notsuccesscrawling"]["different_error"].append(m)
			return
		print(f'if you see this error in stat:{m}')
	return ""

def remove_items(test_list, item):
	res = [i for i in test_list if i != item]

	return res

def Listdifference(**kwargs):
	base=kwargs.pop("base")
	for k in kwargs.keys():
		for v in kwargs[k]:
			base=remove_items(base,v)
	return base

def IdPinvolved(List):
	#use list of idps to differentiate site with - in name
	IDP=["facebook.com","github.com","atlassian.com","microsoftonline.com","orcid.org","live.com","linkedin.com","slack.com","vk.com","kakao.com","line.me","twitter.com","reddit.com","ok.ru","yandex.ru","yahoo.com"]
	idps=dict()
	for i in List:
		for l in IDP:
			#find idp in name
			p=i.find(l)
			if(i[p-1]=="-"and i[p+len(l)]=="-"):
				#idp identified remove it from string
				if(l not in idps.keys()):
					idps[l]=[]
					idps[l].append(i)
				else:
					idps[l].append(i)
				#one and only one idp can match
				break
	#check exact number returned:
	temp=0
	for i in idps.keys():
		temp+=len(idps[i])
	if(temp!=len(List)):
		print("THERE is an error in function call")

	return idps

if __name__ == '__main__':
	#check result folder and find if pathconfusion successful
	#input: folder site, sites analyzed (to get site informations:login pages), new data for redirect request
	#output: 

	Path_File=sys.argv[1]
	namefolder=os.path.basename(os.path.normpath(Path_File))
	print(f'namefolder:{namefolder}')
	sites=json.load(open(sys.argv[2]))

	#check list of file to be analyzed
	directories=os.listdir(Path_File)
	#statistics folder
	Statistics_folder=dict()

	#obtain directories to analize
	targets=[]
	for i in directories:
		if(os.path.isdir(Path_File+"/"+i)):
			targets.append(Path_File+"/"+i)
			Statistics_folder[i]={"measurement":[],"login_disabled":[],"RP_misconf":[],"er0,2,3":[],"timeout":[],"fbbot":[],"linkedinblock":[],"microsoftblock":[],"testissue":[],"bothpoisoned":[],"badlogin":[],"notusableoauth":[],"onlyreqpoisoned":[],"goodlogin":[],"rightinjection":[],"wronginjection":[],"redirecturipoisoned":[],"emptystream":[],"redirecturlunidentified":[],"succesfulattack":[],"idpblock":[],"idpsanitize":[],"idpmelt":[],"rpmelt":[]}

	#site--->login_page-->[idp1,idp2]
	Redo_measurement=dict()
	#analyze each folder
	for t in targets:
		print(f'target analysis:{t}')
		if not exists(t+"/"+t.split("/")[-1]+"-Target.txt"):
			print(f'Target File:{t} not present create file')
			checktrgetfile(t)
		else:
			print(f'check if target file is complete and update it if necessary')
			checktrgetfile(t)


		idpstatus=dict()
		i=t.split("/")[-1]
		print(f'Analyzing forlder:{i}')

		#obtain list of measurements in the folder
		Measurements=GetMeasurements(t)
		for m in Measurements:
			m_info=GetInfoMeasuremnt(m)
			idp=m_info[1]
			sitename=m_info[0]
			print(f'site:{sitename} idp investigated:{idp}')
			Statistics_folder[i]["measurement"].append(m)
			
			#only need crawler log
			Crawlerresult=GetCrawlerResult(t+"/"+m)
			print(f'obatined this crawler result:{Crawlerresult}')


			#check idp and their return from crawling
			if(idp not in idpstatus.keys()):
				idpstatus[idp]=dict()
				idpstatus[idp][Crawlerresult]=1
			else:
				if(Crawlerresult not in idpstatus[idp].keys()):
					idpstatus[idp][Crawlerresult]=1
				else:
					idpstatus[idp][Crawlerresult]+=1
			
			if(Crawlerresult<1):
				print(f'not succesfull crawling stop here!!')
				#save for statistics and knowing what type of error in crawling
				Statistics_folder[i]["badlogin"].append(m)
				if(Crawlerresult==-6 or Crawlerresult==-4 or Crawlerresult==-1):
					print(f'crawling problem not from attack or other factors')
					Statistics_folder[i]["testissue"].append(m)
				if(Crawlerresult==-7):
					print(f'timeout measurement check this')
					Statistics_folder[i]["timeout"].append(m)
					
				if(Crawlerresult==-8):
					print(f'potential facebook block')
					Statistics_folder[i]["fbbot"].append(m)
					
				if(Crawlerresult==-5):
					print(f'check this login procedure:{m}')
					Statistics_folder[i]["linkedinblock"].append(m)

				if(Crawlerresult==-2):
					print(f'error -2 in this login:{m}')
					Statistics_folder[i]["er0,2,3"].append(m)

				if(Crawlerresult==-3):
					print(f'error -3 in this login:{m}')
					Statistics_folder[i]["er0,2,3"].append(m)

				if(Crawlerresult==0):
					print(f'error 0 in this login:{m}')
					Statistics_folder[i]["er0,2,3"].append(m)
				continue

			Statistics_folder[i]["goodlogin"].append(m)
			#here analyze the proxy log
			proxyresult=GetProxyResult(t+"/"+m)

			if(proxyresult==-1):
				print(f'Proxy not able to inject path confusion')
				Statistics_folder[i]["wronginjection"].append(m)
				continue
			
			Statistics_folder[i]["rightinjection"].append(m)

			#check here the stream file get redirect url and look for pathconfusion
			output=ProcessStreamfile(t+"/"+m)
					
			#empty stream file need to redo measurement
			if(len(output)==0):
				print(f'stream file empty stop here check this!!')
				Statistics_folder[i]["emptystream"].append(m)
				continue

			oauth_redirect=findOauthredirect(output,idp,sitename,"FAKEPATH")
			print(f'redirect url extracted from network log: {oauth_redirect}')

			if(oauth_redirect[0]=="idp blocked attack" or oauth_redirect[1]=="idp blocked attack"):
				print(f'IDP blocked the attack!!!')
				Statistics_folder[i]["idpblock"].append(m)
				continue
			
			if(not oauth_redirect or len(oauth_redirect[0])<10 or "http" not in oauth_redirect[0]):
				print("check correctness of parameters")
				#check facebook bot protection result crawler 3
				#continue from here!!!
				if(Crawlerresult==3 and oauth_redirect[1]=="Error extraction redirect url"):
					print("this site need to be inspected further_CHECKIT!!!")
					Statistics_folder[i]["testissue"].append(m)
					continue
				
				if(oauth_redirect[0]=="-1" and oauth_redirect[1]=="RP misconfigured"):
					print(f'RP site misconfigured')
					Statistics_folder[i]["RP_misconf"].append(m)
					continue
				if(oauth_redirect[1]=="not usable oauthflow"):
					print(f'unusable oauthflow')
					Statistics_folder[i]["notusableoauth"].append(m)
					continue
				if(oauth_redirect[1]=="Login deactivated"):
					print(f'login deactivated!!')
					Statistics_folder[i]["login_disabled"].append(m)
					continue
				if(oauth_redirect[1]=="both poisoned"):
					print(f'request and response poisoned')
					Statistics_folder[i]["bothpoisoned"].append(m)
					continue
				if(oauth_redirect[1]=="Bot defence triggered"):
					print(f'Bot defence triggered')
					Statistics_folder[i]["fbbot"].append(m)
					continue
				elif(oauth_redirect[1]=="redirect uri request only poisoned"):
					print(f'redirect uri only poisoned in request but not response')
					Statistics_folder[i]["onlyreqpoisoned"].append(m)
					continue
				else:
					Statistics_folder[i]["redirecturlunidentified"].append(m)
					continue
				print("received an empty list")
				print("NOT ABLE TO IDENTIFY THE OAUTH REDIRECT LINK--->LOOK AT THE INVESTIGATION FUNCTION!!!")
				continue
			
			print(f'result folder:{i} result of request poisoning:{oauth_redirect[1]}')
			if(Crawlerresult==2 and oauth_redirect[1]=="both poisoned"):
				print(f'this means that request and response poisoned but finished with a perfect login so RP melting')
				Statistics_folder[i]["rpmelt"].append(t+"/"+m)

			if(oauth_redirect[1]=="idp melt"):
				print(f'IDP melt the pathconfusion!!!')
				Statistics_folder[i]["idpmelt"].append(m)

			if(oauth_redirect[1]=="both poisoned"):
				print(f'request and response poisoned')
				Statistics_folder[i]["bothpoisoned"].append(m)

			if(oauth_redirect[1]=="idp blocked attack"):
				print(f'IDP blocked the attack!!!')
				Statistics_folder[i]["idpblock"].append(m)

			if(oauth_redirect[1]=="idp sanitized"):
				print(f'IDP sanitized the pathconfusion!!!')
				Statistics_folder[i]["idpsanitize"].append(m)
			
			if(oauth_redirect[1]=="only Response poisoned"):
				print(f'only response poisoned analize this case!!!\nfile:{t+"/"+m}')

			if(oauth_redirect[1]=="end of FUNCTION"):
				print(f'End of function analize this case!!!\nfile:{t+"/"+m}')

			if(oauth_redirect[1]=="redirect uri and response poisoned"):
				print(f'redirect uri poisoned in request and marker in response=successful attack RESULT:1!!!')
				Statistics_folder[i]["redirecturipoisoned"].append(m)

			if(oauth_redirect[1]=="redirect uri request only poisoned"):
				print(f'redirect uri only poisoned in request but not response')
				Statistics_folder[i]["onlyreqpoisoned"].append(m)

			if("FAKEPATH" in oauth_redirect[0]):
				print(f'Found a successful attack!!!RESULT:1')
				Statistics_folder[i]["succesfulattack"].append(m)

		for s in Statistics_folder[i]["redirecturlunidentified"]:
			if("microsoftonline"in s):
				Statistics_folder[i]["microsoftblock"].append(s)


		print(f'idps status:{len(idpstatus.keys())}\n idps:{idpstatus}')

	TotalVulnSites=[]
	TotalIdpsMeltingSites=[]
	TotalSanitizeSites=[]
	TotalNotcompliantOauthflow=[]
	uniquesite=[]
	Totalsitesvectors=[]
	totalgithubcases=dict()
	for p in Statistics_folder.keys():
		print(f'Statistics for folder:{p}')
		potvulnerable=set(Statistics_folder[p]["rightinjection"])-set(Statistics_folder[p]["emptystream"])-set(Statistics_folder[p]["redirecturlunidentified"])-set(Statistics_folder[p]["notusableoauth"])-set(Statistics_folder[p]["RP_misconf"])-set(Statistics_folder[p]["fbbot"])-set(Statistics_folder[p]["login_disabled"])-set(Statistics_folder[p]["testissue"])
		oauthflow=potvulnerable-set(Statistics_folder[p]["idpblock"])
		streamfail=set(Statistics_folder[p]["redirecturlunidentified"])-set(Statistics_folder[p]["microsoftblock"])-set(Statistics_folder[p]["notusableoauth"])-set(Statistics_folder[p]["idpblock"])
		missingvulnerable=oauthflow-set(Statistics_folder[p]["rpmelt"])-set(Statistics_folder[p]["onlyreqpoisoned"])-set(Statistics_folder[p]["idpmelt"])-set(Statistics_folder[p]["succesfulattack"])-set(Statistics_folder[p]["idpsanitize"])
		checkbadlogin=set(Statistics_folder[p]["badlogin"])-set(Statistics_folder[p]["fbbot"])-set(Statistics_folder[p]["testissue"])-set(Statistics_folder[p]["er0,2,3"])-set(Statistics_folder[p]["timeout"])-set(Statistics_folder[p]["linkedinblock"])
		
		#build total for final numbers
		TotalNotcompliantOauthflow.extend(oauthflow)
		TotalVulnSites.extend(set(Statistics_folder[p]["succesfulattack"]))
		TotalSanitizeSites.extend(set(Statistics_folder[p]["idpsanitize"]))
		TotalIdpsMeltingSites.extend(set(Statistics_folder[p]["onlyreqpoisoned"]))
		TotalIdpsMeltingSites.extend(set(Statistics_folder[p]["idpmelt"]))
		Totalsitesvectors.extend(set(Statistics_folder[p]["measurement"]))
		'''
		print(f'statistics:\n\
			Total measurements:{len(set(Statistics_folder[p]["measurement"]))}\n\
			Test issue:{len(set(Statistics_folder[p]["testissue"]))}\n\
			Facebook bot protection:{len(set(Statistics_folder[p]["fbbot"]))} site:{IdPinvolved(Statistics_folder[p]["fbbot"])}\n\
			Manual inspection:{len(set(Statistics_folder[p]["er0,2,3"]))} Idps:{IdPinvolved(Statistics_folder[p]["er0,2,3"])}\n\
			Time out:{len(set(Statistics_folder[p]["timeout"]))}\n\
			Linkedinblock:{len(set(Statistics_folder[p]["linkedinblock"]))} sites:{IdPinvolved(Statistics_folder[p]["linkedinblock"])}\n\
			checkBadlogin:{len(checkbadlogin)} site:{checkbadlogin}\n\
			Badlogin:{len(set(Statistics_folder[p]["badlogin"]))}\n\
			RP misconfigured:{len(set(Statistics_folder[p]["RP_misconf"]))} site:{Statistics_folder[p]["RP_misconf"]}\n\
			Login disabled:{len(set(Statistics_folder[p]["login_disabled"]))} site:{Statistics_folder[p]["login_disabled"]}\n\
			Good login:{len(set(Statistics_folder[p]["goodlogin"]))}\n\
			Right injection:{len(set(Statistics_folder[p]["rightinjection"]))}\n\
			Bad injection:{len(set(Statistics_folder[p]["wronginjection"]))}\n\
			Empty stream file:{len(set(Statistics_folder[p]["emptystream"]))}\n\
			\nRedirect url unidentified:{len(set(Statistics_folder[p]["redirecturlunidentified"]))} Idps:{IdPinvolved(Statistics_folder[p]["redirecturlunidentified"])}\n\
			Microsoft block:{len(set(Statistics_folder[p]["microsoftblock"]))} sites:{Statistics_folder[p]["microsoftblock"]}\n\
			Not usable oauth:{len(set(Statistics_folder[p]["notusableoauth"]))}\n\
			Stream fail:{len(streamfail)} sites:{IdPinvolved(streamfail)}\n\
			\nPotentially vulnerable:{len(potvulnerable)}\n\
			IdP block:{len(set(Statistics_folder[p]["idpblock"]))}Idps:{IdPinvolved(Statistics_folder[p]["idpblock"])}\n\
			OAuthflow:{len(oauthflow)}\n\
			RPmelt:{len(set(Statistics_folder[p]["rpmelt"]))}{Statistics_folder[p]["rpmelt"]}\n\
			onlyrequest poisoned(idp melt?):{len(set(Statistics_folder[p]["onlyreqpoisoned"]))} Idps:{IdPinvolved(Statistics_folder[p]["onlyreqpoisoned"])}\n\
			IdP melt:{len(set(Statistics_folder[p]["idpmelt"]))}Idps:{IdPinvolved(Statistics_folder[p]["idpmelt"])}\n\
			IdP sanitize:{len(set(Statistics_folder[p]["idpsanitize"]))} Idps:{IdPinvolved(Statistics_folder[p]["idpsanitize"])}\n\
			Succesfull attack:{len(set(Statistics_folder[p]["succesfulattack"]))} Idps:{IdPinvolved(Statistics_folder[p]["succesfulattack"])}\n\
			Missing vulnerable sites:{len(missingvulnerable)} sites:{missingvulnerable}\n')
		print(f'unique set for each statistics:')
		print(f'statistics:\nunique total measurements:{len(set(Statistics_folder[p]["measurement"]))}\ntest issue:{len(set(Statistics_folder[p]["testissue"]))}\nunique badlogin:{len(set(Statistics_folder[p]["badlogin"]))}\nunique goodlogin:{len(set(Statistics_folder[p]["goodlogin"]))}\nEmpty stream file:{len(set(Statistics_folder[p]["emptystream"]))}\nPotentially vulnerable:{len(set(Statistics_folder[p]["rightinjection"]))-((len(set(Statistics_folder[p]["emptystream"]))+len(set(Statistics_folder[p]["redirecturlunidentified"]))))}\nlinkedinblock:{len(set(Statistics_folder[p]["linkedinblock"]))}\nMicrosoft block:{len(set(Statistics_folder[p]["microsoftblock"]))}\nfacebook bot protection:{len(set(Statistics_folder[p]["fbbot"]))}\nunique redirect url unidentified:{len(set(Statistics_folder[p]["redirecturlunidentified"]))}\ntime out:{len(set(Statistics_folder[p]["timeout"]))}\nmanual inspection:{len(set(Statistics_folder[p]["er0,2,3"]))}\nunique right injection:{len(set(Statistics_folder[p]["rightinjection"]))}\nnot usable oauth flow(fb access token?):{len(set(Statistics_folder[p]["notusableoauth"]))}{Statistics_folder[p]["notusableoauth"]}\nidp blocked attack(github block):{len(set(Statistics_folder[p]["idpblock"]))}{Statistics_folder[p]["idpblock"]}\nidp sanitized:{len(set(Statistics_folder[p]["idpsanitize"]))}{Statistics_folder[p]["idpsanitize"]}\nidp melt:{len(set(Statistics_folder[p]["idpmelt"]))}\nonlyrequest poisoned(idp melt?):{len(set(Statistics_folder[p]["onlyreqpoisoned"]))}\nunique bad injection:{len(set(Statistics_folder[p]["wronginjection"]))}{Statistics_folder[p]["wronginjection"]}\nredirect uri poisoned:{len(set(Statistics_folder[p]["redirecturipoisoned"]))}:{set(Statistics_folder[p]["redirecturipoisoned"])}\nboth request and response poisoned:{len(set(Statistics_folder[p]["bothpoisoned"]))}:{set(Statistics_folder[p]["bothpoisoned"])}\nunique succesfull attack:{len(set(Statistics_folder[p]["succesfulattack"]))}:{set(Statistics_folder[p]["succesfulattack"])}\n')
		print(f'vulnerable statistics folder:{p}\npot vulnerable{len(potvulnerable)}\nidp block:{len(set(Statistics_folder[p]["idpblock"]))} Idps:{IdPinvolved(Statistics_folder[p]["idpblock"])}\nOAuth:{len(oauthflow)}\nidpsanitize:{len(set(Statistics_folder[p]["idpsanitize"]))}sites:{set(Statistics_folder[p]["idpsanitize"])}\nidpmelt:{len(set(Statistics_folder[p]["onlyreqpoisoned"]))+len(set(Statistics_folder[p]["idpmelt"]))}IdPs:{IdPinvolved(Statistics_folder[p]["idpmelt"]+Statistics_folder[p]["onlyreqpoisoned"])}\nsuccessattack:{len(set(Statistics_folder[p]["succesfulattack"]))} Idps:{IdPinvolved(Statistics_folder[p]["succesfulattack"])}\nmissing:{len(missingvulnerable)} idps:{IdPinvolved(missingvulnerable)} site:{missingvulnerable}')
		'''
		var=set(Statistics_folder[p]["succesfulattack"]+Statistics_folder[p]["idpmelt"]+Statistics_folder[p]["onlyreqpoisoned"]+list(missingvulnerable))
		singlesite=[]
		for s in var:
			singlesite.append(GetInfoMeasuremnt(s)[0])
		print(f'\n\nFor table folder:{p}\n#sites vulnerable{len(set(singlesite))}\nsite:{singlesite}\nflows:{var}\n#IdPS:{len(list(IdPinvolved(var).keys()))}\nIdPs:{IdPinvolved(var).keys()}\n\n')
		'''
		#here extract githubsites to find case study:
		vulnidps=list(IdPinvolved(var).keys())
		if("github.com" in vulnidps):
			totalgithubcases[p]=IdPinvolved(var)["github.com"]

	print("first thing is the github cases I need:injection vector and sites:")
	print(f'{totalgithubcases}')
	
	TotalNotcompliantOauthflowsiteali=[]
	for s in set(TotalNotcompliantOauthflow):
		TotalNotcompliantOauthflowsiteali.append(GetInfoMeasuremnt(s)[0])
	TotalvulnOauthflowsiteali=[]
	TotalvulnOauthflowsitealibase=[]
	TotalvulnOauthflowsitealibase.extend(TotalVulnSites)
	TotalvulnOauthflowsitealibase.extend(TotalIdpsMeltingSites)
	for s in set(TotalvulnOauthflowsitealibase):
		TotalvulnOauthflowsiteali.append(GetInfoMeasuremnt(s)[0])
	TotalsanitizeOauthflowsiteali=[]
	for s in set(TotalSanitizeSites):
		TotalsanitizeOauthflowsiteali.append(GetInfoMeasuremnt(s)[0])
	Totalsiteali=[]
	for s in set(Totalsitesvectors):
		Totalsiteali.append(GetInfoMeasuremnt(s)[0])

	print(f'TOTAL sites vectors len:{len(set(Totalsitesvectors))}sites len:{len(Totalsiteali)}\nsites:{Totalsiteali} \nIdPS len:{len(list(IdPinvolved(Totalsitesvectors).keys()))}IdPs:{list(IdPinvolved(Totalsitesvectors).keys())}')
	print(f'total Oauthflow potentially vulnerable:{len(TotalNotcompliantOauthflow)} unique flows len:{len(set(TotalNotcompliantOauthflow))} Sites len:{len(TotalNotcompliantOauthflowsiteali)}\nSites:{TotalNotcompliantOauthflowsiteali}\nflow:{TotalNotcompliantOauthflow}\n unique IdPs:{list(IdPinvolved(TotalNotcompliantOauthflow).keys())}')
	print(f'total Oauthflow vulnerable ali:{len(TotalvulnOauthflowsitealibase)} unique flows len:{len(set(TotalvulnOauthflowsitealibase))} Sites len:{len(TotalvulnOauthflowsiteali)}\nSites:{TotalvulnOauthflowsiteali}\n unique IdPs:{list(IdPinvolved(TotalvulnOauthflowsitealibase).keys())}')
	print(f'total Oauthflow sanitized ali:{len(TotalSanitizeSites)} unique flows len:{len(set(TotalsanitizeOauthflowsiteali))} Sites len:{len(TotalsanitizeOauthflowsiteali)}\nSites:{TotalsanitizeOauthflowsiteali}\n unique IdPs:{list(IdPinvolved(TotalSanitizeSites).keys())}')
	print(f'total idp melting:{len(TotalIdpsMeltingSites)} unique sites:{len(set(TotalIdpsMeltingSites))} Sites:{sorted(set(TotalIdpsMeltingSites))}')
	print(f'total idp sanitize:{len(TotalSanitizeSites)} unique sites:{len(set(TotalSanitizeSites))} Sites:{sorted(set(TotalSanitizeSites))}')
	print(f'total vulnerable:{len(TotalVulnSites)} unique sites:{len(set(TotalVulnSites))} Sites:{sorted(set(TotalVulnSites))}')
	print(f'')

	
	#save redo measurement Initialresult FirstRedo-OBM FirstRedo-IDPP Third-OBM-onlybadmeasur Third-OBM-idpproblem Third-IDPP-onlybadmeasur Third-IDPP-idpproblem
	#create folder for result
	resultfolder=namefolder+"-analisys_result"
	os.makedirs(resultfolder, exist_ok=True)
	
	jsonFile = open(resultfolder+"/"+"Redo_measurement.json", "w+")
	jsonFile.write(json.dumps(Redo_measurement))
	jsonFile.close()

	#save Statistics
	jsonFile = open(resultfolder+"/"+"Statisticsbyidps.json", "w+")
	jsonFile.write(json.dumps(Savestat))
	jsonFile.close()

	#save Gen_leakreport
	jsonFile = open(resultfolder+"/"+"Gen_leakreport.json", "w+")
	jsonFile.write(json.dumps(Gen_leakreport))
	jsonFile.close()
	'''
