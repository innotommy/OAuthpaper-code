import subprocess
from subprocess import PIPE
from subprocess import TimeoutExpired
import urllib.parse
import re,time,json,os,sys,copy
import hashlib


def Identify_SSO_idp(idp,SSO):
	sso=[]
	for i in SSO:
		if i["provider"]==idp:
			sso.append(i)
	return sso

def GenResultFolder(folder):
	#Path output result
	if not os.path.exists(folder):
		os.makedirs(folder)
	else:
		print("directory alredy present do not override")

def UpdateInfo(sites,newinfo,newsites):
	print(f'received this new info:{newinfo}')
	updatedsites=newsites.keys()
	info=newinfo.split("@@@@")
	temp={}
	print(f'infor after split: {info}')
	if(info[0] not in updatedsites):
		print(f'site to be updated: {info[0]}')
		for s in sites:
			if(s["site"]==info[0]):
				#
				temp=copy.deepcopy(s)
				break
		print(f'old site info:{temp}')
		tomodify={}
		#obtain SSO to be modified		
		for l in temp["loginpages"]:
			if(l["loginpage"]==info[1]):
				for i in l["SSOs"]:
					try:
						if(i["tag"] == info[4]):
							tomodify=copy.deepcopy(i)
					except Exception as e:
						if(i["provider"] in info[3]):
							tomodify=copy.deepcopy(i)
							
		#update sso info
		tomodify["provider"]=info[3]
		
		#add to new sites info
		for l in temp["loginpages"]:
			if(l["loginpage"]==info[1]):
				print(f'len sso before:{len(l["SSOs"])}')
				idptempb=','.join(str(x["provider"]) for x in l["SSOs"])
				#print(f'before idps:{idptempb}')
				l["SSOs"]=[]
				l["SSOs"].append(tomodify)
				print(f'len sso after:{len(l["SSOs"])}')
				idptempa=','.join(str(x["provider"]) for x in l["SSOs"])
				print(f'after idps:{idptempa}')
				
		print(f'the new site info:{temp}')
		newsites[info[0]]=temp
	else:
		print(f'\nsite:{info[0]} already in the dictionary')
		save={}
		for s in sites:
			if(s["site"]==info[0]):
				save=copy.deepcopy(s)
				break

		print(f'get old site info:\n{save}\n \nNew info to be added to site:{newinfo}')
		
		#obtain SSO to be updated
		tomodify={}
		for l in save["loginpages"]:
			if(l["loginpage"]==info[1]):
				for i in l["SSOs"]:
					try:
						if(i["tag"] == info[4]):
							tomodify=copy.deepcopy(i)
					except Exception as e:
						if(i["provider"] in info[3]):
							tomodify=copy.deepcopy(i)

		#update info
		tomodify["provider"]=info[3]

		#add info to new site
		temp= newsites[info[0]]
		print(f'old site info:\n{temp}')
		print(f'new SSO:{tomodify}')
		for l in temp["loginpages"]:
			if(l["loginpage"]==info[1]):
				print(f'len sso before:{len(l["SSOs"])}')
				idptempb=','.join(str(x["provider"]) for x in l["SSOs"])
				print(f'before idps:{idptempb}')				
				l["SSOs"].append(tomodify)
				print(f'len sso after:{len(l["SSOs"])}')
				idptempa=','.join(str(x["provider"]) for x in l["SSOs"])
				print(f'after idps:{idptempa}')
		print(f'the new site info:{temp}')
		newsites[info[0]]=temp


if __name__ == "__main__":
	#input experiment: site and login pages
	#output experiment: file site verified for each logipage each idp xpath and 
	sites = json.load(open(sys.argv[1],'r'))
	outputfolder=sys.argv[2]


	Site_analyzed=[]
	Nologinpage=[]
	NoSSOs=[]
	#key site and content site info
	updatedsites=dict()
	#site key and loginpage/idp value
	Missing_Xpath=dict()
	Wrong_SSOelement=dict()
	Syntactical_Wrong_Xpath=dict()
	CrawlerCrash=dict()
	NoActionElement=dict()
	EmptyResult=dict()

	#site key and list of loginpage as value
	Logingpage_unreachable=dict()
	start_time = time.time()

	GenResultFolder(outputfolder)


	for site in sites:
		if(not site['loginpages']):
			print(f'Site{site["site"]} without login pages')
			Nologinpage.append(site["site"])
			continue

		Site_analyzed.append(site["site"])
		for l in site['loginpages']:
			#no SSO move to next login page
			if(len(l["SSOs"])==0):
				NoSSOs.append(site["site"])
				continue
			
			Idp_sso=l["SSOs"]	
			for s in Idp_sso:
				print(f'Test idp:{s["provider"]} on site: {site["site"]} loginpage:{l["loginpage"]}')

				try:
					if("//script" in s["xpath"]):
						continue

					pagehash=hashlib.md5((l["loginpage"]+s["xpath"]).encode('utf-8')).hexdigest()
					namefile=str(site['site'])+"-"+str(pagehash)
				
				except Exception as e:
					
					print("site with no xpath?")
					#key site and login page/idp
					if(site["site"] not in Missing_Xpath.keys()):
						Missing_Xpath[site["site"]]=[]
						Missing_Xpath[site["site"]].append(l["loginpage"]+";"+s["provider"])
					
					else:
						Missing_Xpath[site["site"]].append(l["loginpage"]+";"+s["provider"])
					
					continue
				
				#build parameter file for crawler
				paramfile="paramfile.json"

				paramters={
				"WEBPAGE":l["loginpage"],
				"NameSITE":site["site"],
				"xpath":s["xpath"],
				"name":namefile,
				"outpath":outputfolder,
				"tag":s["tag"]
				}
				print(f'parameters generated:{paramters}')
				time.sleep(2)

				with open(paramfile, 'w') as f:
					json.dump(paramters,f)

				#parameter file
				cmd=["node","verifysites.js"]
				cmd.append("--parameters="+paramfile)

				time.sleep(2)
				#start crawler
				Crawler_subproc = subprocess.Popen(cmd, stdout=subprocess.PIPE,universal_newlines=True)
				print("crawler started")
				time.sleep(3)
				#wait the crawler to terminate and get return code
				crawlresult=-1
				try:
					crawlresult=Crawler_subproc.wait(timeout=120)
				except TimeoutExpired:
					print("crawler blocked kill it and go ahead")
					crawlresult=Crawler_subproc.kill()
				
				print(f'print result Execution(return code subprocess) crawler:{crawlresult}')
				
				outs=Crawler_subproc.stdout
				buff=outs.read()
				print(f'output of crawler:{buff}')
				
				#save crawler output
				with open(namefile+"-crawlerlog.txt", 'w') as f:
					f.write(buff)

				time.sleep(2)
				print(f'before checking crawlresult:{crawlresult}')
				if(crawlresult==104):
					print("result of crawler succesfull")
					#update site info:		
					with open(outputfolder+"/"+namefile+"-updateinfo.txt",'r') as f:
						newinfo=f.read()
					print(f'new info obtained by the crawler:{newinfo}')

					UpdateInfo(sites,newinfo,updatedsites)

				elif(crawlresult==102):
					print("xpath not producing any action discard element")

					if(site["site"] not in NoActionElement.keys()):
						NoActionElement[site["site"]]=[]
						NoActionElement[site["site"]].append(l["loginpage"]+";"+s["provider"])
					else:
						NoActionElement[site["site"]].append(l["loginpage"]+";"+s["provider"])
				


				elif(crawlresult==107):
					print("search xpath fail no element found wrong xpath")
					#EmptyResult
					if(site["site"] not in EmptyResult.keys()):
						EmptyResult[site["site"]]=[]
						EmptyResult[site["site"]].append(l["loginpage"]+";"+s["provider"])
					else:
						EmptyResult[site["site"]].append(l["loginpage"]+";"+s["provider"])
				


				elif(crawlresult==106):
					print("search xpath fail syntactically wrong xpath")

					if(site["site"] not in Syntactical_Wrong_Xpath.keys()):
						Syntactical_Wrong_Xpath[site["site"]]=[]
						Syntactical_Wrong_Xpath[site["site"]].append(l["loginpage"]+";"+s["provider"])
					else:
						Syntactical_Wrong_Xpath[site["site"]].append(l["loginpage"]+";"+s["provider"])
				

				elif(crawlresult==101):
					print(f'login page unreachable')

					if(site["site"] not in Logingpage_unreachable.keys()):
						Logingpage_unreachable[site["site"]]=[]
						Logingpage_unreachable[site["site"]].append(l["loginpage"]+";"+s["provider"])
					else:
						Logingpage_unreachable[site["site"]].append(l["loginpage"]+";"+s["provider"])
				
				elif(crawlresult==105):
					print("manually anlyze this site because of crawler error")

					if(site["site"] not in CrawlerCrash.keys()):
						CrawlerCrash[site["site"]]=[]
						CrawlerCrash[site["site"]].append(l["loginpage"]+";"+s["provider"])
					else:
						CrawlerCrash[site["site"]].append(l["loginpage"]+";"+s["provider"])

				elif(crawlresult==103):
					print("no oauth parameters in redirection link after click")
					
					if(site["site"] not in Wrong_SSOelement.keys()):
						Wrong_SSOelement[site["site"]]=[]
						Wrong_SSOelement[site["site"]].append(l["loginpage"]+";"+s["provider"])
					else:
						Wrong_SSOelement[site["site"]].append(l["loginpage"]+";"+s["provider"])
				
				#move file to experiment folder
				os.rename(namefile+"-crawlerlog.txt", outputfolder+"/"+namefile+"-crawlerlog.txt")
				
				print("browser ready for next measurement")
				time.sleep(2)
	
	#print new info site
	output_name=outputfolder+"/"+"Result-newinfo.json"
	File = open(output_name, "w+")
	File.write(json.dumps(updatedsites))
	File.close()

	with open(outputfolder+"/"+"Result-NoSSos.txt", 'w') as f:
		for s in range(len(NoSSOs)):
			f.write(str(NoSSOs[s])+"\n")

	with open(outputfolder+"/"+"Result-Nologinpage.txt", 'w') as f:
		for s in range(len(Nologinpage)):
			f.write(str(Nologinpage[s])+"\n")
			
	#print problem site
	output_name=outputfolder+"/"+"Result-Missing_Xpath.json"
	File = open(output_name, "w+")
	File.write(json.dumps(Missing_Xpath))
	File.close()

	#print problem site
	output_name=outputfolder+"/"+"Result-Wrong_SSOelement.json"
	File = open(output_name, "w+")
	File.write(json.dumps(Wrong_SSOelement))
	File.close()

	#print problem site
	output_name=outputfolder+"/"+"Result-Syntactical_Wrong_Xpath.json"
	File = open(output_name, "w+")
	File.write(json.dumps(Syntactical_Wrong_Xpath))
	File.close()

	#print crash crawler site
	output_name=outputfolder+"/"+"Result-CrawlerCrash.json"
	File = open(output_name, "w+")
	File.write(json.dumps(CrawlerCrash))
	File.close()

	#EmptyResult
	#print not oauth element
	output_name=outputfolder+"/"+"Result-EmptyResult.json"
	File = open(output_name, "w+")
	File.write(json.dumps(EmptyResult))
	File.close()

	#print not oauth element
	output_name=outputfolder+"/"+"Result-NoActionElement.json"
	File = open(output_name, "w+")
	File.write(json.dumps(NoActionElement))
	File.close()	

	#print problem site
	output_name=outputfolder+"/"+"Result-Logingpage_unreachable.json"
	File = open(output_name, "w+")
	File.write(json.dumps(Logingpage_unreachable))
	File.close()
	
	
	save=list(updatedsites.values())
	print("save updated site analyzed")
	output_name="Verified_Sites.json"
	File = open(output_name, "w+")
	File.write(json.dumps(save))
	File.close()

	#extract top IdPs from file generated
	sites = json.load(open(output_name,'r'))

	Site_analyzed=[]
	IDP=dict()

	for site in sites:
		if(not site['loginpages']):
			continue
		for l in site['loginpages']:
			#no SSO move to next login page
			if(len(l["SSOs"])==0):continue

			for s in l["SSOs"]:
				if(s["provider"] not in IDP.keys()):
					IDP[s["provider"]]=[site["site"]]
				else:
					if(site["site"]not in IDP[s["provider"]]):
						IDP[s["provider"]].append(site["site"])
					else:
						continue

	arranged=sorted(IDP, key=lambda k: len(IDP[k]), reverse=True)
	for k in arranged:
		print(f'idp:{k}\n{IDP[k]}')
	with open("Top_Idps.json",'w') as f:
		for i in arranged:
			#only IdPs with more than 3 sites are considered
			if(len(IDP[i])>3):
				t={"idp":i,"sites":IDP[i]}
				json.dump(t,f)

