import subprocess 
from subprocess import PIPE
from subprocess import TimeoutExpired
import urllib.parse
import re,time,json,os,sys
import hashlib


def Identify_SSO_idp(idp,SSO):
	sso=[]
	for i in SSO:
		if i["provider"]==idp:
			sso.append(i)
	return sso


if __name__ == "__main__":
	#input experiment:Login pages, IDP to test,output folder
	sites = json.load(open(sys.argv[1],'r'))
	outputfolder=sys.argv[2]
	Pathconf=json.load(open(sys.argv[3]))
	keyword_Pathconf=json.load(open(sys.argv[4]))
	Idp_info=json.load(open(sys.argv[5]))
	measurement= "pathconfusion-fixsitesaddremove3"

	#for each site obatin SSO and modify it,run MITM proxy,Run login crawler.

	Site_analyzed=[]
	restart=False
	start_time = time.time()
	#Path output result
	main_path=outputfolder
	if not os.path.exists(main_path):
		os.makedirs(main_path)
	else:
		print("directory alredy present do not override")

#for each pathc conf
	for p in Pathconf:
		print(f'start analyze pathconfusion:{Pathconf[p]}')
		#Path output pathconfusion
		gen_path=main_path+"/"+p
		if not os.path.exists(gen_path):
			os.makedirs(gen_path)
		else:
			print("directory alredy present do not override")

		Site_analyzed=[]
		fractionate=0
		for site in sites:
			if(not site['loginpages']):
				print(f'Site{site["site"]} without login pages')
				continue
			#use to space measurement
			fractionate+=1
			for l in site['loginpages']:
				#no SSO move to next login page
				if(len(l["SSOs"])==0):continue
				print(f'Test path confusion {p} for idp:{l["SSOs"][0]["provider"]} on site: {site["site"]}')
				
				accIdP=[]
				for k in l["SSOs"]:
					if(k["provider"]not in accIdP):
						accIdP.append(k["provider"])
				
				Idp_sso=[]
				for a in accIdP:
					Idp_sso.extend(Identify_SSO_idp(a,l["SSOs"]))
					
				if(Idp_sso==[]):continue
				for s in Idp_sso:
					refineidp=s["provider"]
					Idp=refineidp
					commands=[]
					pagehash=hashlib.md5((l["loginpage"]+s["xpath"]).encode('utf-8')).hexdigest()
					namefile=str(site["site"])+"-"+str(s["provider"])+"-"+str(pagehash)

					if(s["provider"]not in Idp_info.keys()):
						print(f'Provider {s["provider"]} not included skipß it')
						with open(gen_path+"/"+namefile+"-crawlerlog.txt", 'w') as f:
							f.write("IDP not implemented!!!\nRESULT-EXPERIMENT:-1")
						continue

					if(s["provider"]not in keyword_Pathconf.keys()):
						print(f'Provider {s["provider"]} not included in idps keywords skip it')
						with open(gen_path+"/"+namefile+"-crawlerlog.txt", 'w') as f:
							f.write("Keywords of IDP not present!!!\nRESULT-EXPERIMENT:-1")
						continue
					
					print(f'Testing site:{site["site"]} idp:{s["provider"]} and path confusion:{Pathconf[p]} in login page: {l["loginpage"]}')
					Site_analyzed.append(namefile)

					#build string for mitmproxy
					cmd=["mitmdump","--set","listen_port=7777",
						"--set","http2=false",
						"-s","tamper_http_header-path_conf.py"]
					
					stream="save_stream_file="+namefile+"-stream"
					cmd.append("--set")
					cmd.append(stream)
					
					Idp_keywords=keyword_Pathconf[refineidp]["Keywords"]
					Idp_url_prefix=keyword_Pathconf[refineidp]["Url_Prefix"]

					
					for k in range(len(Idp_keywords)):
						cmd.append("--set")
						cmd.append("keywords"+str(k)+"="+str(Idp_keywords[k]))
					cmd.append("--set")
					cmd.append("inject="+str(Pathconf[p]))
					for r in range(len(Idp_url_prefix)):
						cmd.append("--set")
						cmd.append("linkprefix"+str(r)+"="+str(Idp_url_prefix[r]))
					
					cmd.append("--set")
					cmd.append("idphostname="+str(keyword_Pathconf[refineidp]["idphostname"]))

					print(cmd)
					#save command
					commands.append("command for proxy:")
					commands.append(cmd)

					#start proxy
					Proxy_subproc = subprocess.Popen(cmd, stdout=subprocess.PIPE,universal_newlines=True)
					print("proxy started")
					
					time.sleep(2)
					#build parameter file for crawler
					paramfile="paramfile.json"
					paramters={
					"site":l["loginpage"],
					"idp": Idp,
					"measurement": measurement,
					"idp_info":Idp_info[Idp],
					"xpath":s["xpath"],
					"name":namefile,
					"outpath":gen_path+"/"
					}

					#save params
					commands.append("parameters for crawler:")
					commands.append(paramters)
					
					with open(paramfile, 'w') as f:
						json.dump(paramters,f)

					#parameter file
					cmd=["node","Pup-Crawler.js"]
					cmd.append("--parameters="+paramfile)

					#save command
					commands.append("command for crawler:")
					commands.append(cmd)
					#save command used for the experiment
					with open(namefile+"-commands.txt", 'w') as f:
						for c in commands:
							f.write(str(c))
							f.write('\n')
					
					#wait to let proxy be ready
					time.sleep(2)
					
					#start crawler
					Crawler_subproc = subprocess.Popen(cmd, stdout=subprocess.PIPE,universal_newlines=True)
					print("crawler started")

					#wait the crawler to terminate and get return code
					try:
						crawlresult=Crawler_subproc.wait(timeout=120 )
					except TimeoutExpired:
						print("crawler blocked kill it and go ahead")
						crawlresult=Crawler_subproc.kill()
					print(f'print result crawler:{crawlresult}')
					outs=Crawler_subproc.stdout
					buff=outs.read()
					print(f'output of crawler:{buff}')
					#save crawler output
					with open(namefile+"-crawlerlog.txt", 'w') as f:
						f.write(buff)

					time.sleep(2)
					proxyresult = Proxy_subproc.terminate()
					print(f'print result PROXY:{proxyresult}')
				   #obtain proxy log
					outs=Proxy_subproc.stdout
					buff=outs.read()
					print(f'output proxy:{buff}')

					#save mitm files
					with open(namefile+"-proxylog.txt", 'w') as f:
						f.write(buff)

					#move file to experiment folder
					try:
						os.rename(namefile+"-crawlerlog.txt", gen_path+"/"+namefile+"-crawlerlog.txt")
						os.rename(namefile+"-proxylog.txt", gen_path+"/"+namefile+"-proxylog.txt")
						os.rename(namefile+"-stream", gen_path+"/"+namefile+"-stream")
						os.rename(namefile+"-commands.txt", gen_path+"/"+namefile+"-commands.txt")
					except Exception as e:
						print(f'exception with this measurement go ahead!!!')
					

					print("browser and proxy ready for next measurement")
					#time.sleep(90)
					time.sleep(30)
			
			#change this to modify fraction of site of each stint
			if(fractionate%35==0):
				#save snapshot of sites analyzed and wait for next trance of sites to analyze
				print("save temporary snapshot sites analyzed")
				with open(gen_path+"/"+p+"-Target[temporary-snapshot].txt", 'a') as f:
					for s in range(len(Site_analyzed)):
						if s==len(Site_analyzed)-1:
							f.write(str(Site_analyzed[s])+"\n")
						else:
							f.write(str(Site_analyzed[s])+"\n")
				#wait 3hr between trance of sites
				#time.sleep(10800)
				time.sleep(30)

		#save site analyzed
		print("save site analyzed")
		with open(gen_path+"/"+p+"-Target.txt", 'a') as f:
			for s in range(len(Site_analyzed)):
				if s==len(Site_analyzed)-1:
					f.write(str(Site_analyzed[s])+"\n")
				else:
					f.write(str(Site_analyzed[s])+"\n")
		#remove snapshot of file if present
		if os.path.exists(gen_path+"/"+p+"-Target[temporary-snapshot].txt"):
			os.remove(gen_path+"/"+p+"-Target[temporary-snapshot].txt")

		#wait before next pathconfusion experiment
		print("wait between one path confusion and the other pathconfusion vector")
		time.sleep(30)
		#time.sleep(180)
