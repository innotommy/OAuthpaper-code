from mitmproxy.net.http.http1.assemble import assemble_request
import sys,typing,os
import urllib.parse
from urllib.parse import urlparse
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import types

class PathConfString:
    Keywords=[]
    LinkPrefix=[]

    def load(self, loader):
        loader.add_option(
            name = "inject",
            typespec = str,
            default =  "",
            help = "Provide the pathconfusion string",
        )

        loader.add_option(
            name = "linkprefix0",
            typespec = str,
            default =  "",
            help = "link prefix where to inject the path confusion",
        )

        loader.add_option(
            name = "linkprefix1",
            typespec = str,
            default =  "",
            help = "link prefix where to inject the path confusion",
        )

        loader.add_option(
            name = "counter",
            typespec = int,
            default =  1,
            help = "Define how many request modify",
        )

        loader.add_option(
            name = "keywords0",
            typespec = str,
            default =  "",
            help = "keyword to identify network reqest to modify",
        )

        loader.add_option(
            name = "keywords1",
            typespec = str,
            default =  "",
            help = "keyword to identify network reqest to modify",
        )

        loader.add_option(
            name = "keywords2",
            typespec = str,
            default =  "",
            help = "keyword to identify network reqest to modify",
        )

        loader.add_option(
            name = "keywords3",
            typespec = str,
            default =  "",
            help = "keyword to identify network reqest to modify",
        )

        loader.add_option(
            name = "keywords4",
            typespec = str,
            default =  "",
            help = "keyword to identify network reqest to modify",
        )

        loader.add_option(
            name = "idphostname",
            typespec = str,
            default =  "",
            help = "hostname of idp to be intercepted and modified",
        )


    def checkurlkeywords(self,flow):
        self.Keywords.append(ctx.options.keywords0)
        self.Keywords.append(ctx.options.keywords1)
        self.Keywords.append(ctx.options.keywords2)
        self.Keywords.append(ctx.options.keywords3)
        self.Keywords.append(ctx.options.keywords4)

        self.Keywords=list(filter(None, self.Keywords))
        
        for i in self.Keywords:
            if i not in flow.request.url:
                return False

        return True

    def checkurlprefix(self,flow):
        self.LinkPrefix.append(ctx.options.linkprefix0)
        self.LinkPrefix.append(ctx.options.linkprefix1)

        self.LinkPrefix=list(filter(None, self.LinkPrefix))
        
        found=False
        for i in self.LinkPrefix:
            if i in flow.request.url:
                found=True
        
        if found: return True
        return False


    def request(self,flow):
        print("inspecting request", file=sys.stdout)
        if ctx.options.counter<=0:return
        
        if flow.request.method.strip().upper() == 'GET':
            checkurl = urlparse(flow.request.url)
            #inspect only request with the IDP as domain
            if(ctx.options.idphostname in checkurl.hostname):
                print("request with idphostname", file=sys.stdout)
                #check request with the right prefix
                if not self.checkurlprefix(flow): return

                print(f'found link with rightprefix: {flow.request.url}',file=sys.stdout)
                #check request url with the right keywords
                if not self.checkurlkeywords(flow): return 
                
                print("found a good candidate request to modify", file=sys.stdout)
                
                ctx.options.counter-=1
                if ctx.options.counter>=1:
                    print("first request ignore it",file=sys.stdout)
                    return

                multi_cmd=False
                if("+" in ctx.options.inject):multi_cmd=True
                #modify last w remove it or attach
                if("mdf" in ctx.options.inject and "lw" in ctx.options.inject):
                    #modify last word of redirect uri
                    b=flow.request.url.find("redirect_uri")
                    f=flow.request.url.find("&",b)
                    if(f>0):
                        #find next param or end of string
                        print(f'f greather than 0 so internal param', file=sys.stdout)
                        ret=flow.request.url[b+13:f]
                    else:
                        ret=flow.request.url[b+13:]
                    print(f'extracted redirect uri: {ret}', file=sys.stdout)
                    #search / or %2f from end of redirect_uri
                    cut=ret.rfind("/")
                    if(cut<0):
                        cut=ret.rfind('%2f')
                        if(cut<0):
                            cut=ret.rfind('%2F')
                            if(cut<0):
                                print("not able to find / or %2f or %2F",file=sys.stdout)
                                return
                    #modify word if larger than mod requested
                    mod=4
                    if(len(ret)-cut>mod):
                        t=len(ret)-mod
                        print(f'extracted string to capitalize: {ret[t:]}',file=sys.stdout)
                        up=ret[t:].upper()
                        print(f'upper string:{up}',file=sys.stdout)
                        new=ret[:t]+up
                        print(f'temp string modified with replace: {new}', file=sys.stdout)
                        temp=flow.request.url
                        bb=temp.replace(ret,new)
                        flow.request.url=bb
                        return
                    else:
                        print(f'world shorter: {len(ret)-cut} than mod requested {mod}',file=sys.stdout)
                        return
                elif("rm" in ctx.options.inject and "lw" in ctx.options.inject):
                    #modify last word of redirect uri
                    b=flow.request.url.find("redirect_uri")
                    f=flow.request.url.find("&",b)
                    if(f>0):
                        ret=flow.request.url[b+13:f]
                    else:
                        ret=flow.request.url[b+13:]
                    #search / or %2f from end of redirect_uri
                    cut=ret.rfind("/")
                    if(cut<0):
                        encut=ret.rfind('%2f')
                        if(encut<0):
                            encut=ret.rfind('%2F')
                            if(encut<0):
                                print("not able to find / or %2f",file=sys.stdout)
                                return
                    #remove last word
                    print(f'ret string:{ret} len: {len(ret)}',file=sys.stdout)
                    if(cut<0):
                        print(f'found separator at position {encut} string from cut on {ret[encut:]} before cut {ret[:encut]}')
                    else:
                        print(f'found separator at position {cut} string from cut on {ret[cut:]} before cut {ret[:cut]}')

                    if(cut<0):
                        #means I found the encoded add 3 to keep / encoded
                        new=ret[:encut]
                    else:
                        #normal char #add 1 to keep /
                        new=ret[:cut]

                    temp=flow.request.url
                    bb=temp.replace(ret,new)
                    flow.request.url=bb
                    print(f'temp string modified with replace: {new}', file=sys.stdout)
                    print(f'new temporary url: {flow.request.url}', file=sys.stdout)

                    if(not multi_cmd):return
                    else:second=ctx.options.inject.split("+")[1]

                    print("at this point removed last word plus attach attack",file=sys.stdout)
                    print("attach pathconfusion",file=sys.stdout)
                    
                    b=flow.request.url.find("redirect_uri")
                    f=flow.request.url.find("&",b)

                    if(f>0):
                        #find next param or end of string
                        print(f'f greather than 0 so internal param', file=sys.stdout)
                        ret=flow.request.url[b+13:f]
                    else:
                        ret=flow.request.url[b+13:]
                    print(f'extracted redirect uri: {ret}', file=sys.stdout)
                    
                    #try use lib to concatenate pathconfusion
                    test1=urllib.parse.unquote(ret)
                    print(f'test url unquoted: {test1}', file=sys.stdout)
                    test=urlparse(test1)
                    testpath=test.path
                    print(f'test path extracted: {testpath}', file=sys.stdout)
                    print(f'used second as inject string: {second}',file=sys.stdout)
                    newpath=testpath+second
                    print(f'new path generated: {newpath}', file=sys.stdout)
                    newurl=test._replace(path=newpath).geturl()
                    print(f'new url generated(unquoted): {newurl}', file=sys.stdout)
                    quotedurl=urllib.parse.quote(newurl, safe='')
                    print(f'new url generated(quoted): {quotedurl}', file=sys.stdout)
                    
                    temp=flow.request.url
                    print(f'temp string: {temp}', file=sys.stdout)
                    new=temp.replace(ret,quotedurl)
                    print(f'temp string modified with replace: {new}', file=sys.stdout)
                    flow.request.url=new

                else:
                    print("only attach the pathconfusion string",file=sys.stdout)

                    b=flow.request.url.find("redirect_uri")
                    f=flow.request.url.find("&",b)
                    g=flow.request.url.find('%3F',b)

                    if(f<g or (g==-1)):
                        print(f'& is before %3F or %3F is not present', file=sys.stdout)
                        if(f>0):
                            #find next param or end of string
                            print(f'f greather than 0 so internal param', file=sys.stdout)
                            ret=flow.request.url[b+13:f]
                        else:
                            ret=flow.request.url[b+13:]
                    else:
                        print(f'in this case %3F is present and it is before & pos%3F:{g} pos&:{f}', file=sys.stdout)
                        print(f'g greather than 0 so internal param', file=sys.stdout)
                        ret=flow.request.url[b+13:g]

                        
                    print(f'extracted redirect uri: {ret}', file=sys.stdout)
                    #try use lib to concatenate pathconfusion
                    #test1=urllib.parse.unquote(ret)
                    test1=ret
                    print(f'test url unquoted: {test1}', file=sys.stdout)
                    test=urlparse(test1)
                    testpath=test.path
                    print(f'test path extracted: {testpath}', file=sys.stdout)
                    newpath=testpath+ctx.options.inject
                    print(f'new path generated: {newpath}', file=sys.stdout)
                    newurl=test._replace(path=newpath).geturl()
                    print(f'new url generated used for injection(unquoted): {newurl}', file=sys.stdout)
                    quotedurl=urllib.parse.quote(newurl, safe='')
                    print(f'new url generated(quoted): {quotedurl}', file=sys.stdout)
                    
                    temp=flow.request.url
                    print(f'temp string: {temp}', file=sys.stdout)
                    
                    new=temp.replace(ret,newurl)
                    print(f'temp string modified with replace: {new}', file=sys.stdout)
                    flow.request.url=new


addons = [
    PathConfString()
]







