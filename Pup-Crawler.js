const puppeteer = require('puppeteer');
const FS = require('fs');
const TLDJS = require('tldjs');
const ArgParse = require('argparse');

let SITE = null;
let IDP = null;
let IDP_Info = {};
let XPathSSOElem=null;
let newwindow=false;
let measurement="";

function parseArguments() {
    let parser = new ArgParse.ArgumentParser({
      add_help:true,
      description: 'Argparse example'
    });

    parser.add_argument(
      '--parameters',
      {
        action: 'store',
        required: true,
        help: 'parameters file'
      }
    );

    let args = parser.parse_args();
    PARAMETER= args.parameters;
}

async function Exception(page,commands,step){
    console.log("exception received commands: %s",commands);
    instructions=commands.split('##');
    console.log("instructions lenght:%s",instructions.length);
    console.log(instructions);
    try {
        for (var i = 0; i < instructions.length; i++) {
            console.log("Analyze instruction:%s",instructions[i]);
            if(instructions[i].includes("sleep") && !(instructions[i].includes("%%"))){
                console.log("wait for next instruction:%s",instructions[i]);
                await page.waitForTimeout(Number(instructions[i].replace("sleep",""))*1000);
            }
            else{
                if(instructions[i].includes("%%")){
                    split=instructions[i].split("%%");
                    //first command type second id type third id
                    if(split[0]==="fill"){
                        await Fillform(page,split[1],split[2],split[3]);
                    }
                    else if(split[0]==="click"){
                        await Click_Button(page,split[1],split[2],split[3]);
                    }
                }
                else{
                    console.log("execute next instruction:%s",instructions[i]);
                await page.evaluate(instructions[i]);    
                }
            }
        }
    } catch (ex) {
        console.log("Step: %s Exception in execution of instruction: %s",step,commands);
        return ex.message;
    }
    return true;
}


async function Fillform(page,form_type,form,content){
    //include try catch for node not found and report error
    console.log("Fill form received form type: %s\nform: %s\ncontent: %s",form_type,form,content);
    try {
        if(form_type==="ID"){
            await page.type("[id=\""+form+"\"]",content, { delay: 100 });
            return true;
        }
        else if(form_type==="Name"){
            await page.type("[name=\""+form+"\"]",content, { delay: 100 });
            return true;
        }
        else if(form_type==="ClassName"){
            await page.type("[class=\""+form+"\"]",content, { delay: 100 });
            return true;
        }
        else if(form_type==="exception"){
            return form;
        }
    } catch (ex) {
        console.log("Exception in Filling form: %s and content: %s",form,content);
        console.log(ex);
        return false;
    }    
}

async function Click_Button(page,button_type,button,step){
    console.log("Click Button received button type: %s\nbutton: %s\nstep: %s",button_type,button,step);
    try {
        if(button_type==="XPath"){
            console.log("Click_Button with XPath element");
            var elements = await page.$x(button);
            console.log("obtained this element:%s",elements);
            pr=await elements[0].click();
            console.log("result click: %s",pr);
            return true;
        }
        else if(button_type==="ID"){
            console.log("Click_Button with ID element");
            pr=await page.click("[id=\""+button+"\"]");
            console.log("result click: %s",pr);
            return true;
        }
        else if(button_type==="Classname"){
            console.log("Click_Button with ClassName element");
            pr=await page.click("[class=\""+button+"\"]");
            console.log("result click: %s",pr);
            return true;
        }
        else if(button_type==="Name"){
            console.log("Click_Button with Name element");
            pr=await page.click("[name=\""+button+"\"]");
            console.log("result click: %s",pr);
            return true;
        }
        else if(button_type==="QuerySelector"){
            console.log("Click_Button with QuerySelector element");
            pr=await page.click(button);
            console.log("result click: %s",pr);
            return true;
        }
        else if(button_type==="exception"){
            return Exception(page,button,step);
            //return button;
        }
    } catch (ex) {
        if(step==="Grant"){
            console.log(ex.message);
            console.log("received an error during grant click. Continue the measurement and check if sproper redirect and closed window");
            return true;
        }
        else{
            console.log("Step: %s Exception in execution!!!!!",step);
            console.log(ex.message);
            return ex.message;
        }
    }
}

async function FindIdentifies(html) {
    var identifiers=["Mario Rossi","Mario","Rossi","mario","rossi","mario rossi","tommycall.text@gmail.com","tommycall.text"];
    var arrayLength = identifiers.length;
    for (var i = 0; i < arrayLength; i++) {
        let res = html.search(identifiers[i])
        if(res >0){
            console.log("identifier found");
            console.log(identifiers[i]);
            return true;
        }
    }
    //search for identifies in html
    return false;
}

async function Savehtml(name,html){
    //save file with HTML
    FS.writeFileSync(name+"-HTMLWithID",html);
}

async function ErrorInURL(checkURL) {
    //search for erorr in URL
    //expand error in url to make it complete
    var identifiers=["error","fail"];
    var arrayLength = identifiers.length;
    for (var i = 0; i < arrayLength; i++) {
        let res = checkURL.search(identifiers[i])
        if(res >0){
            console.log("error found in url");
            console.log(identifiers[i]);
            console.log(checkURL);
            return true;
        }
    }
    return false;
}

async function ObtainSelector(type,string){
    //console.log("obtain selector received type: %s\nString: %s",type,string);
    if(type==="exception"){
        instructions=string.split('##');
        for (var i = 0; i < instructions.length; i++) {
            if(instructions[i].includes("fill")){
                div=instructions[i].split('%%');
                temp= await ObtainSelector(div[1],div[2]);
                return temp;
            }
        }
        return "";
    }
    else if(type==="Name"){
        return "[name=\""+string+"\"]";
    }
    else if(type==="ID"){
        return "[id=\""+string+"\"]";
    }
    else if(type==="ClassName"){
        return "[class=\""+string+"\"]";
    }
    return "";
}

async function AnalizeResult(browser,IDP,domainbegin,initial_url,domainreturn,return_url,html,measurement){
    console.log("analyze result measurement:");
    
    if(domainreturn===IDP){
        //blocked in login part
        console.log("login procedure stopped in IDP!!!");
        console.log("RESULT-EXPERIMENT:-1");
        return -1;        
    }
    else{
        let verify=await FindIdentifies(html);
        if(verify){
            Savehtml(OutputPath+OutputName,html);
            console.log("found identifiers in the redirection page");
            console.log("domain return:%s Domain begin:%s",domainreturn,domainbegin);
            if(domainreturn === domainbegin){//back to the same domain of initial page 
                if(return_url === initial_url){
                    console.log("same url after login succesful login!!!");
                    console.log("RESULT-EXPERIMENT:1");
                    return 1;
                }
                else{
                    let check= await ErrorInURL(return_url);
                    console.log("print check url error:%s",check);
                    if(check){
                        //error in url not succesful
                        console.log("found identifier in page but error in redirect url-->visual check!!!");
                        console.log("RESULT-EXPERIMENT:-1");
                        return -1;
                    }
                    else{
                        console.log("success login redirect to initial domain with identifiers in the page");
                        console.log("RESULT-EXPERIMENT:1");
                        return 1;
                    }
                }
            }
            else{
                //diff domain but identifiers in html look for error in url
                let check= await ErrorInURL(return_url);
                console.log("print check url error:%s",check);
                if(check){
                    //error in url not succesful
                    console.log("found identifier in page but redirect to a different domain and error in redirect url-->visual check!!!");
                    console.log("RESULT-EXPERIMENT:-1");
                    return -1;
                }
                else{
                    console.log("redirect to a different domain with identifiers in page and no error check for connected domain!!");
                    console.log("domain return:%s Domain begin:%s",domainreturn,domainbegin);
                    console.log("RESULT-EXPERIMENT:0");
                    return 1;
                }
            }
        }
        else{
            console.log("NOT found identifiers in the redirection page");
            console.log("domain return:%s Domain begin:%s",domainreturn,domainbegin);
            if(domainreturn === domainbegin){//back to the same domain of initial page 
                if(return_url === initial_url){
                    console.log("success login redirect to initial link but identifiers not found in the page->visual check!!!");
                    console.log("RESULT-EXPERIMENT:0");
                    return 0;
                }
                else{
                    let check= await ErrorInURL(return_url);
                    console.log("print check url error:%s",check);
                    if(check){
                        console.log("no identifiers in page redirect to a different page with error in redirect url");
                        console.log("RESULT-EXPERIMENT:-1");
                        return -1;
                    }
                    else{
                        console.log("success login redirect to same domain of initial page no error in url but identifiers not found in the page->visual check!!!");
                        console.log("RESULT-EXPERIMENT:0");
                        return 0;
                    }
                }
            }
            else{
                console.log("redirect to different domain and no identifiers in page not succesful login!!");
                console.log("RESULT-EXPERIMENT:-1");
                return -1;
            }
        }    
    }
}

async function AnalizeResult_New_Window(browser,IDP,page,newwindow,domainbegin,initial_url,measurement){

    console.log("New windows: measurement:%s analyze result received:initial_url:%s\ndomain begin:%s",measurement,initial_url,domainbegin);
    urlcheck=page.url();

    if(urlcheck.includes("#")){
        urlcheck=urlcheck.split("#")[0];
        console.log("remove fragment to make a right comparison new url is:%s",urlcheck);
    }
    console.log("page url extracted from page variable:%s",urlcheck);
    console.log("print variables used for the check:page url%s\nIDP:%s",page.url(),IDP);
    if(urlcheck===initial_url && TLDJS.parse(newwindow.url()).domain===IDP){
        //take screenshot of still open window and stop here error in login!!
        console.log("initial page with the same url and new windows stuck with IDP");
        await newwindow.screenshot({path: OutputPath+OutputName+"_StillOpenWindow_AfterSSOLogin.png" ,fullPage: true});
        var html=await page.content();
        let verify=await FindIdentifies(html);

        if(verify){
            Savehtml(OutputPath+OutputName,html);
            console.log("login window still open check why!!!!");
            console.log("success login redirect to initial domain with identifiers in the page");
            console.log("RESULT-EXPERIMENT:1");
            await browser.close();
            process.exit(1);
        }
        else{
            console.log("new windows still open no identifiers in initial window and no redirection in initial page error in login procedure!!");
            await browser.close();
            console.log("RESULT-EXPERIMENT:-1");
            process.exit(-1);    
        }
    }
    else if(urlcheck===initial_url && TLDJS.parse(newwindow.url()).domain===domainbegin){
        //redirected to initial domain in new window check that window
        console.log("redirected to the initial site domain in the new window, analyze this windows for the result");
        var html=await newwindow.content();
        return_url= await newwindow.url();
        domainreturn= await TLDJS.parse(return_url).domain;

        await AnalizeResult(browser,IDP,domainbegin,initial_url,domainreturn,return_url,html,measurement);
    }
    else if(!(urlcheck===initial_url)){
    //still open new window but not initial url check error and identifiers
    let return_url=page.url();
    let check= await ErrorInURL(return_url);
        console.log("print check url error:%s",check);
        if(check){
            console.log("login windows still open check why!! and error in redirect url-->visual check!!!");
            await browser.close();
            console.log("RESULT-EXPERIMENT:-1");
            process.exit(-1);
        }
        else{
            var html=await page.content();
            let verify=await FindIdentifies(html);
            if(verify){
                Savehtml(OutputPath+OutputName,html);
                console.log("login window still open check why!!!!");
                console.log("success login identifiers in initial page");
                console.log("RESULT-EXPERIMENT:1");
                await browser.close();
                process.exit(1);
            }
            else{
                console.log("new windows still open no identifiers in initial page no error but redirected to a different page -->visual check");
                await browser.close();
                console.log("RESULT-EXPERIMENT:-1");
                process.exit(-1);
            }
        }
    }
}



(async() => {
    console.log("Step1 get info for the crawler");
    parseArguments();
    let rawdata = FS.readFileSync(PARAMETER);
    let params = JSON.parse(rawdata);
    SITE = params["site"];
    IDP = params["idp"];
    measurement =params["measurement"];
    IDP_Info = params["idp_info"];
    XPathSSOElem = params["xpath"];
    OutputName = params["name"];
    OutputPath = params["outpath"];
    console.log("Measurements: %s\nparameters received site: %s\nIDP: %s\nIDP_Info: %s\nXPathSSOelem: %s\nOutputpath: %s\nOutputName: %s",measurement,SITE,IDP,IDP_Info,XPathSSOElem,OutputPath,OutputName);


    //Step2: surf on the login page save initial page url then take a screenshot and then click in the SSO element
    console.log("Step2:start the login procedure")
    //start browser
    //'--proxy-server=http://127.0.0.1:7777',
    const browser = await puppeteer.launch({args:['--disable-gpu',
            '--no-sandbox',
            '--disable-popup-blocking',
            '--disable-notifications',
            '--password-store=basic',
            '--proxy-server=http://127.0.0.1:7777',
            '--ignore-certificate-errors'],
            headless: false,
            executablePath: '/bin/google-chrome-stable'});
    const page = await browser.newPage();
    try{
        await page.goto(SITE, {timeout:120000, waitUntil: 'networkidle2'});
    }catch(ex){
        console.log("error in surfing to the login page!ABORT-EXPERIMENT:YES");
        console.log(ex);
        await browser.close();
        process.exit(1);
    }
    let initial_url=page.url();
    if(initial_url.includes("#")){
        console.log("remove fragment from initial url: %s",initial_url);
        initial_url=initial_url.split("#")[0];
        console.log("new url: %s",initial_url);
    }

    var domainbegin = TLDJS.parse(initial_url).domain;
    await page.waitForTimeout(5000);
    
    //take screenshot
    await page.screenshot({path: OutputPath+OutputName+"_Initial.png" ,fullPage: true});

    //click XPath
    try{
        var SSO_Elem = await page.$x(XPathSSOElem);
    }catch(ex){
        if(ex.message.includes("Evaluation failed")){
            console.log("try using a selector");
            var SSO_Elem= await page.click(XPathSSOElem);
        }
    }
    console.log("SSO_Elem: %s",SSO_Elem);
    try{
        var SSO_Elem = await page.$x(XPathSSOElem);
        console.log("SSO_Elem: %s",SSO_Elem);
        await Promise.all([SSO_Elem[0].click(),
            page.waitForNavigation({timeout:20000, waitUntil: 'networkidle2'})]);
    }
    catch{
        console.log("click do not caused the redirect check if opened a new windows or stop");
    }
    //gives time to obtain any new tab opened
    await page.waitForTimeout(3000);
    var Open_Pages = await browser.pages();
    console.log("numbers of pages after click:%s",Open_Pages.length);
   
    /*
    for (var i = 0; i < Open_Pages.length; i++) {
        console.log("tab:%s) domain tab: %s",i,TLDJS.parse(Open_Pages[i].url()).domain);
    }
    

    let opentabscheck = Open_Pages.length;
    if(opentabscheck<=2){//no new windows
        var check_urlfirst=page.url()
        var domaincheck = TLDJS.parse(check_urlfirst).domain;
        
        if(check_urlfirst===initial_url){
            //try to use different methof to trigger login with IDP
            console.log("test new trigger method");
            if(IDP.includes(".")){
                temp="//*[contains(text(), \'"+IDP.split(".")[0]+"\')]"
            }
            else{
                temp="//*[contains(text(), \'"+IDP+"\')]"
            }
            var new_trigger =  await page.$x(temp);
            try{
                await new_trigger[0].click();
            }
            catch(ex){
                console.log("new trigger not working Continue");
            }
        }
    }
    */
    await page.waitForTimeout(6000);
    
    //Step3: identify new open window(it need one sec to identify new windows) and take a screenshot of initial tab page after SSO click
    console.log("step3:identify if open new window and go ahead with login");
    let opentabs = Open_Pages.length;
    console.log("numbers of pages after click:%s",Open_Pages.length);
    Open_Pages[1].screenshot({path: OutputPath+OutputName+"_AfterSSOClick.png" ,fullPage: true});

    if(opentabs>2){//new window case
        //Step4: look at tabs and if there is one with IDP domain go and perform login
        try{
            var tabindex_IDP=-1;
            for (var i = 0; i < Open_Pages.length; i++) {
                if(Open_Pages[i].url()!=initial_url && Open_Pages[i].url()!="about:blank"){
                    selector=await ObtainSelector(IDP_Info["Fill"]["User-Type"],IDP_Info["Fill"]["Form-User"]);
                    //check if the page has the username form for the login or the IDP as domain
                    console.log("obtained this selector: %s",selector);
                    try{
                        test=await Open_Pages[i].waitForSelector(selector,{timeout:10000});
                    }catch(ex){
                        if(ex.message.includes("failed")){
                            console.log("not found username form in tab!");
                            test=null;
                        }
                    }
                    console.log("result of the selector search:%s",test);
                    if(!(test===null) || TLDJS.parse(Open_Pages[i].url()).domain===IDP){
                        var tabindex_IDP=i;
                    }
                }
            }

            console.log("tab index after search:%s",tabindex_IDP);
            if (tabindex_IDP===-1){
                console.log("tab not found!!");
                console.log("Open a new tab but not with the idp domain check xpath! ABORT-EXPERIMENT:YES");
                await browser.close();
                process.exit(1);
            }
            else{
                newwindow=true;
                let newurl=Open_Pages[tabindex_IDP].url();
                
                //fill forms
                var asd=await Fillform(Open_Pages[tabindex_IDP],IDP_Info["Fill"]["User-Type"],IDP_Info["Fill"]["Form-User"],IDP_Info["Username"]);
                console.log("new window result first fill form: %s",asd);
                if(asd===false){
                    console.log("fill form unsucessful stop ABORT-EXPERIMENT:YES");
                    await browser.close();
                    process.exit(1);
                }
                else if(asd.length!=undefined && !(asd.includes("No node found for selector"))){
                    await Exception(Open_Pages[tabindex_IDP],asd,"login");
                }
                Open_Pages[tabindex_IDP].bringToFront();
                
                await Open_Pages[tabindex_IDP].waitForTimeout(3000);
                asd=await Fillform(Open_Pages[tabindex_IDP],IDP_Info["Fill"]["Pass-Type"],IDP_Info["Fill"]["Form-Pass"],IDP_Info["Password"]);
                console.log("new window result first fill form: %s",asd);
                if(asd===false){
                    console.log("fill form unsucessful stop ABORT-EXPERIMENT:YES");
                    await browser.close();
                    process.exit(1);
                }
                else if(asd.length!=undefined && !(asd.includes("No node found for selector"))){
                    await Exception(Open_Pages[tabindex_IDP],asd,"login");
                }
                
                await Open_Pages[tabindex_IDP].waitForTimeout(5000);
                //click button
                try{
                    await Promise.all([asd= Click_Button(Open_Pages[tabindex_IDP],IDP_Info["Submit"]["Button-Type"],IDP_Info["Submit"]["Button"],"Submit"),
                                Open_Pages[tabindex_IDP].waitForNavigation({ waitUntil: 'load'})]);
                }catch(error){
                    console.log("new windows case:login click do not change page check Login selector!!");
                }

                await Open_Pages[tabindex_IDP].waitForTimeout(5000);
                //wait for confirmation login
                //await Open_Pages[tabindex_IDP].waitForTimeout(100000);
                //grant wait for network idle since some IDP skip this step so no navigation happening
                try{
                    await Promise.all([asd=Click_Button(Open_Pages[tabindex_IDP],IDP_Info["Grant"]["Button-Type"],IDP_Info["Grant"]["Button"],"Grant"),
                                  Open_Pages[tabindex_IDP].waitForNetworkIdle({waitUntil: 'networkidle2'})]);
                }catch(error){
                    console.log("new windows case:potential error in the grant step chek if redirected to initial site and verify login");
                }
                //Check if extra step in dict or just do it based on idp name
                if("ExtraStep" in IDP_Info){
                    await Exception(Open_Pages[tabindex_IDP],IDP_Info["ExtraStep"]["instructions"],"extra-step");
                }
            }
        }catch(ex){
            console.log("error in Step4 continue?");
            console.log(ex);
        }

    }
    else {//Step4alt: no new window check url if IDP domain or found form username and then perform the login in the same tab
        console.log("Step4alt: check url and do login in the same tab");
        await page.waitForTimeout(3000);
        var check_url=page.url();
        var domaincheck = TLDJS.parse(check_url).domain;
        
        if(check_url===initial_url){
            console.log("no new window and same initial url login trigger not working");
            await browser.close();
            console.log("unable to trigger IDP login ABORT-EXPERIMENT:YES");
            process.exit(1);
        }
        else{
            console.log("check IDP:%s and domaincheck:%s",IDP,domaincheck);
            //idp domain or found unername form
            selector=await ObtainSelector(IDP_Info["Fill"]["User-Type"],IDP_Info["Fill"]["Form-User"]);
            console.log("obtained this selector: %s",selector);
            try{
                test=await page.waitForSelector(selector,{timeout:10000});
            }catch(ex){
                if(ex.message.includes("failed")){
                    console.log("not found username form in tab!");
                    test=null;
                }
            }
            console.log("result of the selector search:%s",test);

            if( IDP===domaincheck || !(test===null) ){
                //redirected to IDP page for login

                //fill forms
                var asd=await Fillform(page,IDP_Info["Fill"]["User-Type"],IDP_Info["Fill"]["Form-User"],IDP_Info["Username"]);
                console.log("same page result first fill form: %s",asd);
                if(asd===false){
                    console.log("fill form unsucessful stop ABORT-EXPERIMENT:YES");
                    await browser.close();
                    process.exit(1);
                }
                else if(asd.length!=undefined && !(asd.includes("No node found for selector"))){
                    await Exception(page,asd,"login");
                }
                await page.waitForTimeout(3000);
                asd= await Fillform(page,IDP_Info["Fill"]["Pass-Type"],IDP_Info["Fill"]["Form-Pass"],IDP_Info["Password"]);
                console.log("same page result second fill form: %s",asd);
                if(asd===false){
                    console.log("fill form unsucessful stop ABORT-EXPERIMENT:YES");
                    await browser.close();
                    process.exit(1);
                }
                else if(asd.length!=undefined && !(asd.includes("No node found for selector"))){
                    await Exception(page,asd,"login");
                }
                await page.waitForTimeout(5000);

                //click button
                try{
                    await Promise.all([asd=Click_Button(page,IDP_Info["Submit"]["Button-Type"],IDP_Info["Submit"]["Button"],"Submit"),
                                    page.waitForNavigation({ waitUntil: 'load'})]);
                }catch(error){
                    console.log("same windows case:login click do not change page check Login selector!!");
                }
                await page.waitForTimeout(5000);
                //wait for confirmation login
                //await page.waitForTimeout(100000);
                //grant wait for network idle since some IDP skip this step so no navigation happening
                try{
                await Promise.all([asd= await Click_Button(page,IDP_Info["Grant"]["Button-Type"],IDP_Info["Grant"]["Button"],"Grant"),
                                    page.waitForNetworkIdle({waitUntil: 'networkidle2'})]);
                }catch(error){
                    console.log("same windows case:potential error in the grant step chek if redirected to initial site and verify login");
                }
                //Check if extra step in dict or just do it based on idp name
                if("ExtraStep" in IDP_Info){
                    await Exception(page,IDP_Info["ExtraStep"]["instructions"],"extra-step");
                }
            }
            else{
                console.log("no new window and no redirection to IDP domain but changed url error in xpath!!");
                console.log("initial url:%s \n checkurl:%s",initial_url,check_url);
                //search for error in url or page
                await browser.close();
                console.log("error in dompath or other ABORT-EXPERIMENT:YES");
                process.exit(1);
            }
        }
    }

    //Step5:identify succesfull login:take a screenshot after login,inspect url page,search identifiers
    console.log("Step5:check if succesful login");
    //gives time to redirect and then wait for page to be ready
    await page.waitForTimeout(10000);
    await page.screenshot({path: OutputPath+OutputName+"_AfterSSOLogin.png" ,fullPage: true});
    var checktab= await browser.pages();
    let opentabs2 = checktab.length;
    console.log("number of open tabs after SSOLogin:%s",opentabs2);

    if(newwindow){
        if(opentabs2>2){//open new tab still open check if IDP domain and if initial page with same url
            console.log("more than 3 tabs open at the end of the measurement");
            try{
                var nw_closecode = await AnalizeResult_New_Window(browser,IDP,page,Open_Pages[tabindex_IDP],domainbegin,initial_url,measurement);
            }catch(ex){
                console.log("error in the final evaluation new windows:%s",ex.message);

            }
            await browser.close();
            process.exit(nw_closecode);
        }
        console.log("used new window for login but closed it");
    }
    
    let return_url=page.url();
    var domainreturn = TLDJS.parse(return_url).domain;
    var html=await page.content();

    try{
        var closecode = await AnalizeResult(browser,IDP,domainbegin,initial_url,domainreturn,return_url,html,measurement);
    }
    catch(ex){
        console.log("error in the final evaluation:%s",ex.message);
    }
    //close the browser and use return as exit code
    await browser.close();
    process.exit(closecode);
})();
