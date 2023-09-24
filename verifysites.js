const puppeteer = require('puppeteer');
const FS = require('fs');
const TLDJS = require('tldjs');
const ArgParse = require('argparse');

let WEBPAGE = null;
let NameSITE =  null;
let TAG =  null;
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


async function Oauthurl(checkURL) {
    //search for oauth keyworks in url
    var identifiers=["redirect_uri","oauth"];
    var arrayLength = identifiers.length;
    for (var i = 0; i < arrayLength; i++) {
        let res = checkURL.search(identifiers[i])
        if(res >0){
            console.log("oauth keyword found in url");
            console.log(identifiers[i]);
            console.log(checkURL);
            return true;
        }
    }
    return false;
}

async function Save_textfile(name,content){
    //save file with HTML
    FS.writeFileSync(name,content);
}

(async() => {
    console.log("Step1 get info for the crawler");
    parseArguments();
    let rawdata = FS.readFileSync(PARAMETER);
    let params = JSON.parse(rawdata);
    WEBPAGE = params["WEBPAGE"];
    NameSITE = params["NameSITE"];
    XPathSSOElem = params["xpath"];
    OutputName = params["name"];
    OutputPath = params["outpath"];
    TAG=params["tag"];
    console.log("parameters received WEBPAGE: %s\nXPathSSOelem: %s\nOutputpath: %s\nOutputName: %s\nTAG: %s",WEBPAGE,XPathSSOElem,OutputPath,OutputName,TAG);


    //Step2: surf on the login page save initial page url then take a screenshot and then click in the SSO element
    console.log("Step2:start the login procedure")
    //start browser
    //'--proxy-server=http://127.0.0.1:7777',
    const browser = await puppeteer.launch({args:['--disable-gpu',
            '--no-sandbox',
            '--disable-popup-blocking',
            '--disable-notifications',
            '--password-store=basic',
            '--ignore-certificate-errors'],
            headless: false,
            executablePath: '/bin/google-chrome-stable'});
    
    const page = await browser.newPage();
    
    try{
        await page.goto(WEBPAGE, {waitUntil: 'load'});
    }catch(ex){
        console.log("error in surfing to the login page!ABORT-EXPERIMENT:YES");
        await browser.close();
        process.exit(101);
    }
    
    let initial_url=page.url();
    //initial_url=initial_url.split("#")[0];

    var domainbegin = TLDJS.parse(initial_url).domain;
    await page.waitForTimeout(5000);
    
    //take screenshot
    await page.screenshot({path: OutputPath+"/"+OutputName+"_Initial.png" ,fullPage: true});

    //evaluate XPath
    try{
        var SSO_Elem = await page.$x(XPathSSOElem);
    }catch(ex){
        if(ex.message.includes("Evaluation failed")){
            console.log("evaluation of xpath failed xpath syntactically wrong!");
            await browser.close(); 
            process.exit(106);
            /*
            console.log("wrong xpath use backup procedure as selector");
            try{
                await Promise.all([page.click(XPathSSOElem),
                page.waitForNavigation({timeout:5000, waitUntil: 'networkidle2'})]);
            }catch(error){
                console.log("error in the click as a selector");
                console.log("click as a selector not working wrong xpath? check if open a new tab");
            }
            */
        }
    }

    if(SSO_Elem.length>0){
        console.log("found SSO_Elem: %s",SSO_Elem);
        try{
            var SSO_Elem = await page.$x(XPathSSOElem);
            console.log("SSO_Elem: %s",SSO_Elem);
            console.log("use the SSO_Elem to click");
            await Promise.all([SSO_Elem[0].click(),
            page.waitForNavigation({timeout:5000, waitUntil: 'networkidle2'})]);
        }
        catch{
            console.log("click do not caused the redirect check if opened a new windows or stop");
            //means xpath not working or check new windows

        }
    }else {
        console.log("the xpath is not found stop here the experiment");
        await browser.close();
        //return code for 
        process.exit(107);

    }

    //gives time to obtain any new tab opened
    await page.waitForTimeout(3000);
    var Open_Pages = await browser.pages();
    console.log("numbers of pages after click:%s",Open_Pages.length);
    await page.waitForTimeout(6000);
    
    //Step3: identify new open window and take a screenshot of initial tab page after SSO click
    console.log("step3:identify if open new window and check oauth param in redirect url");
    
    let opentabs = Open_Pages.length;
    console.log("numbers of pages after click:%s",Open_Pages.length);
    await Open_Pages[1].screenshot({path: OutputPath+"/"+OutputName+"_AfterSSOClick.png" ,fullPage: true});

    if(opentabs>2){//new window case
        //Step4: look at tabs and check the new windows if oauth params in url means right xpath so collect domain idp and close browser
        try{
            var tabindex_IDP=-1;
            for (var i = 0; i < Open_Pages.length; i++) {
                if(Open_Pages[i].url()!=initial_url && Open_Pages[i].url()!="about:blank"){
                    //check url contains oauth keywords
                    console.log("verify that new windows url has oauth keywords");
                    url_newwindow=Open_Pages[i].url();
                    let test1=await Oauthurl(url_newwindow);
                    if(test1){
                        idp_domain=TLDJS.parse(url_newwindow).domain;
                        //obtain domain idp and save it to file
                        //namesite;loginpage;xpathelement;idp_domain
                        content=NameSITE+"@@@@"+WEBPAGE+"@@@@"+XPathSSOElem+"@@@@"+idp_domain+"@@@@"+TAG;
                        Save_textfile(OutputPath+"/"+OutputName+"-updateinfo.txt",content);
                        console.log("Click succesfully redirect to a link with oauth param");
                        await browser.close();
                        process.exit(104);
                    }
                }
            }

            console.log("tab index after search:%s",tabindex_IDP);
            if (tabindex_IDP===-1){
                console.log("tab not found!!");
                console.log("Open a new tab but not with oauth check xpath! ABORT-EXPERIMENT:YES");
                await browser.close();
                process.exit(103);
            }
        }catch(ex){
            console.log("error in Step4 inspect test in:");
            testfailed=NameSITE+"@@@@"+WEBPAGE+"@@@@"+XPathSSOElem;
            console.log(testfailed)                        
            console.log(ex);
            await browser.close();
            process.exit(105);

        }

    }
    else {
        console.log("Step4alt: check url for presence of oauthparam");
        try{
            await page.waitForTimeout(3000);
            var check_url=page.url();
            
            if(check_url===initial_url){
                //verify differentiation between xpath not found and sso click not working
                console.log("no new window and same initial url Xpath SSO not working");
                console.log("unable to trigger IDP login ABORT-EXPERIMENT:YES");
                await browser.close();
                process.exit(102);
            }
            else{
                //Step4alt: no new window check url if conatins ouauth keyword and then obatin domain idp
                console.log("Step4alt: check url if contains oauthparam");
                await page.waitForTimeout(3000);
                var check_url=page.url();
                let test= await Oauthurl(check_url);
                if(test){
                    idp_domain=TLDJS.parse(check_url).domain;
                    //obtain domain idp and save it to file
                    //WEBPAGE;loginpage;idp;domain
                    content=NameSITE+"@@@@"+WEBPAGE+"@@@@"+XPathSSOElem+"@@@@"+idp_domain+"@@@@"+TAG;
                    Save_textfile(OutputPath+"/"+OutputName+"-updateinfo.txt",content);
                    console.log("Click succesful idp in url with oauth param");
                    await browser.close();
                    process.exit(104);
                }
                else{
                    console.log("no oauthparam check correctness xpath sso element");
                    await browser.close();
                    process.exit(103);       
                }
            }   
        }catch(ex){
            console.log("error in Step4alt inspect test in:");
            testfailed=NameSITE+"@@@@"+WEBPAGE+"@@@@"+XPathSSOElem+"@@@@"+TAG;
            console.log(testfailed);                        
            console.log(ex);
            await browser.close();
            process.exit(105);
        }
    }

})();
