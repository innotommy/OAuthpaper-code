# IdPs Identification

Crawls a list of websites to search for the OAuth IdPs they use.

## How does it work

On a high level, the script does the following:

1. Visit the homepage of the site
2. If the homepage does not contain the login functionalities:
   1. Crawl the site to find the login page.
3. Search the OAuth URLs and buttons on the login page.

### Login pages identification

To detect a login page, the script looks for the following:

- Searches for links that contain some keywords (e.g., `/signin`, `/login`).
- Checks if the current page contains an input field of type `password`.

### OAuth URLs and buttons identification

To detect the OAuth URLs and buttons, the script looks for the following:

For each **provider**:

- Search for links containing the **provider** name and some keywords (e.g., `auth`, `login`, `signin`).
- Searches for specific HTML tags (`a`, `input`, and `button`) that contain the **provider** name and some keywords (e.g., `auth`, `login`, `signin`).
  - If a tag is not found, it optionally searches through all the other HTML tags

**Note**: the script makes heavy use of **blacklists** to avoid false positives. The blacklists are compiled by observing the results of the script while debugging and are not exhaustive.

## How to run it

- Install the dependencies: `pip install -r requirements.txt`

### On a single website

Run the script: `python3 idps-identification.py -t <target>`

#### Script arguments

```bash
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target website
  -S STATS, --stats STATS
                        Statistics folder
  -R REPORTS, --reports REPORTS
                        Reports folder
  -l LOGS, --logs LOGS  Logs folder
  -L LINKS, --links LINKS
                        File containing the login links
  -m MAX, --max MAX     Maximum number of URLs to crawl (Default: 10)
  -N, --no-headless     Do not use a headless browser
  -r, --retest          Retest the URLs
```

### On a list of websites

Run the script: `python3 launcher.py --sites <sites_file>`

The launcher will test the websites in the file concurrently (up to the maximum number of concurrent tests).

#### Launcher arguments

```bash
  -h, --help            show this help message and exit
  -s SITES, --sites SITES
                        Sites list
  -m MAX, --max MAX     Maximum number of sites to test concurrently (default: 5)
  -a ARGUMENTS, --arguments ARGUMENTS
                        Additional arguments to pass to the crawler (use with = sign: -a="--arg1 --arg2")
  -t, --testall         Test also already tested sites
  -c CRAWLER, --crawler CRAWLER
                        Alternative crawler script name to launch
  -d, --debug           Enable debug mode
```

### Workflow

The structure of the output JSON file of the `idps-identification.py` script is different from the one needed for the next step of **OAuth trigger evaluation**; therefore, we need to convert the JSON file to the correct format. To do so, we use the `convert.sh` script with the same list pof sites used before to identify the OAuth triggers.

Run the script: `/conver.sh <sites_file>`

which:
1. Calls `generate-sites-files.py` to generate the single JSON files with the structure needed by the next step

2. Calls `merge-sites-files.py` to merge the single JSON files into a single one (json/sites.json).

## Notice

The script has a high number of false-positives rates. In our research, this has not been a problem since this was only the first step and, in the next one, we used an automated browser to click on the buttons detected by this script to check whether they are OAuth buttons or not. In this script, we prioritized not missing any OAuth button, even if this means having many false positives. If this script is used for other purposes, improving the blacklists to reduce the false-positives rate is recommended.


# OAuth trigger validation

Receives a list of the site's login pages and verifies the OAuth button identified to verify they can initiate an OAuth flow.
The results are the list of the site's OAuth trigger evaluated (Verified_Sites.json) and the list of TOP IdPs(Top_Idps.json).

## How does it work

On a high level, the script does the following:

1)surf over the login page of the site and one by one exercise the OAuth trigger identified previously
2)the script looks for changes in the browser, such as a new tab opening or a change of the page URL
3)if the change occurs, it evaluates the landing page and searches for login page identifier as the presence of the login button and OAuth identifiers in the page URL

Output:
The output folder contains a series of files with the result for each error type. In the script folder, the file Verified_Sites.json will include the site's login pages with the OAuth trigger correctly functioning, and the file Top_Idps.json will contain the list of most used IdPs among the sites inspected

## How to run it

1)Install NodeJS from https://nodejs.org/en/download/.
Then, run the following command to install all the dependencies:

npm install chrome-launcher chrome-remote-interface url-parse util tldjs path argparse puppeteer fs

Adjust the Chrome executable path in verifysites.js at line 81 to point to the Chrome executable file

Run the script: `python3 Start-SitesVerification.py <sites file.json> <output folder>`

Eg:
`python3 Start-SitesVerification.py json/sites.json outputfolder`

## Notice
The threshold to classify the IdPs as TopIdP is represented by the value at line 385 of the script Start-SitesVerification.py (>3 sites adoption).

# Path confusion Experiment

The script receives the list of sites where to inject the Path Confusion and logs all the network communications

## Notice
Before starting the experiment, the IdPs of interest should be selected, and for those, an account and the login steps need to be codified in the IdPs_info file (step IdP credentials).

To simplify the reviewer's job, we included in the file idps_info.json the login information of 3 IdPs (Facebook, line, Twitter)
The structure of the file is described below.

We provide a limited number of IdPs info to avoid any potential blockage by the IdPs for suspicious login from unrecognized location, which could negatively affect other ongoing research project that currently uses these test accounts.

## IdPs_info file:

The IdPs information file contains the IdPs login information as the credential and the steps to perform the login flow.
The fields *-Type can have an attribute: ID, Name, ClassName or exception.
Each represents the type of the element's attribute the crawler will use to identify and fill or click the element in the IdP's login page.
The Button-Type extends the available attributes to XPath and QuerySelector. Representing the xpath of the element or the query for the selector which identifies the element in the page.
The exception type allows flexibility in the configuration of the action performed by the crawler to accommodate any possible variation in the login procedure between IdPs. 

e.g:fill%%Name%%loginfmt%%test@example.com##sleep3##click%%ID%%idSIButton9%%login##sleep3"
this exception allows one to fill out the username form and click over the button with ID idSIButton9 before filling the password field.

The exception could contain any set of instructions among: fill, click, or sleep.
Fill is composed of the action fill the separator %% the *-type the separator %% the content of the fill action.
Click is composed of the action click the separator %% the *-type the separator %% the attribute  separator %% the loginstep either Login or Grant
Sleep is composed of the action sleep, which represents a pause in the login flow and the number of seconds of the pause.

## How to run it

Before Starting the experiment, the Mitmproxy should be installed in the system.
The installation instructions for each operative system could be found at https://mitmproxy.org/
The required version is 9.0.1

Run the script: `python3 Start-PathConfusion-exp.py <sites file> <measurements name> <attack list file> <idps keywords> <idps informations>`

Example:
`python3 Start-PathConfusion-exp.py Verified_Sites.json PathConfusion-experiment Pathconfusion-attacklist.json idp_keywords.json Idps_info.json`


#### Scripts arguments
sites file: file containing sites information (login pages) with OAuth trigger information for each IdP identified

measurements name: experiment name used for log purpose

attack list file: The attack list file contains a dictionary of attack strings where the name of the attribute would also represent the name of the folder under which all the result file associated with that attack string will be stored and the value field represents the attack string which will be injected in the OAuth flow.(Pathconfusion-attacklist.json provided in the repo)

idps keywords: IdPs keywords are a set of keywords used to identify the Authorization request of the OAuth flow where to inject the Path confusion string.(idp_keywords.json provided in the repo)

idps informations: IdPs information file which contains the IdPs account information and the login step to automate the login procedure.(Idps_info.json provided in the repo)


# Path confusion result

The script received the path to analyze the results file generated at the previous step and the site files where the measurement has been performed.
The script will process all the measurement result files in the folder and identify the IdPs vulnerable to the PathConfusion string injected in the OAuth flow for each folder.
This will provide the total set of IdPs vulnerable to one of the Path confusion strings tested, as reported in Section 4.3.


## How to run it
Run the script: `python3 Analyze_Pathconfusion.py <Path comnfusion experiment result folder> <sites file>`

## Notice
To simplify the reviewer's job, we provide the data obtained from the execution of the previous command on a small subset of tested sites here:
https://drive.google.com/file/d/1JKNcJu8sjCjY5MKPQIk3ar02AFSrpXzB/view?usp=sharing


We provide this data because, potentially, no IdP should be found vulnerable thanks to our previous responsible disclosure to all the IdPs found to be vulnerable.
This data set can be used as input for the Analyze_Pathconfusion.py script to effectively validate the script functionality using this command:

Run the script: `python3 Analyze_Pathconfusion.py Pathconfusion-measurement Smallsetofsites.json`

# OAuth Parameter Pollution:

## How does it work

To identify the IdPs vulnerable to the OPP attack, we implemented a testing Client for each IdP and manually injected an Oauth code parameter in the redirect_uri of the Authorization request. To verify the IdP vulnerability, we observed when the injected code is reflected in the Authorization response. The IdPs that reflect the injected parameter are considered vulnerable.
The number of IdPs vulnerable represents the result reported in Section 5.2.

## How to run it
The execution of the test is relatively simple and does not involve any automation of the procedure.

Before running the script, a folder named templates needs to be created, and the files attack.html and login.html should be placed inside of it
The client application (present in the upper folder of templates) is then initiated by running this command:
`python3 facebook.py`

The Client application has three buttons that allow the authorization request initiation normally or with the PathConfusion or the OPP attack injection.
The attacks are hardcoded in the application methods, and this option is also provided for the redemption step.
Any changes to these methods should be performed in the application code.
The complete cases for each IdP can be tested and inspected using the available requ

## Notice
We provide only the skeleton of a testing Client application (Facebook, for example) we used to test each IdP.
For each IdP it is necessary to create a new configuration file with the IdP, which will include the registered redirect_uri and provide the Client_ID and the Client_secret that should be included in the application code to work correctly.
For Facebook, the instructions to create such a configuration could be found here:
https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow

Once the application parameters (line 16 to 25) has been included, the script can be run, and the experiment could start by using the provided button in the web interface

# redirect URI Validation in Redeem Proces:

## How does it work
By reusing the Client Application used in the previous step to identify the IdPs vulnerable to the OPP attack, we measured the IdPs that improperly validate the redirect_uri in the Redeem Process.
We followed the same methodology of the previous step by injecting an OAuth code in the Authorization step. Once we receive the two OAuth code parameters, we initiate the redeem step with the newly generated code by the IdP with an untouched redeem request. This will create a difference between the redirect_uri used in the Authorization request(poisoned) and the one provided in the Access Token request. The IdPs that allow the flow to proceed are marked as vulnerable. This will give the result of Section 6.2


The execution of the test is relatively simple and does not involve any automation of the procedure.
