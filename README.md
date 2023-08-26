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

- Searches for links that contain the **provider** name and some keywords (e.g., `auth`, `login`, `signin`).
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

The structure of the output JSON file of the `idps-identification.py` script is different from the one needed for the next step of **OAuth trigger evaluation**, therefore, we need to convert the JSON file to the correct format. To do so, we use the `convert.sh` script, which:

1. Calls `generate-sites-files.py` to generate the single JSON files with the structure needed by the next step (requires a Tranco ranking csv file in the `lists` folder called `sites.csv`).
2. Calls `merge-sites-files.py` to merge the single JSON files into a single one.

## Notice

The script has a high number of false-positives rates. In our research, this has not been a problem since this was only the first step and, in the next one, we used an automated browser to click on the buttons detected by this script to check whether they are OAuth buttons or not. In this script, we prioritized not missing any OAuth button, even if this means having a high number of false positives. If this script is used for other purposes, it is recommended to improve the blacklists to reduce the false-positives rate.


# OAuth trigger validation

receives a list of site's login pages and verifies the OAuth button identified to verify they are able to initiate an OAuth flow. The result is the list of site's OAuth trigger evaluated and the list of TOP IdPs.

## How does it work

On a high level, the script does the following:

1)surf over the login page of the site and one by one exercise the OAuth trigger identified previously
2)the script looks for changes in the browser as a new tab opening or a change of the page url
3)if the change occur it evaluates the landing page and searches for login page identifier as the presence of login button a OAuth identifiers in the page url

Output:
The result folder contains a series of files with the result for each error type. in the same folder of the script the file Verified_Sites.json will contains the site's login pages with the OAuth trigger correctly functioning. In the same folder the file Top_Idps.json will contains the list of most used IdPs among the sites inspected.

## How to run it

Run the script: `python3 Start-SitesVerification.py -s <sites file> -o <output folder>`

## Notice
The treshold to classify the IdPs as top IdP is represented by the value at line 385 of the script source code.

To simplify the reviewer work we provide the result of the run of the site verification step for the sites included in the file InitialsetofSites.json.
The results file are included in the folder result

# Path confusion Experiment

The script receives the list of sites where to inject the Path Confusion and logs all the network communications

## Notice
Before starting the experiment the IdPs of interest should be selected and for those an account and the login steps needs to codificated in the IdPs_info file (step IdP credentials) only the OAuth trigger of the selected IdPs should be present in the sites file to limit the number of undesired measurements.

## IdPs_info file:

The IdPs information file contains the IdPs login information as the credential and the steps to perform the login flow.
The fields *-Type can have an attribute that is either: ID, Name, ClassName or exception.
Each of it represents the type of the element's attribute the crawler will use to identify and fill or click the element in the IdP's login page.
The Button-Type extend the available attributes to XPath and QuerySelector. Representing the xpath of the element or the query for the selector which identifies the element in the page.
The exception type allows flexibility in the configuration of the action performed by the crawler to accomodate any possible variation in the login procedure between IdPs. 

e.g:fill%%Name%%loginfmt%%test@example.com##sleep3##click%%ID%%idSIButton9%%login##sleep3"
this excpetion allows to fill the username form and perform a click over the button with ID idSIButton9 before proceeding to the filling of the password field.

The exception could contain any set of instruction among: fill, click or sleep.
Fill is composed of the action fill the separator %% the *-type the separator %% the content of the fill action
Click is composed of the action click the separator %% the *-type the separator %% the attibute  separator %% the loginstep either Login or Grant
Sleep is composed of the action sleep which represent a pause in the login flow and the amount of seconds of the pause.

## How to run it

Run the script: `python3 Start-PathConfusion-exp.py - s <sites file> -m <measurements name> -a <attack list file> -j <idps keywords> -i <idps informations>`

#### Scripts arguments
-m experiment name used for log purpose

-a The attack list file contains a dictionary of attack strings where the name of the attribute would also represent the name of the folder under which all the result file associated with that attack string will be stored and the value field represent the attack string which will be injected in the OAuth flow.

-j IdPs keywords are a set of keyword used to identify the Authorization request of the OAuth flow where to inject the Path confusion string

-i IdPs information file which contains the IdPs account informations and the login step to automate the login procedure

## Notice

We provide a limited number of IdPs info in the IdPs info file to avoid any potential blockage by the IdPs for souspicious login from unrecognized location which could negatively affect other ongoing research project which uses these accounts.

# Path confusion result

The script received the path where to analyze the results file generated at the previous step and the sites files where the measurement has been performed.
The script will process all the measurements result file contained in the folder and identify for each folder the IdPs vulnerable to the PathConfusion string injected in the OAuth flow.
This will provide the total set of IdPs vulnerable to one of the Path confusion string tested as reported in Section 4.3.

## How to run it

Run the script: `python3 Analyze_Pathconfusion.py -f <Path comnfusion experiment result folder> -s <sites file>`

## Notice
To help in the review process we provide the folder Pathconfusion-measurement where a limited number of results file from sites (Smallsetofsites.json). This one could be used to effectively validate our analysis result tool.

# OAuth Parameter Pollution:

## How does it work

To identify the IdPs vulnerable to the OPP attack we implemented a testing Client for each IdP and manually injected an Oauth code parameter in the redirect_uri of the Authorization request. To verify the IdP vulnerability we observed when the injected code is reflected in the Authorization response. The IdPs which reflect back the injected parameter are considered vulnerable.
The number of IdPs vulnerable represent the result reported in Section 5.2.

## How to run it
The execution of the test is rather simple and does not involves any automation of the procedure.
The client application is initiated and then the test is performed.


## Notice
We provide the scheleton of a testing Client application we used to test each IdP, for each IdP it is necessary the creation of configuration file with the IdP which will include the registered redirect_uri and provide the Client_ID as well as the Client_secret.

# redirect URI Validation in Redeem Proces:

## How does it work
By reusing the Client Application used to identify the IdPs vulnerable to the OPP attack we measured the IdPs which improperly validate the redirect_uri in the Redeem Process.
We followed the same methodology of the previous step by injecting an OAuth code in the Authorization step and once we received the two OAuth code parameters we initiate the redeem step with the newly generated code by the IdP with an untouched flow. This will generate a difference between the redirect_uri used in the Authorization request(poisoned) and the one provided in the access token request. The IdPs that allows the flow to proceed are marked as vulnerable. This will provide the result of Section 6.2


The execution of the test is rather simple and does not involves any automation of the procedure.