#change questID, vote payload, vote options, option

import requests
import time
import json
import random
import string 
from faker import Faker
fake = Faker()

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import ElementClickInterceptedException, NoSuchElementException, TimeoutException
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
import re


# Set up Chrome options
chrome_options = Options()
#chrome_options.add_argument("--incognito")
chrome_options.add_argument("--disable-dev-shm-usage")

# Initialize the Chrome driver with the specified options
service = Service(executable_path=r"C:\Program Files (x86)\chromedriver.exe")
driver = webdriver.Chrome(service=service, options=chrome_options)
driver.get('https://quester.io')
wait = WebDriverWait(driver, 10)  # Wait up to 10 seconds


# INTERACT HERE
username = fake.name()
print(f"Generated Username: {username}")
password = 'Password12345'
questName = 'Metrics interviews'

# Define bearer and headers objects to include in later requests
access_token_prefix = 'Bearer '

# Make GET request first to return 'uuid' of individual resources in quest
questID = '133935057'
get_url = f'https://api.quester.io/resource-management/api/v1/pub/quests/{questID}/quest-items'
vote_options = ['Yes', 'No', 'Kinda']

#inivteID 
inviteID = 'jt8Zp73dsSO'

#create email
def CreateEmail():
    import requests
    url = "https://gmailnator.p.rapidapi.com/generate-email"

    payload = { "options": [2] }
    headers = {
        "content-type": "application/json",
        "X-RapidAPI-Key": "ca263c054amshf7a16421e4dd1eap1126cdjsn1de0f0140b58",
        "X-RapidAPI-Host": "gmailnator.p.rapidapi.com"
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.ok:
        # Extracting the email address from the response
        email_address = response.json().get('email', 'No email found')
        print(email_address)
        return email_address
    else:
        print("Error:", response.status_code)

def RegisterFlow(email_address):
    login_button_xpath = '//*[@id="root"]/div/div[2]/div[1]/div[3]/div[1]/div[5]/div[2]/div/div[2]/div/div[3]/div[3]/span'
    login_button = wait.until(EC.element_to_be_clickable((By.XPATH, login_button_xpath)))
    login_button.click()
    time.sleep(1)
    register_button_xpath = '//*[@id="kc-registration"]/span/a'
    register_button = wait.until(EC.element_to_be_clickable((By.XPATH, register_button_xpath)))
    register_button.click()
    time.sleep(1)
    email_xpath = '//*[@id="email"]' 
    email_button = wait.until(EC.element_to_be_clickable((By.XPATH, email_xpath)))
    email_button.click()
    email_button.send_keys(email_address)
    time.sleep(1)
    username_xpath = '//*[@id="username"]'
    username_button = wait.until(EC.element_to_be_clickable((By.XPATH, username_xpath)))
    username_button.click()
    username_button.send_keys(username)
    time.sleep(1)
    password_xpath = '//*[@id="password"]'
    password_button = wait.until(EC.element_to_be_clickable((By.XPATH, password_xpath)))
    password_button.click()
    password_button.send_keys(password)
    time.sleep(1)
    confirm_password_xpath = '//*[@id="password-confirm"]'
    confirm_password_button = wait.until(EC.element_to_be_clickable((By.XPATH, confirm_password_xpath)))
    confirm_password_button.click()
    confirm_password_button.send_keys(password)
    time.sleep(1)
    register_submit_xpath = '//*[@id="kc-form-buttons"]/input'
    register_submit_button = wait.until(EC.element_to_be_clickable((By.XPATH, register_submit_xpath)))
    register_submit_button.click()
    # username_xpath = '//*[@id="username"]'
    # username_button = wait.until(EC.element_to_be_clickable((By.XPATH, username_xpath)))
    # username_button.click()
    # username_button.send_keys('TalvinQuester')
    # password_xpath = '//*[@id="password"]'
    # password_button = wait.until(EC.element_to_be_clickable((By.XPATH, password_xpath)))
    # password_button.click()
    # password_button.send_keys('hlhothaYom6&ApH01rod')
    # sign_in_xpath = '//*[@id="kc-login"]'
    # sign_in_button = wait.until(EC.element_to_be_clickable((By.XPATH, sign_in_xpath)))
    # sign_in_button.click()


def getVerificationEmailID(email_address, attempts=3, delay=5):
    # Inbox
    url = "https://gmailnator.p.rapidapi.com/inbox"
    payload = {"email": email_address, "limit": 1}
    headers = {
        "content-type": "application/json",
        "X-RapidAPI-Key": "ca263c054amshf7a16421e4dd1eap1126cdjsn1de0f0140b58",
        "X-RapidAPI-Host": "gmailnator.p.rapidapi.com"
    }

    attempt = 0
    while attempt < attempts:
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            response_json = response.json()
            print("Response:", response_json)
            if response_json and isinstance(response_json, list) and len(response_json) > 0:
                message_id = response_json[0].get('id', None)
                if message_id:
                    return message_id
                else:
                    print("Email found but no message ID.")
                    return
            else:
                print("No emails found, retrying...")
        else:
            print("Error with response, status code:", response.status_code)
            return

        time.sleep(delay)
        attempt += 1

    print("Failed to retrieve email after multiple attempts.")
    
def getVerificationLink(message_id):
    # Message
    url = "https://gmailnator.p.rapidapi.com/messageid"
    querystring = {"id": message_id}
    headers = {
        "X-RapidAPI-Key": "ca263c054amshf7a16421e4dd1eap1126cdjsn1de0f0140b58",
        "X-RapidAPI-Host": "gmailnator.p.rapidapi.com"
    }
    response = requests.get(url, headers=headers, params=querystring)
    print(response.json())
    email_content = response.json().get('content', '')
    print(email_content)

    # Extract the verification link using regular expression
    verification_link = extract_verification_link(email_content)
    if verification_link:
        # Use Selenium to open the verification link
        driver.get(verification_link)
    else:
        print("Verification link not found in the email content.")

    # except IndexError:
    #     print("No emails found in the inbox.")
    # except Exception as e:
    #     print("An error occurred:", e)

def extract_verification_link(email_content):
    # Use regular expression to find the URL
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_content)
    if urls:
        return urls[0]  # Assuming the first URL is the verification link
    return None

#go to verification link enter credentials

def bearerToken():
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    # Prepare the data for the POST request
    data = {
        'client_id': 'resource-management',
        'username': username,
        'password': password,
        'grant_type': 'password'
    }

    # URL for the request
    url = "https://um.quester.io/auth/realms/quester/protocol/openid-connect/token"

    # Make the POST request
    response = requests.post(url, headers=headers, data=data)

    # Extract the access token from the response
    if response.status_code == 200:
        access_token = access_token_prefix + response.json().get('access_token', None)
        print("Access Token:", access_token)
        return access_token
    else:
        print("Failed to retrieve token. Status Code:", response.status_code)
        return None


def votingAPIs(access_token):
    headers = {'Authorization': access_token}
    get_r = requests.get(get_url, headers=headers) 
    print(get_r.status_code)

    # Format the response of the get request
    get_response = json.loads(get_r.content)

    # Get multiple resource IDs
    resource_ids = [x['uuid'] for x in get_response]
    print(resource_ids)

    # Create multiple POST urls to use in POST request
    post_url_list = []

    for id in resource_ids:
        post_url = f'https://api.quester.io/resource-management/api/v1/quests/{questID}/quest-items/{id}/vote'
        post_url_list.append(post_url)

    # Define options to vote
    vote_options = ['Yes', 'No']
    for resource in post_url_list:
        # Define vote payload
        option = vote_options[random.randint(0,1)]
        vote = {"cells":{"DrkdjDEtobTwgUPZdRo8a":[option]},"dtableSchemaId":"9pnqAAIGFDM"}
        post_r = requests.post(resource, headers=headers, json = vote)
        print(post_r.status_code)
    return post_url_list

def acceptInvite(access_token):
    headers = {'Authorization': access_token}
    post_url = f'https://api.quester.io/resource-management/api/v1/invites/{inviteID}/accept'
    post_r = requests.post(post_url, headers=headers)
    print(post_r.status_code)

def saveQuest(access_token):
    headers = {'Authorization': access_token}
    post_url = f'https://api.quester.io/resource-management/api/v1/quests/{questID}/follow'
    post_r = requests.post(post_url, headers=headers)
    print(post_r.status_code)

def saveResource(access_token, post_urls):
    headers = {'Authorization': access_token}
    
    post_url = f'https://api.quester.io/resource-management/api/v1/quests/{questID}/quest-items/{resourceID}/save'
    post_r = requests.post(post_url, headers=headers)
    print(post_r.status_code)

#login to fake account
def SignInFlow():
    login_button_xpath = '//*[@id="root"]/div/div[2]/div[1]/div[3]/div[1]/div[5]/div[2]/div/div[2]/div/div[3]/div[3]/span'
    login_button = wait.until(EC.element_to_be_clickable((By.XPATH, login_button_xpath)))
    login_button.click()
    username_xpath = '//*[@id="username"]'
    username_button = wait.until(EC.element_to_be_clickable((By.XPATH, username_xpath)))
    username_button.click()
    username_button.send_keys(username)
    password_xpath = '//*[@id="password"]'
    password_button = wait.until(EC.element_to_be_clickable((By.XPATH, password_xpath)))
    password_button.click()
    password_button.send_keys(password)
    sign_in_xpath = '//*[@id="kc-login"]'
    sign_in_button = wait.until(EC.element_to_be_clickable((By.XPATH, sign_in_xpath)))
    sign_in_button.click()

#Go to the quest to vote and comment on 
def navigateToQuest():
    navigate_xpath = '//*[@id="root"]/div/div[2]/div[1]/div[3]/div[1]/div[5]/div[2]/div/div[2]/div/div[2]/div/span'
    navigate_button = wait.until(EC.element_to_be_clickable((By.XPATH, navigate_xpath)))
    navigate_button.click()
    search_xpath = '//*[@id="root"]/div/div[2]/div[1]/div[3]/div[2]/div/div/div/div/div[1]/div[1]/input'
    search_button = wait.until(EC.element_to_be_clickable((By.XPATH, search_xpath)))
    search_button.click()
    search_button.send_keys(questName)
    top_result_xpath = '//*[@id="root"]/div/div[2]/div[1]/div[3]/div[2]/div/div/div/div/div[4]/a/div[2]/div[1]'
    top_result_button = wait.until(EC.element_to_be_clickable((By.XPATH, top_result_xpath)))
    top_result_button.click()
    
#interact with number datapoint 

#interact with select datapoint 
def voteOnSelectDatapoint(driver, wait):
    try:
        for _ in range(6):  # Assuming there are 6 votable tags
            # Re-query for votable tags to get the updated list
            votableTags_selector = "#root > div > div:nth-child(2) > div.mainLayoutWrapper > div.mainArea > div:nth-child(1) > div > div > div > div.container-fluid > div.resourceListAndQuestCommentsWrapper > div.resourceListMegaWrapper > div > div.resourceList > div:nth-child(1) > div.resourceRight > div > div:nth-child(1) > div"
            votableTags = wait.until(EC.presence_of_all_elements_located((By.CSS_SELECTOR, votableTags_selector)))

            if not votableTags:
                print("No votable tags found")
                break

            votableTag = votableTags[0]  # Interact with the first tag in the updated list
            driver.execute_script("arguments[0].scrollIntoView(true);", votableTag)
            try:
                votableTag.click()
            except ElementClickInterceptedException:
                driver.execute_script("arguments[0].click();", votableTag)

            TopOption_xpath = '//*[@id="root"]/div/div[2]/div[1]/div[6]/div[1]/div/div/div/div[2]/div[2]/div[2]/div/div[2]/div[1]/div[2]/div/div[1]/div[2]/div/div[1]'
            TopOption_button = wait.until(EC.element_to_be_clickable((By.XPATH, TopOption_xpath)))
            driver.execute_script("arguments[0].scrollIntoView(true);", TopOption_button)
            try:
                TopOption_button.click()
            except ElementClickInterceptedException:
                driver.execute_script("arguments[0].click();", TopOption_button)

            closeDropdown_xpath = '//*[@id="root"]/div/div[2]/div[1]/div[6]/div[1]/div/div/div/div[2]/div[2]/div[2]/div/div[2]/div[1]/div[2]/div/div[1]/div[2]/div/div[1]'
            closeDropdown_button = wait.until(EC.element_to_be_clickable((By.XPATH, closeDropdown_xpath)))
            driver.execute_script("arguments[0].scrollIntoView(true);", closeDropdown_button)
            try:
                closeDropdown_button.click()
            except ElementClickInterceptedException:
                driver.execute_script("arguments[0].click();", closeDropdown_button)

            time.sleep(1)  # Optional delay

    except TimeoutException:
        print("Timeout occurred while waiting for elements.")
    except NoSuchElementException:
        print("One or more elements could not be found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")



try:
    driver.maximize_window()
    email_address = CreateEmail()  # Capture the email address
    RegisterFlow(email_address)  # Pass email_address to RegisterFlow
    time.sleep(30)
    message_id = getVerificationEmailID(email_address)  # Pass email_address to getVerificationEmail
    getVerificationLink(message_id)
    # Get the bearer token
    access_token = bearerToken()
    if access_token:
        #post_urls = votingAPIs(access_token)  # Pass the access token to the votingAPIs function
        acceptInvite(access_token)
        saveQuest(access_token)
    else:
        print("Failed to retrieve access token.")

except NoSuchElementException as e:
    print("Element not found:", e)
except TimeoutException as e:
    print("Loading took too much time:", e)
except Exception as e:
    print("An error occurred:", e)

finally:
    time.sleep(15)
    driver.quit()  # This will close the browser