import os
try:
	import requests
except ModuleNotFoundError:
	os.system("pip install requests")
try:
	import threading
except ModuleNotFoundError:
	os.system("pip install threading")
print("""
   _____                        _            __           
  / ___/      ______ _____     (_)___  _____/ /_____ _    
  \__ \ | /| / / __ `/ __ \   / / __ \/ ___/ __/ __ `/    
 ___/ / |/ |/ / /_/ / /_/ /  / / / / (__  ) /_/ /_/ /     
/____/|__/|__/\__,_/ .___/  /_/_/ /_/____/\__/\__,_/      
                  /_/    BY @vv1ck  - @TweakPY                
""")
def swap():
	global name,ext,eml,bio,num,target,csrf,sis
	url='https://www.instagram.com/accounts/edit/'
	headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
        'content-length': '288',
        'content-type': 'application/x-www-form-urlencoded',
        'cookie': f'mid=YQvmcwAEAAFVrBezgjwUhwEQuv3c; ig_did=6C10D114-3B6D-4E5E-9E35-5E808661CBAD; ig_nrcb=1; shbid="13126\05446165248972\0541659705862:01f79325778d8f311db6707a0a5683a2e7b8103e61c033c6aacec19b5095d28471538f81"; shbts="1628169862\05446165248972\0541659705862:01f797d7b6eea1b2af63f1feeff065ef36ea4e5d4b45da2e4d4e51b3668a5f6c27278edb"; csrftoken=7TFBnq5Pa2sP42w7uAjYmx0F0YiEkIS5; ds_user_id=46165248972; sessionid={sis}; rur="FTW\05446165248972\0541659797492:01f7b80292fea6e2dc5449b4be3d69f7d4c64373fac5cf9501ac1e9a6963207915612c5d"',
        'origin': 'https://www.instagram.com',
        'referer': 'https://www.instagram.com/accounts/edit/',
        'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
        'sec-ch-ua-mobile': '?0',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
        'x-asbd-id': '437806',
        'x-csrftoken': '7TFBnq5Pa2sP42w7uAjYmx0F0YiEkIS5',
        'x-ig-app-id': '936619743392459',
        'x-ig-www-claim': 'hmac.AR0EWvjix_XsqAIjAt7fjL3qLwQKCRTB8UMXTGL5j7pkgSqj',
        'x-instagram-ajax': '0c6674eae5a1',
        'x-requested-with': 'XMLHttpRequest'}
	data = {
		'first_name': name,
		'email': eml,
		'username': target,
		'phone_number': num,
		'biography': bio,
		'external_url': ext,
		'chaining_enabled': 'on',}
	oke=0 
	don=0
	okee=0
	err=0
	while True:
		send3= requests.post(url,headers=headers,data=data)
		if '"status":"ok"' in send3.text:
			print(f'[+] Done Swap  @{target}  By @vv1ck ..')
			don+=1
			if don==3:
				input('Enter to exit')
				exit()
			else:
				pass
		elif "This username isn't available. Please try another."in send3.text:
			print("[-] username isn't available !")
			oke += 1
			if oke == 50:
				input('Enter to exit')
				exit()
			else:
				pass
		elif '"message":"Please wait a few minutes before you try again."'in send3.text:
			print('[-] Please wait a few minutes before you try again')
			err+=1
			if err == 4:
				input('Enter to exit')
				exit()
			else:
				pass
		else:
			okee += 1
			print('[-] Not swap !')
			if okee == 50:
				input('Enter to exit')
				exit()
			else:
				pass
def send():
	global name,ext,eml,bio,num,target,csrf,sis,username,pess
	target=input('\n[+] Enter target : ')	
	swap()
def info():
	global name,ext,eml,bio,num,csrf,sis,username,pess
	urIN='https://www.instagram.com/accounts/edit/?__a=1'
	hedIN = {
		'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
		'accept-encoding': 'gzip, deflate, br',
		'accept-language': 'en-US,en;q=0.9',
		'cookie': 'mid=YQvmcwAEAAFVrBezgjwUhwEQuv3c; ig_did=6C10D114-3B6D-4E5E-9E35-5E808661CBAD; ig_nrcb=1; csrftoken='+csrf+'; ds_user_id=46165248972; sessionid='+sis+'; shbid="13126\05446165248972\0541659705862:01f79325778d8f311db6707a0a5683a2e7b8103e61c033c6aacec19b5095d28471538f81"; shbts="1628169862\05446165248972\0541659705862:01f797d7b6eea1b2af63f1feeff065ef36ea4e5d4b45da2e4d4e51b3668a5f6c27278edb"; rur="FTW\05446165248972\0541659794009:01f7831a803e51b9f45fb454e14601560d0fd1fc362879dbb3d5a21296d8726d15a794aa"',
		'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
		'sec-ch-ua-mobile': '?0',
		'sec-fetch-dest': 'document',
		'sec-fetch-mode': 'navigate',
		'sec-fetch-site': 'none',
		'sec-fetch-user': '?1',
		'upgrade-insecure-requests': '1',
		'user-agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'}
	datIN = {'__a': '1'}
	info = requests.get(urIN,headers=hedIN,data=datIN)
	try:
		name=str(info.json()['form_data']['first_name'])
		ext=str(info.json()['form_data']['external_url'])
		eml=str(info.json()['form_data']['email'])
		bio=str(info.json()['form_data']['biography'])
		num=str(info.json()['form_data']['phone_number'])
		send()
	except KeyError:
		print('[-] Ops Blocked Account')
		input('Enter to exit')
		exit()
def login():
	global csrf,sis,username,pess
	username=input('[+] Enter username: ')
	pess=input('[+] Enter password: ')
	log='https://www.instagram.com/accounts/login/ajax/'
	log_h={
		'Host': 'www.instagram.com',
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
		'Accept': '*/*',
		'Accept-Language': 'ar,en-US;q=0.7,en;q=0.3',
		'X-CSRFToken': '5o7PN96Y9Ln95EnlXN6t0pmCHDqdbect',
		'X-Instagram-AJAX': '1d6caaf37cd2',
		'X-IG-App-ID': '936619743392459',
		'X-ASBD-ID': '437806',
		'X-IG-WWW-Claim': '0',
		'Content-Type': 'application/x-www-form-urlencoded',
		'X-Requested-With': 'XMLHttpRequest',
		'Content-Length': '347',
		'Origin': 'https://www.instagram.com',
		'Connection': 'keep-alive',
		'Referer': 'https://www.instagram.com/accounts/login/',
		'Cookie': 'ig_did=7B796F1F-ADE7-429C-8ADB-9B131663E5E4; datr=2kDRYNWmjctteBSnOqogPrxv; csrftoken=5o7PN96Y9Ln95EnlXN6t0pmCHDqdbect; mid=YNIa4QALAAGoeESFP8axY9NfC9t3; ig_nrcb=1',
		'TE': 'Trailers'}
	log_dat={
		'username': username,
		'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:&:{pess}',
		'queryParams': "{}",
		'optIntoOneTap': 'false',
		'stopDeletionNonce ': "",
		'trustedDeviceRecords': "{}"}
	req1=requests.post(log, headers=log_h, data=log_dat)
	if '"authenticated":true' in req1.text:
		print('[+] Done login ..')
		csrf=req1.cookies['csrftoken']
		sis=req1.cookies['sessionid']
		info()
	elif ('checkpoint_required') in req1.text:
		print('[-] secure account !')
		input('Enter to exit')
		exit()
	elif ('"user":true,"authenticated":false') in req1.text:
		print('[-] The password is incorrect !')
		print('[-] Try again..')
		return login()
	elif ('"user":false') in req1.text:
		print("[-] Account not found !")
		input('Enter to exit')
		exit()
login()
