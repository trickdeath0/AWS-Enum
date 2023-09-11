import subprocess
import random
import json
import time

def logo():
	# Define Logo
	logo_text = "AWS Enum"
	
	box_options = [
	    "-d diamonds -a hcvc",
	    "-d unicornthink",
	    "-d dog -a c",
	    "-d nuke",
	]
	
	selected_option = random.choice(box_options)

	figlet_process = subprocess.Popen(["figlet", logo_text], stdout=subprocess.PIPE)
	boxes_command = ["boxes"] + selected_option.split()
	boxes_process = subprocess.Popen(boxes_command, stdin=figlet_process.stdout, stdout=subprocess.PIPE)

	output, _ = boxes_process.communicate()

	print(output.decode())
	print("Author: Shay Giladi")


def configureUser():
	# Define your AWS profile name, Access Key ID, and Secret Access Key
	aws_profile_name = input("Enter user name: ")
	aws_access_key_id = input("<your-access-key-id>: ")
	aws_secret_access_key = input("<your-secret-access-key>: ")
	aws_region_name = input("Enter the region: ")
	aws_output_format = input("Enter format: ")

	command = f"aws configure --profile {aws_profile_name}"
	process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	input_data = f"{aws_access_key_id}\n{aws_secret_access_key}\n{aws_region_name}\n{aws_output_format}\n"
	process.stdin.write(input_data.encode())
	process.stdin.flush()
	process.communicate()
	
	return aws_profile_name, aws_region_name


def selectUser():
	print("Collection the users from .aws/config...")
	time.sleep(0.5)
	command = "cat ~/.aws/config | grep -E '^\[.*\s' | sed 's/\[profile \([^]]*\)\]/\\1/'"
	output = subprocess.check_output(command, shell=True, text=True)
	profile_names = output.strip().split('\n')
	for index, name in enumerate(profile_names):
		print(f'{index+1}. {name}')
		
	while True:
		try:
			select_profile_name = int(input(f"Select a profile (1-{len(profile_names)}): "))	
			    
			if 1 <= select_profile_name <= len(profile_names):
				print("\n")
				break
			else:
				raise ValueError
		except ValueError:
			print(f"Invalid input. Please enter a valid number between 1 and {len(profile_names)}.")
			
	selected_profile = profile_names[select_profile_name - 1]
	command = f"grep -E '^\[profile {selected_profile}]' -A 2 ~/.aws/config | grep 'region' | sed 's/region\\s*=\\s*//'"
	region = subprocess.check_output(command, shell=True, text=True)
	if region == "":
		region = "us-west-2"

	return selected_profile, region.strip()


def get_user_arn(aws_profile_name):
	print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	print("~	Collect information from account	~")
	print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	command = f"aws sts get-caller-identity --profile {aws_profile_name}"
	try:
		output = subprocess.check_output(command, shell=True, text=True)
		caller_identity = json.loads(output)
		arn = caller_identity.get("Arn", "Arn not found")
		print(output)
		arnUser = arn.split("/")
		arn_user_name = arnUser[1]
		return arn_user_name
	except subprocess.CalledProcessError as e:
		print(f"Error: {e}")
		return None

def list_attached_user_policies(arn_user_name, aws_profile_name):
	print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	print("~	Collect list attached user policies	~")
	print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	command = f"aws iam list-attached-user-policies --user-name {arn_user_name} --profile {aws_profile_name}"
	try:
		output = subprocess.check_output(command, shell=True, text=True)
		print(output)

		policy_data = json.loads(output)
		policyList = []

		print("----------------------------------------------------------")
		attached_policies = policy_data.get("AttachedPolicies", [])
		for index, policy in enumerate(attached_policies):
			policy_arn = policy.get("PolicyArn", "PolicyArn not found")
			print(f"{index + 1}. {policy_arn}")
			policyList.append(policy_arn)

		print("----------------------------------------------------------")

		return policyList
	except subprocess.CalledProcessError as e:
		print(f"Error: {e}")
		return []

def get_policy(aws_profile_name, policy_arn):
	print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	print("~		get policy 			~")
	print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	command = f"aws iam get-policy --policy-arn {policy_arn} --profile {aws_profile_name}"
	try:
		output = subprocess.check_output(command, shell=True, text=True)
		print(output)

		policy_data = json.loads(output)
		policy = policy_data.get("Policy", {})
		default_version_id = policy.get("DefaultVersionId", "DefaultVersionId not found")
		#print(f"DefaultVersionId: {default_version_id}")
		return default_version_id
	except subprocess.CalledProcessError as e:
		print(f"Error: {e}")

def get_policy_version(aws_profile_name, policy_arn, default_version_id):
	print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	print("~		get policy version		~")
	print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")	
	command = f"aws iam get-policy-version --policy-arn {policy_arn} --version-id {default_version_id} --profile {aws_profile_name}"
	try:
		output = subprocess.check_output(command, shell=True, text=True)
		print(output)
	except subprocess.CalledProcessError as e:
		print(f"Error: {e}")

def list_functions(aws_profile_name, aws_profile_region):
	command = f"aws lambda list-functions --profile {aws_profile_name} --region {aws_profile_region}"
	try:
		output = subprocess.check_output(command, shell=True, text=True)
		print(output)
		
		function_data = json.loads(output)
		functions = function_data.get("Functions", [])
		function_names = []
		
		for function in functions:
			function_name = function.get("FunctionName", "FunctionName not found")
			function_names.append(function_name)

		if len(function_names) >= 1:
			return function_names[0]
		else:
			Exception

	except subprocess.CalledProcessError as e:
		print(f"Error: {e}")
		return None

def get_lambda_policy(aws_profile_name, aws_region_name, function_name):
	command = f"aws lambda get-policy --function-name {function_name} --region {aws_region_name} --profile {aws_profile_name}"				
	try:
		output = subprocess.check_output(command, shell=True, text=True)
		print(output)

	except subprocess.CalledProcessError as e:
		print(f"Error: {e}")
		

def enum_aws(aws_profile_name, aws_region_name):
	while True:
		print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
		print("~\t	E N U M E R A T I O N \t~")
		print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
		print("1. List attached user policies")
		print("2. List S3 buckets")
		print("3. List Lambda functions")
		print("q. Quit")

		option = input("Enum::>> ")

		if option == "1":
			print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
			print("~\tCollect information from user\t~")
			print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
			arn_user_name = get_user_arn(aws_profile_name)
			if arn_user_name is not None:
				policyList = list_attached_user_policies(arn_user_name, aws_profile_name)
				if policyList:
					while True:
						try:
							select_arn_policy = int(input(f"Select a policy (1-{len(policyList)}): "))
							if 1 <= select_arn_policy <= len(policyList):
								print("\n")
								default_version_id = get_policy(aws_profile_name, policyList[select_arn_policy - 1])
								get_policy_version(aws_profile_name, policyList[select_arn_policy - 1], default_version_id)
								break
							else:
								raise ValueError
						except ValueError:
							print(f"Invalid input. Please enter a valid number between 1 and {len(policyList)}.")

		elif option == "2":
			print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
			print("~\tCollect information from S3 Buckets\t~")
			print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
			command = f"aws s3 ls --profile {aws_profile_name}"
			try:
				output = subprocess.check_output(command, shell=True, text=True)
				print(output)
			except subprocess.CalledProcessError as e:
				print(f"Error: {e}")
		
		elif option == "3":
			print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
			print("~\tCollect information from Lambda Functions\t~")
			print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
			function_name = list_functions(aws_profile_name, aws_region_name)
			if function_name is not None:
				get_lambda_policy(aws_profile_name, aws_region_name, function_name)

		elif option == "q":
			break
		    
		else:
			print("Invalid option. Please enter a valid option (1, 2, 3 or q).")

	



if __name__=='__main__':
	logo()
	print("Do you have a configure user or want to create one?\n\t1. Configure new one\n\t2. Select from existing users")
	isConfig = 1
	aws_profile_name = ""
	while True:
		user_input = input(">> ")
	
		try:
			isConfig = int(user_input)
			if isConfig == 1 or isConfig == 2:
				break
			else:
				raise ValueError
		except ValueError:
			print("Invalid input. Please enter a valid number. [1 or 2]")
			
	if isConfig == 1:
		aws_profile_name, aws_region_name = configureUser()
	else:
		aws_profile_name, aws_region_name = selectUser()
		
	
	enum_aws(aws_profile_name, aws_region_name)
		
		
		
		
    
