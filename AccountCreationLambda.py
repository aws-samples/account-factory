
####
 # Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy of this
 # software and associated documentation files (the "Software"), to deal in the Software
 # without restriction, including without limitation the rights to use, copy, modify,
 # merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 # permit persons to whom the Software is furnished to do so.
 #
 # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 # INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 # PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 # OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 # SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 #### 


#!/usr/bin/env python

from __future__ import print_function
import boto3
import botocore
import time
import sys
import argparse
import os
import urllib
import json
from botocore.vendored import requests

'''AWS Organizations Create Account and Provision Resources via CloudFormation

This module creates a new account using Organizations, then calls CloudFormation to deploy baseline resources within that account via a local tempalte file.

'''

__version__ = '1.0'
__author__ = '@VKK@'
__email__ = 'vkkuchib@'

def get_client(service):
  client = boto3.client(service)
  return client

def create_account(accountname,accountemail,accountrole,access_to_billing,scp,root_id):
    account_id = 'None'
    client = get_client('organizations')
    try:
        create_account_response = client.create_account(Email=accountemail, AccountName=accountname,
                                                        RoleName=accountrole,
                                                        IamUserAccessToBilling=access_to_billing)
    except botocore.exceptions.ClientError as e:
        print(e)
        sys.exit(1)
    #time.sleep(30)
    create_account_status_response = client.describe_create_account_status(CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
    account_id = create_account_status_response.get('CreateAccountStatus').get('AccountId')
    while(account_id is None ):
        create_account_status_response = client.describe_create_account_status(CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
        account_id = create_account_status_response.get('CreateAccountStatus').get('AccountId')
    #move_response = client.move_account(AccountId=account_id,SourceParentId=root_id,DestinationParentId=organization_unit_id)
    return(create_account_response,account_id)


def get_template(sourcebucket,baselinetemplate):
    

    '''
        Read a template file and return the contents
    '''
    #print("Reading resources from " + templatefile)
    s3 = boto3.resource('s3')
    #obj = s3.Object('cf-to-create-lambda','5-newbaseline.yml')
    obj = s3.Object(sourcebucket,baselinetemplate)
    return obj.get()['Body'].read().decode('utf-8') 


def delete_default_vpc(credentials,currentregion):
    #print("Default VPC deletion in progress in {}".format(currentregion))
    ec2_client = boto3.client('ec2',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=currentregion)

    vpc_response = ec2_client.describe_vpcs()
    for i in range(0,len(vpc_response['Vpcs'])):
        if((vpc_response['Vpcs'][i]['InstanceTenancy']) == 'default'):
            default_vpcid = vpc_response['Vpcs'][0]['VpcId']

    subnet_response = ec2_client.describe_subnets()
    subnet_delete_response = []
    default_subnets = []
    for i in range(0,len(subnet_response['Subnets'])):
        if(subnet_response['Subnets'][i]['VpcId'] == default_vpcid):
            default_subnets.append(subnet_response['Subnets'][i]['SubnetId'])
    for i in range(0,len(default_subnets)):
        subnet_delete_response.append(ec2_client.delete_subnet(SubnetId=default_subnets[i],DryRun=False))
    
    #print("Default Subnets" + currentregion + "Deleted.")

    igw_response = ec2_client.describe_internet_gateways()
    for i in range(0,len(igw_response['InternetGateways'])):
        for j in range(0,len(igw_response['InternetGateways'][i]['Attachments'])):
            if(igw_response['InternetGateways'][i]['Attachments'][j]['VpcId'] == default_vpcid):
                default_igw = igw_response['InternetGateways'][i]['InternetGatewayId']
    #print(default_igw)
    detach_default_igw_response = ec2_client.detach_internet_gateway(InternetGatewayId=default_igw,VpcId=default_vpcid,DryRun=False)
    delete_internet_gateway_response = ec2_client.delete_internet_gateway(InternetGatewayId=default_igw)
    
    #print("Default IGW " + currentregion + "Deleted.")

    time.sleep(10)
    delete_vpc_response = ec2_client.delete_vpc(VpcId=default_vpcid,DryRun=False)
    print("Deleted Default VPC in {}".format(currentregion))
    return delete_vpc_response

def create_custom_vpc(credentials,stackregion,AZ1Name,AZ2Name,VPCCIDR,SubnetAPublicCIDR,SubnetBPublicCIDR,SubnetAPrivateCIDR,SubnetBPrivateCIDR,VPCName):
    #print(credentials,stackregion,AZ1Name,AZ2Name,VPCCIDR,SubnetAPublicCIDR,SubnetBPublicCIDR,SubnetAPrivateCIDR,SubnetBPrivateCIDR)
    ec2 = boto3.client('ec2', aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=stackregion)

    # create VPC
    vpc = ec2.create_vpc(CidrBlock=VPCCIDR)
    # # we can assign a name to vpc, or any resource, by using tag
    #vpc.create_tags(Tags=[{"Key": "Name", "Value": VPCName}])
    # vpc.wait_until_available()
    vpc_id = vpc['Vpc']['VpcId']
    create_tags_response = ec2.create_tags(Resources = [vpc_id], Tags = [ {'Key' : 'Name' , 'Value' : VPCName}])
    print("VPC ID : {}".format(vpc_id))

    #create an EIP for NAT Gateway
    eipnatgwA = ec2.allocate_address(Domain='vpc')
    eipnatgwB = ec2.allocate_address(Domain='vpc')
    print("EIP for NatGW A : {}".format(eipnatgwA['AllocationId']))
    print("EIP for NatGW B : {}".format(eipnatgwB['AllocationId']))


    # create then attach internet gateway
    ig = ec2.create_internet_gateway()
    ig_id = ig['InternetGateway']['InternetGatewayId']
    ec2.attach_internet_gateway(InternetGatewayId=ig_id,VpcId=vpc_id)
    print("InternetGateway : {}".format(ig_id))


    # create a route table and a public route
    public_route_table = ec2.create_route_table(VpcId=vpc_id)
    public_route_table_id = public_route_table['RouteTable']['RouteTableId']
    public_route = ec2.create_route(DestinationCidrBlock='0.0.0.0/0',GatewayId=ig_id,RouteTableId=public_route_table_id)
    print("Public Route Table ID : {}".format(public_route_table_id))

    

    # create subnets
    publicsubnetA = ec2.create_subnet(AvailabilityZone=AZ1Name,CidrBlock=SubnetAPublicCIDR, VpcId=vpc_id)
    publicsubnetB = ec2.create_subnet(AvailabilityZone=AZ2Name,CidrBlock=SubnetBPublicCIDR, VpcId=vpc_id)
    public_subnetA_id = publicsubnetA['Subnet']['SubnetId']
    public_subnetB_id = publicsubnetB['Subnet']['SubnetId']
    print("Public SubnetA ID : {}".format(public_subnetA_id))
    print("Public SubnetB ID : {}".format(public_subnetB_id))

    privatesubnetA = ec2.create_subnet(AvailabilityZone=AZ1Name,CidrBlock=SubnetAPrivateCIDR, VpcId=vpc_id)
    privatesubnetB = ec2.create_subnet(AvailabilityZone=AZ2Name,CidrBlock=SubnetBPrivateCIDR, VpcId=vpc_id)
    private_subnetA_id = privatesubnetA['Subnet']['SubnetId']
    private_subnetB_id = privatesubnetB['Subnet']['SubnetId']
    print("Private SubnetA ID : {}".format(private_subnetA_id))
    print("Private SubnetB ID : {}".format(private_subnetB_id))
    

    # associate the route table with the subnet
    public_route_table_associationA = ec2.associate_route_table(SubnetId=public_subnetA_id,RouteTableId=public_route_table_id)
    public_route_table_associationB = ec2.associate_route_table(SubnetId=public_subnetB_id,RouteTableId=public_route_table_id)
    print("Public Route Table Association ID for Subnet A : {}".format(public_route_table_associationA['AssociationId']))
    print("Public Route Table Association ID for Subnet B : {}".format(public_route_table_associationB['AssociationId']))


    # create then attach a NAT gateway
    ngwsubnetA = ec2.create_nat_gateway(AllocationId=eipnatgwA['AllocationId'],SubnetId=public_subnetA_id)
    ngwsubnetB = ec2.create_nat_gateway(AllocationId=eipnatgwB['AllocationId'],SubnetId=public_subnetB_id)
    ngwsubnetA_id = ngwsubnetA['NatGateway']['NatGatewayId']
    ngwsubnetB_id = ngwsubnetB['NatGateway']['NatGatewayId']
    print("NAT GW in Subnet A : {}".format(ngwsubnetA_id))
    print("NAT GW in Subnet B : {}".format(ngwsubnetB_id))

    time.sleep(60)
    
    private_route_table_A = ec2.create_route_table(VpcId=vpc_id)
    private_route_table_A_id = private_route_table_A['RouteTable']['RouteTableId']
    private_route_A = ec2.create_route(DestinationCidrBlock='0.0.0.0/0',NatGatewayId=ngwsubnetA_id,RouteTableId=private_route_table_A_id)
    print("Private Route Table A ID : {}".format(private_route_table_A_id))
    
    private_route_table_B = ec2.create_route_table(VpcId=vpc_id)
    private_route_table_B_id = private_route_table_B['RouteTable']['RouteTableId']
    private_route_B = ec2.create_route(DestinationCidrBlock='0.0.0.0/0',NatGatewayId=ngwsubnetB_id,RouteTableId=private_route_table_B_id)
    print("Private Route Table B ID : {}".format(private_route_table_B_id))
    
    private_route_table_associationA = ec2.associate_route_table(SubnetId=private_subnetA_id,RouteTableId=private_route_table_A_id)
    private_route_table_associationB = ec2.associate_route_table(SubnetId=private_subnetB_id,RouteTableId=private_route_table_B_id)
    print("Private Route Table Association ID for Subnet A : {}".format(private_route_table_associationA['AssociationId']))
    print("Private Route Table Association ID for Subnet B : {}".format(private_route_table_associationB['AssociationId']))

def deploy_resources(credentials, template, stackname, stackregion, adminusername, adminpassword,account_id,newrole_arn):

    '''
        Create a CloudFormation stack of resources within the new account
    '''

    datestamp = time.strftime("%d/%m/%Y")
    client = boto3.client('cloudformation',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=stackregion)
    print("Creating stack " + stackname + " in " + account_id)
    creating_stack = True
    while creating_stack is True:
        try:
            creating_stack = False
            create_stack_response = client.create_stack(
                StackName=stackname,
                TemplateBody=template,
                Parameters=[
                    {
                        'ParameterKey' : 'AdminUsername',
                        'ParameterValue' : adminusername
                    },
                    {
                        'ParameterKey' : 'AdminPassword',
                        'ParameterValue' : adminpassword
                    },
                    {
                        'ParameterKey' : 'NewRoleArn',
                        'ParameterValue' : newrole_arn
                    }
                ],
                NotificationARNs=[],
                Capabilities=[
                    'CAPABILITY_NAMED_IAM',
                ],
                OnFailure='ROLLBACK',
                Tags=[
                    {
                        'Key': 'ManagedResource',
                        'Value': 'True'
                    },
                    {
                        'Key': 'DeployDate',
                        'Value': datestamp
                    }
                ]
            )
        except botocore.exceptions.ClientError as e:
            creating_stack = True
            print(e)
            print("Retrying...")
            time.sleep(10)

    stack_building = True
    print("Stack creation in process...")
    print(create_stack_response)
    while stack_building is True:
        event_list = client.describe_stack_events(StackName=stackname).get("StackEvents")
        stack_event = event_list[0]

        if (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
           stack_event.get('ResourceStatus') == 'CREATE_COMPLETE'):
            stack_building = False
            print("Stack construction complete.")
        elif (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
              stack_event.get('ResourceStatus') == 'ROLLBACK_COMPLETE'):
            stack_building = False
            print("Stack construction failed.")
            sys.exit(1)
        else:
            print(stack_event)
            print("Stack building . . .")
            time.sleep(10)
    stack = client.describe_stacks(StackName=stackname)
    return stack

def assume_role(account_id, account_role):
    sts_client = boto3.client('sts')
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + account_role
    assuming_role = True
    while assuming_role is True:
        try:
            assuming_role = False
            assumedRoleObject = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="NewAccountRole"
            )
        except botocore.exceptions.ClientError as e:
            assuming_role = True
            print(e)
            print("Retrying...")
            time.sleep(30)

    # From the response that contains the assumed role, get the temporary
    # credentials that can be used to make subsequent API calls
    return assumedRoleObject['Credentials']

def get_ou_name_id(root_id,organization_unit_name):

    ou_client = get_client('organizations')
    list_of_OU_ids = []
    list_of_OU_names = []
    ou_name_to_id = {}

    list_of_OUs_response = ou_client.list_organizational_units_for_parent(ParentId=root_id)
    
    for i in list_of_OUs_response['OrganizationalUnits']:
        list_of_OU_ids.append(i['Id'])
        list_of_OU_names.append(i['Name'])
        
    if(organization_unit_name not in list_of_OU_names):
        print("The provided Organization Unit Name doesnt exist. Creating an OU named: {}".format(organization_unit_name))
        try:
            ou_creation_response = ou_client.create_organizational_unit(ParentId=root_id,Name=organization_unit_name)
            for k,v in ou_creation_response.items():
                for k1,v1 in v.items():
                    if(k1 == 'Name'):
                        organization_unit_name = v1
                    if(k1 == 'Id'):
                        organization_unit_id = v1
        except botocore.exceptions.ClientError as e:
            print("Error in creating the OU: {}".format(e))
            respond_cloudformation(event, "FAILED", { "Message": "Could not list out AWS Organization OUs. Account creation Aborted."})

    else:
        for i in range(len(list_of_OU_names)):
            ou_name_to_id[list_of_OU_names[i]] = list_of_OU_ids[i]
        organization_unit_id = ou_name_to_id[organization_unit_name]
    
    return(organization_unit_name,organization_unit_id)

def create_newrole(newrole,top_level_account,credentials,newrolepolicy):
    iam_client = boto3.client('iam',aws_access_key_id=credentials['AccessKeyId'],
                                  aws_secret_access_key=credentials['SecretAccessKey'],
                                  aws_session_token=credentials['SessionToken'])
    print("arn:aws:iam::"+top_level_account+":root")
    trust_policy_document = json.dumps( 
                                        {
                                          "Version": "2012-10-17",
                                          "Statement": [
                                            {
                                              "Effect": "Allow",
                                              "Principal": {
                                                "AWS": "arn:aws:iam::"+top_level_account+":root"
                                              },
                                              "Action": "sts:AssumeRole"
                                            }
                                          ]
                                        } 
                                    )
    print(trust_policy_document)
    #new_role_policy = json.dumps(newrolepolicy)
    print(newrolepolicy)
    try:
        create_role_response = iam_client.create_role(RoleName=newrole,AssumeRolePolicyDocument=trust_policy_document,Description=newrole,MaxSessionDuration=3600)
        print(create_role_response['Role']['Arn'])
        
    except botocore.exceptions.ClientError as e:    
        print("Error Occured in creating a role : {}",format(e))
    try:
        #attach_policy_response = iam_client.attach_role_policy(RoleName=newrole,PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        update_role_response = iam_client.put_role_policy(RoleName=newrole,PolicyName='NewRolePolicy',PolicyDocument=newrolepolicy)
    except botocore.exceptions.ClientError as e:
        print("Error attaching policy to the role : {}".format(e))
    
    print("{},{},{}".format(newrole,top_level_account,credentials))
    return create_role_response['Role']['Arn']

def selfinvoke(event,status):
    lambda_client = boto3.client('lambda')
    function_name = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    event['RequestType'] = status
    print('invoking itself ' + function_name)
    response = lambda_client.invoke(FunctionName=function_name, InvocationType='Event',Payload=json.dumps(event))

def respond_cloudformation(event, status, data=None):
    responseBody = {
        'Status': status,
        'Reason': 'See the details in CloudWatch Log Stream',
        'PhysicalResourceId': event['ServiceToken'],
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': data
    }

    print('Response = ' + json.dumps(responseBody))
    print(event)
    requests.put(event['ResponseURL'], data=json.dumps(responseBody))

def delete_respond_cloudformation(event, status, data=None):
    responseBody = {
        'Status': status,
        'Reason': 'See the details in CloudWatch Log Stream',
        'PhysicalResourceId': event['ServiceToken'],
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': data
    }

    print('Response = ' + json.dumps(responseBody))
    print(event)
    lambda_client = get_client('lambda')
    function_name = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    print('Deleting Lambda')
    lambda_client.delete_function(FunctionName=function_name)
    requests.put(event['ResponseURL'], data=json.dumps(responseBody))        

def main(event,context):
    print(event)
    client = get_client('organizations')
    accountname = os.environ['accountname']
    accountemail = os.environ['accountemail']
    newrole = os.environ['newrole']
    newrolepolicy = os.environ['newrolepolicy']
    organization_unit_name = os.environ['organizationunitname']
    accountrole = 'OrganizationAccountAccessRole'
    stackname = os.environ['stackname']
    stackregion = os.environ['stackregion']
    adminusername = os.environ['adminusername']
    adminpassword = os.environ['adminpassword']
    sourcebucket = os.environ['sourcebucket']
    baselinetemplate = os.environ['baselinetemplate']
    AZ1Name = os.environ['AZ1Name']
    AZ2Name = os.environ['AZ2Name']
    VPCCIDR = os.environ['VPCCIDR']
    SubnetAPublicCIDR = os.environ['SubnetAPublicCIDR']
    SubnetBPublicCIDR = os.environ['SubnetBPublicCIDR']
    SubnetAPrivateCIDR = os.environ['SubnetAPrivateCIDR']
    SubnetBPrivateCIDR = os.environ['SubnetBPrivateCIDR']
    VPCName = os.environ['VPCName']
    access_to_billing = "DENY"
    scp = None

    if (event['RequestType'] == 'Create'):
        selfinvoke(event,'Wait')
        top_level_account = event['ServiceToken'].split(':')[4]
        #print(top_level_account)
        org_client = get_client('organizations')
        #print("about to try")
        try:
            list_roots_response = org_client.list_roots()
            #print(list_roots_response)
            root_id = list_roots_response['Roots'][0]['Id']
        except:
            root_id = "Error"
    
        if root_id  is not "Error":
            print("Creating new account: " + accountname + " (" + accountemail + ")")
            list_policy_response = org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')
            policy_list = {}
            for i in range(0,len(list_policy_response['Policies'])):
                policy_list.update({list_policy_response['Policies'][i]['Name'] : list_policy_response['Policies'][i]['Id']})
            if 'DenySCP' not in policy_list.keys():
                assume_role_policy_document = json.dumps(
                                                {
                                                    "Version": "2012-10-17",
                                                    "Statement": [
                                                        {
                                                            "Sid": "Stmt1536433535000",
                                                            "Effect": "Deny",
                                                            "Action": [
                                                                "organizations:*"
                                                            ],
                                                            "Resource": [
                                                                "*"
                                                            ]
                                                        }
                                                    ] 
                                                } )
    
                scp_create_response = org_client.create_policy(Description='DenySCP',Name='DenySCP',Type='SERVICE_CONTROL_POLICY',Content = assume_role_policy_document)
                scp_id= scp_create_response['Policy']['PolicySummary']['Id']
            else:
                for scpname,scpid in policy_list.items():
                    if(scpname == 'DenySCP'):
                        scp_id = scpid

            ### List the available AWS Oranization OU's 
            #if(organization_unit_name is not None):
                #(organization_unit_name,organization_unit_id) = get_ou_name_id(root_id,organization_unit_name)
            (create_account_response,account_id) = create_account(accountname,accountemail,accountrole,access_to_billing,scp,root_id)
            #print(create_account_response)
            print("Created acount:{}\n".format(account_id))
            
            
            attach_policy_response = org_client.attach_policy(PolicyId=scp_id,TargetId=account_id)
            credentials = assume_role(account_id, accountrole)
            
            #print("Deploying resources from " + templatefile + " as " + stackname + " in " + stackregion)
            # template = get_template(sourcebucket,baselinetemplate)
            # stack = deploy_resources(credentials, template, stackname, stackregion, adminusername, adminpassword,account_id)
            # print(stack)

            ec2_client = get_client('ec2')
            try:
                custom_vpc_id = create_custom_vpc(credentials,stackregion,AZ1Name,AZ2Name,VPCCIDR,SubnetAPublicCIDR,SubnetBPublicCIDR,SubnetAPrivateCIDR,SubnetBPrivateCIDR,VPCName)
            except:
                print("There might be an error creating the custom VPC. Please log in the account and validate the VPC setup.")
            try:
                newrole_arn = create_newrole(newrole,top_level_account,credentials,newrolepolicy)
            except:
                print("There might be an error creating the specified role. Please log in the account and validate the role definition.")
                newrole_arn = "arn:aws:iam::"+account_id+":role/"+newrole
            
            print(newrole_arn)
            template = get_template(sourcebucket,baselinetemplate)
            stack = deploy_resources(credentials, template, stackname, stackregion, adminusername, adminpassword,account_id,newrole_arn)
            print(stack)

            print("Resources deployment for account " + account_id + " (" + accountemail + ") complete !!")
            
            
            
            #regions = ["us-west-2","us-west-1","us-east-1","us-east-2"]
            regions = []
            regions_response = ec2_client.describe_regions()
            for i in range(0,len(regions_response['Regions'])):
                regions.append(regions_response['Regions'][i]['RegionName']) 
            for r in regions:
                try:
                    #print('In the VPC deletion block - {}'.format(r))
                    delete_vpc_response = delete_default_vpc(credentials,r)
                except botocore.exceptions.ClientError as e:
                    print("An error occured while deleting Default VPC in {}. Error: {}".format(r,e))
                    i+=1

            root_id = client.list_roots().get('Roots')[0].get('Id')
            print(root_id)
            print('Outside try block - {}'.format(organization_unit_name))
            if(organization_unit_name!='None'):
                try:
                    (organization_unit_name,organization_unit_id) = get_ou_name_id(root_id,organization_unit_name)
                    move_response = org_client.move_account(AccountId=account_id,SourceParentId=root_id,DestinationParentId=organization_unit_id)
                    
                except Exception as ex:
                    template = "An exception of type {0} occurred. Arguments:\n{1!r} "
                    message = template.format(type(ex).__name__, ex.args)
                    print(message)
            if scp is not None:
                attach_policy_response = client.attach_policy(PolicyId=scp, TargetId=account_id)
                print("Attach policy response "+str(attach_policy_response))
            #respond_cloudformation(event, "SUCCESS", { "Message": "Account Created! URL : https://" +account_id+".signin.aws.amazon.com/console", "AccountID" : account_id, "LoginURL" : "https://console.aws.amazon.com", "Username" : adminusername })
            respond_cloudformation(event, "SUCCESS", { "Message": "Account Created!", "Login URL" : "https://" +account_id+".signin.aws.amazon.com/console", "AccountID" : account_id, "Username" : adminusername, "Role" : newrole })
        else:
            print("Cannot access the AWS Organization ROOT. Contact the master account Administrator for more details.")
            sys.exit(1)

    if(event['RequestType'] == 'Update'):
        print("Template in Update Status")
        respond_cloudformation(event, "SUCCESS", { "Message": "Resource update successful!" })
        #respond_cloudformation(event, "SUCCESS", { "Message": "Account Created!","Login URL : "https://" +account_id+".signin.aws.amazon.com/console", "AccountID" : account_id, "Username" : adminusername, "Role" : newrole })

    
    # elif(event['RequestType'] == 'Wait'):
    #     # account_status = 'IN_PROGRESS'
    #     # create_account_status_response = client.describe_create_account_status(CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
    #     # while account_status == 'IN_PROGRESS':
    #     #     create_account_status_response = client.describe_create_account_status(CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
    #     #     print("Create In Progress. Create Account Status Response : {} \n".format(create_account_status_response))
    #     #     account_status = create_account_status_response.get('CreateAccountStatus').get('State')
    #     #     if account_status == 'SUCCEEDED':
    #     #         account_id = create_account_status_response.get('CreateAccountStatus').get('AccountId')
    #     #         print("Account Creation SUCCEEDED. Create Account Status Response for account URL : {}\n".format(create_account_status_response))
    #     #     elif account_status == 'FAILED':
    #     #         print("Account creation failed: " + create_account_status_response.get('CreateAccountStatus').get('FailureReason'))
    #     time.sleep(30)
    #     respond_cloudformation(event, "Aborted", { "Message": "Retuned back form the wait condition !!" })
    #     exit()
            

    elif(event['RequestType'] == 'Delete'):
        try:
            delete_respond_cloudformation(event, "SUCCESS", {"Message":"Delete Request Initiated. Deleting Lambda Function."})
        except:
            print("Couldnt initiate delete response.")

