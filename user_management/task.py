import json
import boto3
import os

# xray: str = os.environ['XRAY_TRACING_SETTING']
# # If Tracing is Active, Patch libs
# if xray == 'Active':
#     from aws_xray_sdk.core import patch_all
#     patch_all()
client = boto3.client('cognito-idp')
user_pool = os.environ['USERPOOL']


def handler(event, context):
    print(event)
    if 'resolver' in event and 'arguments' in event:
        response = globals()[event['resolver']](event['arguments'])
    else:
        raise Exception('arguments are missing')

    return response


def listGroups(arguments):
    params = {
        'UserPoolId': user_pool
    }
    if 'limit' in arguments and arguments['limit'] != None:
        params['Limit'] = arguments['limit']
    if 'token' in arguments and arguments['token'] != None:
        params['NextToken'] = arguments['token']

    try:
        response = client.list_groups(**params)
        return getGroupsFromResponse(response)
    except Exception as e:
        print(e)
        raise


def listGroupsForUser(arguments):
    params = {}
    if 'username' in arguments and arguments['username'] != None:
        params['Username'] = arguments['username']
    else:
        raise KeyError('username is required')

    params['UserPoolId'] = user_pool

    try:
        response = client.admin_list_groups_for_user(**params)
        if 'Groups' in response:
            groups = [group['GroupName'] for group in response['Groups']]
            return groups
        else:
            return []
    except Exception as e:
        print(e)
        raise


def updateGroupsForUser(arguments):
    if 'username' not in arguments or arguments['username'] == None:
        raise KeyError('username is required')

    try:
        params = {}
        params['Username'] = arguments['username']
        params['UserPoolId'] = user_pool

        usergroups = client.admin_list_groups_for_user(
            UserPoolId=user_pool,
            Username=arguments['username'])

        if 'Groups' in usergroups:
            for group in usergroups['Groups']:
                client.admin_remove_user_from_group(
                    UserPoolId=user_pool,
                    Username=arguments['username'],
                    GroupName=group['GroupName']
                )

        for group in arguments['groups']:
            client.admin_add_user_to_group(
                UserPoolId=user_pool,
                Username=arguments['username'],
                GroupName=group['groupname']
            )
        return listGroupsForUser(arguments)
    except Exception as e:
        print(e)
        raise


def getGroupsFromResponse(response):
    if 'Groups' in response:
        groups = [group['GroupName'] for group in response['Groups']]
        return {
            "groups": groups,
            "nextToken": response['NextToken'] if 'NextToken' in response else None
        }
    else:
        return {}


def listUsers(arguments):
    params = {
        'UserPoolId': user_pool
    }
    if 'limit' in arguments and arguments['limit'] != None:
        params['Limit'] = arguments['limit']

    if 'token' in arguments and arguments['token'] != None:
        params['PaginationToken'] = arguments['token']

    try:
        response = client.list_users(**params)
        users = getUsersFromResponse(response)
        for user in users['users']:
            user['groups'] = listGroupsForUser(user)
        return users
    except Exception as e:
        print(e)
        raise


def getUsersFromResponse(response):
    users = []
    for user in response['Users']:
        users.append(getUserFromResponse(user))

    if 'PaginationToken' in response:
        nextToken = response['PaginationToken']
    elif 'NextToken' in response:
        nextToken = response['NextToken']
    else:
        nextToken = None

    return {
        'users': users,
        'nextToken': nextToken
    }


def getUserFromResponse(user):
    obj = {}
    attributes = user['UserAttributes'] if 'UserAttributes' in user else user['Attributes']

    for item in attributes:
        if item['Name'] == 'custom:displayName':
            obj['name'] = item['Value']

        if item['Name'] == 'email':
            obj['email'] = item['Value']

    obj['username'] = user['Username']
    obj['id'] = user['Username']

    return obj


def listUsersInGroup(arguments):
    params = {
        'UserPoolId': user_pool
    }
    if 'limit' in arguments and arguments['limit'] != None:
        params['Limit'] = arguments['limit']

    if 'token' in arguments and arguments['token'] != None:
        params['NextToken'] = arguments['token']

    if 'groupname' in arguments and arguments['groupname'] != None:
        params['GroupName'] = arguments['groupname']
    else:
        raise KeyError('groupname is required')

    try:
        response = client.list_users_in_group(**params)
        print(response)
        users = getUsersFromResponse(response)
        print(users)
        for user in users['users']:
            user['groups'] = listGroupsForUser(user)
        return users
    except Exception as e:
        print(e)
        raise


def getUserParams(arguments):
    params = {}
    params['UserPoolId'] = user_pool

    if 'user' not in arguments or arguments['user'] == None:
        raise KeyError('user is required')

    if 'username' in arguments['user'] and arguments['user']['username'] != None:
        params['Username'] = arguments['user']['username']
    else:
        raise KeyError('username is required')

    params['UserAttributes'] = []
    if 'email' in arguments['user'] and arguments['user']['email'] != None:
        params['UserAttributes'].append({
            'Name': 'email',
            'Value': arguments['user']['email']
        })
    else:
        raise KeyError('email is required')

    if 'name' in arguments['user'] and arguments['user']['name'] != None:
        params['UserAttributes'].append({
            'Name': 'custom:displayName',
            'Value': arguments['user']['name']
        })

    return params


def createUser(arguments):
    params = getUserParams(arguments)

    user = {}
    try:
        response = client.admin_create_user(**params)
        user = getUserFromResponse(response['User'])
    except Exception as e:
        print(e)
        raise

    try:
        if 'groups' in arguments['user'] \
                and arguments['user']['groups'] != None \
                and len(arguments['user']['groups']) > 0:
            user['groups'] = updateGroupsForUser(arguments['user'])
        else:
            user['groups'] = []
    except Exception as e:
        print(e)
        raise

    return user


def updateUser(arguments):
    params = getUserParams(arguments)
    user = {}

    try:
        client.admin_update_user_attributes(**params)
        response = client.admin_get_user(
            UserPoolId=user_pool,
            Username=arguments['user']['username'])
        print(response)
        user = getUserFromResponse(response)
    except Exception as e:
        print(e)
        raise

    try:
        if 'groups' in arguments['user'] \
                and arguments['user']['groups'] != None \
                and len(arguments['user']['groups']) > 0:
            user['groups'] = updateGroupsForUser(arguments['user'])
        else:
            user['groups'] = []
    except Exception as e:
        print(e)
        raise

    return user


def getUser(arguments):
    params = {}
    params['UserPoolId'] = user_pool

    if 'username' not in arguments or arguments['username'] == None:
        raise KeyError('username is required')

    user = {}
    try:
        response = client.admin_get_user(
            UserPoolId=user_pool,
            Username=arguments['username'])
        user = getUserFromResponse(response)
    except Exception as e:
        print(e)
        raise

    try:
        user['groups'] = listGroupsForUser(arguments)
    except Exception as e:
        print(e)
        raise

    return user


def deleteUser(arguments):
    if 'username' not in arguments or arguments['username'] == None:
        raise KeyError('username is required')

    try:
        client.admin_delete_user(
            UserPoolId=user_pool,
            Username=arguments['username'])
        return

    except Exception as e:
        print(e)
        raise


def setUserPassword(arguments):
    params = {}
    params['UserPoolId'] = user_pool

    if 'user' in arguments and 'username' in arguments['user'] and arguments['user']['username'] != None:
        params['Username'] = arguments['user']['username']
    else:
        raise KeyError('username is required')

    if 'password' in arguments and arguments['password'] != None:
        params['Password'] = arguments['password']
    else:
        raise KeyError('password is required')

    if 'permanent' in arguments and arguments['permanent'] != None:
        params['Permanent'] = arguments['permanent']

    try:
        client.admin_set_user_password(**params)
        return

    except Exception as e:
        print(e)
        raise
