import base64
import time
import hmac
import os
import hashlib
import six
import sys

import json
import pprint
import requests
from six.moves import urllib
import urllib as ul
import xmltodict

import exceptions

import yaml

global_vars = {
    'access_key': None,
    'secret_key': None,
    'iam_url': None,
    'is_secure': False,
}


common_headers = {
    # 'User-Agent': 'curl/7.35.0', # not required I guess
    'Content-Type': 'application/json',
    'Accept-Encoding': 'identity',
}

common_params_v2 = {
    'JCSAccessKeyId': global_vars['access_key'],
    'SignatureVersion': '2',
    'SignatureMethod': 'HmacSHA256',
    'Version': '2016-03-01',
    'Timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}


def setup_client_from_env_vars():
    """Populates client from environment variables."""
    setup_client(os.environ.get('ACCESS_KEY'),
                          os.environ.get('SECRET_KEY'),
                          os.environ.get('IAM_URL'))


def setup_client(access_key, secret_key, iam_url):
    global global_vars
    global_vars['access_key'] = access_key
    global_vars['secret_key'] = secret_key
    if iam_url is None:
        iam_url = "https://iam.ind-west-1.jiocloudservices.com"
    global_vars['iam_url'] = iam_url
    global common_params_v2
    common_params_v2['JCSAccessKeyId'] = access_key

def _get_utf8_value(value):
    """Get the UTF8-encoded version of a value."""
    if not isinstance(value, (six.binary_type, six.text_type)):
        value = str(value)
    if isinstance(value, six.text_type):
        return value.encode('utf-8')
    else:
        return value


def list_users():
    """ListUsers."""
    valid_optional_params = []
    optional_params = {}
    mandatory_params = {'Action': 'ListUsers'}
    return do_iam_request(valid_optional_params, optional_params, mandatory_params)

def do_iam_request(valid_optional_params, supplied_optional_params,
        supplied_mandatory_params=None):
    setup_client_from_env_vars()
    _ensure_global_vars_populated()
    request_dict = _create_valid_request_dictionary(
        valid_optional_params,
        supplied_optional_params,
        supplied_mandatory_params)
    global global_vars
    request_string = requestify(global_vars['iam_url'], request_dict)
    resp_dict = do_request('GET', request_string)
    return _remove_item_keys(resp_dict)

def _ensure_global_vars_populated():
    """Raises exception if global vars are not populated."""
    # TODO(himanshu): doing 'global global_vars' is error prone -- somebody
    # might forget to do it and this will cause all kind of bugs. Better we
    # write a method _populate_global_vars(key, value) and use only that to
    # populate global vars
    global global_vars
    for key in ['access_key', 'secret_key', 'iam_url']:
        if global_vars[key] is None:
            print 'Global variable %s not populated!!' % key 
            raise Exception


def do_request(method, url, headers=None):
    """
    Performs HTTP request, and returns response as an ordered dict.

    Method can be 'GET' (string).
    url, also a string, is the URL to make request to.
    headers, a dictionary, can contain request headers.
    """

    global global_vars

    current_headers = common_headers.copy()

    if headers is not None:
        current_headers.update(headers)

    if method in ['GET', 'POST']:
        #print 'url is', url, 'header is', current_headers
        if method == 'GET':
            resp = requests.get(url, headers=current_headers,
                    verify=global_vars['is_secure'])
        elif method == 'POST':
            resp = requests.post(url, headers=current_headers,
                    verify=global_vars['is_secure'])

        if resp.status_code >= 400:
            print 'Exception %s thrown!!! Status code:' % resp.status_code
            print 'Error content: ', json.dumps(json.loads(resp.content), indent=4, sort_keys=True)
            print 'Refer to, jcs --help'
            if resp.status_code == 400:
                raise exceptions.HTTP400()
            elif resp.status_code == 404:
                raise exceptions.HTTP404()
            raise Exception
        response = resp.content
        print "\'--------------------------------------------------\'"
        import pdb; pdb.set_trace()
        try:
            resp_dict = dict()
            if response is not '':
                resp_dict = json.loads(response)
                print json.dumps(resp_dict, indent=4, sort_keys=True)
        except:
            resp_dict = dict()
            resp_ordereddict = xmltodict.parse(response)
            resp_dict = yaml.safe_load(json.dumps(resp_ordereddict))
            print json.dumps(resp_dict, indent=4, sort_keys=True)
        print "\n\nRequest successfully executed !"
        return resp_dict
    else:
        print "verb not found"


def _create_valid_request_dictionary(valid_params, supplied_optional_params,
        supplied_mandatory_params):
    """
    Create a valid request dictionary from user supplied key-values.

    valid_params is a list, e.g. ['InstanceCount', 'KeyName']
    supplied_optional_params is a dictionary, e.g. {'InstanceCount': 3}
    supplied_mandatory_params is a dictionary of mandatory params.

    Returns a dictionary of valid parameters for the given request
    """
    final_dict = {}

    if supplied_mandatory_params:
        final_dict = supplied_mandatory_params.copy()

    for key, value in supplied_optional_params.items():
        # NOTE: for now, we're turning off validation of supplied params.
        # The commented 4 lines will add back validation
        final_dict[key] = str(value)
        # if key in valid_params:
        #     final_dict[key] = str(value)  # Everything must be stringified
        # else:
        #     print 'Unsupported key! Dropping key-value', key, value

    return final_dict





def requestify(host_or_ip, request, verb='GET'):
    """
    Method which generates final request URL to be sent to JCS servers.

    Input:
        host_or_ip: e.g. 'http://12.34.56.78'
        request: dictionary, e.g.. {'Action': 'DescribeInstances'}

    Response: Request URL. e.g.  'https://<ip>/?<query-params>'
    """
    if not type(request) == dict:
        raise Exception

    if not host_or_ip.endswith('/'):
        host_or_ip += '/'
    host_or_ip += '?'

    request['Signature'] = get_signature(verb, host_or_ip, request)
    request_string = host_or_ip
    for key, value in request.items():
        request_string += str(key) + '=' + str(value) + '&'
    request_string = request_string[:-1]  # remove last '&'
    return request_string


def get_signature(method, host, params):
    global global_vars
    hmac_256 = hmac.new(str(global_vars['secret_key']), digestmod=hashlib.sha256)
    canonical_string = string_to_sign(method, host, params)
    hmac_256.update(canonical_string.encode('utf-8'))
    b64 = base64.b64encode(hmac_256.digest()).decode('utf-8')
    return ul.quote(b64)


def string_to_sign(method, host, params):
    # For the 'host' param, strip off 'http[s]://' part from the start, and
    # strip off everything after the first slash. E.g.
    # 'https://example.com/one/two/three'  will
    # become 'example.com'
    if host.startswith('http') or host.startswith('https'):
        host = host.split('//')[1]
    else:
        raise Exception('your iam url must start with http:// or https://')
    if host.find('/') != -1:
        host = host.split('/')[0]
    ss = method + '\n' + host + '\n' + '/' + '\n'
    params.update(common_params_v2)
    # Timestamp should be updated always while making request.
    # TODO(himanshu): don't update TimeStamp at the top when declaring the dict
    params['Timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    qs = get_query_string_from_params(params)
    ss += qs
    return ss


def get_query_string_from_params(params):
    keys = params.keys()
    keys.sort()
    pairs = []
    for key in keys:
        val = _get_utf8_value(params[key])
        val = urllib.parse.quote(val, safe='-_~')
        pairs.append(urllib.parse.quote(key, safe='') + '=' + val)
    qs = '&'.join(pairs)
    return qs


def _remove_item_keys(response, cli=False):
    """
    Remove all 'item' keys from 'response' dictionary.

    The value for 'item' key can be either a dictionary or a list of
    dictionaries. Replace the dict whose key is 'item' with the value of
    'item' key. And if this value is a dict, then make it a list which
    contains only that dict.

    See the corresponding test for more examples.

    Examples:
        Input: {'instances': {'item': {'key1': 'value1'}}}
        Output: {'instances': [{'key1': 'value1'}]}

        Input: {'instances': {'item': [{'key1': 'value1'}, {'key2': 'value2'}]}}
        Output: {'instances': [{'key1': 'value1'}, {'key2': 'value2'}]}
    """
    if cli:
        return "--------------------------------------------------"

    if type(response) != dict:
        raise Exception

    # 'item' can't be a first-level key
    if 'item' in response.keys():
        raise Exception

    for key, value in response.items():
        if type(value) == dict:
            item_value = value.get('item')
            if item_value is not None:
                # If the dictionary has a key 'item', then this dictionary
                # shouldn't have any more keys
                if len(value.keys()) != 1:
                    raise Exception

                # Value for 'item' key should be a list or a dict
                if type(item_value) not in [list, dict]:
                    raise Exception

                response[key] = item_value if type(item_value) == list else [item_value]

                response[key] = [_remove_item_keys(d) for d in response[key]]
            else:
                response[key] = _remove_item_keys(value)


    return response


