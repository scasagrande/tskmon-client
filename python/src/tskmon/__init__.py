#!/usr/bin/python
# -*- coding: utf-8 -*-
##
# __init__: Client for the tskmon API.
##
# © 2013 Christopher E. Granade (cgranade@gmail.com)
#
# This file is a part of the tskmon project.
# Licensed under the AGPL version 3.
##
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
##

## IMPORTS #####################################################################

import oauth2 as oauth
import urlparse
import urllib
import json
import webbrowser
import time

import os


import tskmon.config

## CONSTANTS ###################################################################

SERVER = (
    "tskmon.appspot.com"
    if os.getenv('TSKMON_SERVER') is None
    else
    os.getenv('TSKMON_SERVER')
)

ENDPOINT_BASE = "https://" + SERVER + "/_ah/"
request_token_url = ENDPOINT_BASE + "OAuthGetRequestToken"
authorize_url = ENDPOINT_BASE + "OAuthAuthorizeToken"
access_token_url = ENDPOINT_BASE + "OAuthGetAccessToken"

API_BASE      = "http://" + SERVER + "/api"

consumer_key = "anonymous"
consumer_secret = "anonymous"

## CLASSES #####################################################################

class Task(object):
    def __init__(self, client, json_body):
        self._client = client
        self._json_body = json_body
        
    def delete(self):
        self._client.delete(self._json_body['uri'])
        
    def set_progress(self, new_prog):
        # TODO: implement as a property
        self._client.update(self._json_body['uri'], progress=new_prog)

class TskmonClient(object):

    def __init__(self):
        
        # Setup an OAuth consumer and client.
        consumer = oauth.Consumer(consumer_key, consumer_secret)
        self._consumer = consumer
        client = oauth.Client(consumer)
        
        # Check if there's already a token in the config file.
        conf = config.read_config()
        if conf.has_section(SERVER) and conf.has_option(SERVER, 'oauth_token'):
            self._access_token = oauth.Token(
                conf.get(SERVER, 'oauth_token'),
                conf.get(SERVER, 'oauth_token_secret')
                )
        else:
            # We need to get one, so let's do that now.
        
            # Step 1: Request a token.
            resp, content = client.request(request_token_url, 'POST',
                body=urllib.urlencode({
                    'oauth_callback': 'oob'
                })
            )
            if resp['status'] != '200':
                raise Exception("Invalid response %s." % resp['status'])
            
            request_token = dict(urlparse.parse_qsl(content))
        
            # Step 2: Get the user to authorize the token for us.        
            webbrowser.open("{url}?oauth_token={token}".format(url=authorize_url, token=request_token['oauth_token']))        
            verifer = raw_input("Please paste the code you obtained here:\n")
            
            # Step 3: Request the access token that has just been authorized.
            token = oauth.Token(request_token['oauth_token'], request_token['oauth_token_secret'])
            token.set_verifier(verifer)
            client = oauth.Client(consumer, token)
        
            resp, content = client.request(access_token_url, 'POST')
            access_token = dict(urlparse.parse_qsl(content))
            self._access_token = oauth.Token(access_token['oauth_token'], access_token['oauth_token_secret'])
            
            # Finally, save the access token so we won't need it again.
            if not conf.has_section(SERVER):
                conf.add_section(SERVER)
            conf.set(SERVER, 'oauth_token', access_token['oauth_token'])
            conf.set(SERVER, 'oauth_token_secret', access_token['oauth_token_secret'])
            config.save_config(conf)
        
    def _oauth_params(self):
        params = {
            'oauth_version': "1.0",
            'oauth_nonce': oauth.generate_nonce(),
            'oauth_timestamp': int(time.time())            
        }
        
        params['oauth_token'] = self._access_token.key
        params['oauth_consumer_key'] = self._consumer.key
        
        return params
        
    def new_task(self, title, status="", progress=0, max_progress=None):
        # TODO: make this return a Task object that can be updated,
        #       instead of just returning the JSON.
        params = {
            'title': title,
            'status': status,
            'progress': progress
        }
        if max_progress is not None: params['max'] = max_progress
        params.update(self._oauth_params())
        
        request = oauth.Request(
            method='GET',
            url=API_BASE + "/tasks/new",
            parameters=params)
        signature_method = oauth.SignatureMethod_HMAC_SHA1()
        request.sign_request(signature_method, self._consumer, self._access_token)
        
        client = oauth.Client(self._consumer, self._access_token)
        response = client.request(
            API_BASE + "/tasks/new?" + urllib.urlencode(params),
            'GET')
        
        json_body = json.loads(response[1])
        if json_body['result'] != "success":
            raise RuntimeError("Didn't work!\n" + str(json_body['error']))
    
        return Task(self, json_body['new_task'])
        
    def delete(self, task_uri):
        params = self._oauth_params()
        
        # TODO: make this not relative!~!
        full_task_uri = "http://" + SERVER + task_uri
        
        # TODO: consolidate common code into a utility method.
        request = oauth.Request(
            method='DELETE',
            url=full_task_uri,
            parameters=params)
        signature_method = oauth.SignatureMethod_HMAC_SHA1()
        request.sign_request(signature_method, self._consumer, self._access_token)
        
        client = oauth.Client(self._consumer, self._access_token)
        response = client.request(
            full_task_uri,
            'DELETE')
        
        json_body = json.loads(response[1])
        if json_body['result'] != "success":
            raise RuntimeError("Didn't work!\n" + str(json_body['error']))
        
    def update(self, task_uri, **args):
        body = json.dumps(args)
        params = self._oauth_params()
        
        # TODO: make this not relative!~!
        full_task_uri = "http://" + SERVER + task_uri
        
        request = oauth.Request(
            method='POST',
            url=full_task_uri,
            parameters=params)
        signature_method = oauth.SignatureMethod_HMAC_SHA1()
        request.sign_request(signature_method, self._consumer, self._access_token)
        
        client = oauth.Client(self._consumer, self._access_token)
        response = client.request(
            full_task_uri,
            'POST',
            headers={
                'Content-Type': 'application/json'
            },
            body=body)
        
        json_body = json.loads(response[1])
        if json_body['result'] != "success":
            raise RuntimeError("Didn't work!\n" + str(json_body['error']))
    
        self._json_body = json_body['updated_task']
        
