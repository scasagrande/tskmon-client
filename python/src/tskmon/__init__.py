#!/usr/bin/python
# -*- coding: utf-8 -*-
##
# __init__: Client for the tskmon API.
##
# © 2013 Christopher E. Granade (cgranade@gmail.com) and
#        Steven Casagrande (stevencasagrande@gmail.com)
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

import pushnotify

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
    def __init__(self, client, json_body, notify_param={}):
        self._client = client
        self._json_body = json_body
        self._notify_param = notify_param.copy()
        
        if self._notify_param.has_key('params'):
            task_title = self._notify_param.get('params').get('title')
            task_status = self._notify_param.get('params').get('status')
        
        # Send new task notification
        if self._notify_param.has_key('new'):
            if self._notify_param.get('new') is 1:
                self._client.notify('Status: ' + str(task_status) , 'New task: ' + str(task_title))
        
    def delete(self):
        self._client.delete(self._json_body['uri'])
        
    # TODO: expose as properties once json_body bug is fixed.
        
    def set_progress(self, new_prog):
        # TODO: implement as a property
        self._client.update(self._json_body['uri'], progress=new_prog)
        
        # Send task progress update notification
        if self._notify_param.has_key('progress'):
            milestones = self._notify_param.get('progress')
            task_title = self._notify_param.get('params').get('title')
            if len(milestones) > 0: # If at least 1 progress milestone
                old_prog = self._notify_param.get('params').get('progress')
                # Check if we have passed a milestone
                for ms in reversed(milestones):
                    if (old_prog < ms) and (new_prog >= ms):
                        self._client.notify('Task at ' + str(new_prog) + '%' , str(task_title))
                        break
                self._notify_param.get('params')['progress'] = new_prog
        
    def set_max(self, new_max):
        # TODO: implement as a property
        self._client.update(self._json_body['uri'], max=new_max)
        
    def set_title(self, new_title):
        # TODO: implement as a property
        self._client.update(self._json_body['uri'], title=new_title)
        
    def set_status(self, new_status):
        # TODO: implement as a property
        self._client.update(self._json_body['uri'], status=new_status)
        
        # Send task status updated notification
        if self._notify_param.has_key('status'):
            if self._notify_param.get('status') is 1:
                task_title = self._notify_param.get('params').get('title')
                self._client.notify('New status: ' + str(new_status) , str(task_title))
        

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
        
        # PUSHOVER #
        api_token = ''
        user_key = ''
        # Check if config file has entries for Pushover keys
        if conf.has_section('PUSHOVER') and conf.has_option('PUSHOVER', 'api_token'):
            api_token = conf.get('PUSHOVER', 'api_token')
            user_key = conf.get('PUSHOVER', 'user_key')
        else:
            # Check if user wishes to use pushover
            api_token = raw_input("Please enter Pushover API key. If you don't wish to use Pushover, leave blank:\n")
            if api_token is not '':
                user_key = raw_input("Please enter your Pushover user key:\n")
                
            # Save API and User keys to config file
            if not conf.has_section('PUSHOVER'):
                conf.add_section('PUSHOVER')
            conf.set('PUSHOVER', 'api_token', api_token)
            conf.set('PUSHOVER', 'user_key', user_key)
            config.save_config(conf)
        
        # Setup pushover client
        if api_token is not '':
            self._pushover = pushnotify.pushover.Client(api_token)
            self._pushover.add_key(user_key)  
            # Check to make sure user_key is valid
            if not self._pushover.verify_user(user_key):
                raise RuntimeError("User key not valid: " + user_key) 
        
    def _oauth_params(self):
        params = {
            'oauth_version': "1.0",
            'oauth_nonce': oauth.generate_nonce(),
            'oauth_timestamp': int(time.time())            
        }
        
        params['oauth_token'] = self._access_token.key
        params['oauth_consumer_key'] = self._consumer.key
        
        return params
        
    def new_task(self, title, status="", progress=0, max_progress=None, notify_rules={}):
        # TODO: make this return a Task object that can be updated,
        #       instead of just returning the JSON.
        '''
            notify_params is a dictionary containing conditions when 
            notifications should be sent out. Any missing parameters
            are assumed to be false.

            notify_rules = {   'new' : 1 ,                 # on new task
                                'delete': 1 ,               # on task delete
                                'progress': [10,20,...] ,   # list of progress milestones
                                'status' : 1,               # on status change
                            }
        '''
        params = {
            'title': title,
            'status': status,
            'progress': progress
        }
        
        # Make a copy so we don't mess with the user's original
        notify_params = notify_rules.copy()
        
        # Add params to notify_params if notify_params not empty
        if notify_params:
            notify_params['params'] = params.copy()
            
        # If it exists, sort the progress notification milestone list
        if notify_params.has_key('progress'):
            notify_params['progress'].sort()
        
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
        
        try:
            json_body = json.loads(response[1])
        except:
            json_body = None
            raise RuntimeError("Reponse wasn't JSON-formatted: {}".format(response[1]))
        if json_body['result'] != "success":
            raise RuntimeError("Didn't work!\n" + str(json_body['error']))
    
        return Task(self, json_body['new_task'], notify_params)
        
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
        
    def notify(self, description, event, split=True, kwargs=None):
        return self._pushover.notify(description,event,split,kwargs)
        
