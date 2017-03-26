#!/usr/bin/env python
"""Python 3 library to utilize all of Nessus' API
"""

import requests
from urllib.parse import urljoin

class NessusConnect(object):
    """A connection to the Nessus server. 
    It requires either a user and password or API keys
    
    Attributes:
        base_url: A string representing the url to the Nessus server
            example: "https://127.0.0.1:8834"
        verify_ssl: A string of a path to a CA_Bundle file or directory 
    """
    def __init__(self, base_url, verify_ssl=False):
        self.base_url = base_url
        self.verify_ssl = verify_ssl

   
    def _set_headers(self, auth_type):
        """Sets headers for future API calls based on if the object created
        contained either username and password or accesskeys
        """
        if auth_type is "session":
            json = {
                "username": self.user,
                "password": self.password
            }

            response = self._connect(method="POST", endpoint="/session",
                                    json=json)
            token = response['token']
            self.headers = {
                "content-type": "application/json",
                "X-Cookie": "token=%s" % token
            }
        elif auth_type is "api": 
            self.headers = {
                "content-type": "application/json",
                "X-ApiKeys": "accessKey=%s; secretKey=%s" %
                             (self.access_key, self.secret_key)
            }


    def _connect(self, method, endpoint, json=None):
        """Connects to the Nessus Server 
    
        method: GET, POST, HEAD, PUT, PATCH, DELETE, OPTIONS
        endpoint: api section of the url, such as "/scans"
        json: json specific parameters to pass to api when requested by nessus
    
        returns either json response, or download content
        """
        url = urljoin(self.base_url, endpoint)

        if "session" in url:
            r = requests.post(url, json=json, verify=self.verify_ssl)
        elif method in ['GET', 'POST', 'PUT', 'DELETE']:
            r = requests.request(method, url, headers=self.headers, json=json,
                             verify=self.verify_ssl)
        else:
            print("Could not connect")

        if r.status_code in [200, 201]:
            return r.json()
        else:
            print("Did not receive 200/201, look into")
        

    def auth_api(self, access_key, secret_key):
        """Use the provided API keys to create log on headers
        """
        self.access_key = access_key
        self.secret_key = secret_key

        self._set_headers(auth_type="api")

    def auth_session_token(self, user, password):
        """Use the provided login information to create a session token
        and create headers based on that
        """
        self.user = user
        self.password = password

        self._set_headers(auth_type = "session")
    

    def get_scan_attachments(self, scan_id, attachment_id):
        """Gets the requested scan attachment file
    
        scan_id: The id of the scan containing the attachment
        attachment_id: The id of the scan attachment
    
        returns dict of 
        """
        # TODO: Figure out exactly what is a scan attachment
        pass


    def get_scans_list(self, folder_id=None, last_modification_date=None):
        """Gets a list of scans the user is authorized to see

        optional parameters:
            folder_id: A string of the folder id the scan should reside in
            last_mod_date: Limits the resultst to scans that have been modified
            since this date
        Sets self.scan_list
        """
        json = {
            'folder_id': folder_id,
            'last_modification_date': last_modification_date
        }

        r = self._connect('GET', endpoint='/scans', json=json)
        return r

    
    def get_scan_details(self, scan_id, history_id=None):
        """Gets details from a particular scan

        required parameters:
            scan_id: A string of the desired scan

        optional parameters:
            history_id: A string of the history_id of historical data that 
            should be returned
        """
        json = {'history_id': history_id}
        endpoint = '/scans/{}'.format(scan_id)
        r = self._connect(method='GET', endpoint=endpoint, json=json)

        return r
