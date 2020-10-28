import requests
from bs4 import BeautifulSoup
import re, os
from googletrans import Translator
import configparser
from ast import literal_eval
import argparse


config = configparser.ConfigParser()
config.read('config.ini')

class trendMicro():
    def __init__(self,args):
        self.tsl_id = args.search

        self.login_url = f"https://tisportal.trendmicro.com/home/authenticate"
        self.session = self.login()
        self.info = self.search(self.tsl_id, self.session)

        if self.info:
            for info in self.info:
                self.download(info, self.session)

    def login(self):
        """ return the trendmicro login session

        Returns: request.Session()
        """
        print("# trendmicro login")

        s = requests.Session()

        try:
            # convert string to dictionary
            login_info = literal_eval(config['trendmicro']['LOGIN_INFO'])
            login_req = s.post('https://tisportal.trendmicro.com/home/authenticate', data=login_info)

            # if login fail, return
            if login_req.status_code == 200:
                print("> trendmicro login success\n")
                return s
            else:
                print("> trendmicro login fail\n")
                s.close()
                return

        except Exception as e:
            print(e)
            s.close()

    def search(self, tsl_id, s):
        """ search vulnerabilities list, return validate list

        Args:
            tsl_id : search vulnerabilities id
            s : sessions(login function return value)
        Returns:
            search_list: validate vulnerabilities list
        """

        print(f"# search {tsl_id} information")

        search_url = f"https://tisportal.trendmicro.com/search/search_results?kw={tsl_id}&km=All&sv=4&dr=All&tt=1&fr=ER&cid=&iid=&ob=TSL&om=Desc"
        search_req = s.get(search_url)
        search_html = search_req.text
        search_obj = BeautifulSoup(search_html, 'html.parser')

        search_list = []

        try:
            summary_list = search_obj.find(id='summary_list')

            # if can't find table, fail to search vulnerabilities
            if summary_list.find('table', width='100%'):
                for table in summary_list.find_all('table', width='100%'):
                    threat_item = table.find('div', class_='threat_item_resources')

                    # it's validate vulnerabilities list?
                    if "Vulnerability Report PDF" in threat_item.text:
                        threat_title = table.find('th', class_='threat_title')
                        search_dict = {'title': threat_title.text.replace("\n", ""),
                                       'tsl_id': (threat_title.find('a')['href']).replace('/threat/','')}
                        search_list.append(search_dict)

        except Exception as e:
            print(f"> not found")
            print(f"[!] {e}")
            return

        # print validate vulnerabilities list
        if search_list:
            for search in search_list:
                print(f"> {search['title']}")
        else:
            print(f"> not found")

        print("")
        return search_list

    def download(self,info,s):
        """ download validate vulnerabilities list

        Args:
            info : validate vulnerabilities list(dictionary)
            s : sessions(login function return value)
        Returns:
            create vulnerabilities file
        """
        print(f"# download {info['title']}")

        tsl_id_list = [{'url': f"https://tisportal.trendmicro.com/asset/{info['tsl_id']}/vulnerability_report_pdf/",
                 'filename':f'{info["title"]}/{info["tsl_id"]}.pdf'},
                {'url': f"https://tisportal.trendmicro.com/asset/{info['tsl_id']}/vulnerability_report_xml/",
                 'filename':f'{info["title"]}/{info["tsl_id"]}.xml'},
                {'url': f"https://tisportal.trendmicro.com/asset/{info['tsl_id']}/vulnerability_baseline_pcap/",
                 'filename':f'{info["title"]}/nomal.zip'},
                {'url': f"https://tisportal.trendmicro.com/asset/{info['tsl_id']}/vulnerability_attack_pcap/",
                 'filename':f'{info["title"]}/attack.zip'},
                {'url': f"https://tisportal.trendmicro.com/asset/{info['tsl_id']}/vulnerability_proof_of_concept/",
                 'filename':f'{info["title"]}/poc.zip'}
                ]
        try:
            os.mkdir(info['title'])

            for list in tsl_id_list:
                with open(list['filename'], "wb") as file:
                    download_file = s.get(list['url'])
                    file.write(download_file.content)

        except Exception as e:
            print(f"[!] {e}")
            return

        print(f"> download complete\n")

text = "python trendmicro.py -t -s (cve_id or tsl_id)"
arg_parser = argparse.ArgumentParser(description=text)
arg_parser.add_argument('--search', '-s', required=False, help='search cve_id or tsl_id')
arg_parser.add_argument('--file', '-f', required=False, help='search file cve_id or tsl_id')
arg_parser.add_argument('--translation', '-t', action='store_true')
args = arg_parser.parse_args()

tm = trendMicro(args)
