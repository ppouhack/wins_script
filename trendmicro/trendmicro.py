import requests
from bs4 import BeautifulSoup
import re, os
from googletrans import Translator
import configparser
from ast import literal_eval
import argparse
from time import sleep

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
                if args.translation:
                    self.brief(info,True)
                else:
                    self.brief(info, False)

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

    def google_translation(self,data):
        """ english string translation korean string

        Args:
            data: english string

        Returns:
            korean string
        """
        try:
            sleep(0.1)
            translator = Translator()
            return translator.translate(data, src="en", dest="ko").text
        except Exception as e:
            return "[!] translator error"

    def brief(self,info,flag):
        """ brief xml file

        Args:
            info : validate vulnerabilities list(dictionary)
            flag : if flag is true, call google_translation

        Returns:
            translation.txt
        """
        if flag:
            print(f"# translation brief {info['title']}")
        else:
            print(f"# brief {info['title']}")
        filename = f"{info['title']}/{info['tsl_id']}.xml"

        xml = open(filename, "r")
        xmlObj = BeautifulSoup(xml, 'html.parser')

        with open(f"{info['title']}/brief.txt", 'w', encoding='UTF8') as w:

            # Summary Information
            print(f"# 0.Summary Information", file=w)
            print(f"", file=w)

            try:
                for shortname in xmlObj.identity.findAll('shortname'):
                    title = shortname.text
                    print(f"> title", file=w)
                    print(f"{title}", file=w)
                    print(f"", file=w)

            except Exception as e:
                print(f"> title", file=w)
                print(f"No", file=w)
                print(f"", file=w)

            try:
                for vendor_advisory in xmlObj.identity.findAll('vendor_advisory'):
                    vendor_advisory_name = vendor_advisory.get('name')
                    vendor_advisory_url = vendor_advisory.get('url')

                    print(f"> vendor_advisory_name", file=w)
                    print(f"{vendor_advisory_name}", file=w)
                    print(f"",file=w)

                    print(f"> vendor_advisory_url", file=w)
                    print(f"{vendor_advisory_url}", file=w)
                    print(f"", file=w)

            except Exception as e:
                print(f"> vendor_advisory_name", file=w)
                print(f"No", file=w)
                print(f"", file=w)

            try:
                for cve in xmlObj.identity.findAll('cve'):
                    cve_id = cve.get('id')
                    print(f"> CVE ID", file=w)
                    print(f"{cve_id}", file=w)
                    print(f"", file=w)

            except Exception as e:
                print(f"> CVE ID", file=w)
                print(f"No", file=w)

            try:
                for discovereradvisory in xmlObj.identity.findAll('discovereradvisory'):
                    discovereradvisory_name = discovereradvisory.get('name')
                    discovereradvisory_url = discovereradvisory.get('url')

                    print(f"> discovereradvisory_name", file=w)
                    print(f"{discovereradvisory_name}", file=w)
                    print(f"", file=w)

                    print(f"> discovereradvisory_url", file=w)
                    print(f"{discovereradvisory_url}", file=w)
                    print(f"", file=w)

            except Exception as e:
                print(f"> discovereradvisory_name", file=w)
                print(f"No", file=w)
                print(f"", file=w)

                print(f"> discovereradvisory_url", file=w)
                print(f"No", file=w)
                print(f"", file=w)

            try:
                print(f"> product_data", file=w)

                for vendor in xmlObj.affectedproducts.affecteddirectly.findAll('vendor'):
                    vendor_name = vendor.get('name')
                    for product in vendor.findAll('product'):
                        product_name = product.get('name')
                        for version in product.findAll('version'):
                            version_name = version.get('name')
                            product_data = f"{vendor_name} {product_name} {version_name}"

                            print(f"{product_data}", file=w)

            except Exception as e:
                print(f"No", file=w)

            print(f"", file=w)

            try:
                print(f"> public exploit", file=w)
                for url in xmlObj.publicexploits.description.findAll('url'):
                    publicexploits_url = url.text
                    print(f"{publicexploits_url}", file=w)

            except Exception as e:
                print(f"No", file=w)

            print(f"", file=w)

            # Brief Description
            try:
                print(f"# 1.Brief Description", file=w)
                for para in xmlObj.identity.description.findAll('para'):
                    identity_paras = para.text
                    identity_paras = identity_paras.replace("\n"," ")
                    print(f"{identity_paras}", file=w)
                    print(f"", file=w)
                    if flag:
                        print(f"{self.google_translation(identity_paras)}", file=w)
                        print(f"", file=w)

            except Exception as e:
                print(f"No", file=w)
            print(f"", file=w)

            # Detail Analysis
            try:
                print(f"# 2.Detail Analysis", file=w)
                for para in xmlObj.mechanism.description.findAll('para'):
                    if para.findAll('code'):  # <code>가 포함되어 있는 경우 건너뜀
                        for code in para.findAll('code'):
                            mechanism_code = code.text
                            print(f"{mechanism_code}", file=w)
                            print(f"", file=w)
                    else:
                        mechanisms_paras = para.text
                        mechanisms_paras = mechanisms_paras.replace("\n", " ")

                        print(f"{mechanisms_paras}", file=w)
                        print(f"", file=w)

                        if flag:
                            print(f"{self.google_translation(mechanisms_paras)}", file=w)
                            print(f"", file=w)

            except Exception as e:
                print(f"No", file=w)

            # Detection
            try:
                print(f"# 3.Detection", file=w)

                for para in xmlObj.attackdetection.genericattacks.findAll('para'):
                    global attackdetection_data
                    if para.findAll('code'):
                        for code in para.findAll('code'):
                            attack_detection_code = code.text
                            print(f"{attack_detection_code}", file=w)
                            print(f"", file=w)
                    else:
                        attack_detection_paras = para.text
                        attack_detection_paras = attack_detection_paras.replace("\n", " ")

                        print(f"{attack_detection_paras}", file=w)
                        print(f"", file=w)

                        if flag:
                            print(f"{self.google_translation(attack_detection_paras)}", file=w)
                            print(f"", file=w)

            except Exception as e:
                print(f"No", file=w)

        print(f"> brief complete")

if __name__ == "__main__":
    text = "python trendmicro.py -t -s (cve_id or tsl_id)"
    arg_parser = argparse.ArgumentParser(description=text)
    arg_parser.add_argument('--search', '-s', required=True, help='search cve_id or tsl_id')
    arg_parser.add_argument('--translation', '-t', action='store_true', help='brief translation')
    args = arg_parser.parse_args()

    tm = trendMicro(args)
