import argparse
import re
import geoip2.database as gd
from collections import defaultdict
import operator

class searchGeoIp():
    def __init__(self):
        self.src_dict = None
        self.dst_dict = None
        self.set_dict()

    def def_value(self):
        """ set defaultdict value None

        Returns:
            None
        """
        return None

    def set_dict(self):
        """ set defaultdict

        """
        self.src_dict = defaultdict(self.def_value)
        self.dst_dict = defaultdict(self.def_value)

    def search_ip(self, log):
        """ search src ip, dst ip in log file

        Args:
            log: log line
        Returns:
            return re.object
        """
        return re.search('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5} \-> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5}$', log)

    def ip_whois_country(self,ip):
        """ search country in mmdb file

        Args:
            ip: ip

        Returns:
            country name
        """
        try:
            reader = gd.Reader('GeoLite2-Country.mmdb')
            data = reader.country(ip)

            return data.country.name

        except Exception as e:
            pass

    def ip_whois_city(self,ip):
        """ search city in mmdb file

        Args:
            ip:ip
        Returns:
            city name
        """
        try:
            reader = gd.Reader('GeoLite2-City.mmdb')
            data = reader.city(ip)

            return data.city.name

        except Exception as e:
            pass

    def count_log_ip(self, src, dst):
        """ count default dictionary data

        Args:
            src : src country, city text
            dst : dst country, city text
        """

        if self.src_dict[src] == None:
            self.src_dict[src] = 1
        else:
            self.src_dict[src] +=1


        if self.dst_dict[dst] == None:
            self.dst_dict[dst] = 1
        else:
            self.dst_dict[dst] +=1

    def sort_print(self, number):
        """ default dctionary sort, print top N

        Args:
            number: print top N
        """

        # sort top N
        sort_src = sorted(self.src_dict.items(), key=operator.itemgetter(1), reverse=True)
        sort_dst = sorted(self.dst_dict.items(), key=operator.itemgetter(1), reverse=True)

        # count start 1
        for count, (src, dst) in enumerate(zip(sort_src, sort_dst),1):
            print(f"{count}.src -> {src[0]}:{src[1]}")
            print(f"{count}.dst -> {dst[0]}:{dst[1]}")
            print()
            if count == number:
                break

if __name__ == "__main__":
    text = '''
    Search GEO IP    
    '''
    arg_parser = argparse.ArgumentParser(description=text)
    arg_parser.add_argument('--ip', '-i', help='ip string')
    arg_parser.add_argument('--file', '-f', help='(default: filename is sample.log')
    arg_parser.add_argument('--city', '-c', action='store_true', help='search city (default: country)')
    arg_parser.add_argument('--number', '-n', type=int, default=3, help='print top number (default: 3)')
    args = arg_parser.parse_args()

    sg = searchGeoIp()

    if args.ip:
        if args.city:
            print(sg.ip_whois_city(args.ip))
        else:
            print(sg.ip_whois_country(args.ip))

    if args.file:
        if args.city:
            with open(args.file, "r") as file:
                for count, line in enumerate(file.readlines()):
                    match_ip = sg.search_ip(line)
                    if match_ip:
                        sg.count_log_ip(sg.ip_whois_city(match_ip.group(1)), sg.ip_whois_city(match_ip.group(2)))

        else:
            with open(args.file, "r") as file:
                for count, line in enumerate(file.readlines()):
                    match_ip = sg.search_ip(line)
                    if match_ip:
                        sg.count_log_ip(sg.ip_whois_country(match_ip.group(1)), sg.ip_whois_country(match_ip.group(2)))

        sg.sort_print(args.number)