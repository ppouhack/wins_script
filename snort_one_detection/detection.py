import os,re
import subprocess
import difflib
import argparse
from idstools import rule
from collections import defaultdict

class snort_detection():
    def __init__(self,args):
        self.rule = None
        self.rule_path = r'C:\Snort\rules\mytest.rules'
        self.alert_path = r'C:\Snort\log\alert.ids'
        self.pcap = None
        self.rule_packet_dict = []

        self.init_set(args)

    def init_set(self, args):
        ''' set variable

        Args:
            args :

        Returns:
        '''

        # if input rule line, write rules file
        if args.rule_line:
            self.rule = args.rule_line.replace("'","")
            with open(self.rule_path, 'w') as output_rule_file:
                print(f'{self.rule}', file=output_rule_file)

        # if input rule file, read rule file and write rules file
        elif args.rule_file:
            with open(args.rule_file, 'r') as input_rule_file, open(self.rule_path, 'w') as output_rule_file:
                self.rule = input_rule_file.readlines()
                for rule in self.rule:
                    output_rule_file.write(rule)
        else:
            return

    def set_packet(self):
        # if input rule file
        if isinstance(self.rule, list):
            for rule_line in self.rule:
                tools_rule = rule.parse(rule_line)
                for (path, dir, files) in os.walk("./"):
                    for file in files:
                        if tools_rule['msg'] in file:
                            data = defaultdict()
                            data['msg'] = tools_rule['msg']
                            data['rule'] = tools_rule
                            data['packet'] = f"{file}"
                            self.rule_packet_dict.append(data)

        # if input rule line
        else:
            tools_rule = rule.parse(self.rule)
            for (path, dir, files) in os.walk("./"):
                for file in files:
                    print(tools_rule['msg'])
                    if tools_rule['msg'] in file:
                        data = defaultdict()
                        data['msg'] = tools_rule['msg']
                        data['rule'] = tools_rule
                        data['packet'] = f"{file}"
                        self.rule_packet_dict.append(data)

    def snort_run(self):
        ''' snort run, print detection result

        '''
        for rule_packet in self.rule_packet_dict:
            print(rule_packet['msg'])
            print(rule_packet['packet'])

            diff_check1 = None
            diff_check2 = None

            # before snort run
            with open(self.alert_path, 'r') as f:
                diff_check1 = f.read().splitlines()

            # run snort
            com = f'C:\\Snort\\bin\\snort.exe -A fast -c C:\\Snort\\etc\\snort.conf -l C:\\Snort\\log -r "{rule_packet["packet"]}"'
            subprocess.run(com, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # after snort run
            with open(self.alert_path, 'r') as f:
                diff_check2 = f.read().splitlines()

            # check diff log
            diff = difflib.unified_diff(diff_check1, diff_check2,fromfile='origin', tofile='append')

            # diff result print
            diff_result = []
            for line in diff:
                if re.search('^\+\d', line):
                    diff_result.append(line)

            if diff_result:
                for result in diff_result:
                    print(result)
                    print()
            else:
                print("[Not Found]")
                print()

if __name__ == "__main__":
    text = '''
    Detection Snort, Sniper ONE    
    '''
    arg_parser = argparse.ArgumentParser(description=text)
    arg_parser.add_argument('--snort', '-s', help='Detection Snort')
    arg_parser.add_argument('--one', '-o', help='Detection Sniper One')
    arg_parser.add_argument('--rule_line', '-l', help="input rule line, you must use single quote, don't use double quote")
    arg_parser.add_argument('--rule_file', '-f', default='mytest.rules', help='input rule file (default:mytest.rules')
    arg_parser.add_argument('--match_packet', '-m', default='mytest.rules', help='input rule file (default:mytest.rules')

    args = arg_parser.parse_args()

    sd = snort_detection(args)
    sd.set_packet()
    sd.snort_run()

