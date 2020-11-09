import csv, json
import argparse
from collections import defaultdict
from datetime import date

def csv2json(inputfile):
    with open(inputfile, 'r') as csvfile, open(f'WINS_cvereport_{date.today()}_0.json', 'w') as jsonfile:
        csv_dict = csv.DictReader(csvfile)
        json_data = []
        for dict in csv_dict:
            data = defaultdict()

            data['cve_number'] = dict['cve_number']

            if dict['signature_name']:
                data['signature_created'] = "Yes"
                data['signature_name'] = f"{dict['signature_name']} ({dict['cve_number']})"
            else:
                data['signature_created'] = "No"
                data['signature_name'] = ''

            data['detection_type'] = dict['detection_type']
            data['mapp_json_version'] = '1.0'

            json_data.append(data)

        jsonfile.write(json.dumps(json_data, indent=0))
        return jsonfile.name

if __name__ == "__main__":
    text = '''
    Create MAPP Reports    
    '''
    arg_parser = argparse.ArgumentParser(description=text)
    arg_parser.add_argument('--input', '-i', default='wins.csv', help='input file (default:win.csv)')

    args = arg_parser.parse_args()

    print("[Create File]")
    print(csv2json(args.input))

