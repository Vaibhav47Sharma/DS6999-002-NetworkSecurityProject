import json, csv, datetime

class honeypotmodel:
  def __init__(self, input_string):
    json_input = json.loads(input_string)
    self.timestamp = json_input['timestamp']
    self.src_ip = json_input['src']
    self.direction = 0 if str.casefold(json_input['direction']) == 'inbound' else 1 \
      if str.casefold(json_input['direction']) == 'outbound' else 2
    self.protocol = json_input['protocol']
    self.signature = json_input['signature']
    self.transport = json_input['transport']
    self.severity = json_input['severity']
    self.type = json_input['type']
    self.sensor = json_input['sensor']
    self.app = json_input['app']
    self.vendor_product = json_input['vendor_product']
    self.src_port = json_input['src_port']

  @staticmethod
  def get_honeypot_formatted_json(ip_line):
    #to convert into unix time .... utc is take now
    ip_line = ip_line.replace('=', '\":').replace('\", ', '\", \"')
    timestamp, body = ip_line.split('src', 1)
    year = timestamp.rsplit('mhn', 1)[1].strip().split('-')[0]
    timestamp = year + '-' + timestamp.split('mhn', 1)[0].strip()
    timestamp = datetime.datetime.strptime(timestamp.strip(), '%Y-%b  %d %H:%M:%S').timestamp()
    body = '{\"timestamp\":\"' + str(timestamp) + '\", \"src' + str(body) + '}'
    return body


with open('C:\\Users\\vaibhav\\Documents\\UVA\\Summer\\Project\\honeypot\\2018-01-01-mhn.log') as f:
  contents = f.readlines()

error_vals = 0
with open(r'C:\Users\vaibhav\Documents\UVA\Summer\Project\Code\Vaibhav\HoneypotCSV\2018-01-01-mhn.csv', 'w') as file:
  writer = csv.writer(file, delimiter=',', lineterminator='\n')
  writer.writerow(
    ['timestamp', 'src', 'src_port', 'protocol', 'signature', 'direction', 'transport', 'app', 'vendor_product',
     'sensor', 'type', 'severity'])

  for line in contents:
    try:
      honeypot = honeypotmodel(honeypotmodel.get_honeypot_formatted_json(line))
      writer.writerow([honeypot.timestamp, honeypot.src_ip, honeypot.src_port, honeypot.protocol, honeypot.signature,
                       honeypot.direction, honeypot.transport, honeypot.app, honeypot.vendor_product, honeypot.sensor,
                       honeypot.type, honeypot.severity])
    except ValueError as e:
      error_vals += 1
      print(e)
print(error_vals)
