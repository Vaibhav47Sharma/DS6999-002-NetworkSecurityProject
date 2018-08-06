import json, csv, os


class fireeyemodel:
  def __init__(self, input_string):
    json_input = json.loads(input_string)
    self.timestamp = json_input['rt']
    #source ip
    self.src_ip = json_input['src']
    #destination ip
    self.dst_ip = json_input['dst']
    #network protocol
    self.protocol = json_input['proto']
    #smac
    self.smac = json_input['smac']
    #cs4 event- stripped earlier
    # self.cs4 = 'https://fireeye3.ispro.virginia.edu/event_stream/events_for_bot?ev_id\=' + json_input['cs4']
    # cs6 event- stripped earlier
    # self.cs6 = 'GET /fcg-bin/cgi_get_portrait.fcg?uins\=' + json_input['cs6']
    # request - stripped earlier
    # self.request = 'hxxp://users.qzone.qq.com/fcg-bin/cgi_get_portrait.fcg?uins\=' + json_input['request']
    #dmac
    self.dmac = json_input['dmac']
    self.cs1 = json_input['cs1']
    self.cs1_label = json_input['cs1Label']

  @staticmethod
  def get_fireeye_formatted_json(ip_line):
    # ip_line = ip_line.replace('https://fireeye3.ispro.virginia.edu/event_stream/events_for_bot?ev_id\=', '')
    # ip_line = ip_line.replace('GET /fcg-bin/cgi_get_portrait.fcg?uins\=', '')
    # ip_line = ip_line.replace('hxxp://users.qzone.qq.com/fcg-bin/cgi_get_portrait.fcg?uins\=', '')
    ip_line = ip_line.replace('\n', '')
    ip_line = ip_line.replace('\|', '---')
    ip_line = ip_line.replace('\=', ';;')
    cs5_index = ip_line.index('cs5=', 1)
    rt_index = ip_line.index('rt=', 1)

    first_key = 'cs5=' if cs5_index < rt_index else 'rt='
    body = ip_line.split(first_key, 1)[1]
    body = first_key + body
    body_arr = body.split('=')
    output = '{\"' + first_key.split('=')[0]+ '\":'
    for i in range(1, len(body_arr) - 1):
      (value, key) = body_arr[i].rsplit(' ', 1)
      output += ('\"' + value.strip() + '\", \"' + key.strip() + '\":')
    output += '\"' + body_arr[len(body_arr) - 1].strip() + '\"}'
    return output

with open('C:\\Users\\vaibhav\\Documents\\UVA\\Summer\\Project\\Fireeye\\fireeye\\felog-2018-05-30.log') as f:
  contents = f.readlines()

# print(fireeyemodel.get_fireeye_formatted_json(contents[0]))

error_vals = 0
with open(r'C:\Users\vaibhav\Documents\UVA\Summer\Project\Code\Vaibhav\FireeyeCSV\2018-05-30.csv', 'w') as file:
  writer = csv.writer(file, delimiter=',', lineterminator='\n')
  writer.writerow(
    ['timestamp', 'src', 'dst', 'protocol', 'smac', 'dmac', 'cs1', 'cs1Label'])

  for line in contents:
    try:
      fireeye = fireeyemodel(fireeyemodel.get_fireeye_formatted_json(line))
      writer.writerow([fireeye.timestamp, fireeye.src_ip, fireeye.dst_ip, fireeye.protocol, fireeye.smac,
                       fireeye.dmac, fireeye.cs1, fireeye.cs1_label])
    except ValueError as e:
      print(line)
      print(e)
      error_vals += 1

print(error_vals)
