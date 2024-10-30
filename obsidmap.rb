require 'nokogiri'
require 'net/http'
require 'uri'

$apikey=ENV['obsidian_apikey']
$port="27124"
#doc = File.open("test.xml") { |f| Nokogiri::XML(f) }

#For windows nmap under wsl
command = %Q|cmd.exe /c nmap -sV -p 80 --open #{ARGV.join(' ')} -oX -|

#For Linux
#command = %Q|nmap -sV -Pn -p- --open #{ARGV.join(' ')} -oX -|


doc = Nokogiri::XML(`#{command}`)

def send_data(filename, body)

  uri = URI.parse("https://127.0.0.1:#{$port}/vault/scans/#{filename}.md")
  request = Net::HTTP::Put.new(uri)
  request.content_type = "text/markdown"
  request["Accept"] = "*/*"
  request["Authorization"] = "Bearer #{$apikey}"
  request.body = %Q|#{body}|


  req_options = {
    use_ssl: uri.scheme == "https",
    verify_mode: OpenSSL::SSL::VERIFY_NONE,
  }

  response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
    http.request(request)
  end

  # response.code
  # response.body

end


def prepare_data(port_dict, servicefp)

notes=%Q|## Notes|

if !servicefp[0].nil?

sfp_arr=[]

servicefp.each do |s|

sfp_arr.push(%Q|
```
#{s}
```
|)
end
  notes=%Q|#{notes}
  ### Service Fingerprints

  #{sfp_arr.join("\n")}
 
  |
end

arr=[]
port_dict.each do |k,v|
  puts k
  $ip = k.split('-')[1]
  $hostname = k.split('-')[0]
  $filename = k
  v.each do |j|
    port = j[0]
    proto = j[1]
    state = j[2]
    service = j[3]
    arr.push(%Q|- "#{port}:#{proto}:#{service}"|)
  end

end

body= %Q|---
  datetime: #{Time.now}
  hostname: #{$hostname}
  ip: #{$ip}
  open_ports:
    #{arr.join("\n    ")}
  tags:
    - asset
---

#{notes}

|
puts $filename
send_data($filename, body)
end

doc.xpath("//nmaprun/host").each do |node|
  port_dict={}
  port_arr=[]
  name_arr=[]
  servicefp=[]
  node.children.each do |child|
    if child.name  == 'hostnames'

      child.children.each do |x|
        if !x['name'].nil?
	        name_arr.push(x['name'])
	      end
      end
    end

    if child.name == 'address'
      address=child['addr']
    end

    if child.name == 'ports'
      child.children.each do |x|
        c_arr=[]
        portid =  x['portid']
	      protocol = x['protocol']
        c_arr.push(portid)
        c_arr.push(protocol)
        x.children.each do |y|
          if y.name == 'state'
            state = y['state']
            c_arr.push(state)
          end
	        if y.name == 'service'
            service = y['name']
            c_arr.push(service)
            if !y['servicefp'].nil?
              servicefp.push(y['servicefp'])
            end
          end
        end
        if !c_arr[0].nil?
          port_arr.push(c_arr)
        end
      end
      port_arr.push("#{name_arr.uniq[0]}")
      port_dict["#{name_arr.uniq[0]}-#{address}"] = port_arr
      prepare_data(port_dict, servicefp)
    end

  end
end


