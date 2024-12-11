require 'ipaddr'

def convert_ip_range(start_ip, end_ip)
  start_ip = IPAddr.new(start_ip)
  end_ip = IPAddr.new(end_ip)
  return (start_ip..end_ip).map(&:to_s)
end


ips=convert_ip_range(ARGV[0], ARGV[1])

ips.each_slice(ARGV[2]) do |list|
  puts list.join(' ')
end
