#!/usr/bin/env ruby

require "./lib/iqeo/scan"

address = '127.0.0.1-2'
services = {
  tcp: [ 80, 3306 ],
  udp: [ 53, 631 ]
}

scanner = Iqeo::Scan::Scanner.new address, services: services

scanner.start
scanner.started? # => true
scanner.finished? # => false

sleep 10

scanner.finished? # => true
scanner.results  
 # => [{:address=>"127.0.0.1",
 #      :protocol=>:tcp,
 #      :port=>80,
 #      :ping=>false,
 #      :time=>nil,
 #      :exception=>#<Errno::ECONNREFUSED: Connection refused>},
 #     {:address=>"127.0.0.1",
 #      :protocol=>:tcp,
 #      :port=>3306,
 #      :ping=>true,
 #      :time=>0.001068348,
 #      :exception=>nil},
 #     {:address=>"127.0.0.1",
 #      :protocol=>:udp,
 #      :port=>53,
 #      :ping=>false,
 #      :time=>nil,
 #      :exception=>#<Errno::ECONNREFUSED: Connection refused - recvfrom(2)>},
 #     {:address=>"127.0.0.1",
 #      :protocol=>:udp,
 #      :port=>631,
 #      :ping=>false,
 #      :time=>nil,
 #      :exception=>#<Timeout::Error: execution expired>},
 #     {:address=>"127.0.0.2",
 #      :protocol=>:tcp,
 #      :port=>80,
 #      :ping=>false,
 #      :time=>nil,
 #      :exception=>#<Errno::ECONNREFUSED: Connection refused>},
 #     {:address=>"127.0.0.2",
 #      :protocol=>:tcp,
 #      :port=>3306,
 #      :ping=>false,
 #      :time=>nil,
 #      :exception=>#<Errno::ECONNREFUSED: Connection refused>},
 #     {:address=>"127.0.0.2",
 #      :protocol=>:udp,
 #      :port=>53,
 #      :ping=>false,
 #      :time=>nil,
 #      :exception=>#<Errno::ECONNREFUSED: Connection refused - recvfrom(2)>},
 #     {:address=>"127.0.0.2",
 #      :protocol=>:udp,
 #      :port=>631,
 #      :ping=>false,
 #      :time=>nil,
 #      :exception=>#<Timeout::Error: execution expired>}]

