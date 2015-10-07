require 'spec_helper'
 
RSpec::Matchers.define_negated_matcher :not_be_alive, :be_alive

describe Iqeo::Ping::Pinger do

  HOST_SPEC           = '127.0.0.1'
  ALL_HOSTS_SPEC      = '127.0.0.1-3,252-254'
  FAST_HOSTS          = [ '127.0.0.1','127.0.0.2','127.0.0.3' ]
  FAST_HOSTS_SPEC     = '127.0.0.1-3'
  SLOW_HOSTS          = [ '127.0.0.252','127.0.0.253','127.0.0.254' ]
  SLOW_HOSTS_SPEC     = '127.0.0.252-254'
  SLOW_HOSTS_IPTABLES = '127.0.0.252/30'
  RESULT_KEYS         = [ :ip, :ping, :time, :exception ]

  before( :all ) { `iptables -I INPUT -d #{SLOW_HOSTS_IPTABLES} -j DROP` }

  context '.new' do

    context 'with defaults' do
      it( 'accepts an IP address string' ) { expect { Iqeo::Ping::Pinger.new HOST_SPEC }.to_not raise_error }
      it( 'accepts a Hostspec' )           { expect { Iqeo::Ping::Pinger.new( Iqeo::Hostspec::Hostspec.new HOST_SPEC ) }.to_not raise_error }
      it( 'requires an argument' )         { expect { Iqeo::Ping::Pinger.new }.to raise_error ArgumentError }
    end

    context 'with specifics' do
     
      it ( 'accepts timeout' )  { expect( Iqeo::Ping::Pinger.new( HOST_SPEC, timeout: 99).timeout ).to eq 99 }

      context 'ICMP' do
        before( :all )            { @pinger = Iqeo::Ping::Pinger.new HOST_SPEC, protocol: :icmp, timeout: 99 }
        it ( 'accepts protocol' ) { expect( @pinger.protocol ).to eq :icmp }
        it ( 'sets ping class' )  { expect( @pinger.klass ).to eq Net::Ping::ICMP }
        it ( 'sets port' )        { expect( @pinger.port ).to be nil }
      end

      context 'TCP' do
        before( :all )            { @pinger = Iqeo::Ping::Pinger.new HOST_SPEC, protocol: :tcp, timeout: 99 }
        it ( 'accepts protocol' ) { expect( @pinger.protocol ).to eq :tcp }
        it ( 'sets ping class' )  { expect( @pinger.klass ).to eq Net::Ping::TCP }
        it ( 'sets port' )        { expect( @pinger.port ).to be 80 }
      end

      context 'UDP' do
        before( :all )            { @pinger = Iqeo::Ping::Pinger.new HOST_SPEC, protocol: :udp, timeout: 99 }
        it ( 'accepts protocol' ) { expect( @pinger.protocol ).to eq :udp }
        it ( 'sets ping class' )  { expect( @pinger.klass ).to eq Net::Ping::UDP }
        it ( 'sets port' )        { expect( @pinger.port ).to be 53 }
      end

    end
    
  end

  context '#hostspec' do
    it( 'is from string' )      { expect( Iqeo::Ping::Pinger.new(HOST_SPEC).hostspec ).to be_a Iqeo::Hostspec::Hostspec }
    it( 'is passed from .new' ) { expect( Iqeo::Ping::Pinger.new( Iqeo::Hostspec::Hostspec.new HOST_SPEC ).hostspec ).to be_a Iqeo::Hostspec::Hostspec }
  end

  context '.classes' do
    it( 'is a hash' )  { expect( Iqeo::Ping::Pinger.classes ).to be_a Hash }
    it( 'maps names' ) { expect( Iqeo::Ping::Pinger.classes.keys ).to include :icmp, :tcp, :udp }
    it( 'to classes' ) { expect( Iqeo::Ping::Pinger.classes.values ).to include Net::Ping::ICMP, Net::Ping::TCP, Net::Ping::UDP }
  end

  context 'defaults' do
    before( :all )     { @pinger = Iqeo::Ping::Pinger.new HOST_SPEC }
    it( '#protocol' )  { expect( @pinger.protocol ).to eq Iqeo::Ping::Pinger::PROTOCOL }
    it( '#port' )      { expect( @pinger.port ).to eq Iqeo::Ping::Pinger::PORT }
    it( '#timeout' )   { expect( @pinger.timeout ).to eq Iqeo::Ping::Pinger::TIMEOUT }
  end

  context 'short scan' do

    before( :all ) { @pinger = Iqeo::Ping::Pinger.new FAST_HOSTS_SPEC }

    it( '#start' ) do
      expect { @pinger.start }.to_not raise_error
      sleep 0.1 # wait for it
    end

    context 'state' do
      it( 'is #started?' )  { expect( @pinger ).to be_started }
      it( 'is #running?' )  { expect( @pinger ).to_not be_running }
      it( 'is #finished?' ) { expect( @pinger ).to be_finished }
    end

    context '#threads' do
      it( 'one per host' )  { expect( @pinger.threads.count ).to eq @pinger.hostspec.count }
      it( 'all finished' )  { expect( @pinger.threads.none?(&:alive?) ).to be true }
    end

    context 'finishes' do
      it( 'successfully' )  { expect( @pinger.threads.first.value[:exception] ).to_not be_a Exception }
    end

    context '#results' do
      it( 'expected keys' ) { expect( @pinger.results ).to all( include *RESULT_KEYS ) }
      it( 'for each host' ) { expect( @pinger.results.collect { |r| r[:ip] } ).to eq FAST_HOSTS }
    end

  end

  context 'long scan' do

    before( :all ) { @pinger = Iqeo::Ping::Pinger.new SLOW_HOSTS_SPEC }

    it( '#start' ) do
      expect { @pinger.start }.to_not raise_error
      sleep 0.1 # wait for it
    end

    context 'state' do
      it( 'is #started?' )   { expect( @pinger ).to be_started }
      it( 'is #running?' )   { expect( @pinger ).to be_running }
      it( 'not #finished?' ) { expect( @pinger ).to_not be_finished }
    end

    context '#threads' do
      it( 'one per host' )   { expect( @pinger.threads.count ).to eq @pinger.hostspec.count }
      it( 'some alive' )     { expect( @pinger.threads.any?(&:alive?) ).to be true }
      it( 'some timeout' )   { expect( @pinger.threads.any? { |t| t.value[:exception].is_a? TimeoutError } ).to be true }
    end

    context '#results' do
      it( 'expected keys' )  { expect( @pinger.results ).to all( include *RESULT_KEYS ) }
      it( 'for each host' )  { expect( @pinger.results.collect { |r| r[:ip] } ).to eq SLOW_HOSTS }
    end

  end

  context 'stop scan' do

    before( :all ) { @pinger = Iqeo::Ping::Pinger.new ALL_HOSTS_SPEC }

    it( '#start' ) do
      expect { @pinger.start }.to_not raise_error
    end

    context 'state' do
      before( :all )         { sleep 0.1 } # wait for it
      it( 'is #started?' )   { expect( @pinger ).to be_started }
      it( 'is #running?' )   { expect( @pinger ).to be_running }
      it( 'not #finished?' ) { expect( @pinger ).to_not be_finished }
    end

    context '#stop scan'  do
      before( :all ) do 
        @stop = @pinger.stop
        sleep 0.1 # wait for it
      end
      it ( 'returns true' )  { expect( @stop ).to be true }
      it ( 'kills threads' ) { expect( @pinger.threads ).to all( not_be_alive ) }
    end

    context '#results' do
      context 'for complete hosts' do
        it( 'have expected keys' ) { expect( @pinger.results[0..2] ).to all( include *RESULT_KEYS ) }
        it( 'for each host' )      { expect( @pinger.results[0..2].collect { |r| r[:ip] } ).to eq FAST_HOSTS }
      end
      context 'for incomplete hosts' do
        it( 'are nil' )            { expect( @pinger.results[3..5] ).to all( be_nil ) }
      end
    end

  end

  after( :all ) { `iptables -D INPUT -d #{SLOW_HOSTS_IPTABLES} -j DROP` }

end

