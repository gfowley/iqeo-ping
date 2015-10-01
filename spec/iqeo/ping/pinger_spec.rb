require 'spec_helper'

describe Iqeo::Ping::Pinger do

  context '#new' do

    it 'accepts an IP address string' do
      expect { Iqeo::Ping::Pinger.new '127.0.0.1' }.to_not raise_error
    end

    it 'accepts a Hostspec' do
      expect { Iqeo::Ping::Pinger.new( Iqeo::Hostspec::Hostspec.new '127.0.0.1' ) }.to_not raise_error
    end

    it 'requires an argument' do
      expect { Iqeo::Ping::Pinger.new }.to raise_error ArgumentError
    end

  end

  context '#hostspec' do

    it 'is created from string' do
      expect( Iqeo::Ping::Pinger.new('127.0.0.1').hostspec ).to be_a Iqeo::Hostspec::Hostspec 
    end

    it 'is passed from #new' do
      expect( Iqeo::Ping::Pinger.new( Iqeo::Hostspec::Hostspec.new '127.0.0.1' ).hostspec ).to be_a Iqeo::Hostspec::Hostspec
    end

  end

  context 'defaults' do
    subject { Iqeo::Ping::Pinger.new '127.0.0.1' }
    its(:protocol) { is_expected.to eq :icmp }
    its(:port)     { is_expected.to eq nil }
  end

end

