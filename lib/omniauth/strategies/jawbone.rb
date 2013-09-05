require 'cgi'
require 'uri'
require 'oauth2'
require 'omniauth'
require 'timeout'
require 'securerandom'
require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Jawbone < OmniAuth::Strategies::OAuth2

      option :client_options, {
        :site => 'https://jawbone.com',
        :authorize_url => '/auth/oauth2/auth',
        :token_url => '/auth/oauth2/token'
      }

      option :authorize_options, [
        :scope
      ]

      def request_phase
        req = Rack::Request.new(@env)
        options.update(req.params)
        ua = req.user_agent.to_s
        if !options.has_key?(:scope)
          options[:scope] = 'extended_read'
        end
        super
      end

      #uid { raw_info['xid'].to_s }

      info do
        {
          'id' => raw_info['xid'],
          'photo' => raw_info['photo'],
          'first_name' => raw_info['first'],
          'last_name' => raw_info['last'],
        }
      end


      def user_data
        access_token.options[:mode] = :query
        user_data ||= access_token.get('/nudge/api/users/@me').parsed
      end

    end
  end
end


OmniAuth.config.add_camelization 'jawbone', 'Jawbone'
