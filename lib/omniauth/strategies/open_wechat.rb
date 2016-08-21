require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class OpenWechat < OmniAuth::Strategies::OAuth2
      option :name, "open_wechat"

      option :client_options, {
        site:          "https://api.weixin.qq.com",
        authorize_url: "https://open.weixin.qq.com/connect/oauth2/authorize#wechat_redirect",
        token_url:     "/sns/oauth2/component/access_token",
        token_method:  :get
      }

      option :authorize_params, {scope: "snsapi_userinfo"}

      option :token_params, {parse: :json}

      option :userinfo_params, {lang: 'en'}

      uid do
        raw_info['openid']
      end

      info do
        {
          nickname:   raw_info['nickname'],
          sex:        raw_info['sex'],
          province:   raw_info['province'],
          city:       raw_info['city'],
          country:    raw_info['country'],
          headimgurl: raw_info['headimgurl']
        }
      end

      extra do
        {raw_info: raw_info}
      end

      def request_phase
        params = client.auth_code.authorize_params.merge(redirect_uri: callback_url).merge(authorize_params).merge(appid: options[:appid])
        component_appid = params.delete("client_id")
        query = params.to_options.sort.map do |key, value|
          "#{key}=#{value}"
        end.join('&')
        query = "#{query}&component_appid=#{component_appid}#wechat_redirect"
        url =  "https://open.weixin.qq.com/connect/oauth2/authorize?#{query}"
        redirect url
#         redirect client.authorize_url(params)
      end

      def raw_info
        @uid ||= access_token["openid"]
        @raw_info ||= begin
          access_token.options[:mode] = :query
          if access_token["scope"] == "snsapi_userinfo"
            response = access_token.get("/sns/userinfo", :params => options[:userinfo_params].merge({"openid" => @uid}), parse: :text)
            @raw_info = JSON.parse(response.body.gsub(/[\u0000-\u001f]+/, ''))
          else
            @raw_info = {"openid" => @uid }
            @raw_info.merge!("unionid" => access_token["unionid"]) if access_token["unionid"]
            @raw_info
          end
        end
      end

      protected
      def build_access_token
        params = {
          'appid' => options[:appid], 
          'component_appid' => client.id, 
          'component_access_token' => options[:component_access_token], 
          'code' => request.params['code'],
          'grant_type' => 'authorization_code' 
          }.merge(token_params.to_hash(symbolize_keys: true))
        client.get_token(params, deep_symbolize(options.auth_token_params))
      end

    end
  end
end
