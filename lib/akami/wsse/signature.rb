require "akami/wsse/certs"
require "uuid"

module Akami
  class WSSE
    class Signature
      include Akami::XPathHelper
      include Akami::C14nHelper
      include Akami::EncodeHelper

      class MissingCertificate < RuntimeError; end

      # For a +Savon::WSSE::Certs+ object. To hold the certs we need to sign.
      attr_accessor :certs, :use_binary_security_token

      # Without a document, the document cannot be signed.
      # Generate the document once, and then set document and recall #to_token
      def document
        @document ? @document.to_s : nil
      end

      def document=(document)
        @document = Nokogiri::XML(document)
      end

      SIGNED_PARTS_MAP = {
        body: '//Envelope/Body',
        message_id: '//Envelope/Header/MessageID',
        timestamp: '//Envelope/Header/Security/Timestamp',
        reply_to: '//Envelope/Header/ReplyTo',
        to: '//Envelope/Header/To',
        from: '//Envelope/Header/From',
        action: '//Envelope/Header/Action',
        fault_to: '//Envelope/Header/FaultTo',
        relates_to: '//Envelope/Header/RelatesTo'
      }.freeze

      def part_id(part)
         @ids[part] ||= "#{part.to_s}-#{uid}".freeze
      end

      def reset_ids!
         @ids = {}
      end

      def timestamp_id
         part_id :timestamp
      end

      def security_token_id
         part_id :security_token
      end

      def initialize(certs = Certs.new, options = {})
        @certs = certs
        @ids = {}
        @options = {
          use_binary_security_token: true,
          signed_parts: [ :attachments, :body, :reply_to, :to, :from, :message_id, :fault_to, :action, :relates_to, :timestamp ]
        }.merge(options)

        @use_binary_security_token = @options[:use_binary_security_token]
      end

      def have_document?
        !!document
      end

      # Cache "now" so that digests match...
      # TODO: figure out how we might want to expire this cache...
      def now
        @now ||= Time.now
      end

      def body_attributes
        { 'xmlns:wsu' => WSU_NAMESPACE, 'wsu:Id' => part_id(:body) }
      end

      def to_token
        return {} unless have_document?

        sig = signed_info.merge(key_info).merge(signature_value)
        sig.merge! :order! => []
        [ 'ds:SignedInfo', 'ds:SignatureValue', 'ds:KeyInfo' ].each do |key|
          sig[:order!] << key if sig[key]
        end

        token = {
          'ds:Signature' => sig,
          :attributes! => {
            'ds:Signature' => { 'xmlns:ds' => SignatureNamespace }
          }
        }

        token.deep_merge!(binary_security_token) if (use_binary_security_token and certs.cert)

        token.merge! :order! => []
        [ 'wsse:BinarySecurityToken', 'ds:Signature' ].each do |key|
          token[:order!] << key if token[key]
        end

        token
      end

      private

      def binary_security_token
        {
          'wsse:BinarySecurityToken' => encode(certs.cert.to_der),
          :attributes! => {
            'wsse:BinarySecurityToken' => {
              'wsu:Id' => security_token_id,
              'EncodingType' => Base64EncodingType,
              'ValueType' => X509v3ValueType,
              'xmlns:wsu' => WSU_NAMESPACE
            }
          }
        }
      end

      def binary_security_token_reference
        {
          'wsse:Reference/' => nil,
          :attributes! => {
            'wsse:Reference/' => { 'ValueType' => X509v3ValueType, 'URI' => "##{part_id(:security_token)}" }
          }
        }
      end

      def x509_data
        {
          'ds:X509Data' => {
            'ds:X509IssuerSerial' => {
              'ds:X509IssuerName' => certs.cert.issuer.to_s(OpenSSL::X509::Name::RFC2253),
              'ds:X509SerialNumber' => certs.cert.serial
            }
          }
        }
      end

      def key_info
        {
          'ds:KeyInfo' => {
            'wsse:SecurityTokenReference' => use_binary_security_token ? binary_security_token_reference : x509_data
          }
        }
      end

      def signature_value
        { 'ds:SignatureValue' => the_signature }
      rescue MissingCertificate
        {}
      end

      def signed_info
        reference = []
        reference_uri = []

        @options[:signed_parts].each do |part|
          digest = digest_xpath(SIGNED_PARTS_MAP[part])
          next if digest.nil?
          reference << signed_info_transforms.merge(signed_info_digest_method).merge({
            'ds:DigestValue' => digest
          })
          reference_uri << "##{part_id(part)}"
        end

        {
          'ds:SignedInfo' => {
            'ds:CanonicalizationMethod/' => nil,
            'ds:SignatureMethod/' => nil,
            'ds:Reference' => reference,
            :attributes! => {
              'ds:CanonicalizationMethod/' => { 'Algorithm' => ExclusiveXMLCanonicalizationAlgorithm },
              'ds:SignatureMethod/' => { 'Algorithm' => RSASHA1SignatureAlgorithm },
              'ds:Reference' => { 'URI' => reference_uri },
            },
            :order! => [ 'ds:CanonicalizationMethod/', 'ds:SignatureMethod/', 'ds:Reference' ]
          }
        }
      end

      def the_signature
        raise MissingCertificate, 'Expected a private_key for signing' unless certs.private_key
        signed_info = at_xpath(@document, '//Envelope/Header/Security/Signature/SignedInfo')
        signed_info = signed_info ? canonicalize(signed_info) : ''
        signature = certs.private_key.sign(OpenSSL::Digest::SHA1.new, signed_info)
        encode(signature)
      end

      def digest_xpath(xpath)
        val = at_xpath(@document, xpath)
        val.nil? ? nil : encode(OpenSSL::Digest::SHA1.digest(canonicalize(val)))
      end

      def signed_info_digest_method
        { 'ds:DigestMethod/' => nil, :attributes! => { 'ds:DigestMethod/' => { 'Algorithm' => SHA1DigestAlgorithm } } }
      end

      def signed_info_transforms
        { 'ds:Transforms' => { 'ds:Transform/' => nil, :attributes! => { 'ds:Transform/' => { 'Algorithm' => ExclusiveXMLCanonicalizationAlgorithm } } } }
      end

      def uid
        UUID.new.generate
      end

    end
  end
end
