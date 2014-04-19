require "akami/wsse/certs"

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

      def initialize(certs = Certs.new, use_binary_security_token = true)
        @certs = certs
        @use_binary_security_token = use_binary_security_token
      end

      def have_document?
        !!document
      end

      # Cache "now" so that digests match...
      # TODO: figure out how we might want to expire this cache...
      def now
        @now ||= Time.now
      end

      def body_id
        @body_id ||= "Body-#{uid}".freeze
      end

      def timestamp_id
        @timestamp_id ||= "Timestamp-#{uid}".freeze
      end

      def security_token_id
        @security_token_id ||= "SecurityToken-#{uid}".freeze
      end

      def body_attributes
        { 'xmlns:wsu' => WSU_NAMESPACE, 'wsu:Id' => body_id }
      end

      def to_token
        return {} unless have_document?

        sig = signed_info.merge(key_info).merge(signature_value)
        sig.merge! :order! => []
        [ 'SignedInfo', 'SignatureValue', 'KeyInfo' ].each do |key|
          sig[:order!] << key if sig[key]
        end

        token = {
          'Signature' => sig,
          :attributes! => {
            'Signature' => { 'xmlns' => SignatureNamespace }
          }
        }

        token.deep_merge!(binary_security_token) if (use_binary_security_token and certs.cert)

        token.merge! :order! => []
        [ 'wsse:BinarySecurityToken', 'Signature' ].each do |key|
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
            'wsse:Reference/' => { 'ValueType' => X509v3ValueType, 'URI' => "##{security_token_id}" }
          }
        }
      end

      def x509_data
        {
          'X509Data' => {
            'X509IssuerSerial' => {
              'X509IssuerName' => certs.cert.issuer.to_s(OpenSSL::X509::Name::RFC2253),
              'X509SerialNumber' => certs.cert.serial
            }
          }
        }
      end

      def key_info
        {
          'KeyInfo' => {
            'wsse:SecurityTokenReference' => use_binary_security_token ? binary_security_token_reference : x509_data,
            # :attributes! => {
            #   'wsse:SecurityTokenReference' => { 'xmlns:wsu' => WSU_NAMESPACE }
            # },
          },
        }
      end

      def signature_value
        { 'SignatureValue' => the_signature }
      rescue MissingCertificate
        {}
      end

      def signed_info
        reference = []
        reference_uri = []

        reference << signed_info_transforms.merge(signed_info_digest_method).merge({ 'DigestValue' => body_digest })
        reference_uri << "##{body_id}"
        if timestamp_digest
          reference << signed_info_transforms.merge(signed_info_digest_method).merge({ 'DigestValue' => timestamp_digest })
          reference_uri << "##{timestamp_id}"
        end

        {
          'SignedInfo' => {
            'CanonicalizationMethod/' => nil,
            'SignatureMethod/' => nil,
            'Reference' => reference,
            :attributes! => {
              'CanonicalizationMethod/' => { 'Algorithm' => ExclusiveXMLCanonicalizationAlgorithm },
              'SignatureMethod/' => { 'Algorithm' => RSASHA1SignatureAlgorithm },
              'Reference' => { 'URI' => reference_uri },
            },
            :order! => [ 'CanonicalizationMethod/', 'SignatureMethod/', 'Reference' ]
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

      def body_digest
        body = canonicalize(at_xpath(@document, '//Envelope/Body'))
        encode(OpenSSL::Digest::SHA1.digest(body))
      end

      def timestamp_digest
        ts = at_xpath(@document, '//Envelope/Header/Security/Timestamp')
        return nil unless ts
        ts = canonicalize(ts)
        encode(OpenSSL::Digest::SHA1.digest(ts))
      end

      def signed_info_digest_method
        { "DigestMethod/" => nil, :attributes! => { "DigestMethod/" => { "Algorithm" => SHA1DigestAlgorithm } } }
      end

      def signed_info_transforms
        { "Transforms" => { "Transform/" => nil, :attributes! => { "Transform/" => { "Algorithm" => ExclusiveXMLCanonicalizationAlgorithm } } } }
      end

      def uid
        OpenSSL::Digest::SHA1.hexdigest([Time.now, rand].collect(&:to_s).join('/'))
      end

    end
  end
end
