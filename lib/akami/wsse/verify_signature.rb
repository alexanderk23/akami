module Akami
  class WSSE
    class InvalidSignature < RuntimeError; end

    class VerifySignature
      include Akami::XPathHelper
      include Akami::C14nHelper
      include Akami::EncodeHelper

      class InvalidDigest < RuntimeError; end
      class InvalidSignedValue < RuntimeError; end
      class UnsupportedAlgorithm < RuntimeError; end

      attr_reader :response_body, :document

      def initialize(response_body)
        @response_body = response_body
        @document = create_document
      end

      def signature_value
        # element = element_for_xpath("//Security/Signature/SignatureValue")
        element = xpath(document, '//Security/Signature/SignatureValue') # ignore namespaces
        element ? element.text.gsub(/\s*/, '') : ""
      end

      def certificate
        # certificate_value = element_for_xpath("//Security/BinarySecurityToken").text.strip
        certificate_value = xpath(document, '//Security/BinarySecurityToken').text # ignore namespaces
        return nil if certificate_value.empty?
        OpenSSL::X509::Certificate.new decode(certificate_value)
      end

      def valid?
        verify
      rescue InvalidDigest, InvalidSignedValue
        return false
      end

      def verify!
        verify
      rescue InvalidDigest, InvalidSignedValue => e
        raise InvalidSignature, e.message
      end

      private

      def apply_algorithm(ref, element)
        algorithm = ref.attribute('Algorithm').to_s
        node = ref.at_xpath('ec:InclusiveNamespaces', { 'ec' => algorithm  })
        inclusive_namespaces = node ? node.attributes['PrefixList'].to_s.squeeze(' ').split(' ') : nil
        if algorithm == ExclusiveXMLCanonicalizationWithCommentsAlgorithm
          with_comments = true
        elsif algorithm == ExclusiveXMLCanonicalizationAlgorithm
          with_comments = false
        else
          raise UnsupportedAlgorithm, "Unsupported c14n algorithm: #{algorithm}"
        end
        canonicalize(element, inclusive_namespaces, with_comments)
      end

      def verify
        # Check digests
        xpath(document, '//Security/Signature/SignedInfo/Reference').each do |ref|
          element_id = ref.attributes['URI'].to_s[1..-1] # strip leading '#'
          element = document.at_xpath("//*[@wsu:Id='#{element_id}']", 'wsu' => WSU_NAMESPACE)
          if !element.blank?
            supplied_digest = ref.at_xpath('ds:DigestValue', 'ds' => SignatureNamespace).text.strip
            # no multiple transformations yet (only first one applies)
            t = ref.at_xpath('ds:Transforms/ds:Transform', 'ds' => SignatureNamespace)
            xml = apply_algorithm(t, element)
            generated_digest = digest(xml).strip
            raise InvalidDigest, "Invalid digest for #{element_id}: got #{generated_digest}, expected #{supplied_digest}" unless supplied_digest == generated_digest
          else
            raise InvalidDigest, "Element #{element_id} is not found in document"
          end
        end
        return true if certificate.nil? # !!!
        # Check signature
        element = signed_info
        t = element.xpath('ds:CanonicalizationMethod', 'ds' => SignatureNamespace)
        xml = apply_algorithm(t, element)
        signature = decode signature_value
        certificate.public_key.verify(OpenSSL::Digest::SHA1.new, signature, xml) or raise InvalidSignedValue, "Signature is INVALID"
      end

      def create_document
        Nokogiri::XML response_body
      end

      def element_for_xpath(xpath)
        document.at_xpath xpath
      end

      def signed_info
        at_xpath document, "//Security/Signature/SignedInfo"
      end

      def digest(string)
        encode OpenSSL::Digest::SHA1.digest(string)
      end
    end
  end
end
