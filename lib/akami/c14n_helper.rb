module Akami
  module C14nHelper
    def canonicalize(xml, inclusive_namespaces=nil, with_comments=false)
      return unless xml
      xml.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0, inclusive_namespaces, with_comments)
    end
  end
end
