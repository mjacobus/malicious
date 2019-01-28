# frozen_string_literal: true

module Malicious
  class Samples
    def urls
      [
        'https://thetowelfactory.com/new/login/index.php',
        'https://grosfeld.global/me/login/index.php',
        'https://gilsondaub.cf/index/newpage/index.php',
        'https://vatsparivar.com/Admin/login/index.php',
        'https://agilemsc.com/Acci/wp-includes/index.php',
        'https://liascatering.com/fax/login/index.php',
      ]
    end

    def domains
      urls.map do |url|
        url.split('/')[2]
      end
    end
  end
end
