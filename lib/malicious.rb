# frozen_string_literal: true

require 'malicious/version'

module Malicious
  class Report
    def initialize(result)
      @result = result
    end

    def scan_time
      Time.parse(@result['scan_date'])
    end

    def verbose_message
      @result['verbose_msg']
    end

    def filescan_id
      @result['filescan_id']
    end

    def resource
      @result['resource']
    end

    def response_code
      @result['response_code']
    end

    def exists?
      @result.exists?
    end

    def positives
      @result['positives']
    end

    def url
      @result['url']
    end

    def permalink
      @result['permalink']
    end

    def total
      @result['total']
    end

    def malicious?
      positives.positive?
    end

    def ready?
      total.to_i.positive?
    end

    def scan_id
      @result['scan_id']
    end

    def scans
      Array(@result['scans']).map do |scan|
        Scan.new(scan.first, scan.last)
      end
    end
  end

  class Scan
    def initialize(reporter, report_scan)
      @reporter = reporter
      @report_scan = report_scan
    end

    def detected?
      @report_scan['detected']
    end
  end

  class Client
    def initialize(api_key:)
      @api_key = api_key
    end

    def url_scan(url)
      report = VirustotalAPI::URLReport.find(url, @api_key, 1)

      unless report.exists?
        return
      end

      Report.new(report.report)
    end
  end
end
