module Malicious
  module VirusTotal
    # https://developers.virustotal.com/v2.0/reference#domain-report
    class DomainReport
      def initialize(data)
        @data = data
      end

      def detected_urls
        Array(@data['detected_urls']).map do |data|
          DetectedUrl.new(data)
        end
      end

      def positives
        detected_urls.sum(&:positives)
      end

      def vulnerable?
        detected_urls.size.positive?
      end
    end

    class DetectedUrl
      def initialize(data)
        @data = data
      end

      def to_s
        @data['url']
      end

      def url
        @data['url']
      end

      def positives
        @data['positives'].to_i
      end

      def total
        @data['total'].to_i
      end

      def scan_date
        Time.parse(@data['scan_date'])
      end
    end

    class UrlReport
      def initialize(data)
        @data = data
      end

      def scan_date
        Time.parse(@data['scan_date'])
      end

      def verbose_message
        @data['verbose_msg']
      end

      def filescan_id
        @data['filescan_id']
      end

      def resource
        @data['resource']
      end

      def response_code
        @data['response_code']
      end

      def exists?
        @data.exists?
      end

      def positives
        @data['positives']
      end

      def url
        @data['url']
      end

      def permalink
        @data['permalink']
      end

      def total
        @data['total']
      end

      def malicious?
        positives.positive?
      end

      def ready?
        total.to_i.positive?
      end

      def scan_id
        @data['scan_id']
      end

      def scans
        Array(@data['scans']).map do |scan|
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

        UrlReport.new(report.report)
      end

      def domain_scan(url)
        report = VirustotalAPI::DomainReport.find(url, @api_key)

        unless report.exists?
          return
        end

        DomainReport.new(report.report)
      end
    end
  end
end
