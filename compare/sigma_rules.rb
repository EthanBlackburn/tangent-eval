# Sigma's rules as JSON, which sigma.py and cloud_sigma.py read: Python's
# standard library has no YAML, and the system's ruby does.
#
#   ruby sigma_rules.rb PRODUCTS DIR [DIR ...] > rules.json
#
# Every .yml under each DIR of a checkout of SigmaHQ/sigma whose
# `logsource.product` is one of PRODUCTS (comma-separated), in path order, each with the file it
# came from as `_file`.
require "yaml"
require "json"
require "date"
products = ARGV.shift.split(",")
files = ARGV.flat_map { |d| Dir[File.join(d, "**", "*.yml")] }.sort
rules = files.map do |f|
  r = YAML.safe_load(File.read(f), permitted_classes: [Date, Time])
  r.is_a?(Hash) ? r.merge("_file" => f) : nil
end
puts JSON.generate(rules.select { |r| r && products.include?((r["logsource"] || {})["product"]) })
