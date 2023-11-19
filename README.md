# SEMS MITM Exporter

This is a Prometheus exporter for the Goodwe devices which integrate with the cloud-hosted Smart Energy Managment System (SEMS) portal.

It works by implementing a [MITM attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) on the SEMS portal protocol, hence the name.

## Hardware support

Currently hardware support is limited to the Homekit 1000.
PRs welcome if you want to add support for your device - see below.

## How to get it

You have a couple of options:

* Download a release binary from the Releases page.
* Pull an image from the image registry.

## How to use it

1. Start the exporter.
1. Get traffic to the exporter. For example:
    * Point the DNS of `tcp.goodwe-power.com` to the IP of the exporter; or
    * Reconfigure your hardware to connect to the IP of the exporter.
1. Configure Prometheus to scrape from the exporter on port 14028.
1. (Optional) Grab the Grafana dashboard and visualise your metrics.

## Why does this exist?

### Short version

Homekit 1000 does not support Modbus for metrics querying.
Other Goodwe hardware probably supports Modbus, which is much more convenient for scraping metrics.

### Long version

See the blog post.
