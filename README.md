# Goodwe Prometheus Exporters

This repository contains Prometheus metrics exporters for Goodwe solar energy devices including inverters and smart meters.

Currently only the SEMS MITM Exporter is implemented, although a Modbus exporter is planned.

## SEMS MITM Exporter

This is a Prometheus exporter for Goodwe devices which integrate with the cloud-hosted Smart Energy Managment System (SEMS) portal.
It works by implementing a [MITM attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) on the SEMS portal protocol, hence the name.

## Motivation / Features

The SEMS MITM exporter has the following advantages over just using the SEMS Portal:

* Transparently forwards data to SEMS Portal (option not to forward traffic is a WIP).
* Allows you to store your data in a Prometheus instance that you control.
* Visualise your data using standard tools like Grafana.
* Drops unrecognised incoming packets to block e.g. firmware upgrades.
* (optionally) summons Batman to the SEMS Portal.

### Hardware support

Currently hardware support in the SEMS MITM Exporter is limited to the equipment I own:

* [Goodwe Homekit 1000](https://www.goodwe.com.au/single-phase-homekit) smart meter (implemented)
* [DNS G3](https://www.goodwe.com.au/dns-g3-au) inverter is a WIP.

PRs welcome if you want to add support for your device.

### How to get it

You have a couple of options:

* Pull a docker image from the Github image registry (recommended!).
* Download a release binary from the Releases page.

### How to use it

At a high level:

1. Start the exporter.
1. Get traffic to the exporter. Either:
    * Point the DNS of `tcp.goodwe-power.com` to the IP of the exporter; or
    * Reconfigure your hardware to connect to the IP of the exporter.
1. Configure Prometheus to scrape from the exporter on port 14028.
1. Grab the Grafana dashboard and visualise your metrics.

Detailed instructions for supported hardware is a WIP.

## Why does this exist?

### Short version

Homekit 1000 does not support Modbus for metrics querying, so the only way to get data out of it appears to be from the SEMS Portal traffic.

Other Goodwe hardware probably supports Modbus, which may be more convenient for scraping metrics.

### Long version

See the blog post.
