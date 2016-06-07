Virtual Private Network Detector (VPND)
======

##Synopsis

Virtual Private Network Detector (VPND) is an attempt to expand upon current Virtual Private Network traffic detection techniques by using advanced traffic profiling and geolocation. This project was completed as part of the 18-731 Network Security course at Carnegie Mellon University.

The main tool, tool.py, is written in Python. VPND also contains a javascript component for the geolocation portion of the detection mechanism. Specifically, VPND is using geolocation to estimate the distance between the actual user and their supposed IP address to determine if it is realistic. It also looks for unique fingerprints in HTTP header fields and Round Trip Times.

## Motivation

With the increasing popularity of content providers that broadcast TV shows, movies, and sporting events; a legal concern has been raised that VPN users can access content that is restricted in their countries. This content includes anything that has copyright issues together with the companies’ commercial decisions or governmental requirements to restrict some content in various parts of the world. For example, Netflix only exists in the market of a set of countries whereas it doesn’t provide content to a majority of countries. However, a user that lives in a country where Netflix does not exist in the market, can easily VPN through a country where Netflix broadcasts content. Another case is related to sporting events that are subject to restrictions in the viewer’s country. For instance, ESPN had broadcasting rights for the 2014 FIFA World Cup games in the United States whereas ZDF had these rights in Germany. These rights make it illegal for these channels to broadcast to other countries.

There are several concerns with VPN tunnels enabling users all around the world access the content broadcasted in a specific country. First of all, it causes a waste of resources for the content provider, and this may result in a lower quality of service for legitimate users. Secondly, there are legal issues forcing the provider to restrict the content within some set of countries, therefore, there may be legal issues behind broadcasting to other countries through VPN tunneling. Finally, the provider can choose not to broadcast some content in a set of countries for commercial reasons, and VPN tunneling would violate commercial policies. For all these reasons, a content provider would want to detect such VPN connections and block them when necessary.

## Installation

* **tool.py** - should be deployed and run on the content provider's server.
* **geolocation.js** - should be deployed on the web interface through which the client is accessing the content. 

## Contributors

* [Serhat Kiyak](https://github.com/serhatkiyak) - Carnegie Mellon University
* [Chase Miller](https://github.com/cnmiller) - Carnegie Mellon University
* Nicholas Caron - Carnegie Mellon University
