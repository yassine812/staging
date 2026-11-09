Country names, capitals and time zones
=====================================

`countries.csv` is derived from the GeoNames `countryInfo.txt` and
`cities15000.zip` datasets retrieved on 2026-11-09.

Sources and license

- https://download.geonames.org/export/dump/countryInfo.txt
- https://download.geonames.org/export/dump/cities15000.zip
- https://download.geonames.org/export/dump/readme.txt
- GeoNames data is licensed under CC BY 4.0, https://creativecommons.org/licenses/by/4.0/

The extract keeps current country/territory codes and capital time zones.
Retired codes AN and CS are excluded. GeoNames records 2462881, 281184 and
7303419 provide the capital zones for EH, IL and PS. When a territory has no
capital record, its single IANA country zone is used if one exists.
AQ, BV, HM and UM have no unambiguous capital zone and retain an empty zone.
The form requests clarification for these territories.

Localized country names come from Unicode CLDR through the Babel dependency.
Additional common names are defined in `countries.py`. For matricules, Germany
uses the user-requested internal code GR. Other countries use their ISO code.
