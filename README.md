![Logo](admin/vw-connect.png)
# ioBroker.vw-connect

[![NPM version](http://img.shields.io/npm/v/iobroker.vw-connect.svg)](https://www.npmjs.com/package/iobroker.vw-connect)
[![Downloads](https://img.shields.io/npm/dm/iobroker.vw-connect.svg)](https://www.npmjs.com/package/iobroker.vw-connect)
[![Dependency Status](https://img.shields.io/david/ta2k/iobroker.vw-connect.svg)](https://david-dm.org/ta2k/iobroker.vw-connect)
[![Known Vulnerabilities](https://snyk.io/test/github/ta2k/ioBroker.vw-connect/badge.svg)](https://snyk.io/test/github/ta2k/ioBroker.vw-connect)

[![NPM](https://nodei.co/npm/iobroker.vw-connect.png?downloads=true)](https://nodei.co/npm/iobroker.vw-connect/)

**Tests:**: [![Travis-CI](http://img.shields.io/travis/ta2k/ioBroker.vw-connect/master.svg)](https://travis-ci.org/ta2k/ioBroker.vw-connect)

## vw-connect adapter for ioBroker

Adapter for VW We Connect and Skoda Connect

## Usage
Use the state under remote control to control your car remotly.

##  Status fields Explanation


'0x0101010002.0x0101010002': //distanceCovered

'0x0204FFFFFF.0x02040C0001': //adBlueInspectionData_km

'0x0203FFFFFF.0x0203010001': //oilInspectionData_km

'0x0203FFFFFF.0x0203010002': //oilInspectionData_days

'0x0203FFFFFF.0x0203010003': //serviceInspectionData_km

'0x0203FFFFFF.0x0203010004': //serviceInspectionData_days

'0x030101FFFF.0x0301010001': //status_parking_light_off

'0x030103FFFF.0x0301030001': //parking brake

'0x030103FFFF.0x0301030007': //fuel type

'0x030103FFFF.0x030103000A': //fuel level

'0x030103FFFF.0x0301030006': //fuel range

'0x030103FFFF.0x0301030009': //secondary_typ - erst ab Modelljahr 2018

'0x030103FFFF.0x0301030002': //soc_ok

'0x030103FFFF.0x0301030008': //secondary_range - erst ab Modelljahr 2018

'0x030103FFFF.0x0301030005': //hybrid_range - erst ab Modelljahr 2018

1 = open 2 = Locked 3 = Closed
//door1 - front/left

'0x030104FFFF.0x0301040001':
//door2 - rear/left

'0x030104FFFF.0x0301040004':
//door3 - front/right

'0x030104FFFF.0x0301040007':
//door4 - rear/right

'0x030104FFFF.0x030104000A':
//door5 - rear

'0x030104FFFF.0x030104000D':
//door6 - hood

'0x030104FFFF.0x0301040010':
//window1 - front/left

'0x030105FFFF.0x0301050001':
//window2 - rear/left

'0x030105FFFF.0x0301050003':
//window3 - front/right

'0x030105FFFF.0x0301050005':
//window4 - rear/right

'0x030105FFFF.0x0301050007':
//window4 - roof window

'0x030105FFFF.0x030105000B':

## Changelog

### 0.0.5
* add honk and flash, fix address format

### 0.0.4
* add Skoda support

### 0.0.3
* (ta2k) add more information
* (ta2k) add remote controls
  
### 0.0.2
* (ta2k) add car status capturing

### 0.0.1
* (ta2k) initial release

## License
MIT License

Copyright (c) 2019 ta2k <tombox2020@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.