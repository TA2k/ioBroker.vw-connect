class LatLng {
  constructor(lat, lng) {
    this.lat = lat;
    this.lng = lng;
  }
}

function load(params) {
  var startCoords = SMap.Coords.fromWGS84(params[0].lng, params[0].lat);
  var destinationCoords = SMap.Coords.fromWGS84(
    params[params.length - 1].lng,
    params[params.length - 1].lat
  );

  params.shift();
  params.pop();

  var mapUrl = new SMap.URL.Route()
    .addStart(startCoords)

  params.forEach(latLng =>
    mapUrl.addWaypoint(SMap.Coords.fromWGS84(latLng.lng, latLng.lat))
  )

  mapUrl.addDestination(destinationCoords)

  return mapUrl.toString()
};