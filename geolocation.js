function success(position) {
    var latitude  = position.coords.latitude;
    var longitude = position.coords.longitude;

    var oReq = new XMLHttpRequest();

    var str1 = "http://www.domain.com/geolocation?lat=";
    var str2 = String(latitude);
    var str3 = "&lon=";	
    var str4 = String(longitude);
    var res = str1.concat(str2,str3,str4); 

    oReq.open("GET", res);
    oReq.send();
};

function error() {
    return;
};

if (navigator.geolocation)
{
    navigator.geolocation.getCurrentPosition(success, error);
}
