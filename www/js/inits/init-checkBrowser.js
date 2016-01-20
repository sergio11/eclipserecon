var oldIE, is_chrome = /chrom(e|ium)/.test(navigator.userAgent.toLowerCase()); 
// Detect Any IE
function msieversion () {
	var ua = window.navigator.userAgent;
	var msie = ua.indexOf("MSIE ");
	var ie = false;

	if (msie > 0 || !!navigator.userAgent.match(/Trident.*rv\:11\./)) {    // If Internet Explorer, return version number
		ie = true;
		$html.addClass('ie');
	}

	return false;
}
// Медиазапросы кросс
function modSm () {
	if (Modernizr.mq('(min-width: 768px) and (max-width: 991px)')) {
		$body.addClass("sm");
	} else {
		// Clear the settings etc
		$body.removeClass("sm");
	}
	if (Modernizr.mq('(min-width: 320px) and (max-width: 767px)')) {
		$body.addClass("xs");
	} else {
		// Clear the settings etc
		$body.removeClass("xs");
	}
}
ls.init.checkBrowser = function(){
	if (is_chrome) $html.addClass('chrome');
	if ($html.is('.ie6, .ie7, .ie8')) oldIE = true;

	msieversion(); // Detect Any IE version
	modSm(); // check media queries
}