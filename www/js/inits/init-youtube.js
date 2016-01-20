ls.init.youtube = function(){
	var $video = $('#s-video'),
		$text = $video.find('.video-text'),
		$dummy = $('#ytpl');
	if (!($video.length && $dummy.length)) return;

	var	data = $dummy.data(),
		muted = ( data.muted !== undefined ) ? 1 : 0,
		autoplay = ( data.autoplay !== undefined ) ? 1 : 0,
		// autoplay in settings won't work, API's broken right now.
		// so we'll fake its action manually onReady
		settings = {
			showinfo: ( data.showinfo !== undefined ) ? 1 : 0,
			controls: ( data.controls !== undefined ) ? 1 : 0,
			playlist: data.src,
			loop: ( data.loop !== undefined ) ? 1 : 0,
		}, player, string = '', textShowDelay,
		scrollCheckDelay, alreadyScrolled = false;
		
	string += data.src + '?enablejsapi=1';
	string += '&showinfo=' + settings.showinfo;
	string += '&controls=' + settings.controls;
	string += '&playlist=' + settings.playlist;
	string += '&loop=' + settings.loop;

	$iframe = $('<iframe src="https://www.youtube.com/embed/' + string + '">').insertBefore($dummy);
	$dummy.remove();

	player = new YT.Player($iframe.get(0), {
		events: {
			'onStateChange': function(e){
				if ( e.data === YT.PlayerState.PAUSED || e.data === YT.PlayerState.ENDED){
					clearTimeout(textShowDelay);
					textShowDelay = setTimeout(function(){
						$text.fadeIn('fast');
					}, 1000);
				} else if ( e.data === YT.PlayerState.PLAYING ){
					clearTimeout(textShowDelay);
					$text.fadeOut('fast');
				}
			},
			'onReady': function(e){
				$video.find('.poster:first').remove();
				muted && e.target.mute();
				autoplay && e.target.playVideo();
			},
		}
	});

	$text.on('click', '.b-title', function(){
		$text.fadeOut('fast');
		player.playVideo();
	});

	function scrollCheck(){
		if (alreadyScrolled) return;
		var scrollTop = $w.scrollTop() + $('#main-header').outerHeight(),
			vTop = $video.offset().top,
			wHalf = $w.outerHeight() / 2,
			scrollTargetTop = vTop - wHalf,
			scrollTargetBottom = vTop,
			isInside = (scrollTop >= scrollTargetTop &&
						scrollTop <= scrollTargetBottom);

		if (isInside && typeof player.playVideo === 'function'){
			player.playVideo();
			alreadyScrolled = true;
			clearTimeout(scrollCheckDelay);
		} else {
			scrollCheckDelay = setTimeout(scrollCheck, 500);
		}
	}
	scrollCheck();
}

//=========== CHANGED FOR COMPOSITE MODE TO WORK ===========//
function onYouTubePlayerAPIReady() {
	if (typeof window.frameCacheVars !== "undefined") 
	{
		if( isFrameDataReceived ) {
			if (typeof ls.init.youtube === 'function') ls.init.youtube();
		} else {
			BX.addCustomEvent("onFrameDataReceived", function(json) {
				if (typeof ls.init.youtube === 'function') ls.init.youtube();
			});
		}
	}
	else
	{
		if ( windowLoaded ) {
			if (typeof ls.init.youtube === 'function') ls.init.youtube();
		} else {
			$(window).load(function(){
				if (typeof ls.init.youtube === 'function') ls.init.youtube();
			});
		}
	}
}

var tag = document.createElement('script');
tag.src = "http://www.youtube.com/player_api";
var firstScriptTag = document.getElementsByTagName('script')[0];
firstScriptTag.parentNode.insertBefore(tag, firstScriptTag);