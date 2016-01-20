ls.clientSlider = null;
function cliSlPadding(destroy){
	if(!destroy){
		var $sl = $('.clients-slider'),
			$active = $sl.find('.swiper-slide-active'),
			$tool = $active.find('.tooltip-content');
		h = $tool.innerHeight() + 30;
		var $scliTitle = $('.s-clients .b-title');

		$scliTitle.css({
			'padding-bottom' : h
		});
	}
}
ls.init.clientSlider = function(){
	//other browser versions launching for old platforms
	if ($body.hasClass('sm')) {
		ls.clientSlider = new Swiper('.clients-slider', bdSettings.settingsClSlSm);
		// 750px version of clients slider initialization
	}
	else if ($body.hasClass('xs')) {
		ls.clientSlider = new Swiper('.clients-slider', bdSettings.settingsClSlXs);
	} else {
		ls.clientSlider = new Swiper('.clients-slider', bdSettings.settingsClSl); // CLients slider initialization
	}

	if ( device.mobile() ) cliSlPadding();

	if (oldIE || device.mobile() || device.tablet()) {
		$('.cli-prev-arrow').on('click', function (e) {
			e.preventDefault();
			ls.clientSlider.swipePrev();
		});
		$('.cli-next-arrow').on('click', function (e) {
			e.preventDefault();
			ls.clientSlider.swipeNext();
		});
	}

	function resizeUpdate() {
		modSm();
		if ($body.hasClass('sm')) {
			// +++
			if (typeof ls.clientSlider.destroy != 'function') return;
			// ^^^
			ls.clientSlider.destroy();
			$('.s-clients .b-title').attr('style', '');
			ls.clientSlider = new Swiper('.clients-slider', bdSettings.settingsClSlSm);
		}
		else if ($body.hasClass('xs')) {
			// +++
			if (typeof ls.clientSlider.destroy != 'function') return;
			// ^^^
			ls.clientSlider.destroy();
			ls.clientSlider = new Swiper('.clients-slider', bdSettings.settingsClSlXs);
		} else {
			// +++
			if (typeof ls.clientSlider.destroy != 'function') return;
			// ^^^
			ls.clientSlider.destroy();
			$('.s-clients .b-title').attr('style', '');

			ls.clientSlider = new Swiper('.clients-slider', bdSettings.settingsClSl);
		}
		if ($body.hasClass('xs')) {
			cliSlPadding();

		} else {
			cliSlPadding(true);
		}
	}

	ls.resizeHandlers.push(resizeUpdate);
}