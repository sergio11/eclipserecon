ls.init.modalDetailed = function($content){
	$content.find('.bootstrap-select').remove();
	$content.find('.selectpicker').selectpicker();
	copyClassCurSel($content.find('.bootstrap-select'));
	callButtonsClicked($content);
	ls.init.numberInputs($content);

	var thumbsSlides, itemGallery;
	var slider = $content.find('.it-gallery');

	var itemGallery = new Swiper(slider, {
		spaceBetween : 10,
		onSlideChangeStart: function(swiper){
			$thumbsSlides.sly('activate', swiper.activeIndex);
		},
		onlyExternal : oldIE ? true : false,
		mousewheelControl: oldIE ? true : false
	});

	var $thumbsSlides = $content.find('.it-gallery-thumbs');
	var $thumbs = $thumbsSlides.find('.it-thumb');
	$thumbs.length && $thumbsSlides.sly({
		horizontal: true, // Switch to horizontal mode.

		// Item based navigation
		itemNav:        'basic',  // Item navigation type. Can be: 'basic', 'centered', 'forceCentered'.
		smart:          true, // Repositions the activated item to help with further navigation.
		activateOn:     'click',  // Activate an item on this event. Can be: 'click', 'mouseenter', ...

		// Dragging
		mouseDragging: true,
		touchDragging: true, // Enable navigation by dragging the SLIDEE with touch events.
		elasticBounds: true, // Stretch SLIDEE position limits when dragging past FRAME boundaries.

		// Mixed options
		speed:         400,       // Animations speed in milliseconds. 0 to disable animations.
		startAt:       0,    // Starting offset in pixels or items.
		keyboardNavBy: 'items',    // Enable keyboard navigation by 'items' or 'pages'.
	}, {
		active: function(e, i){
			if (oldIE) itemGallery.swipeTo(i);
			else itemGallery.slideTo(i);			
		}
	});

	 // zoom initialization
	if (!device.mobile()) {
		$content.find('.zoom-img').each(function(){
			var $t = $(this);
			$t.magnify({
				src: $t.data('zoom-image')
			})
			$t.parent().on('mouseleave', function(){
				$t.siblings('.magnify-lens').fadeOut('fast');
			})
		})
	}

	function update(){
		$thumbs.length && $thumbsSlides.sly('reload');
	}
	ls.resizeHandlers.push(update);
}