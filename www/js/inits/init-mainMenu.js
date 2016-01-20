ls.init.mainMenu = function(){
	var $listing = $mainNav.find('.listing'),
		listingWidth = $listing.outerWidth(),
		$slidee = $listing.find('.navbar-nav'),
		$prev = $listing.find('.prev'),
		$next = $listing.find('.next');

	$body.scrollspy({ 
		target: '#main-nav',
		offset: getOffset() + 10
	});

	$('.refresh-waypoints').click(fixSpy);

	$mainNav.on('click', 'a', function(e){
		var $t = $(this),
			offset = getOffset();
		e.preventDefault();
		$(window).stop(true).scrollTo(this.hash, {
			duration: 600,
			interrupt: true,
			offset: -offset,
			onAfter: function(){
				if (offset !== getOffset()){
					$t.trigger('click');
				}
			}
		});
	}).on('activate.bs.scrollspy', function(e){
		$listing.sly('activate', $(e.target).index());
	})

	function updateMenuSly(){
		if (Modernizr.mq('(min-width: 768px)')){
			if ($listing.data('sly-inited')) $listing.sly('reload');
			else {
				$listing.sly({
					horizontal: true, // Switch to horizontal mode.
					slidee: $slidee,

					itemNav: 'basic',
					smart: true,

					// Dragging
					dragSource:    null,  // Selector or DOM element for catching dragging events. Default is FRAME.
					mouseDragging: true, // Enable navigation by dragging the SLIDEE with mouse cursor.
					touchDragging: true, // Enable navigation by dragging the SLIDEE with touch events.
					swingSpeed:    0.2,   // Swing synchronization speed, where: 1 = instant, 0 = infinite.
					elasticBounds: true, // Stretch SLIDEE position limits when dragging past FRAME boundaries.
					// interactive:   'a',  // Selector for special interactive elements.

					// Navigation buttons
					prevPage: $prev, // Selector or DOM element for "previous page" button.
					nextPage: $next, // Selector or DOM element for "next page" button.

					// Mixed options
					speed: 500,       // Animations speed in milliseconds. 0 to disable animations.
				}, {
					load: function(){
						$(this.frame).data('sly-inited', true);
						// console.log(this);
					},
				});
			}
		} else {
			$listing.sly('destroy').data('sly-inited', false);
		}
	}
	updateMenuSly();
	ls.resizeHandlers.push(updateMenuSly);
}