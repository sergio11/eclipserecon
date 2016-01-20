ls.init.numberAnimation = function(){
	if (device.mobile() || !$('.s-shopnum').length) return;
	
	// Animate the element's value from x to y:
	var flagAnimate = true;
	function animateNumbers(){
		if (!flagAnimate) return;
	
		$('.num-animate').each(function(){
			var $this = $(this);
			$({someValue: 0}).animate({someValue: $this.attr('data-finish')}, {
				duration: 2000,
				easing:'swing', // can be anything
				step: function() { // called on every step
					// Update the element's text with rounded-up value:
					$this.text(Math.round(this.someValue));
				}
			});
		});
		flagAnimate = false;
	}

	if ($w.scrollTop() >= parseInt($('.s-shopnum').offset().top - $w.height() + 100)){
		animateNumbers();
	} else $doc.on('scroll.numberAnimation', function(){
		if ($w.scrollTop() >= parseInt($('.s-shopnum').offset().top - $w.height() + 100)){
			animateNumbers();
			$doc.off('scroll.numberAnimation');
		}
	});
}