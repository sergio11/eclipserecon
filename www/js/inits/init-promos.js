ls.init.promos = function(){
	var discountSl = new Swiper('.discount-slider', {
		pagination          : '.discount-pagination',
		paginationClickable : true,
		autoplayDisableOnInteraction: false,
		autoplay: 7000, // pagination swipes interval
		speed: 300, // swipe speed
	});
	$('.discount-slider').hover(function(){
			discountSl.stopAutoplay();
		},function(){
			discountSl.startAutoplay();
		});


	// promo counters
	$('[data-countdown]').each(function () {
		var $this = $(this),
			finalDate = $(this).data('countdown');
		
		$this.countdown(finalDate)
		.on('update.countdown', function (event) {
			$this.html(event.strftime('' + '<div class="ib mr10"><div class="t-num">%D</div><div class="t-label">Days</div></div>' + '<div class="ib"><div class="t-num">%H<div class="ib t-sep">:</div></div><div class="t-label">Hours</div></div>' + '<div class="ib"><div class="t-num">%M<div class="ib t-sep hidden-sm">:</div></div><div class="t-label">mins</div></div>' + '<div class="ib"><div class="t-num hidden-sm">%S</div><div class="t-label hidden-sm">Secs</div></div>'));
		})
		.on('finish.countdown', function(){
			$(this).closest('.countdown-disc').addClass('hidden');
		});
	});
}