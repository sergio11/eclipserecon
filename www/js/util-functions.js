function changesSettAnimation(target, option, value){
	if (typeof value !== 'undefined'){
	    $(target).removeClass(bdSettings[option]).addClass(bdSettings[option] = value);
	}
}
function callButtonsClicked(target) {
	var buttonsClicked = $(target).find('.btn-clicked'),
	// var buttonsClicked = Array.prototype.slice.call(document.querySelectorAll('.btn-clicked')),
	totalButtonsClicked = buttonsClicked.length;
	// console.log(totalButtonsClicked)

	// buttonsClicked.forEach(function (el, i) {
	// el.addEventListener('click', activate, false);
	buttonsClicked.each(function (el, i) {
		$(this).on('click', activate);
	});

	function activate() {
		var $t = $(this),
			activatedClass = 'btn-activated';

		// if ($(this).hasClass('btn-validate')) {
		//     // if it is the first of the two btn-7h then activatedClass = 'btn-error';
		//     // if it is the second then activatedClass = 'btn-success'
		//     activatedClass = buttonsClicked.indexOf(this) === totalButtonsClicked - 2 ? 'btn-error' : 'btn-success';
		// }
		if ($t.hasClass('disabled')) {
			return false;
		}

		if (!$t.hasClass(activatedClass)) {
			$t.addClass(activatedClass);
			setTimeout(function () {
				$t.removeClass(activatedClass);
			}, 1000);
		}
	}
}

// NOT NEEDED ON READY SOLUTION
function updateCartLinks(){
	bdSettings.cartView === 'popup' ?
		$('.btn-cart-alert, .shop-cart').attr('data-target', '#modal_cart')
	:	$('.btn-cart-alert, .shop-cart').attr('data-target', '#cart-alert');
}
// END OF!

// Подставка иконок выбора ягодного селекта
$.fn.filterClassPrefix = function (prefix) {
	if (!prefix)
		return this;

	var sel = '[class^="' + prefix + '"], [class*="' + prefix + '"]';
	return this.filter(sel);
};
function copyClassCurSel(el) {
	$(el).each(function () {
		var $block = $(this),
			$current = $block.find('li.selected a'),
			$currVis = $block.find('span.filter-option'),
			currVisClass = $currVis.attr('class'),
			classCur = $current.attr('class');

		if ($currVis.filterClassPrefix('ico-')) {
			$currVis.removeClass(function (index, css) {
				return (css.match(/\ico-\S+/g) || []).join(' ');
			});
			$currVis.addClass(classCur);
		}
	});
}

$doc.on('change', '.sel-berry', function () {
	$('select option:selected').each(function () {
		copyClassCurSel('.bootstrap-select');
	});
});

// send to the cart animation
function addToCart(selection){
	$(selection).find('.btn-buy').on('click', function () {
		var cart = $('#main-header').hasClass('affix') ? $('.shop-cart.sticky') : $('.shop-cart').eq(0),
			cartOffset = cart.offset(),
			cartOffsetTop = cartOffset.top,
			cartOffsetLeft = cartOffset.left;

		var imgtodrag = $(this).parents('.item').find("img").eq(0),
			imgWidth = imgtodrag.width(),
			imgHeight = imgtodrag.height(),
			imgOffset = imgtodrag.offset(),
			imgOffsetTop = imgOffset.top,
			imgOffsetLeft = imgOffset.left;

		if (imgtodrag) {
			var imgclone = imgtodrag.clone().addClass('anim-to-cart')
				.css({
					'width': imgWidth,
					'height': imgHeight,
					'-webkit-transform': 'translate3d(' + imgOffsetLeft + 'px, ' +imgOffsetTop+ 'px, 0)',
					'transform': 'translate3d(' + imgOffsetLeft + 'px, ' +imgOffsetTop+ 'px, 0)',
			}).appendTo($body)
			.delay(100)
			.queue( function(next){
				$(this).css({
					'width': imgWidth / 10,
					'height': imgHeight / 10,
					'-webkit-transform': 'translate3d(' + cartOffsetLeft + 'px, ' +cartOffsetTop+ 'px, 0)',
					'transform': 'translate3d(' + cartOffsetLeft + 'px, ' +cartOffsetTop+ 'px, 0)',
					'opacity': 0
				});
				next();
			})
			.on("transitionend webkitTransitionEnd oTransitionEnd MSTransitionEnd", function(e){
				$(this).detach();
				$(this).off(e);
			});
		}
	});

	var cartAlert = $('.cart-alert');
	cartAlert.addClass('closed');

	$doc.off('click.btnbuy').on('click.btnbuy', '.btn-buy', function () {
		cartAlert.removeClass('closed');
		return false;
	});
}