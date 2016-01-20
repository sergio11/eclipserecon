ls.entry = function(){
	if (typeof ls.init.settings === 'function') ls.init.settings();
	if (typeof ls.init.checkBrowser === 'function') ls.init.checkBrowser();

	// top fixed menu
	if (typeof ls.init.affix === 'function') ls.init.affix();

	if (typeof ls.init.bigSlider === 'function') ls.init.bigSlider();
	if (typeof ls.init.clientSlider === 'function') ls.init.clientSlider();
	
	// main menu: scrollspy, smoothscroll, left-right sliding
	if (typeof ls.init.mainMenu === 'function') ls.init.mainMenu();

	// categories' bottom bar flying on switching active category
	// also set height on menu items
	if (typeof ls.init.categories === 'function') ls.init.categories();
	
	if (typeof ls.init.promos === 'function') ls.init.promos();

	if (typeof ls.init.cart === 'function') ls.init.cart();

	if (!oldIE && !device.mobile() && !device.tablet() && typeof WOW !== 'undefined') {
		var wow = new WOW({ offset: 100 }); // elements animation
		wow.init();
	}

	// NOT NEEDED ON READY SOLUTION
	$('.tab-content .row.text-center button').click(function(){
		var $parent=$(this).parents('.tab-pane:first').find('.row:first'),
			newElems=$parent.children().clone();
		//it's simple – just use new elements in template without .wow class in article!
		newElems.find('article').removeClass('wow');
		$parent.append(newElems);
		addToCart(newElems);
		callButtonsClicked(newElems);
	});
	// NOT NEEDED ON READY SOLUTION

	$('.selectpicker').selectpicker();
	callButtonsClicked(document);
	updateCartLinks(); // NOT NEEDED ON READY SOLUTION
	addToCart('.items-place');

	// Items Modal
	$(document).on('show.bs.modal', function (e) {
		var $t = $(e.relatedTarget);
		if ($t.hasClass('link-item')) {
			var target = $t.data('id') ? '#item-detail-content' + $t.data('id')
					: $t.closest('.item').parent().next(),
				$modal = $($t.data('target')) || $($t.attr('href')),
				$content = $modal.find('.modal-content').html($(target).html());
				
			$modal.one('bsTransitionEnd', function(){
				ls.init.modalDetailed($content);
			});
		}

		if ($(e.target).is('#modal_cart')){
			$('.cart-alert').addClass('closed');
		}
	});

	// Moving out cart closing
	$(document).on('click', '.cart-alert-close', function (e) {
		var movCart = $(this).closest('.cart-alert');
		if (movCart.hasClass('in')) {
			movCart.modal('hide');
			return false;
		} else {
			movCart.toggleClass('closed');
		}
		return false;
	});

	$('.shop-cart').on('click', function(){
		bdSettings.cartView === 'page' ? $('.cart-alert').removeClass('closed') : null;
	})
}

if (docReady) ls.entry();
else $(ls.entry);

$w.load(function(){
	$('.preloader-block').fadeOut('slow');

	if (typeof ls.init.numberAnimation === 'function') ls.init.numberAnimation();
	if (typeof ls.init.numberInputs === 'function') ls.init.numberInputs(document);
	if (typeof ls.init.validation === 'function') ls.init.validation(); 
	// ^ can be changed/refactored to use bootstrap validator, but for now works as it is
})