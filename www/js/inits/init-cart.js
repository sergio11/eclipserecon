ls.init.cart = function(){
	var cart = bdSettings.cartView === 'modal' ? '#modal_cart' : '#cart-alert';
	callButtonsClicked(cart);
	initValidation($(cart + ' form'), cart + ' form .form-req');
	
	ls.init.numberInputs(cart);
	ls.init.phoneMasking(cart);

	// NOT NEEDED ON READY SOLUTION
	vea.initBasketTable({ // Cart calculator
		row            : '.ci-item',
		price          : '.ci-sum-single',
		count          : '.ci-count',
		buttonMines    : '.btn-minus',
		buttonPlus     : '.btn-plus',
		buttonDelete   : '.btn-remove',
		rowSum         : '.ci-sum-item',
		basketSum      : '.ci-sum-final',
		basketCount    : '.ci-length',
		sumWithoutZero : true,
		afterCalculate : function () { // final sum discount deduction
			var $final = $('.ci-sum-final'),
				$promo = $('.ci-sum-promo'),
				after;
			if ($final.length && $promo.length){
				after = vea.formatStringToNumeric($final.html()) - vea.formatStringToNumeric($promo.html());
				if (after > 0) $final.html(after);
			}
		}
	});
	// NOT NEEDED END OF.
}