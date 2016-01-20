ls.init.numberInputs = function(target){
	//plugin bootstrap minus and plus
	//http://jsfiddle.net/laelitenetwork/puJ6G/
	$(target).off('click.numberInputs')
	.on('click.numberInputs', '.btn-number', function (e) {
		e.preventDefault();
		e.stopPropagation();
		var $t = $(this);

		fieldName = $t.attr('data-field');
		type = $t.attr('data-type');
		var input = $("input[name='" + fieldName + "']");
		var currentVal = parseInt(input.val());
		if (!isNaN(currentVal)) {
			if (type == 'minus') {

				if (currentVal > input.attr('data-min')) {
					input.val(currentVal - 1).change();
				}
				// if (parseInt(input.val()) == input.attr('data-min')) {
				// 	$(this).attr('disabled', true);
				// }

			} else if (type == 'plus') {
				if (currentVal < input.attr('data-max')) {
					input.val(currentVal + 1).change();
				}
				// if (parseInt(input.val()) == input.attr('data-max')) {
				// 	$(this).attr('disabled', true);
				// }

			}
		} else {
			input.val(0);
		}
	});

	$(target).find('.input-number').each(function(){
		var $t = $(this);
		if ($t.data('number-input-inited')) return;

		// input select on focus
		$t.focusin(function () {
			$(this).data('oldValue', $t.val()).select();
		}).mouseup(function(e){
			e.preventDefault();
		});// END OF input select on focus
		
		// allowed keys check
		$t.keydown(function (e) {
			// Allow: backspace, delete, tab, escape, enter and .
			if ($.inArray(e.keyCode, [46, 8, 9, 27, 13, 190]) !== -1 ||
					// Allow: Ctrl+A
				(e.keyCode == 65 && e.ctrlKey === true) ||
					// Allow: home, end, left, right
				(e.keyCode >= 35 && e.keyCode <= 39)) {
				// let it happen, don't do anything
				return;
			}
			// Ensure that it is a number and stop the keypress
			if ((e.shiftKey || (e.keyCode < 48 || e.keyCode > 57)) && (e.keyCode < 96 || e.keyCode > 105)) {
				e.preventDefault();
			}
		}) // END OF allowed keys check
		
		// testLengthInpNumb(): Items counter maximal and minimal value definition
		$t.keyup(function () {
			if(this.value.length > $(this).data('max').length)
				this.value = this.value.substr(0, $(this).data('max').length);

			if(this.value > $(this).data('max'))
				this.value = $(this).data('max');

			if(this.value < $(this).data('min'))
				this.value = $(this).data('min');
		}).data('number-input-inited', true);
	})
}