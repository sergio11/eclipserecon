function getOffset(){
	return hasPanel && $panel.hasClass('bx-panel-fixed') ?
		$mainHeader.outerHeight() + $panel.outerHeight() :
		$mainHeader.outerHeight();
}
function fixSpy() {
	var $t = $(this),
		newOffset = getOffset() + 10;
	// console.log('fixed spy to offset', newOffset);
    // grab a copy the scrollspy data for the element
    var data = $body.data('bs.scrollspy');
    // if there is data, lets fiddle with the offset value
    if (data) {
        // change the data's offset option to match
        data.options.offset = newOffset;
        // now stick it back in the element
        $body.data('bs.scrollspy', data);
        // and finally refresh scrollspy
        $body.scrollspy('refresh');
    }

	$mainNav.find('.listing').sly('reload');
}

ls.init.affix = function(){
	var $wrap = $('#landing-wrap'),
		$shopcart = $mainHeader.find('a.shop-cart.sticky');

	function setAffix(){
		$mainHeader.css({
			top: hasPanel && $panel.hasClass('bx-panel-fixed') ? $panel.outerHeight() : 0
		});
		$shopcart.removeClass('hide');
	}
	function setTop(){
		$mainHeader.css('top', '');
		$shopcart.addClass('hide');
	}

	$mainHeader.on('affix-top.bs.affix', setTop)
	.on('affix.bs.affix', setAffix)
	.on('affixed.bs.affix affixed-top.bs.affix', function(){
		fixSpy();
	}).affix({
		offset:{
			top: function(){
				return hasPanel && $panel.hasClass('bx-panel-fixed') ? 
					$wrap.offset().top + 100 - $panel.outerHeight() : $wrap.offset().top + 100;
			}
		}
	})
};