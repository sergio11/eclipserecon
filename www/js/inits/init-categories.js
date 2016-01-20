ls.init.categories = function(){
	var $categories = $('#categories'),
		$cBar = $('#categories-bar'),
		$active = $categories.find('.active'),
		/*maxHeightA = 0, */winWidth = $w.width();

	if (!$categories.length) return;
	if (!$active.length) $active = $categories.children('li').eq(0).addClass('active');

	$cBar.css({
		'left': $active.position().left,
		'width': $active.outerWidth()
	});

	$categories.on('show.bs.tab', function( e ) {
		var $target = $(e.target);
		$cBar.css({
			'left': $target.position().left,
			'width': $target.outerWidth()
		});
	});

	/*function findMaxHeightA(){
		$categories.find('a').each(function(i){
			var itsHeight = $(this).outerHeight();
			if (maxHeightA < itsHeight)
				maxHeightA = itsHeight;
		});
	}*/
	function setHeightMenuCatalog(notFirstCall){
		$categories.css('height', '');
		setTimeout(function(){
			var height = $categories.outerHeight();
			$categories.css('height', height);
		}, 0);
	}
	setHeightMenuCatalog();
	if ($body.width() < 768){
		$('.snum-items.justify').removeClass('justify');
	}

	function resizeUpdate(){
		var curWidth = $w.width();
		if (Math.abs(winWidth - curWidth) > 50) setHeightMenuCatalog(true);
		
		winWidth = curWidth;
		if ($body.width()<768) $('.snum-items.justify').removeClass('justify');
		if ($body.width()>767) $('.snum-items').addClass('justify');

		$active = $categories.find('.active');
		$cBar.css({
			'left': $active.position().left,
			'width': $active.outerWidth()
		});
	}

	ls.resizeHandlers.push(resizeUpdate);
}