ls.init.bigSlider = function(){
	// +++
	if (!document.getElementById('main-banner')) return;
	// ^^^
	var support = { animations : Modernizr.cssanimations },
		animEndEventNames = {
			'WebkitAnimation' : 'webkitAnimationEnd',
			'OAnimation' : 'oAnimationEnd',
			'msAnimation' : 'MSAnimationEnd',
			'animation' : 'animationend'
		},
		// animation end event name
		animEndEventName = animEndEventNames[ Modernizr.prefixed( 'animation' ) ],
		effectSlider = bdSettings.mainSlFx,//document.getElementById( 'fxselect-slider' ),
		component = document.getElementById( 'main-banner' ),
		compClass = component.className,
		effectDef = String(compClass.match(/\bfx.*?\b/g)),
		items = component.querySelector( 'ul.itemwrap' ).children,
		current = 0,
		itemsCount = items.length,
		nav = component.querySelector( '.bd-arrows' ),
		navNext = nav.querySelector( '.main-bd-arrow-next' ),
		navPrev = nav.querySelector( '.main-bd-arrow-prev' ),
		isAnimating = false;
	function init() {
		$(navNext).on( 'click', function( ev ) { ev.preventDefault(); navigate( 'next' ); } );
		$(navPrev).on( 'click', function( ev ) { ev.preventDefault(); navigate( 'prev' ); } );
		// effectSlider.addEventListener( 'change', changeEffect );
	}

	function hideNav() {  nav.style.display = 'none';  }
	function showNav() {  nav.style.display = 'block';  }


	function navigate( dir ) {
		if( isAnimating || !effectSlider ) return false;
		isAnimating = true;
		var cntAnims = 0;


		var currentItem = items[ current ];

		if( dir === 'next' ) {
			current = current < itemsCount - 1 ? current + 1 : 0;
		}
		else if( dir === 'prev' ) {
			current = current > 0 ? current - 1 : itemsCount - 1;
		}

		var nextItem = items[ current ];

		var onEndAnimationCurrentItem = function() {

			// console.log('end',currentItem, dir)
			currentItem.removeEventListener( animEndEventName, onEndAnimationCurrentItem );
			$(currentItem).removeClass(  'current' );
			$(currentItem).removeClass(  dir === 'next' ? 'navOutNext' : 'navOutPrev' );
			++cntAnims;
			if( cntAnims === 2 ) {
				isAnimating = false;
			}
		};

		var onEndAnimationNextItem = function() {
			nextItem.removeEventListener( animEndEventName, onEndAnimationNextItem );
			$(nextItem).addClass(  'current' );
			$(nextItem).removeClass( dir === 'next' ? 'navInNext' : 'navInPrev' );
			++cntAnims;
			if( cntAnims === 2 ) {
				isAnimating = false;
			}
		};

		if( support.animations) {
			currentItem.addEventListener( animEndEventName, onEndAnimationCurrentItem );
			nextItem.addEventListener( animEndEventName, onEndAnimationNextItem );
		}
		else {
			onEndAnimationCurrentItem();
			onEndAnimationNextItem();
		}

		$(currentItem).addClass(dir === 'next' ? 'navOutNext' : 'navOutPrev' );
		$(nextItem).addClass( dir === 'next' ? 'navInNext' : 'navInPrev' );
	}

	init();
}