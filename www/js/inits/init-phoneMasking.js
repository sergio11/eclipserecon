ls.init.phoneMasking = function(target) {
	// country code selector
	$(target).find('.form-tel').intlTelInput({
		// typing digits after a valid number will be added to the extension part of the number
		allowExtensions  : false,
		// automatically format the number according to the selected country
		autoFormat       : true,
		// add or remove input placeholder with an example number for the selected country
		autoPlaceholder  : true,
		// if there is just a dial code in the input: remove it on blur, and re-add it on focus
		autoHideDialCode : true,
		// token for ipinfo
		// required for https or over 1000 daily page views support
		ipinfoToken      : "",
		// don't insert international dial codes
		nationalMode     : false,
		// number type to use for placeholders
		numberType       : "MOBILE",
		defaultCountry   : "ru",
		onlyCountries    : ["us", "gb", "au", "ca", "ru", "ua"],
	});
};