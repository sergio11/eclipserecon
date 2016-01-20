var gulp 	= require('gulp'),
	sass 	= require('gulp-sass'),
	prefix 	= require('gulp-autoprefixer'),
	include = require('gulp-file-include'),
	bs 		= require('browser-sync');

// CORE OPERATIONS
gulp.task('sass-main', function(){
	gulp.src('src/scss/styles.scss')
		.pipe(sass({
			outputStyle: 'compressed',
		}).on('error', sass.logError))
		.pipe(prefix())
		.pipe(gulp.dest('www/styles/css'))
		.pipe(bs.stream());
	gulp.src('src/scss/mpc-panel.scss')
		.pipe(sass({
			outputStyle: 'compressed',
		}).on('error', sass.logError))
		.pipe(prefix())
		.pipe(gulp.dest('www/styles/css'))
		.pipe(bs.stream());	
});
gulp.task('sass-themes', function(){
	gulp.src('src/scss/theme-*.scss')
		.pipe(sass({
			outputStyle: 'compressed',
		}).on('error', sass.logError))
		.pipe(prefix())
		.pipe(gulp.dest('www/styles/css'))
		.pipe(bs.stream());
});
gulp.task('html', function(){
	gulp.src('src/*.html')
		.pipe(include({
			prefix: '@@',
			basepath: './src/'
		}))
		.pipe(gulp.dest('www/'));
});
// END OF CORE OPERATIONS

// WRAPPING UP: initial compile and start watchers
gulp.task('default', ['html', 'sass-main', 'sass-themes'], function(){
	bs({
		proxy: 'http://localhost:7010',
	});
	gulp.watch(['src/*.html', 'src/partials/**/*.html'], ['html']);
	gulp.watch(['src/scss/**/*.scss'], ['sass-main', 'sass-themes']);
});