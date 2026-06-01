<?php
/**
 * {{THEME_NAME}} front page.
 *
 * Renders for the home page when the static-front-page setting points
 * here. The hero heading + subheading are editable from wp-admin via
 * the field API; the body comes from the page's main content area.
 *
 * Replace the hero markup with something distinctive for the brand.
 * This template is intentionally sparse so the AI can refine it for
 * the user's actual design.
 */
?>
<?php get_header(); ?>

<main class="flex-1">
	<section class="bg-gradient-to-br from-primary-50 to-background py-20">
		<div class="max-w-4xl mx-auto px-6 text-center">
			<h1 class="text-5xl font-bold tracking-tight text-neutral" <?php function_exists( 'wpvibe_edit_attr' ) && wpvibe_edit_attr( get_the_ID(), 'hero_heading' ); ?>>
				<?php echo esc_html( get_post_meta( get_the_ID(), 'hero_heading', true ) ?: 'Welcome to {{THEME_NAME}}.' ); ?>
			</h1>
			<p class="mt-4 text-xl text-secondary-600 max-w-2xl mx-auto" <?php function_exists( 'wpvibe_edit_attr' ) && wpvibe_edit_attr( get_the_ID(), 'hero_subheading' ); ?>>
				<?php echo esc_html( get_post_meta( get_the_ID(), 'hero_subheading', true ) ?: 'Edit this on the home page in wp-admin.' ); ?>
			</p>
		</div>
	</section>

	<?php if ( have_posts() ) : while ( have_posts() ) : the_post(); ?>
		<?php if ( get_the_content() ) : ?>
			<article class="prose max-w-3xl mx-auto px-6 py-16">
				<?php the_content(); ?>
			</article>
		<?php endif; ?>
	<?php endwhile; endif; ?>
</main>

<?php get_footer(); ?>
