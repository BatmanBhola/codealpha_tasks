// Dynamic Navigation Scroll Background Effect
document.addEventListener('DOMContentLoaded', () => {
    const header = document.querySelector('header');
    
    window.addEventListener('scroll', () => {
        if (window.scrollY > 20) {
            header.classList.add('bg-brand-deep/95', 'shadow-xl', 'border-gray-800/80');
            header.classList.remove('bg-brand-deep/80');
        } else {
            header.classList.add('bg-brand-deep/80');
            header.classList.remove('bg-brand-deep/95', 'shadow-xl', 'border-gray-800/80');
        }
    });
});
