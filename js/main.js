// Main JavaScript for Sri Lanka Tourist Website

document.addEventListener('DOMContentLoaded', function() {
    // Initialize all features
    initNavbar();
    initMobileMenu();
    initDropdowns();
    initScrollReveal();
    initParallax();
    initForms();
    initSmoothScroll();
    initAnimations();
    initFilters();
    initSearch();
    initWishlist();
    initWeather();
    initNearbyDiscovery();
    initGallery();
    initFAQ();
    initCostCalculator();
    initTooltips();
    initLazyLoading();
});

// Navbar scroll effect with auto-hide
function initNavbar() {
    const navbar = document.querySelector('.navbar');
    if (!navbar) return;

    let lastScrollY = window.scrollY;
    let ticking = false;

    window.addEventListener('scroll', function() {
        if (!ticking) {
            window.requestAnimationFrame(function() {
                const currentScrollY = window.scrollY;

                // Add/remove scrolled class for styling
                if (currentScrollY > 50) {
                    navbar.classList.add('scrolled');
                } else {
                    navbar.classList.remove('scrolled');
                }

                // Auto-hide navbar when scrolling down, show when scrolling up
                if (currentScrollY > lastScrollY && currentScrollY > 100) {
                    navbar.classList.add('nav-hidden');
                } else {
                    navbar.classList.remove('nav-hidden');
                }

                lastScrollY = currentScrollY;
                ticking = false;
            });
            ticking = true;
        }
    }, { passive: true });
}

// Mobile menu toggle
function initMobileMenu() {
    const mobileMenuToggle = document.getElementById('mobileMenuToggle');
    const navMenu = document.getElementById('navMenu');
    if (!mobileMenuToggle || !navMenu) return;

    mobileMenuToggle.addEventListener('click', function() {
        navMenu.classList.toggle('active');
        const icon = mobileMenuToggle.querySelector('i');
        if (icon) {
            icon.classList.toggle('fa-bars');
            icon.classList.toggle('fa-times');
        }
    });

    // Close menu when clicking on links
    navMenu.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', () => {
            navMenu.classList.remove('active');
            const icon = mobileMenuToggle.querySelector('i');
            if (icon) {
                icon.classList.remove('fa-times');
                icon.classList.add('fa-bars');
            }
        });
    });
}

// Dropdown menus
function initDropdowns() {
    document.querySelectorAll('.nav-dropdown').forEach(dropdown => {
        const toggle = dropdown.querySelector('.nav-dropdown-toggle');
        if (!toggle) return;

        toggle.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const isOpen = dropdown.classList.contains('open');

            // Close all other dropdowns
            document.querySelectorAll('.nav-dropdown.open').forEach(d => {
                if (d !== dropdown) {
                    d.classList.remove('open');
                    const t = d.querySelector('.nav-dropdown-toggle');
                    if (t) t.setAttribute('aria-expanded', 'false');
                }
            });

            dropdown.classList.toggle('open', !isOpen);
            toggle.setAttribute('aria-expanded', !isOpen);
        });
    });

    // Close dropdowns when clicking outside
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.nav-dropdown')) {
            document.querySelectorAll('.nav-dropdown.open').forEach(d => {
                d.classList.remove('open');
                const t = d.querySelector('.nav-dropdown-toggle');
                if (t) t.setAttribute('aria-expanded', 'false');
            });
        }
    });
}

// Scroll reveal animations
function initScrollReveal() {
    const revealElements = document.querySelectorAll('.destination-card, .tour-card, .tip-card, .testimonial-card, .category-card, .section-header');

    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                setTimeout(() => {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }, index * 100);
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    revealElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(el);
    });
}

// Parallax effect for hero sections
function initParallax() {
    const heroes = document.querySelectorAll('.hero, .page-header');

    window.addEventListener('scroll', () => {
        const scrolled = window.pageYOffset;
        heroes.forEach(hero => {
            const speed = 0.5;
            hero.style.backgroundPositionY = `${scrolled * speed}px`;
        });
    }, { passive: true });
}

// Form submissions
function initForms() {
    // Newsletter form
    const newsletterForm = document.getElementById('newsletterForm');
    if (newsletterForm) {
        newsletterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const email = this.querySelector('input[type="email"]')?.value;
            if (email) {
                showNotification('Thank you for subscribing! We\'ll keep you updated.', 'success');
                this.reset();
            }
        });
    }

    // Contact form
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            showNotification('Thank you for your message! We\'ll get back to you within 24 hours.', 'success');
            this.reset();
        });
    }

    // Booking form
    const bookingForm = document.getElementById('bookingForm');
    if (bookingForm) {
        bookingForm.addEventListener('submit', function(e) {
            e.preventDefault();
            showNotification('Your booking request has been submitted! We\'ll contact you shortly.', 'success');
            this.reset();
        });
    }
}

// Smooth scroll for anchor links
function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            const href = this.getAttribute('href');
            if (href === '#') return;

            const target = document.querySelector(href);
            if (target) {
                e.preventDefault();
                const headerOffset = 80;
                const elementPosition = target.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });
}

// Additional animations
function initAnimations() {
    // Add floating animation to hero elements
    const heroContent = document.querySelector('.hero-content');
    if (heroContent) {
        heroContent.classList.add('fade-in-up');
    }

    // Animate stats on scroll
    const statsSection = document.querySelector('.stats-section');
    if (statsSection) {
        const statObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    animateStats();
                    statObserver.unobserve(entry.target);
                }
            });
        }, { threshold: 0.5 });

        statObserver.observe(statsSection);
    }
}

// Animate stat numbers
function animateStats() {
    const statNumbers = document.querySelectorAll('.stat-item h3');
    statNumbers.forEach(num => {
        const finalValue = parseInt(num.textContent);
        const suffix = num.textContent.replace(/[0-9]/g, '');
        let currentValue = 0;
        const increment = finalValue / 50;
        const timer = setInterval(() => {
            currentValue += increment;
            if (currentValue >= finalValue) {
                num.textContent = finalValue + suffix;
                clearInterval(timer);
            } else {
                num.textContent = Math.floor(currentValue) + suffix;
            }
        }, 30);
    });
}

// Filter functionality
function initFilters() {
    const filterButtons = document.querySelectorAll('.filter-btn');
    const destinationCards = document.querySelectorAll('.destination-card-full');

    if (filterButtons.length > 0 && destinationCards.length > 0) {
        filterButtons.forEach(button => {
            button.addEventListener('click', function() {
                filterButtons.forEach(btn => btn.classList.remove('active'));
                this.classList.add('active');

                const filter = this.getAttribute('data-filter');

                destinationCards.forEach(card => {
                    const category = card.getAttribute('data-category');
                    if (filter === 'all' || category === filter) {
                        card.style.display = 'block';
                        setTimeout(() => {
                            card.style.opacity = '1';
                            card.style.transform = 'translateY(0)';
                        }, 10);
                    } else {
                        card.style.opacity = '0';
                        card.style.transform = 'translateY(20px)';
                        setTimeout(() => {
                            card.style.display = 'none';
                        }, 300);
                    }
                });
            });
        });
    }
}

// Gallery lightbox
function initGallery() {
    const galleryImages = document.querySelectorAll('.gallery-image');
    galleryImages.forEach(img => {
        img.addEventListener('click', function() {
            openLightbox(this.src, this.alt);
        });
    });
}

// FAQ Accordion
function initFAQ() {
    const faqItems = document.querySelectorAll('.faq-item');
    faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');
        if (question) {
            question.addEventListener('click', function() {
                const isActive = item.classList.contains('active');

                // Close all items
                faqItems.forEach(otherItem => {
                    otherItem.classList.remove('active');
                    const answer = otherItem.querySelector('.faq-answer');
                    if (answer) answer.style.maxHeight = '0';
                });

                // Toggle current
                if (!isActive) {
                    item.classList.add('active');
                    const answer = item.querySelector('.faq-answer');
                    if (answer) answer.style.maxHeight = answer.scrollHeight + 'px';
                }
            });
        }
    });
}

// Cost calculator
function initCostCalculator() {
    const tourSelect = document.getElementById('tourSelect');
    const travelersInput = document.getElementById('travelersInput');
    const totalCostDisplay = document.getElementById('totalCost');

    if (tourSelect && travelersInput && totalCostDisplay) {
        const tourPrices = {
            'cultural': 899,
            'beach-wildlife': 1299,
            'hill-country': 699,
            'complete': 1899
        };

        function updateCost() {
            const tour = tourSelect.value;
            const travelers = parseInt(travelersInput.value) || 1;
            const pricePerPerson = tourPrices[tour] || 0;
            const total = pricePerPerson * travelers;
            totalCostDisplay.textContent = '$' + total.toLocaleString();
        }

        tourSelect.addEventListener('change', updateCost);
        travelersInput.addEventListener('input', updateCost);
    }
}

// Weather widget
function initWeather() {
    const weatherWidget = document.getElementById('weatherWidget');
    if (!weatherWidget) return;

    const weatherSection = weatherWidget.closest('.filter-section');
    if (weatherSection) {
        let lastScrollY = window.scrollY;
        window.addEventListener('scroll', function() {
            const currentScrollY = window.scrollY;
            if (currentScrollY > lastScrollY && currentScrollY > 300) {
                weatherSection.classList.add('weather-hidden');
            } else if (currentScrollY < lastScrollY) {
                weatherSection.classList.remove('weather-hidden');
            }
            lastScrollY = currentScrollY;
        }, { passive: true });
    }
}

// Wishlist functionality
function initWishlist() {
    if (!localStorage.getItem('wishlist')) {
        localStorage.setItem('wishlist', JSON.stringify([]));
    }

    document.querySelectorAll('[data-wishlist-id]').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const id = this.getAttribute('data-wishlist-id');
            const name = this.getAttribute('data-wishlist-name');
            const type = this.getAttribute('data-wishlist-type');
            toggleWishlistItem(this, id, name, type);
        });
    });
}

function toggleWishlistItem(btn, id, name, type) {
    const wishlist = JSON.parse(localStorage.getItem('wishlist') || '[]');
    const existing = wishlist.find(w => w.id === id);
    const icon = btn.querySelector('i');

    if (existing) {
        const filtered = wishlist.filter(w => w.id !== id);
        localStorage.setItem('wishlist', JSON.stringify(filtered));
        if (icon) {
            icon.classList.remove('fas');
            icon.classList.add('far');
        }
        showNotification('Removed from trip planner', 'info');
    } else {
        wishlist.push({ id, name, type, addedAt: new Date().toISOString() });
        localStorage.setItem('wishlist', JSON.stringify(wishlist));
        if (icon) {
            icon.classList.remove('far');
            icon.classList.add('fas');
        }
        showNotification('Added to trip planner!', 'success');
    }
}

// Tooltip initialization
function initTooltips() {
    const tooltipTriggers = document.querySelectorAll('[data-tooltip]');
    tooltipTriggers.forEach(trigger => {
        trigger.addEventListener('mouseenter', function(e) {
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.textContent = this.getAttribute('data-tooltip');
            tooltip.style.cssText = `
                position: absolute;
                background-color: #333;
                color: white;
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 12px;
                z-index: 1000;
                pointer-events: none;
                white-space: nowrap;
            `;
            document.body.appendChild(tooltip);

            const rect = this.getBoundingClientRect();
            tooltip.style.left = rect.left + rect.width / 2 - tooltip.offsetWidth / 2 + 'px';
            tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + window.scrollY + 'px';

            this._tooltip = tooltip;
        });

        trigger.addEventListener('mouseleave', function() {
            if (this._tooltip) {
                this._tooltip.remove();
                this._tooltip = null;
            }
        });
    });
}

// Lazy loading for images
function initLazyLoading() {
    if ('IntersectionObserver' in window) {
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    if (img.dataset.src) {
                        img.src = img.dataset.src;
                        img.removeAttribute('data-src');
                    }
                    img.classList.add('loaded');
                    observer.unobserve(img);
                }
            });
        }, { rootMargin: '50px' });

        document.querySelectorAll('img[data-src], img[loading="lazy"]').forEach(img => {
            imageObserver.observe(img);
        });
    }
}

// Main initialization removed - using modular functions above
// Original code below is kept for reference

// Main JavaScript for Sri Lanka Tourist Website - LEGACY SECTION

document.addEventListener('DOMContentLoaded', function() {
    // Navbar scroll effect
    const navbar = document.querySelector('.navbar');
    const mobileMenuToggle = document.getElementById('mobileMenuToggle');
    const navMenu = document.getElementById('navMenu');

    // Scroll event for navbar with auto-hide functionality
    let lastScrollY = window.scrollY;
    let ticking = false;

    window.addEventListener('scroll', function() {
        if (!ticking) {
            window.requestAnimationFrame(function() {
                const currentScrollY = window.scrollY;

                // Add/remove scrolled class for styling
                if (currentScrollY > 50) {
                    navbar.classList.add('scrolled');
                } else {
                    navbar.classList.remove('scrolled');
                }

                // Auto-hide navbar when scrolling down, show when scrolling up
                if (currentScrollY > lastScrollY && currentScrollY > 100) {
                    // Scrolling down - hide navbar
                    navbar.classList.add('nav-hidden');
                } else {
                    // Scrolling up - show navbar
                    navbar.classList.remove('nav-hidden');
                }

                lastScrollY = currentScrollY;
                ticking = false;
            });
            ticking = true;
        }
    });

    // Mobile menu toggle
    if (mobileMenuToggle) {
        mobileMenuToggle.addEventListener('click', function() {
            navMenu.classList.toggle('active');
            const icon = mobileMenuToggle.querySelector('i');
            if (navMenu.classList.contains('active')) {
                icon.classList.remove('fa-bars');
                icon.classList.add('fa-times');
            } else {
                icon.classList.remove('fa-times');
                icon.classList.add('fa-bars');
            }
        });
    }

    // Close mobile menu when clicking on a link
    const navLinks = document.querySelectorAll('.nav-menu a');
    navLinks.forEach(link => {
        link.addEventListener('click', function() {
            if (navMenu) navMenu.classList.remove('active');
            if (mobileMenuToggle) {
                const icon = mobileMenuToggle.querySelector('i');
                if (icon) {
                    icon.classList.remove('fa-times');
                    icon.classList.add('fa-bars');
                }
            }
        });
    });

    // "More" dropdown toggle (works on mobile + desktop click)
    document.querySelectorAll('.nav-dropdown').forEach(dropdown => {
        const toggle = dropdown.querySelector('.nav-dropdown-toggle');
        if (!toggle) return;

        function setOpen(nextOpen) {
            dropdown.classList.toggle('open', nextOpen);
            toggle.setAttribute('aria-expanded', nextOpen ? 'true' : 'false');
        }

        toggle.addEventListener('click', (e) => {
            e.preventDefault();
            const isOpen = dropdown.classList.contains('open');
            document.querySelectorAll('.nav-dropdown.open').forEach(d => {
                if (d !== dropdown) {
                    const t = d.querySelector('.nav-dropdown-toggle');
                    d.classList.remove('open');
                    if (t) t.setAttribute('aria-expanded', 'false');
                }
            });
            setOpen(!isOpen);
        });
    });

    document.addEventListener('click', (e) => {
        if (e.target.closest('.nav-dropdown')) return;
        document.querySelectorAll('.nav-dropdown.open').forEach(d => {
            const t = d.querySelector('.nav-dropdown-toggle');
            d.classList.remove('open');
            if (t) t.setAttribute('aria-expanded', 'false');
        });
    });

    // Newsletter form submission
    const newsletterForm = document.getElementById('newsletterForm');
    if (newsletterForm) {
        newsletterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const email = this.querySelector('input[type="email"]').value;
            showNotification('Thank you for subscribing! We\'ll keep you updated with the latest travel tips.', 'success');
            this.reset();
            // For a production-ready site, this form submission would send data to a backend.
            // Example: fetch('/api/subscribe', { method: 'POST', body: JSON.stringify({ email }) });
        });
    }

    // Contact form submission
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            showNotification('Thank you for your message! We\'ll get back to you within 24 hours.', 'success');
            this.reset();
            // For a production-ready site, this form submission would send data to a backend.
            // Example: fetch('/api/contact', { method: 'POST', body: JSON.stringify({ /* form data */ }) });
        });
    }

    // Booking form submission
    const bookingForm = document.getElementById('bookingForm');
    if (bookingForm) {
        bookingForm.addEventListener('submit', function(e) {
            e.preventDefault();
            showNotification('Your booking request has been submitted! We\'ll contact you shortly.', 'success');
            this.reset();
            // For a production-ready site, this form submission would send data to a backend.
            // Example: fetch('/api/book', { method: 'POST', body: JSON.stringify({ /* form data */ }) });
        });
    }

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                const headerOffset = 80;
                const elementPosition = target.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });

    // Intersection Observer for fade-in animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Observe elements for animation
    const animateElements = document.querySelectorAll('.destination-card, .tour-card, .tip-card, .testimonial-card, .category-card');
    animateElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(el);
    });

    // Destination filter functionality
    const filterButtons = document.querySelectorAll('.filter-btn');
    const destinationCards = document.querySelectorAll('.destination-card-full');

    if (filterButtons.length > 0 && destinationCards.length > 0) {
        filterButtons.forEach(button => {
            button.addEventListener('click', function() {
                // Remove active class from all buttons
                filterButtons.forEach(btn => btn.classList.remove('active'));
                // Add active class to clicked button
                this.classList.add('active');

                const filter = this.getAttribute('data-filter');

                destinationCards.forEach(card => {
                    if (filter === 'all' || card.getAttribute('data-category') === filter) {
                        card.style.display = 'block';
                        setTimeout(() => {
                            card.style.opacity = '1';
                            card.style.transform = 'scale(1)';
                        }, 10);
                    } else {
                        card.style.opacity = '0';
                        card.style.transform = 'scale(0.9)';
                        setTimeout(() => {
                            card.style.display = 'none';
                        }, 300);
                    }
                });
            });
        });
    }

    // Image gallery lightbox
    const galleryImages = document.querySelectorAll('.gallery-image');
    if (galleryImages.length > 0) {
        galleryImages.forEach(img => {
            img.addEventListener('click', function() {
                openLightbox(this.src, this.alt);
            });
        });
    }

    // FAQ Accordion
    const faqItems = document.querySelectorAll('.faq-item');
    if (faqItems.length > 0) {
        faqItems.forEach(item => {
            const question = item.querySelector('.faq-question');
            const answer = item.querySelector('.faq-answer');
            
            question.addEventListener('click', function() {
                const isActive = item.classList.contains('active');

                // Close all other items
                faqItems.forEach(otherItem => {
                    if (otherItem !== item) {
                        otherItem.classList.remove('active');
                        const otherAnswer = otherItem.querySelector('.faq-answer');
                        if (otherAnswer) {
                            otherAnswer.style.maxHeight = '0';
                        }
                    }
                });

                // Toggle current item
                if (!isActive) {
                    item.classList.add('active');
                    if (answer) {
                        answer.style.maxHeight = answer.scrollHeight + 'px';
                    }
                } else {
                    item.classList.remove('active');
                    if (answer) {
                        answer.style.maxHeight = '0';
                    }
                }
            });
        });
    }

    // Tour package tab switching
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    if (tabButtons.length > 0) {
        tabButtons.forEach(button => {
            button.addEventListener('click', function() {
                const tabId = this.getAttribute('data-tab');

                // Remove active class from all buttons and contents
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));

                // Add active class to clicked button and corresponding content
                this.classList.add('active');
                document.getElementById(tabId).classList.add('active');
            });
        });
    }

    // Calendar availability checker
    const dateInputs = document.querySelectorAll('input[type="date"]');
    dateInputs.forEach(input => {
        // Set min date to today
        const today = new Date().toISOString().split('T')[0];
        input.setAttribute('min', today);
    });

    // Cost calculator for tours
    const tourSelect = document.getElementById('tourSelect');
    const travelersInput = document.getElementById('travelersInput');
    const totalCostDisplay = document.getElementById('totalCost');

    if (tourSelect && travelersInput && totalCostDisplay) {
        const tourPrices = {
            'cultural': 899,
            'beach-wildlife': 1299,
            'hill-country': 699,
            'complete': 1899
        };

        function updateCost() {
            const tour = tourSelect.value;
            const travelers = parseInt(travelersInput.value) || 1;
            const pricePerPerson = tourPrices[tour] || 0;
            const total = pricePerPerson * travelers;
            totalCostDisplay.textContent = '$' + total.toLocaleString();
        }

        tourSelect.addEventListener('change', updateCost);
        travelersInput.addEventListener('input', updateCost);
    }

    // Weather widget (simulated)
    const weatherWidget = document.getElementById('weatherWidget');
    const weatherSection = weatherWidget?.closest('.filter-section');

    if (weatherWidget) {
        const destinations = {
            'colombo': { temp: 32, condition: 'Sunny', humidity: 75 },
            'kandy': { temp: 26, condition: 'Cloudy', humidity: 80 },
            'nuwara-eliya': { temp: 18, condition: 'Cool', humidity: 85 },
            'galle': { temp: 30, condition: 'Sunny', humidity: 78 }
        };

        const destinationSelect = document.getElementById('destinationWeather');
        if (destinationSelect) {
            destinationSelect.addEventListener('change', function() {
                const dest = destinations[this.value];
                if (dest) {
                    updateWeatherDisplay(dest);
                }
            });
        }
    }

    // Auto-hide weather widget on scroll
    if (weatherSection) {
        let lastWeatherScrollY = window.scrollY;
        window.addEventListener('scroll', function() {
            if (!ticking) {
                window.requestAnimationFrame(function() {
                    const currentScrollY = window.scrollY;
                    if (currentScrollY > lastWeatherScrollY && currentScrollY > 300) {
                        weatherSection.classList.add('weather-hidden');
                    } else if (currentScrollY < lastWeatherScrollY) {
                        weatherSection.classList.remove('weather-hidden');
                    }
                    lastWeatherScrollY = currentScrollY;
                });
            }
        });
    }

    // Initialize tooltips
    initTooltips();

    // Add current year to copyright
    const yearSpan = document.getElementById('currentYear');
    if (yearSpan) {
        yearSpan.textContent = new Date().getFullYear();
    }

    // Hotel filter functionality
    const hotelFilterButtons = document.querySelectorAll('.filter-btn');
    const hotelCards = document.querySelectorAll('.hotel-card');

    if (hotelFilterButtons.length > 0 && hotelCards.length > 0) {
        hotelFilterButtons.forEach(button => {
            button.addEventListener('click', function() {
                // Remove active class from all buttons
                hotelFilterButtons.forEach(btn => btn.classList.remove('active'));
                // Add active class to clicked button
                this.classList.add('active');

                const filter = this.getAttribute('data-filter');

                hotelCards.forEach(card => {
                    const categories = card.getAttribute('data-category');
                    if (filter === 'all' || (categories && categories.includes(filter))) {
                        card.style.display = 'block';
                        setTimeout(() => {
                            card.style.opacity = '1';
                            card.style.transform = 'scale(1)';
                        }, 10);
                    } else {
                        card.style.opacity = '0';
                        card.style.transform = 'scale(0.9)';
                        setTimeout(() => {
                            card.style.display = 'none';
                        }, 300);
                    }
                });
            });
        });
    }
});

// Notification system
function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.notification');
    existingNotifications.forEach(n => n.remove());

    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
        <span>${message}</span>
    `;

    // Add styles
    notification.style.cssText = `
        position: fixed;
        top: 100px;
        right: 20px;
        background-color: ${type === 'success' ? '#2E7D32' : type === 'error' ? '#d32f2f' : '#1976d2'};
        color: white;
        padding: 15px 25px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        gap: 10px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;

    document.body.appendChild(notification);

    // Remove after 4 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 4000);
}

// Lightbox functionality
function openLightbox(src, alt) {
    const lightbox = document.createElement('div');
    lightbox.className = 'lightbox';
    lightbox.innerHTML = `
        <div class="lightbox-overlay"></div>
        <div class="lightbox-content">
            <img src="${src}" alt="${alt}">
            <button class="lightbox-close"><i class="fas fa-times"></i></button>
        </div>
    `;

    lightbox.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 10000;
        display: flex;
        align-items: center;
        justify-content: center;
    `;

    lightbox.querySelector('.lightbox-overlay').style.cssText = `
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0,0,0,0.9);
    `;

    lightbox.querySelector('.lightbox-content').style.cssText = `
        position: relative;
        z-index: 1;
        max-width: 90%;
        max-height: 90%;
    `;

    lightbox.querySelector('img').style.cssText = `
        max-width: 100%;
        max-height: 85vh;
        border-radius: 8px;
    `;

    const closeBtn = lightbox.querySelector('.lightbox-close');
    closeBtn.style.cssText = `
        position: absolute;
        top: -40px;
        right: 0;
        background: none;
        border: none;
        color: white;
        font-size: 24px;
        cursor: pointer;
    `;

    closeBtn.addEventListener('click', () => lightbox.remove());
    lightbox.querySelector('.lightbox-overlay').addEventListener('click', () => lightbox.remove());

    document.body.appendChild(lightbox);
}

// Tooltip initialization
function initTooltips() {
    const tooltipTriggers = document.querySelectorAll('[data-tooltip]');
    tooltipTriggers.forEach(trigger => {
        trigger.addEventListener('mouseenter', function(e) {
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.textContent = this.getAttribute('data-tooltip');
            tooltip.style.cssText = `
                position: absolute;
                background-color: #333;
                color: white;
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 12px;
                z-index: 1000;
                pointer-events: none;
            `;
            document.body.appendChild(tooltip);

            const rect = this.getBoundingClientRect();
            tooltip.style.left = rect.left + rect.width / 2 - tooltip.offsetWidth / 2 + 'px';
            tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + 'px';

            this._tooltip = tooltip;
        });

        trigger.addEventListener('mouseleave', function() {
            if (this._tooltip) {
                this._tooltip.remove();
                this._tooltip = null;
            }
        });
    });
}

// Weather display update
function updateWeatherDisplay(weather) {
    const widget = document.getElementById('weatherWidget');
    if (widget) {
        widget.innerHTML = `
            <div class="weather-main">
                <i class="fas ${getWeatherIcon(weather.condition)}"></i>
                <span class="temperature">${weather.temp}°C</span>
            </div>
            <div class="weather-details">
                <span>${weather.condition}</span>
                <span>Humidity: ${weather.humidity}%</span>
            </div>
        `;
    }
}

function getWeatherIcon(condition) {
    const icons = {
        'Sunny': 'fa-sun',
        'Cloudy': 'fa-cloud',
        'Rainy': 'fa-cloud-rain',
        'Cool': 'fa-wind'
    };
    return icons[condition] || 'fa-cloud';
}

// Add CSS animation keyframes dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }

    .fade-in {
        opacity: 1 !important;
        transform: translateY(0) !important;
    }
`;
document.head.appendChild(style);

// Lazy loading for images
if ('IntersectionObserver' in window) {
    const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                img.src = img.dataset.src || img.src;
                img.classList.remove('lazy');
                observer.unobserve(img);
            }
        });
    });

    document.querySelectorAll('img[data-src]').forEach(img => {
        imageObserver.observe(img);
    });
}

// Print functionality for itineraries
function printItinerary() {
    window.print();
}

// Select tour for booking
function selectTour(tourId) {
    const tourSelect = document.getElementById('tourSelect');
    if (tourSelect) {
        tourSelect.value = tourId;
        // Trigger the change event to update the cost
        tourSelect.dispatchEvent(new Event('change'));
        // Scroll to the booking form
        document.getElementById('booking').scrollIntoView({ behavior: 'smooth' });
    }
}

// Share functionality
function sharePage(platform) {
    const url = encodeURIComponent(window.location.href);
    const title = encodeURIComponent(document.title);

    const shareUrls = {
        'facebook': `https://www.facebook.com/sharer/sharer.php?u=${url}`,
        'twitter': `https://twitter.com/intent/tweet?url=${url}&text=${title}`,
        'whatsapp': `https://wa.me/?text=${title}%20${url}`,
        'email': `mailto:?subject=${title}&body=Check%20out%20this%20page:%20${url}`
    };

    if (shareUrls[platform]) {
        window.open(shareUrls[platform], '_blank', 'width=600,height=400');
    }
}

// Currency Converter
const EXCHANGE_RATES = {
    'USD': { rate: 1, symbol: '$' },
    'EUR': { rate: 0.85, symbol: '€' },
    'GBP': { rate: 0.73, symbol: '£' },
    'LKR': { rate: 300, symbol: 'Rs. ' },
    'AUD': { rate: 1.35, symbol: 'A$' },
    'CAD': { rate: 1.25, symbol: 'C$' },
    'JPY': { rate: 110, symbol: '¥' },
    'INR': { rate: 74, symbol: '₹' }
};

function convertCurrency(amount, fromCurrency, toCurrency) {
    if (fromCurrency === toCurrency) return amount;

    // Convert to USD first, then to target currency
    const inUSD = amount / EXCHANGE_RATES[fromCurrency].rate;
    return inUSD * EXCHANGE_RATES[toCurrency].rate;
}

function formatConvertedCurrency(amount, currency) {
    const symbol = EXCHANGE_RATES[currency].symbol;
    return symbol + amount.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

// Search functionality
const searchIndex = [];

function buildSearchIndex() {
    searchIndex.length = 0;

    // This would normally be populated from actual content
    // For now, we'll add some basic searchable content
    const pages = [
        { title: 'Destinations', url: 'destinations.html', content: 'sigiriya kandy galle ella mirissa yala beaches wildlife' },
        { title: 'Tour Packages', url: 'tours.html', content: 'cultural beach wildlife hill country complete booking' },
        { title: 'Hotels', url: 'accommodation.html', content: 'cinnamon grand amanwella fortress heritance booking' },
        { title: 'Travel Guide', url: 'travel-guide.html', content: 'visa weather transport currency health safety tips' },
        { title: 'Attractions', url: 'attractions.html', content: 'beaches wildlife yala sigiriya unawatuna surfing' },
        { title: 'Culture', url: 'culture.html', content: 'festivals temples kandy perahera buddhist heritage' },
        { title: 'Food & Dining', url: 'food.html', content: 'rice curry hoppers kottu roti lamprais sambol' },
        { title: 'Gallery', url: 'gallery.html', content: 'photos beaches tea plantations wildlife culture' },
        { title: 'Contact', url: 'contact.html', content: 'contact support planning help message' },
        { title: 'Reviews', url: 'reviews.html', content: 'testimonials reviews traveler experiences' },
        { title: 'My Bookings', url: 'bookings.html', content: 'booking payment voucher itinerary' },
        { title: 'Trip Planner', url: 'trip-planner.html', content: 'wishlist planner saved places itinerary' }
    ];

    pages.forEach(page => {
        searchIndex.push(page);
    });
}

function search(query) {
    if (!query || query.length < 2) return [];

    const lowerQuery = query.toLowerCase();
    return searchIndex.filter(item =>
        item.title.toLowerCase().includes(lowerQuery) ||
        item.content.toLowerCase().includes(lowerQuery)
    );
}

function initSearch() {
    buildSearchIndex();

    // Ensure search UI exists (prefer markup, fallback to inject)
    let searchInput = document.getElementById('navSearch');
    let searchResults = document.getElementById('searchResults');

    if (!searchInput || !searchResults) {
        const navWrapper = document.querySelector('.nav-wrapper');
        if (!navWrapper) return;

        const searchContainer = document.createElement('div');
        searchContainer.className = 'nav-search';
        searchContainer.innerHTML = `
            <div class="search-box">
                <input type="text" id="navSearch" placeholder="Search destinations, tours, tips..." autocomplete="off">
                <i class="fas fa-search search-icon"></i>
                <div class="search-results" id="searchResults"></div>
            </div>
        `;
        // Insert after logo if possible, otherwise at end
        const logo = navWrapper.querySelector('.logo');
        if (logo && logo.nextSibling) {
            navWrapper.insertBefore(searchContainer, logo.nextSibling);
        } else {
            navWrapper.appendChild(searchContainer);
        }

        searchInput = document.getElementById('navSearch');
        searchResults = document.getElementById('searchResults');
    }

    if (!searchInput || !searchResults) return;
    if (searchInput.dataset.searchInit === 'true') return;
    searchInput.dataset.searchInit = 'true';

    let searchTimeout;
    let activeIndex = -1;

    function closeResults() {
        searchResults.classList.remove('active');
        searchResults.innerHTML = '';
        activeIndex = -1;
    }

    function getResultItems() {
        return Array.from(searchResults.querySelectorAll('a.search-result-item'));
    }

    function setActiveIndex(nextIndex) {
        const items = getResultItems();
        if (items.length === 0) {
            activeIndex = -1;
            return;
        }
        activeIndex = Math.max(0, Math.min(nextIndex, items.length - 1));
        items.forEach((el, idx) => el.classList.toggle('is-active', idx === activeIndex));
    }

    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        const query = this.value.trim();

        if (query.length < 2) {
            closeResults();
            return;
        }

        searchTimeout = setTimeout(() => {
            const results = search(query);
            displaySearchResults(results, searchResults);
            setActiveIndex(0);
        }, 200);
    });

    searchInput.addEventListener('keydown', function(e) {
        const items = getResultItems();
        if (e.key === 'Escape') {
            closeResults();
            return;
        }
        if (!searchResults.classList.contains('active') || items.length === 0) return;

        if (e.key === 'ArrowDown') {
            e.preventDefault();
            setActiveIndex(activeIndex + 1);
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setActiveIndex(activeIndex - 1);
        } else if (e.key === 'Enter') {
            if (activeIndex >= 0 && items[activeIndex]) {
                e.preventDefault();
                items[activeIndex].click();
            }
        }
    });

    document.addEventListener('click', function(e) {
        if (!e.target.closest('.nav-search')) closeResults();
    });
}

function displaySearchResults(results, container) {
    if (results.length === 0) {
        container.innerHTML = '<div class="search-result-item"><p>No results found</p></div>';
    } else {
        container.innerHTML = results.map(r => `
            <a href="${r.url}" class="search-result-item">
                <h4>${r.title}</h4>
                <p>${r.content.substring(0, 50)}...</p>
            </a>
        `).join('');
    }
    container.classList.add('active');
}

// Discover Nearby (geolocation-based recommendations)
function initNearbyDiscovery() {
    const btn = document.getElementById('useMyLocationBtn');
    const statusEl = document.getElementById('nearbyStatus');
    const resultsEl = document.getElementById('nearbyResults');

    if (!btn || !statusEl || !resultsEl) return;
    if (btn.dataset.nearbyInit === 'true') return;
    btn.dataset.nearbyInit = 'true';

    const DESTINATIONS = [
        {
            id: 'colombo',
            name: 'Colombo',
            region: 'Western Province',
            url: 'destinations.html#colombo',
            img: 'https://images.unsplash.com/photo-1580058572462-98e2c0e0e2f0?w=800',
            lat: 6.9271,
            lon: 79.8612
        },
        {
            id: 'kandy',
            name: 'Kandy',
            region: 'Central Province',
            url: 'destinations.html#kandy',
            img: 'https://images.unsplash.com/photo-1626264457719-4c29a88b2be0?w=800',
            lat: 7.2906,
            lon: 80.6337
        },
        {
            id: 'sigiriya',
            name: 'Sigiriya',
            region: 'Central Province',
            url: 'destinations.html#sigiriya',
            img: 'https://images.unsplash.com/photo-1621261397780-3c2e65f9da00?w=800',
            lat: 7.9547,
            lon: 80.7547
        },
        {
            id: 'galle',
            name: 'Galle',
            region: 'Southern Province',
            url: 'destinations.html#galle',
            img: 'https://images.unsplash.com/photo-1588424801439-cd90601e8343?w=800',
            lat: 6.0535,
            lon: 80.2210
        },
        {
            id: 'ella',
            name: 'Ella',
            region: 'Uva Province',
            url: 'destinations.html#ella',
            img: 'https://images.unsplash.com/photo-1546703869-15e54e33e878?w=800',
            lat: 6.8667,
            lon: 81.0466
        },
        {
            id: 'mirissa',
            name: 'Mirissa',
            region: 'Southern Province',
            url: 'destinations.html#mirissa',
            img: 'https://images.unsplash.com/photo-1596895111956-bf1cf0599ce5?w=800',
            lat: 5.9486,
            lon: 80.4716
        },
        {
            id: 'nuwara-eliya',
            name: 'Nuwara Eliya',
            region: 'Central Province',
            url: 'destinations.html#nuwara-eliya',
            img: 'https://images.unsplash.com/photo-1566847438217-c09a9c8f9d3f?w=800',
            lat: 6.9497,
            lon: 80.7891
        },
        {
            id: 'trincomalee',
            name: 'Trincomalee',
            region: 'Eastern Province',
            url: 'destinations.html#trincomalee',
            img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=800',
            lat: 8.5874,
            lon: 81.2152
        },
        {
            id: 'jaffna',
            name: 'Jaffna',
            region: 'Northern Province',
            url: 'destinations.html#jaffna',
            img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=800',
            lat: 9.6615,
            lon: 80.0255
        }
    ];

    function haversineKm(lat1, lon1, lat2, lon2) {
        const R = 6371;
        const toRad = (deg) => (deg * Math.PI) / 180;
        const dLat = toRad(lat2 - lat1);
        const dLon = toRad(lon2 - lon1);
        const a =
            Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }

    function renderResults(sorted) {
        const top = sorted.slice(0, 3);
        resultsEl.innerHTML = top.map((d) => `
            <div class="nearby-result">
                <a class="img" href="${d.url}" aria-label="Open ${d.name}">
                    <img src="${d.img}" alt="${d.name}" loading="lazy">
                </a>
                <div class="content">
                    <div class="title">${d.name}</div>
                    <div class="meta">
                        <span><i class="fas fa-map-marker-alt"></i> ${d.region}</span>
                        <span>${d.distanceKm.toFixed(0)} km</span>
                    </div>
                    <div class="actions">
                        <a class="btn-small" href="${d.url}">View</a>
                        <a class="btn-small" style="background: var(--secondary-color);" href="tours.html">Tours</a>
                    </div>
                </div>
            </div>
        `).join('');
        resultsEl.style.display = 'grid';
    }

    btn.addEventListener('click', async () => {
        resultsEl.style.display = 'none';
        statusEl.textContent = '';

        if (!('geolocation' in navigator)) {
            statusEl.textContent = 'Your browser does not support location.';
            return;
        }

        btn.disabled = true;
        btn.setAttribute('aria-busy', 'true');
        statusEl.textContent = 'Getting your location…';

        navigator.geolocation.getCurrentPosition(
            (pos) => {
                const lat = pos.coords.latitude;
                const lon = pos.coords.longitude;

                const sorted = DESTINATIONS
                    .map(d => ({ ...d, distanceKm: haversineKm(lat, lon, d.lat, d.lon) }))
                    .sort((a, b) => a.distanceKm - b.distanceKm);

                statusEl.textContent = 'Closest matches based on your location:';
                renderResults(sorted);

                btn.disabled = false;
                btn.removeAttribute('aria-busy');
            },
            (err) => {
                const msg =
                    err && err.code === 1
                        ? 'Location permission denied. You can still browse by region below.'
                        : 'Could not get your location. Please try again.';
                statusEl.textContent = msg;
                btn.disabled = false;
                btn.removeAttribute('aria-busy');
            },
            { enableHighAccuracy: false, timeout: 8000, maximumAge: 600000 }
        );
    });
}

// Wishlist/Trip Planner functionality
function initWishlist() {
    if (!localStorage.getItem('wishlist')) {
        localStorage.setItem('wishlist', JSON.stringify([]));
    }
}

// Initialize everything
document.addEventListener('DOMContentLoaded', function() {
    if (typeof initBookings === 'function') initBookings();
    initSearch();
    initWishlist();
    initWishlistButtons();
});

// Wishlist button handler
function initWishlistButtons() {
    document.querySelectorAll('[data-wishlist-id]').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const id = this.getAttribute('data-wishlist-id');
            const name = this.getAttribute('data-wishlist-name');
            const type = this.getAttribute('data-wishlist-type');
            toggleWishlistHandler(this, id, name, type);
        });
    });
}

function toggleWishlistHandler(btn, id, name, type) {
    const wishlist = JSON.parse(localStorage.getItem('wishlist') || '[]');
    const existing = wishlist.find(w => w.id === id);
    const icon = btn.querySelector('i');
    
    if (existing) {
        removeFromWishlist(id);
        icon.classList.remove('fas');
        icon.classList.add('far');
        btn.classList.remove('btn-primary');
        btn.classList.add('btn-outline');
        showNotification('Removed from trip planner', 'info');
    } else {
        addToWishlist({ id, name, type });
        icon.classList.remove('far');
        icon.classList.add('fas');
        btn.classList.remove('btn-outline');
        btn.classList.add('btn-primary');
        showNotification('Added to trip planner!', 'success');
    }
}

function addToWishlist(item) {
    const wishlist = JSON.parse(localStorage.getItem('wishlist') || '[]');
    if (!wishlist.find(w => w.id === item.id)) {
        wishlist.push({ ...item, addedAt: new Date().toISOString() });
        localStorage.setItem('wishlist', JSON.stringify(wishlist));
        showNotification('Added to your trip planner!', 'success');
        return true;
    }
    showNotification('Already in your trip planner', 'info');
    return false;
}

function removeFromWishlist(id) {
    const wishlist = JSON.parse(localStorage.getItem('wishlist') || '[]');
    const filtered = wishlist.filter(w => w.id !== id);
    localStorage.setItem('wishlist', JSON.stringify(filtered));
}

function getWishlist() {
    return JSON.parse(localStorage.getItem('wishlist') || '[]');
}

// Weather Data (simulated for demo purposes)
const weatherData = {
    colombo: {
        name: 'Colombo',
        temp: 31,
        desc: 'Partly Cloudy',
        icon: 'fa-sun',
        humidity: 75,
        wind: 12,
        uv: 8
    },
    kandy: {
        name: 'Kandy',
        temp: 26,
        desc: 'Clear',
        icon: 'fa-sun',
        humidity: 70,
        wind: 8,
        uv: 7
    },
    sigiriya: {
        name: 'Sigiriya',
        temp: 33,
        desc: 'Sunny',
        icon: 'fa-sun',
        humidity: 65,
        wind: 10,
        uv: 10
    },
    ella: {
        name: 'Ella',
        temp: 22,
        desc: 'Cloudy',
        icon: 'fa-cloud-sun',
        humidity: 80,
        wind: 6,
        uv: 5
    },
    galle: {
        name: 'Galle',
        temp: 30,
        desc: 'Sunny',
        icon: 'fa-sun',
        humidity: 78,
        wind: 15,
        uv: 9
    },
    trincomalee: {
        name: 'Trincomalee',
        temp: 32,
        desc: 'Sunny',
        icon: 'fa-sun',
        humidity: 72,
        wind: 18,
        uv: 10
    },
    jaffna: {
        name: 'Jaffna',
        temp: 33,
        desc: 'Hot',
        icon: 'fa-sun',
        humidity: 68,
        wind: 14,
        uv: 10
    },
    nuwaraeliya: {
        name: 'Nuwara Eliya',
        temp: 18,
        desc: 'Cool & Misty',
        icon: 'fa-cloud',
        humidity: 85,
        wind: 5,
        uv: 3
    }
};

const forecastDays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const forecastIcons = ['fa-sun', 'fa-sun', 'fa-cloud-sun', 'fa-cloud-rain', 'fa-sun', 'fa-cloud', 'fa-sun'];

function updateWeather() {
    const location = document.getElementById('weatherLocation')?.value || 'colombo';
    const data = weatherData[location];
    
    if (!data) return;
    
    document.getElementById('weatherIcon').innerHTML = `<i class="fas ${data.icon}"></i>`;
    document.getElementById('weatherTemp').innerHTML = `${data.temp}<span>°C</span>`;
    document.getElementById('weatherDesc').textContent = data.desc;
    document.getElementById('weatherLocName').textContent = data.name;
    
    // Update forecast
    const forecastContainer = document.getElementById('weatherForecast');
    if (forecastContainer) {
        const today = new Date().getDay();
        let forecastHTML = '';
        for (let i = 0; i < 5; i++) {
            let dayIndex = (today + i) % 7;
            let tempVariation = Math.floor(Math.random() * 4) - 2;
            forecastHTML += `
                <div class="forecast-day">
                    <div class="forecast-day-name">${forecastDays[dayIndex]}</div>
                    <div class="forecast-icon"><i class="fas ${forecastIcons[dayIndex]}"></i></div>
                    <div class="forecast-temp">${data.temp + tempVariation}°</div>
                </div>
            `;
        }
        forecastContainer.innerHTML = forecastHTML;
    }
}

// Initialize weather on page load
document.addEventListener('DOMContentLoaded', function() {
    updateWeather();
    
    // Update weather every 10 minutes
    setInterval(updateWeather, 600000);
});

// Initialize everything
document.addEventListener('DOMContentLoaded', function() {
    // (removed duplicate initializer)
});

// Sri Lanka District Data
const sriLankaDistricts = {
    colombo: {
        name: 'Colombo',
        province: 'Western Province',
        description: 'The commercial capital and largest city, offering vibrant nightlife, shopping, and colonial heritage.',
        weather: { temp: 31, icon: 'fa-sun' },
        places: [
            { name: 'Gangaramaya Temple', desc: 'Historic Buddhist temple with a museum', type: 'cultural', img: 'https://source.unsplash.com/v6br7tqrZ3Q/800x600' },
            { name: 'Galle Face Green', desc: 'Iconic oceanfront urban park', type: 'nature', img: 'https://source.unsplash.com/4xJHMhz7e5s/800x600' },
            { name: 'National Museum', desc: 'Sri Lanka\'s largest museum with colonial artifacts', type: 'historic', img: 'https://images.unsplash.com/photo-1569515371421-e9e6f0f74e0b?w=400' },
            { name: 'Dutch Hospital', desc: 'Colonial shopping and dining complex', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' },
            { name: 'Mount Lavinia Beach', desc: 'Popular beach south of Colombo', type: 'beach', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' }
        ]
    },
    gampaha: {
        name: 'Gampaha',
        province: 'Western Province',
        description: 'A rapidly developing district with beaches, temples, and water parks.',
        weather: { temp: 30, icon: 'fa-sun' },
        places: [
            { name: 'Negombo Beach', desc: 'Golden sands and fish market', type: 'beach', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' },
            { name: 'St. Mary\'s Church', desc: 'Historic Dutch-era Catholic church', type: 'cultural', img: 'https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?w=400' },
            { name: 'Muthurawachchiya', desc: 'Traditional village experience', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Watapuluwa', desc: 'Scenic water bodies and temples', type: 'cultural', img: 'https://images.unsplash.com/photo-1586183189334-1a673a9b2731?w=400' }
        ]
    },
    kalutara: {
        name: 'Kalutara',
        province: 'Western Province',
        description: 'Famous for the iconic Kalutara Bodhiya and beautiful coastline.',
        weather: { temp: 30, icon: 'fa-sun' },
        places: [
            { name: 'Kalutara Bodhiya', desc: 'Hollow Buddhist dagoba by the sea', type: 'cultural', img: 'https://images.unsplash.com/photo-1586183189334-1a673a9b2731?w=400' },
            { name: 'Richmond Castle', desc: 'Grand colonial mansion', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' },
            { name: 'Kalutara Beach', desc: 'Beautiful coastal scenery', type: 'beach', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' },
            { name: 'Kaltota Waterfalls', desc: 'Scenic waterfall on Bentota River', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' }
        ]
    },
    kandy: {
        name: 'Kandy',
        province: 'Central Province',
        description: 'The hill capital and cultural heart of Sri Lanka with the sacred Temple of the Tooth.',
        weather: { temp: 26, icon: 'fa-cloud-sun' },
        places: [
            { name: 'Temple of the Tooth', desc: 'UNESCO site housing Buddha\'s relic', type: 'cultural', img: 'https://source.unsplash.com/isdvqf04MDk/800x600' },
            { name: 'Kandy Lake', desc: 'Serene lake in city center', type: 'nature', img: 'https://images.unsplash.com/photo-1626264457719-4c29a88b2be0?w=400' },
            { name: 'Royal Botanic Gardens', desc: 'Stunning tropical gardens in Peradeniya', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Udawatta Kele Sanctuary', desc: 'Ancient forest reserve above the city', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Bahiravokanda Vihara', desc: 'Giant Buddha statue overlooking city', type: 'cultural', img: 'https://images.unsplash.com/photo-1586183189334-1a673a9b2731?w=400' },
            { name: 'Kandy Esala Perahera', desc: 'World-famous cultural procession', type: 'cultural', img: 'https://images.unsplash.com/photo-1626264457719-4c29a88b2be0?w=400' }
        ]
    },
    nuwaraeliya: {
        name: 'Nuwara Eliya',
        province: 'Central Province',
        description: 'Known as "Little England" with cool climate, tea plantations, and colonial charm.',
        weather: { temp: 18, icon: 'fa-cloud' },
        places: [
            { name: 'Horton Plains', desc: 'World\'s End and Baker\'s Falls', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Tea Plantations', desc: 'Visit tea factories and plantations', type: 'nature', img: 'https://source.unsplash.com/xaZWb4UtIc0/800x600' },
            { name: 'Gregory Lake', desc: 'Scenic lake with boat rides', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Hakgala Botanical Garden', desc: 'One of the oldest botanical gardens', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Lover\'s Leap Waterfall', desc: 'Romantic waterfall legend', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Victoria Dam', desc: 'Large reservoir with scenic views', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' }
        ]
    },
    matale: {
        name: 'Matale',
        province: 'Central Province',
        description: 'Gateway to the Cultural Triangle with spice gardens and ancient temples.',
        weather: { temp: 28, icon: 'fa-sun' },
        places: [
            { name: 'Aluvihara Temple', desc: 'Rock cave temple with Buddhist murals', type: 'cultural', img: 'https://images.unsplash.com/photo-1602216056096-3b40cc0c9944?w=400' },
            { name: 'Spice Gardens', desc: 'Learn about Sri Lankan spices', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Knuckles Mountain Range', desc: 'UNESCO World Heritage site', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Riverston Peak', desc: 'Scenic mountain viewpoint', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' }
        ]
    },
    galle: {
        name: 'Galle',
        province: 'Southern Province',
        description: 'UNESCO World Heritage Dutch colonial fort and beautiful southern beaches.',
        weather: { temp: 30, icon: 'fa-sun' },
        places: [
            { name: 'Galle Fort', desc: 'Best-preserved Dutch fort in Asia', type: 'historic', img: 'https://source.unsplash.com/O0YmMPG56KI/800x600' },
            { name: 'Unawatuna Beach', desc: 'Paradise beach with coral reefs', type: 'beach', img: 'https://source.unsplash.com/l5QjpiLwJ_E/800x600' },
            { name: 'Dutch Reformed Church', desc: 'Colonial church inside the fort', type: 'cultural', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' },
            { name: 'Japanese Peace Pagoda', desc: 'Buddhist temple with ocean views', type: 'cultural', img: 'https://images.unsplash.com/photo-1586183189334-1a673a9b2731?w=400' },
            { name: 'Jungle Beach', desc: 'Secluded beach surrounded by forest', type: 'beach', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' },
            { name: 'Koggala Lake', desc: 'Largest lake in Southern Province', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Martin Wickramsinghe Museum', desc: 'Heritage of traditional Sri Lanka', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' }
        ]
    },
    matara: {
        name: 'Matara',
        province: 'Southern Province',
        description: 'Historic port city with Dutch fort, beaches, and ancient temples.',
        weather: { temp: 30, icon: 'fa-sun' },
        places: [
            { name: 'Dutch Fort Matara', desc: 'Colonial fort with star-shaped design', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' },
            { name: 'Gangarama Vihara', desc: 'Ancient Buddhist temple', type: 'cultural', img: 'https://images.unsplash.com/photo-1586183189334-1a673a9b2731?w=400' },
            { name: 'Tangalle Beach', desc: 'Pristine unspoiled beaches', type: 'beach', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' },
            { name: 'Mulkirigala Rock Temple', desc: 'Ancient cave temple complex', type: 'cultural', img: 'https://images.unsplash.com/photo-1602216056096-3b40cc0c9944?w=400' },
            { name: 'Rekawa Beach', desc: 'Turtle nesting site', type: 'wildlife', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' }
        ]
    },
    hambantota: {
        name: 'Hambantota',
        province: 'Southern Province',
        description: 'Wildlife and nature destination with national parks and salt plains.',
        weather: { temp: 31, icon: 'fa-sun' },
        places: [
            { name: 'Yala National Park', desc: 'Leopard spotting and wildlife', type: 'wildlife', img: 'https://source.unsplash.com/3TwThGdEUZA/800x600' },
            { name: 'Bundala National Park', desc: 'Wetland and bird sanctuary', type: 'wildlife', img: 'https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?w=400' },
            { name: 'Tissa Wewa Lake', desc: 'Ancient reservoir with wildlife', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Sithulpawwa Rock Temple', desc: 'Ancient Buddhist monastery', type: 'cultural', img: 'https://images.unsplash.com/photo-1602216056096-3b40cc0c9944?w=400' },
            { name: 'Magam Ruhunupura', desc: 'Katharagama Temple complex', type: 'cultural', img: 'https://images.unsplash.com/photo-1586183189334-1a673a9b2731?w=400' }
        ]
    },
    jaffna: {
        name: 'Jaffna',
        province: 'Northern Province',
        description: 'Cultural heart of Sri Lankan Tamil heritage with ancient temples and colonial forts.',
        weather: { temp: 33, icon: 'fa-sun' },
        places: [
            { name: 'Jaffna Fort', desc: 'Massive Portuguese-Dutch fort', type: 'historic', img: 'https://commons.wikimedia.org/wiki/Special:FilePath/Jaffna_fort-7-jaffna-Sri_Lanka.jpg?width=800' },
            { name: 'Nallur Kandaswamy Temple', desc: 'Hindu temple with golden spires', type: 'cultural', img: 'https://images.unsplash.com/photo-1586183189334-1a673a9b2731?w=400' },
            { name: 'Delft Island', desc: 'Quiet island with colonial ruins', type: 'historic', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' },
            { name: 'Point Pedro', desc: 'Northernmost tip of Sri Lanka', type: 'nature', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' },
            { name: 'Keerimalai Wells', desc: 'Sacred springs with healing waters', type: 'cultural', img: 'https://images.unsplash.com/photo-1586183189334-1a673a9b2731?w=400' },
            { name: 'Jaffna Library', desc: 'Rebuilt symbol of Tamil culture', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' }
        ]
    },
    kilinochchi: {
        name: 'Kilinochchi',
        province: 'Northern Province',
        description: 'Recently developed area with historical significance and scenic landscapes.',
        weather: { temp: 32, icon: 'fa-sun' },
        places: [
            { name: 'Kilinochchi Town', desc: 'Rebuilt city center', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' },
            { name: 'Elephant Pass', desc: 'Strategic military location', type: 'historic', img: 'https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?w=400' },
            { name: 'Poonakary Mangrove', desc: 'Coastal mangrove ecosystem', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' }
        ]
    },
    mannar: {
        name: 'Mannar',
        province: 'Northern Province',
        description: 'Unique ecosystems with baobab trees, bird sanctuaries, and colonial history.',
        weather: { temp: 32, icon: 'fa-sun' },
        places: [
            { name: 'Mannar Baobab Trees', desc: 'Ancient African trees in Sri Lanka', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Wilpattu National Park', desc: 'Oldest national park, leopards', type: 'wildlife', img: 'https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?w=400' },
            { name: 'Mannar Fort', desc: 'Portuguese-Dutch colonial fort', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' },
            { name: 'Talaimannar Pier', desc: 'Gateway to Adam\'s Bridge', type: 'historic', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' }
        ]
    },
    vavuniya: {
        name: 'Vavuniya',
        province: 'Northern Province',
        description: 'Gateway to the north with ancient temples and reservoirs.',
        weather: { temp: 32, icon: 'fa-sun' },
        places: [
            { name: 'Vavuniya Kanda', desc: 'Rock outcrop with temple', type: 'cultural', img: 'https://images.unsplash.com/photo-1586183189334-1a673a9b2731?w=400' },
            { name: 'Pampa Kulama', desc: 'Ancient tank system', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Madasa Kanda', desc: 'Scenic rock formation', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' }
        ]
    },
    mullaitivu: {
        name: 'Mullaitivu',
        province: 'Northern Province',
        description: 'Coastal district with beaches and wildlife sanctuaries.',
        weather: { temp: 32, icon: 'fa-sun' },
        places: [
            { name: 'Mullaitivu Beach', desc: 'Pristine coastal area', type: 'beach', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' },
            { name: 'Nanthavava Lake', desc: 'Coastal lagoon with birds', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Karuwalagaswewa', desc: 'Ancient Buddhist site', type: 'cultural', img: 'https://images.unsplash.com/photo-1602216056096-3b40cc0c9944?w=400' }
        ]
    },
    anuradhapura: {
        name: 'Anuradhapura',
        province: 'North Central Province',
        description: 'Ancient capital with UNESCO World Heritage ruins and the sacred Sri Maha Bodhi.',
        weather: { temp: 32, icon: 'fa-sun' },
        places: [
            { name: 'Sri Maha Bodhi', desc: 'Oldest historically authenticated tree', type: 'cultural', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' },
            { name: 'Ruwanwelisaya', desc: 'Great stupa with elephant wall', type: 'cultural', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' },
            { name: 'Jetavanaramaya', desc: 'World\'s tallest brick pagoda', type: 'cultural', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' },
            { name: 'Abhayagiri Monastery', desc: 'Monastic complex ruins', type: 'cultural', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' },
            { name: 'Mihintale', desc: 'Birthplace of Buddhism in Sri Lanka', type: 'cultural', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' },
            { name: 'Kuttam Pokuna', desc: 'Twin ponds of ancient kings', type: 'historic', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' }
        ]
    },
    polonnaruwa: {
        name: 'Polonnaruwa',
        province: 'North Central Province',
        description: 'Second ancient capital with well-preserved ruins and Gal Vihara Buddha statues.',
        weather: { temp: 31, icon: 'fa-sun' },
        places: [
            { name: 'Gal Vihara', desc: 'Four Buddha statues carved in rock', type: 'cultural', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' },
            { name: 'Royal Palace', desc: 'Ruins of the king\'s residence', type: 'historic', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' },
            { name: 'Parakrama Samudra', desc: 'Massive ancient reservoir', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Vatadage', desc: 'Circular relic house', type: 'cultural', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' },
            { name: 'Lankatilaka Temple', desc: 'Buddha image house with murals', type: 'cultural', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' },
            { name: 'Pothgul Vehera', desc: 'Monastery with library ruins', type: 'cultural', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' }
        ]
    },
    trincomalee: {
        name: 'Trincomalee',
        province: 'Eastern Province',
        description: 'Stunning east coast harbor with beaches, diving, and colonial history.',
        weather: { temp: 32, icon: 'fa-sun' },
        places: [
            { name: 'Nilaveli Beach', desc: 'Crystal clear waters and corals', type: 'beach', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' },
            { name: 'Pigeon Island', desc: 'Marine national park for snorkeling', type: 'wildlife', img: 'https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?w=400' },
            { name: 'Koneswaram Temple', desc: 'Hindu temple on Swami Rock', type: 'cultural', img: 'https://images.unsplash.com/photo-1586183189334-1a673a9b2731?w=400' },
            { name: 'Fort Frederick', desc: 'Colonial fort built by Portuguese', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' },
            { name: 'Whale Watching', desc: 'Blue whales and dolphins', type: 'wildlife', img: 'https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?w=400' },
            { name: 'Hot Springs', desc: 'Jungle hot springs near town', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' }
        ]
    },
    batticaloa: {
        name: 'Batticaloa',
        province: 'Eastern Province',
        description: 'Lagoon-filled coastline with Dutch forts and the famous singing fish.',
        weather: { temp: 31, icon: 'fa-sun' },
        places: [
            { name: 'Batticaloa Fort', desc: 'Dutch fort by the lagoon', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' },
            { name: 'Batticaloa Lagoon', desc: 'Largest lagoon in Sri Lanka', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Passikudah Beach', desc: 'Shallow calm waters for swimming', type: 'beach', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' },
            { name: 'Kalkudah Beach', desc: 'Pristine beach destination', type: 'beach', img: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=400' },
            { name: 'Dutch Forts in Valaichennai', desc: 'Colonial coastal fortification', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' }
        ]
    },
    ampara: {
        name: 'Ampara',
        province: 'Eastern Province',
        description: 'Vast district with reservoirs, wildlife, and ancient Buddhist sites.',
        weather: { temp: 31, icon: 'fa-sun' },
        places: [
            { name: 'Gal Oya National Park', desc: 'Elephants and boat safaris', type: 'wildlife', img: 'https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?w=400' },
            { name: 'Magul Maha Vihara', desc: 'Ancient Buddhist temple ruins', type: 'cultural', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' },
            { name: 'Sankhamati', desc: 'Scenic mountain range', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Potuvila Estate', desc: 'Tea plantations in highlands', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' }
        ]
    },
    badulla: {
        name: 'Badulla',
        province: 'Uva Province',
        description: 'Scenic highlands with waterfalls, tea estates, and ancient temples.',
        weather: { temp: 24, icon: 'fa-cloud-sun' },
        places: [
            { name: 'Dunhinda Falls', desc: 'Beautiful waterfall with bridge', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Adisham Bungalow', desc: 'Colonial tea estate bungalow', type: 'historic', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Muthiyangana Temple', desc: 'Ancient Buddhist temple', type: 'cultural', img: 'https://images.unsplash.com/photo-1586183189334-1a673a9b2731?w=400' },
            { name: 'Ella Gap', desc: 'Spectacular mountain views', type: 'nature', img: 'https://images.unsplash.com/photo-1605649487212-47bdab064df7?w=400' },
            { name: 'Nine Arch Bridge', desc: 'Iconic railway bridge in Demodara', type: 'historic', img: 'https://source.unsplash.com/6XKzVmeeGOU/800x600' },
            { name: 'Little Adam\'s Peak', desc: 'Popular hiking destination', type: 'nature', img: 'https://images.unsplash.com/photo-1605649487212-47bdab064df7?w=400' }
        ]
    },
    monaragala: {
        name: 'Monaragala',
        province: 'Uva Province',
        description: 'Remote highlands with wildlife, ancient sites, and scenic beauty.',
        weather: { temp: 28, icon: 'fa-sun' },
        places: [
            { name: 'Udawalawe National Park', desc: 'Elephant herds and safari', type: 'wildlife', img: 'https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?w=400' },
            { name: 'Lunugamvehera Reservoir', desc: 'Large reservoir near Yala', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Buddhangala Monastery', desc: 'Rock monastery in mountains', type: 'cultural', img: 'https://images.unsplash.com/photo-1602216056096-3b40cc0c9944?w=400' },
            { name: 'Maha Ravana Kovila', desc: 'Ancient Buddhist temple', type: 'cultural', img: 'https://images.unsplash.com/photo-1604922824961-87cefb9e6b4b?w=400' },
            { name: 'Nawayalathenna', desc: 'Mountain viewpoint', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' }
        ]
    },
    ratnapura: {
        name: 'Ratnapura',
        province: 'Sabaragamuwa Province',
        description: 'Gem mining capital with rainforests, waterfalls, and ancient temples.',
        weather: { temp: 27, icon: 'fa-cloud-sun' },
        places: [
            { name: 'Sinharaja Forest Reserve', desc: 'UNESCO rainforest biodiversity', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Gem Mines', desc: 'Learn about gem mining', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' },
            { name: 'Udawalawe Falls', desc: 'Scenic waterfall', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Samanalawewa', desc: 'Reservoir with dam viewpoint', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Mahaweli River', desc: 'Longest river in Sri Lanka', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' }
        ]
    },
    kegalle: {
        name: 'Kegalle',
        province: 'Sabaragamuwa Province',
        description: 'Pinnawala orphanage, spice gardens, and traditional crafts.',
        weather: { temp: 28, icon: 'fa-cloud-sun' },
        places: [
            { name: 'Pinnawala Elephant Orphanage', desc: 'World\'s largest herd of captive elephants', type: 'wildlife', img: 'https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?w=400' },
            { name: 'Spice Gardens', desc: 'Learn about Sri Lankan spices', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Kegalle Royal Palace', desc: 'Remains of Kandyan palace', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' },
            { name: 'Mawanella', desc: 'Traditional crafts and shops', type: 'cultural', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' }
        ]
    },
    kurunegala: {
        name: 'Kurunegala',
        province: 'North Western Province',
        description: 'Strategic location with lakes, ancient sites, and colonial history.',
        weather: { temp: 29, icon: 'fa-sun' },
        places: [
            { name: 'Kandy Lake', desc: 'Ancient reservoir in city center', type: 'nature', img: 'https://images.unsplash.com/photo-1626264457719-4c29a88b2be0?w=400' },
            { name: 'Pandawacharya', desc: 'Traditional mask carving village', type: 'cultural', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' },
            { name: 'Ramboda Falls', desc: 'Scenic waterfall', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Wilpattu National Park', desc: 'Leopard and bear wildlife', type: 'wildlife', img: 'https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?w=400' }
        ]
    },
    puttalam: {
        name: 'Puttalam',
        province: 'North Western Province',
        description: 'Lagoons, flamingos, and salt production with Dutch colonial sites.',
        weather: { temp: 30, icon: 'fa-sun' },
        places: [
            { name: 'Wilpattu National Park', desc: 'Leopards and wildlife', type: 'wildlife', img: 'https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?w=400' },
            { name: 'Kalpitiya', desc: 'Dolphins and whale watching', type: 'wildlife', img: 'https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?w=400' },
            { name: 'Dutch Fort Puttalam', desc: 'Colonial fort ruins', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' },
            { name: 'Dutch Fort Negombo', desc: 'Fishing port with colonial fort', type: 'historic', img: 'https://images.unsplash.com/photo-1596394516093-501ba68a0ba6?w=400' }
        ]
    },
    dambulla: {
        name: 'Dambulla',
        province: 'Central Province',
        description: 'Famous cave temple and base for Sigiriya explorations.',
        weather: { temp: 30, icon: 'fa-sun' },
        places: [
            { name: 'Dambulla Cave Temple', desc: 'UNESCO World Heritage cave complex', type: 'cultural', img: 'https://images.unsplash.com/photo-1602216056096-3b40cc0c9944?w=400' },
            { name: 'Golden Temple Dambulla', desc: 'Large Buddha statue and museum', type: 'cultural', img: 'https://images.unsplash.com/photo-1602216056096-3b40cc0c9944?w=400' },
            { name: 'Rose Quartz Mountain', desc: 'Pink quartz deposits', type: 'nature', img: 'https://images.unsplash.com/photo-1587015990127-424b954e38b5?w=400' },
            { name: 'Ishkinda Temple', desc: 'Ancient rock temple', type: 'cultural', img: 'https://images.unsplash.com/photo-1602216056096-3b40cc0c9944?w=400' }
        ]
    },
    sigiriya: {
        name: 'Sigiriya',
        province: 'Central Province',
        description: 'Iconic Lion Rock fortress and ancient palace ruins.',
        weather: { temp: 33, icon: 'fa-sun' },
        places: [
            { name: 'Sigiriya Rock Fortress', desc: 'UNESCO World Heritage ancient citadel', type: 'cultural', img: 'https://source.unsplash.com/r-vUs1jhhLA/800x600' },
            { name: 'Sigiriya Frescoes', desc: 'Ancient painted ladies gallery', type: 'cultural', img: 'https://images.unsplash.com/photo-1621261397780-3c2e65f9da00?w=400' },
            { name: 'Mirror Wall', desc: 'Polished ancient wall with graffiti', type: 'historic', img: 'https://images.unsplash.com/photo-1621261397780-3c2e65f9da00?w=400' },
            { name: 'Water Gardens', desc: 'Symmetrical garden complex', type: 'historic', img: 'https://images.unsplash.com/photo-1621261397780-3c2e65f9da00?w=400' },
            { name: 'Pidurangala Rock', desc: 'Alternative viewpoint of Sigiriya', type: 'nature', img: 'https://images.unsplash.com/photo-1621261397780-3c2e65f9da00?w=400' }
        ]
    }
};

let currentDistrict = null;
let currentFilter = 'all';

function showDistrict(districtId) {
    const district = sriLankaDistricts[districtId];
    if (!district) return;
    
    currentDistrict = districtId;
    
    // Remove active class from all districts
    document.querySelectorAll('.district').forEach(d => d.classList.remove('active'));
    
    // Add active class to selected district
    const districtElement = document.getElementById(districtId);
    if (districtElement) {
        districtElement.classList.add('active');
    }
    
    // Update panel header
    const header = document.querySelector('.district-info-panel .district-header');
    header.innerHTML = `
        <h3><i class="fas fa-map-marker-alt"></i> ${district.name}</h3>
        <p class="district-desc">${district.province}</p>
        <p class="district-desc" style="margin-top: 5px;">${district.description}</p>
        <div class="district-weather">
            <i class="fas ${district.weather.icon}"></i>
            <span>${district.weather.temp}°C</span>
        </div>
    `;
    
    // Render places
    renderDistrictPlaces(district.places);
}

function renderDistrictPlaces(places) {
    const container = document.getElementById('districtPlacesList');
    
    let filteredPlaces = places;
    if (currentFilter !== 'all') {
        filteredPlaces = places.filter(p => p.type === currentFilter);
    }
    
    if (filteredPlaces.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 40px 20px; color: #999;">
                <i class="fas fa-search" style="font-size: 2rem; margin-bottom: 10px;"></i>
                <p>No ${currentFilter} attractions in this district</p>
            </div>
        `;
        return;
    }
    
    const FALLBACK_IMAGES = {
        beach: 'https://source.unsplash.com/l5QjpiLwJ_E/800x600',
        wildlife: 'https://source.unsplash.com/3TwThGdEUZA/800x600',
        cultural: 'https://source.unsplash.com/v6br7tqrZ3Q/800x600',
        historic: 'https://source.unsplash.com/O0YmMPG56KI/800x600',
        nature: 'https://source.unsplash.com/xaZWb4UtIc0/800x600'
    };

    // If a place still uses one of our old generic/repeated images, swap it to a
    // deterministic (stable) real-photo pick based on name + type.
    const GENERIC_IMAGE_PREFIXES = [
        'https://images.unsplash.com/photo-1507525428034', // generic beach
        'https://images.unsplash.com/photo-1587015990127', // generic nature
        'https://images.unsplash.com/photo-1596394516093', // generic historic
        'https://images.unsplash.com/photo-1586183189334', // generic temple/culture
        'https://images.unsplash.com/photo-1547471080'      // generic wildlife
    ];

    const IMAGE_POOL = {
        beach: [
            'https://source.unsplash.com/l5QjpiLwJ_E/800x600',
            'https://source.unsplash.com/cuZbrYoimv8/800x600',
            'https://source.unsplash.com/1waZIrVVgMk/800x600'
        ],
        wildlife: [
            'https://source.unsplash.com/3TwThGdEUZA/800x600',
            'https://source.unsplash.com/qcwJHZu9ZAY/800x600'
        ],
        cultural: [
            'https://source.unsplash.com/v6br7tqrZ3Q/800x600',
            'https://source.unsplash.com/isdvqf04MDk/800x600',
            'https://source.unsplash.com/Xj28T1jQSlc/800x600'
        ],
        historic: [
            'https://source.unsplash.com/O0YmMPG56KI/800x600',
            'https://source.unsplash.com/iOhQxUsyD4s/800x600',
            'https://source.unsplash.com/ycsSfJGVxEQ/800x600'
        ],
        nature: [
            'https://source.unsplash.com/xaZWb4UtIc0/800x600',
            'https://source.unsplash.com/6XKzVmeeGOU/800x600',
            'https://source.unsplash.com/96kYpFXhoMk/800x600'
        ]
    };

    function hashString(str) {
        const s = String(str || '');
        let h = 2166136261;
        for (let i = 0; i < s.length; i++) {
            h ^= s.charCodeAt(i);
            h = Math.imul(h, 16777619);
        }
        return (h >>> 0);
    }

    function pickImage(place) {
        const raw = (place && place.img) ? String(place.img).trim() : '';
        const t = String(place?.type || '').toLowerCase();
        const typeKey = IMAGE_POOL[t] ? t : 'nature';

        const looksGeneric = raw && GENERIC_IMAGE_PREFIXES.some(p => raw.startsWith(p));
        if (raw && !looksGeneric) return raw;

        const pool = IMAGE_POOL[typeKey] || [FALLBACK_IMAGES.nature];
        const idx = hashString(`${place?.name || ''}|${typeKey}`) % pool.length;
        return pool[idx] || FALLBACK_IMAGES[typeKey] || FALLBACK_IMAGES.nature;
    }

    function buildDetailedDescription(place) {
        const district = (currentDistrict && sriLankaDistricts[currentDistrict]) ? sriLankaDistricts[currentDistrict] : null;
        const districtName = district ? district.name : 'Sri Lanka';
        const provinceName = district ? district.province : '';
        const base = String(place?.desc || '').trim();
        const type = String(place?.type || 'nature').toLowerCase();

        const typeLines = {
            beach: 'Expect calm waters and beautiful light—go early morning for swimming and late afternoon for sunset.',
            wildlife: 'Best experienced with a guided safari or nature walk; keep a respectful distance and bring binoculars.',
            cultural: 'Dress modestly and allow time to explore the surroundings—local guides add a lot of context.',
            historic: 'Take time to walk the area slowly; the best details are often in the small corners and viewpoints.',
            nature: 'Wear comfortable shoes and carry water—many viewpoints and trails are best enjoyed at a relaxed pace.'
        };

        const contextLine = provinceName
            ? `Located in ${districtName} (${provinceName}).`
            : `Located in ${districtName}.`;

        const extra = typeLines[type] || typeLines.nature;

        // If base already looks detailed, keep it and just add one helpful line.
        if (base.length >= 80) return `${base} ${extra}`;

        return `${base || 'A popular highlight for visitors.'} ${contextLine} ${extra}`;
    }

    container.innerHTML = filteredPlaces.map(place => `
        <div class="place-card">
            <div class="place-image">
                <img src="${pickImage(place)}" alt="${place.name}" loading="lazy"
                     onerror="this.onerror=null;this.src='${FALLBACK_IMAGES.nature}'">
            </div>
            <div class="place-info">
                <h4>${place.name}</h4>
                <p>${buildDetailedDescription(place)}</p>
                <div class="place-tags">
                    <span class="place-tag ${place.type}">${place.type}</span>
                </div>
            </div>
        </div>
    `).join('');
}

function filterDistrictPlaces(filter) {
    currentFilter = filter;
    
    // Update tab styles
    document.querySelectorAll('.district-tab').forEach(tab => {
        tab.classList.remove('active');
        if (tab.textContent.toLowerCase().includes(filter) || 
            (filter === 'all' && tab.textContent === 'All')) {
            tab.classList.add('active');
        }
    });
    
    // Re-render places
    if (currentDistrict && sriLankaDistricts[currentDistrict]) {
        renderDistrictPlaces(sriLankaDistricts[currentDistrict].places);
    }
}

// Initialize map if on destinations page
document.addEventListener('DOMContentLoaded', function() {
    // Show Colombo by default
    if (document.getElementById('districtInfoPanel')) {
        showDistrict('colombo');
    }
});
