// Booking System JavaScript

// Tour and Hotel Data
const TOUR_PRICES = {
    'cultural': { name: 'Cultural Triangle Explorer', price: 899, duration: '7 Days' },
    'beach-wildlife': { name: 'Beach & Wildlife Safari', price: 1299, duration: '10 Days' },
    'hill-country': { name: 'Hill Country Escape', price: 699, duration: '5 Days' },
    'complete': { name: 'Complete Sri Lanka Experience', price: 1899, duration: '14 Days' }
};

const HOTEL_DATA = {
    'cinnamon-grand': { name: 'Cinnamon Grand Colombo', price: 150, location: 'Colombo' },
    'amanwella': { name: 'Amanwella', price: 800, location: 'Tangalle' },
    'fortress': { name: 'The Fortress Resort & Spa', price: 250, location: 'Galle' },
    'heritance': { name: 'Heritance Kandalama', price: 180, location: 'Dambulla' },
    'cantaloupe': { name: 'Cantaloupe Aqua', price: 120, location: 'Talpe' },
    'paradise-beach': { name: 'Paradise Beach Club', price: 90, location: 'Mirissa' },
    'hangover': { name: 'Hangover Hostels', price: 15, location: 'Multiple' },
    'ella-nature': { name: 'Ella Nature View', price: 25, location: 'Ella' },
    'tea-trails': { name: 'Ceylon Tea Trails', price: 400, location: 'Hatton' }
};

// Initialize bookings from localStorage
function initBookings() {
    if (!localStorage.getItem('bookings')) {
        localStorage.setItem('bookings', JSON.stringify([]));
    }
    if (!localStorage.getItem('wishlist')) {
        localStorage.setItem('wishlist', JSON.stringify([]));
    }
}

// Generate unique booking ID
function generateBookingId() {
    return 'BK' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).substr(2, 4).toUpperCase();
}

// Save booking to localStorage
function saveBooking(bookingData) {
    const bookings = JSON.parse(localStorage.getItem('bookings') || '[]');
    const newBooking = {
        id: generateBookingId(),
        ...bookingData,
        status: 'pending',
        createdAt: new Date().toISOString(),
        paid: false
    };
    bookings.push(newBooking);
    localStorage.setItem('bookings', JSON.stringify(bookings));
    return newBooking;
}

// Get all bookings
function getBookings() {
    return JSON.parse(localStorage.getItem('bookings') || '[]');
}

// Get booking by ID
function getBookingById(id) {
    return getBookings().find(b => b.id === id);
}

// Update booking status
function updateBookingStatus(id, status, additionalData = {}) {
    const bookings = getBookings();
    const index = bookings.findIndex(b => b.id === id);
    if (index !== -1) {
        bookings[index] = { ...bookings[index], status, ...additionalData };
        localStorage.setItem('bookings', JSON.stringify(bookings));
        return true;
    }
    return false;
}

// Cancel booking
function cancelBooking(id) {
    return updateBookingStatus(id, 'cancelled', { cancelledAt: new Date().toISOString() });
}

// Process payment (simulation)
function processPayment(bookingId, paymentMethod) {
    // Simulate payment processing
    return new Promise((resolve) => {
        setTimeout(() => {
            const success = Math.random() > 0.1; // 90% success rate
            if (success) {
                updateBookingStatus(bookingId, 'confirmed', {
                    paid: true,
                    paidAt: new Date().toISOString(),
                    paymentMethod: paymentMethod
                });
                resolve({ success: true, message: 'Payment processed successfully' });
            } else {
                resolve({ success: false, message: 'Payment failed. Please try again.' });
            }
        }, 1500);
    });
}

// Calculate total cost
function calculateTourCost(tourId, travelers) {
    const tour = TOUR_PRICES[tourId];
    return tour ? tour.price * parseInt(travelers) : 0;
}

// Format date
function formatDate(dateString) {
    if (!dateString) return 'Not specified';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        weekday: 'short',
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

// Format currency
function formatCurrency(amount) {
    return '$' + parseInt(amount).toLocaleString();
}

// Render booking card
function renderBookingCard(booking) {
    const tour = TOUR_PRICES[booking.tour] || { name: booking.customTour || 'Custom Tour', price: 0 };
    const isPast = new Date(booking.startDate) < new Date();
    const headerClass = booking.status === 'cancelled' ? 'cancelled' : (isPast ? 'past' : '');

    const actions = [];
    if (booking.status !== 'cancelled' && !isPast) {
        if (!booking.paid) {
            actions.push(`<button class="btn btn-primary" onclick="showPaymentModal('${booking.id}')">Pay Now</button>`);
        } else {
            actions.push(`<button class="btn btn-outline" onclick="downloadBookingVoucher('${booking.id}')">Download Voucher</button>`);
        }
        actions.push(`<button class="btn btn-outline" onclick="cancelBookingPrompt('${booking.id}')">Cancel</button>`);
    } else if (booking.status === 'cancelled') {
        actions.push(`<span class="btn" style="background: #d32f2f; color: white; cursor: default;">Cancelled</span>`);
    }

    return `
        <div class="booking-card">
            <div class="booking-header ${headerClass}">
                <div class="booking-header-content">
                    <h4>${tour.name}</h4>
                    <span class="booking-id">Booking ID: ${booking.id}</span>
                </div>
                <span class="booking-status">${booking.status.toUpperCase()}</span>
            </div>
            <div class="booking-body">
                <div class="booking-details">
                    <div class="booking-detail">
                        <i class="fas fa-calendar"></i>
                        <div class="booking-detail-content">
                            <div class="label">Travel Date</div>
                            <div class="value">${formatDate(booking.startDate)}</div>
                        </div>
                    </div>
                    <div class="booking-detail">
                        <i class="fas fa-users"></i>
                        <div class="booking-detail-content">
                            <div class="label">Travelers</div>
                            <div class="value">${booking.travelers} persons</div>
                        </div>
                    </div>
                    <div class="booking-detail">
                        <i class="fas fa-user"></i>
                        <div class="booking-detail-content">
                            <div class="label">Booked By</div>
                            <div class="value">${booking.firstName} ${booking.lastName}</div>
                        </div>
                    </div>
                    <div class="booking-detail">
                        <i class="fas fa-envelope"></i>
                        <div class="booking-detail-content">
                            <div class="label">Email</div>
                            <div class="value">${booking.email}</div>
                        </div>
                    </div>
                    <div class="booking-detail">
                        <i class="fas fa-clock"></i>
                        <div class="booking-detail-content">
                            <div class="label">Booked On</div>
                            <div class="value">${formatDate(booking.createdAt)}</div>
                        </div>
                    </div>
                    <div class="booking-detail">
                        <i class="fas fa-credit-card"></i>
                        <div class="booking-detail-content">
                            <div class="label">Payment Status</div>
                            <div class="value">${booking.paid ? 'Paid ✓' : 'Pending'}</div>
                        </div>
                    </div>
                </div>
                <div class="booking-footer">
                    <div class="booking-price">
                        Total: <strong>${formatCurrency(booking.totalAmount || (tour.price * booking.travelers))}</strong>
                    </div>
                    <div class="booking-actions">
                        <button class="btn btn-outline" onclick="viewBookingDetails('${booking.id}')">View Details</button>
                        ${actions.join('')}
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Render bookings page
function renderBookingsPage() {
    const bookings = getBookings();
    const upcomingList = document.getElementById('upcomingBookingsList');
    const pastList = document.getElementById('pastBookingsList');
    const cancelledList = document.getElementById('cancelledBookingsList');

    const now = new Date();

    const upcoming = bookings.filter(b => new Date(b.startDate) >= now && b.status !== 'cancelled');
    const past = bookings.filter(b => new Date(b.startDate) < now && b.status !== 'cancelled');
    const cancelled = bookings.filter(b => b.status === 'cancelled');

    // Update stats
    document.getElementById('bookingStats').style.display = bookings.length > 0 ? 'block' : 'none';
    document.getElementById('totalBookings').textContent = bookings.length;
    document.getElementById('upcomingTrips').textContent = upcoming.length;
    document.getElementById('completedTrips').textContent = past.length;
    document.getElementById('totalSpent').textContent = formatCurrency(
        bookings.filter(b => b.paid).reduce((sum, b) => sum + (b.totalAmount || 0), 0)
    );

    // Render lists
    if (upcomingList) {
        upcomingList.innerHTML = upcoming.length ? upcoming.map(renderBookingCard).join('') : '';
        document.getElementById('noUpcoming').style.display = upcoming.length ? 'none' : 'block';
    }

    if (pastList) {
        pastList.innerHTML = past.length ? past.map(renderBookingCard).join('') : '';
        document.getElementById('noPast').style.display = past.length ? 'none' : 'block';
    }

    if (cancelledList) {
        cancelledList.innerHTML = cancelled.length ? cancelled.map(renderBookingCard).join('') : '';
        document.getElementById('noCancelled').style.display = cancelled.length ? 'none' : 'block';
    }
}

// View booking details
function viewBookingDetails(bookingId) {
    const booking = getBookingById(bookingId);
    if (!booking) return;

    const tour = TOUR_PRICES[booking.tour] || { name: 'Custom Tour', duration: 'N/A' };

    const modalBody = document.getElementById('modalBody');
    modalBody.innerHTML = `
        <div class="booking-details-expanded">
            <div class="detail-row">
                <span class="detail-label">Booking ID:</span>
                <span class="detail-value">${booking.id}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Tour Package:</span>
                <span class="detail-value">${tour.name}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Duration:</span>
                <span class="detail-value">${tour.duration}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Travel Date:</span>
                <span class="detail-value">${formatDate(booking.startDate)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Number of Travelers:</span>
                <span class="detail-value">${booking.travelers}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Price per Person:</span>
                <span class="detail-value">${formatCurrency(tour.price)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Total Amount:</span>
                <span class="detail-value" style="font-size: 1.3rem; color: var(--primary-color);">${formatCurrency(booking.totalAmount || tour.price * booking.travelers)}</span>
            </div>
            <hr style="margin: 20px 0;">
            <h4>Contact Information</h4>
            <div class="detail-row">
                <span class="detail-label">Name:</span>
                <span class="detail-value">${booking.firstName} ${booking.lastName}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Email:</span>
                <span class="detail-value">${booking.email}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Phone:</span>
                <span class="detail-value">${booking.phone || 'Not provided'}</span>
            </div>
            ${booking.message ? `
            <hr style="margin: 20px 0;">
            <h4>Special Requirements</h4>
            <p>${booking.message}</p>
            ` : ''}
        </div>
    `;

    document.getElementById('bookingModal').classList.add('active');
}

// Close modal
function closeBookingModal() {
    document.getElementById('bookingModal').classList.remove('active');
}

// Cancel booking prompt
function cancelBookingPrompt(bookingId) {
    if (confirm('Are you sure you want to cancel this booking? This action cannot be undone.')) {
        if (cancelBooking(bookingId)) {
            showNotification('Booking cancelled successfully', 'success');
            renderBookingsPage();
        } else {
            showNotification('Failed to cancel booking', 'error');
        }
    }
}

// Show payment modal
function showPaymentModal(bookingId) {
    const booking = getBookingById(bookingId);
    if (!booking) return;

    const tour = TOUR_PRICES[booking.tour] || { price: 0 };
    const amount = booking.totalAmount || tour.price * booking.travelers;

    const modalBody = document.getElementById('modalBody');
    modalBody.innerHTML = `
        <div class="payment-form">
            <div style="background: var(--bg-light); padding: 20px; border-radius: 10px; margin-bottom: 25px; text-align: center;">
                <div style="font-size: 0.9rem; color: var(--text-medium); margin-bottom: 5px;">Amount to Pay</div>
                <div style="font-size: 2rem; font-weight: 700; color: var(--primary-color);">${formatCurrency(amount)}</div>
                <div style="font-size: 0.85rem; color: var(--text-light); margin-top: 5px;">Booking ID: ${bookingId}</div>
            </div>

            <h4>Select Payment Method</h4>
            <div class="payment-methods">
                <div class="payment-method active" data-method="card" onclick="selectPaymentMethod(this)">
                    <i class="fas fa-credit-card"></i>
                    <span>Credit Card</span>
                </div>
                <div class="payment-method" data-method="paypal" onclick="selectPaymentMethod(this)">
                    <i class="fab fa-paypal"></i>
                    <span>PayPal</span>
                </div>
                <div class="payment-method" data-method="bank" onclick="selectPaymentMethod(this)">
                    <i class="fas fa-university"></i>
                    <span>Bank Transfer</span>
                </div>
            </div>

            <div id="cardForm">
                <div class="form-row">
                    <div class="form-group" style="flex: 2;">
                        <label>Card Number *</label>
                        <input type="text" id="cardNumber" placeholder="1234 5678 9012 3456" maxlength="19">
                    </div>
                    <div class="form-group" style="flex: 1;">
                        <label>Expiry (MM/YY) *</label>
                        <input type="text" id="cardExpiry" placeholder="MM/YY" maxlength="5">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group" style="flex: 1;">
                        <label>CVV *</label>
                        <input type="text" id="cardCvv" placeholder="123" maxlength="3">
                    </div>
                    <div class="form-group" style="flex: 2;">
                        <label>Cardholder Name *</label>
                        <input type="text" id="cardName" placeholder="Name on card">
                    </div>
                </div>
            </div>

            <div id="processingMessage" style="display: none; text-align: center; padding: 30px;">
                <i class="fas fa-spinner fa-spin" style="font-size: 2.5rem; color: var(--primary-color); margin-bottom: 15px;"></i>
                <p>Processing your payment...</p>
            </div>

            <div id="paymentResult" style="display: none;"></div>

            <button class="btn btn-primary" style="width: 100%; margin-top: 20px;" id="payButton" onclick="processPaymentFlow('${bookingId}')">
                Pay ${formatCurrency(amount)}
            </button>
        </div>
    `;

    document.getElementById('bookingModal').classList.add('active');

    // Add card number formatting
    document.getElementById('cardNumber')?.addEventListener('input', function(e) {
        let value = e.target.value.replace(/\s/g, '').replace(/[^0-9]/gi, '');
        let formattedValue = value.match(/.{1,4}/g)?.join(' ') || value;
        e.target.value = formattedValue;
    });
}

// Select payment method
function selectPaymentMethod(element) {
    document.querySelectorAll('.payment-method').forEach(el => el.classList.remove('active'));
    element.classList.add('active');

    const method = element.getAttribute('data-method');
    const cardForm = document.getElementById('cardForm');
    if (cardForm) {
        cardForm.style.display = method === 'card' ? 'block' : 'none';
    }
}

// Process payment flow
async function processPaymentFlow(bookingId) {
    const selectedMethod = document.querySelector('.payment-method.active')?.getAttribute('data-method') || 'card';

    // Hide form, show processing
    document.getElementById('cardForm').style.display = 'none';
    document.querySelector('.payment-methods').style.display = 'none';
    document.getElementById('payButton').style.display = 'none';
    document.getElementById('processingMessage').style.display = 'block';

    // Process payment
    const result = await processPayment(bookingId, selectedMethod);

    document.getElementById('processingMessage').style.display = 'none';
    const resultDiv = document.getElementById('paymentResult');
    resultDiv.style.display = 'block';

    if (result.success) {
        resultDiv.innerHTML = `
            <div class="confirmation-box">
                <i class="fas fa-check-circle"></i>
                <h3>Payment Successful!</h3>
                <p>Your booking has been confirmed.</p>
                <span class="booking-ref">${bookingId}</span>
            </div>
            <button class="btn btn-primary" style="width: 100%;" onclick="closeBookingModal(); renderBookingsPage();">
                View My Bookings
            </button>
        `;
    } else {
        resultDiv.innerHTML = `
            <div style="background: #d32f2f; color: white; padding: 30px; border-radius: 16px; text-align: center; margin-bottom: 20px;">
                <i class="fas fa-times-circle" style="font-size: 3rem; margin-bottom: 10px;"></i>
                <h3>Payment Failed</h3>
                <p>${result.message}</p>
            </div>
            <button class="btn btn-primary" style="width: 100%;" onclick="closeBookingModal(); showPaymentModal('${bookingId}');">
                Try Again
            </button>
        `;
    }
}

// Download booking voucher
function downloadBookingVoucher(bookingId) {
    const booking = getBookingById(bookingId);
    if (!booking) return;

    const tour = TOUR_PRICES[booking.tour] || { name: 'Custom Tour', duration: 'N/A' };

    const voucherContent = `
BOOKING CONFIRMATION
====================

Booking ID: ${booking.id}
Tour Package: ${tour.name}
Duration: ${tour.duration}

Traveler Information:
- Name: ${booking.firstName} ${booking.lastName}
- Email: ${booking.email}
- Phone: ${booking.phone || 'N/A'}

Trip Details:
- Travel Date: ${formatDate(booking.startDate)}
- Number of Travelers: ${booking.travelers}
- Price per Person: ${formatCurrency(tour.price)}
- Total Amount: ${formatCurrency(booking.totalAmount || tour.price * booking.travelers)}

Payment Status: PAID
Booking Date: ${formatDate(booking.createdAt)}

Thank you for choosing Visit Sri Lanka!
For any inquiries, contact us at connect.abdulr@gmail.com
    `;

    const blob = new Blob([voucherContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Booking-${booking.id}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showNotification('Voucher downloaded successfully', 'success');
}

// Download itinerary summary
function downloadItinerary() {
    const bookings = getBookings().filter(b => b.status !== 'cancelled');

    let summary = `
TRAVEL ITINERARY SUMMARY
========================

Generated on: ${new Date().toLocaleDateString()}

`;

    if (bookings.length === 0) {
        summary += 'No bookings found.\n';
    } else {
        bookings.forEach((booking, index) => {
            const tour = TOUR_PRICES[booking.tour] || { name: 'Custom Tour', duration: 'N/A' };
            summary += `
Trip ${index + 1}: ${tour.name}
Booking ID: ${booking.id}
Status: ${booking.status}
Travel Date: ${formatDate(booking.startDate)}
Travelers: ${booking.travelers}
Total: ${formatCurrency(booking.totalAmount || tour.price * booking.travelers)}
Paid: ${booking.paid ? 'Yes' : 'No'}

`;
        });
    }

    summary += `
---
Visit Sri Lanka
www.visitsrilanka.com
connect.abdulr@gmail.com
+94 72 486 1536
    `;

    const blob = new Blob([summary], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Travel-Itinerary-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showNotification('Itinerary downloaded successfully', 'success');
}

// Enhanced form submission for tours page
function enhanceTourBooking() {
    const bookingForm = document.getElementById('bookingForm');
    if (bookingForm) {
        bookingForm.addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(this);
            const bookingData = {
                tour: formData.get('tour'),
                firstName: formData.get('firstName'),
                lastName: formData.get('lastName'),
                email: formData.get('email'),
                phone: formData.get('phone'),
                travelers: parseInt(formData.get('travelers')) || 1,
                startDate: formData.get('startDate'),
                nationality: formData.get('nationality'),
                message: formData.get('message'),
                totalAmount: calculateTourCost(formData.get('tour'), formData.get('travelers'))
            };

            if (!bookingData.tour) {
                showNotification('Please select a tour package', 'error');
                return;
            }

            const newBooking = saveBooking(bookingData);

            // Show confirmation
            const tour = TOUR_PRICES[bookingData.tour];
            showNotification(`Booking saved! ID: ${newBooking.id}. Proceed to payment.`, 'success');

            // Redirect to bookings page after short delay
            setTimeout(() => {
                window.location.href = 'bookings.html';
            }, 2000);
        });
    }
}

// Tab switching for bookings page
function initBookingTabs() {
    const tabButtons = document.querySelectorAll('.booking-tabs .tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-tab');

            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            button.classList.add('active');
            document.getElementById(tabId)?.classList.add('active');
        });
    });
}

// User Profile Management
function getUserProfile() {
    const profile = localStorage.getItem('vsl_user_profile');
    return profile ? JSON.parse(profile) : null;
}

function saveUserProfile(profileData) {
    localStorage.setItem('vsl_user_profile', JSON.stringify(profileData));
}

function initProfileForm() {
    const profileForm = document.getElementById('profileForm');
    if (!profileForm) return;

    const savedProfile = getUserProfile();
    if (savedProfile) {
        document.getElementById('profileName').value = savedProfile.name || '';
        document.getElementById('profileEmail').value = savedProfile.email || '';
        document.getElementById('profilePhone').value = savedProfile.phone || '';
        document.getElementById('profileLocation').value = savedProfile.location || '';
    }

    profileForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const profileData = {
            name: document.getElementById('profileName').value,
            email: document.getElementById('profileEmail').value,
            phone: document.getElementById('profilePhone').value,
            location: document.getElementById('profileLocation').value,
            updatedAt: new Date().toISOString()
        };
        saveUserProfile(profileData);
        showNotification('Profile updated successfully!', 'success');
    });
}

// Initialize everything when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initBookings();
    renderBookingsPage();
    enhanceTourBooking();
    initBookingTabs();
    initProfileForm();
});

// Close modal on outside click
document.addEventListener('click', function(e) {
    const modal = document.getElementById('bookingModal');
    if (e.target === modal) {
        closeBookingModal();
    }
});
