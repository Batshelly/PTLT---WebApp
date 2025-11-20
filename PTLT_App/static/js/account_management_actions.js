// Get CSRF token from the form
const getCsrfToken = () => {
    return document.querySelector('form').elements[0].value;
};

// Handle toggle status button
document.addEventListener('click', function(e) {
    if (e.target.closest('.toggle-status-btn')) {
        const btn = e.target.closest('.toggle-status-btn');
        const accountId = btn.dataset.id;
        const newStatus = btn.dataset.status;
        const userId = btn.dataset.userId;
        
        // Confirmation dialog
        const action = newStatus === 'Active' ? 'activate' : 'deactivate';
        if (!confirm(`Are you sure you want to ${action} account ${userId}?`)) {
            return;
        }
        
        // Send the toggle request
        fetch(`/toggle-account-status/${accountId}/`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCsrfToken(),
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                'status': newStatus
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Show success message
                showAlert(data.message, 'success');
                
                // Update the button and badge
                const row = btn.closest('tr');
                const badge = row.querySelector('[class*="badge"]');
                
                // Update badge
                if (newStatus === 'Active') {
                    badge.className = 'badge bg-success';
                    badge.textContent = 'Active';
                } else {
                    badge.className = 'badge bg-danger';
                    badge.textContent = 'Inactive';
                }
                
                // Update button
                if (newStatus === 'Active') {
                    // Change to deactivate button
                    btn.dataset.status = 'Inactive';
                    btn.className = 'btn btn-sm btn-outline-warning toggle-status-btn';
                    btn.innerHTML = '<i class="bi bi-lock"></i> Deactivate';
                } else {
                    // Change to activate button
                    btn.dataset.status = 'Active';
                    btn.className = 'btn btn-sm btn-outline-success toggle-status-btn';
                    btn.innerHTML = '<i class="bi bi-unlock"></i> Activate';
                }
            } else {
                showAlert(data.message || 'An error occurred', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showAlert('An error occurred while updating the account status', 'error');
        });
    }
});

// Handle edit button (existing functionality)
document.addEventListener('click', function(e) {
    if (e.target.closest('.edit-btn')) {
        const btn = e.target.closest('.edit-btn');
        const userId = btn.dataset.id;
        // Add your edit functionality here
        console.log('Edit account:', userId);
    }
});

// Helper function to show alerts
function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type === 'success' ? 'success' : 'danger'} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Insert at top of container
    const container = document.querySelector('.container');
    container.insertBefore(alertDiv, container.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}