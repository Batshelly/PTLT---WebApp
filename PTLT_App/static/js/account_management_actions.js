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
        
        // Confirmation dialog - FIXED: Changed backticks to parentheses
        const action = newStatus === 'Active' ? 'activate' : 'deactivate';
        if (!confirm(`Are you sure you want to ${action} account ${userId}?`)) {
            return;
        }
        
        // Send the toggle request - FIXED: Changed backticks to parentheses
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

// Handle edit button - Inline editing
document.addEventListener('click', function(e) {
    if (e.target.closest('.edit-btn')) {
        const btn = e.target.closest('.edit-btn');
        const row = btn.closest('tr');
        const accountId = row.dataset.id;  // This is the primary key (id)
        const userId = btn.dataset.id;      // This is the user_id
        
        console.log('Edit button clicked');
        console.log('Button text:', btn.textContent);
        console.log('Account ID (pk):', accountId);
        console.log('User ID:', userId);
        
        // Check if already in edit mode
        if (btn.textContent.includes('Save')) {
            console.log('Save mode activated');
            // Save mode - collect data and send to server
            const roleCell = row.querySelector('.role');
            const emailCell = row.querySelector('.email');
            const courseCell = row.querySelector('.course_section');
            
            const roleSelect = roleCell.querySelector('select');
            const emailInput = emailCell.querySelector('input');
            const courseSelect = courseCell.querySelector('select');
            
            const newRole = roleSelect.value;
            const newEmail = emailInput.value;
            const newCourse = courseSelect.value;
            
            // Basic email validation
            const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailPattern.test(newEmail)) {
                showAlert('Please enter a valid email address', 'error');
                return;
            }
            
            // Send update request
            // Use accountId (primary key) for the URL
            fetch(`/update_account/${accountId}/`, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': getCsrfToken(),
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    role: newRole,
                    email: newEmail,
                    course_section: newCourse
                })
            })
            .then(response => {
                console.log('Response status:', response.status);
                console.log('Response headers:', response.headers.get('content-type'));
                
                // Check if response is JSON
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    return response.text().then(text => {
                        console.error('Non-JSON response:', text);
                        throw new Error('Server returned non-JSON response. Check console for details.');
                    });
                }
                
                return response.json();
            })
            .then(data => {
                if (data.status === 'success') {
                    showAlert(data.message || 'Account updated successfully', 'success');
                    
                    // Update cells with new values
                    roleCell.textContent = newRole;
                    emailCell.textContent = newEmail;
                    courseCell.textContent = newCourse || 'N/A';
                    
                    // Change button back to Edit
                    btn.className = 'btn btn-sm btn-outline-primary edit-btn';
                    btn.innerHTML = '<i class="bi bi-pencil"></i> Edit';
                    
                    // Remove the cancel button
                    const cancelBtn = row.querySelector('.cancel-edit-btn');
                    if (cancelBtn) {
                        cancelBtn.remove();
                    }

                    // Re-enable other action buttons
                    const actionButtons = row.querySelectorAll('.toggle-status-btn');
                    actionButtons.forEach(b => b.disabled = false);
                } else {
                    showAlert(data.message || 'Failed to update account', 'error');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('An error occurred while updating the account', 'error');
            });
            
        } else {
            // Edit mode - make cells editable
            const roleCell = row.querySelector('.role');
            const emailCell = row.querySelector('.email');
            const courseCell = row.querySelector('.course_section');
            
            // Store original values
            const originalRole = roleCell.textContent.trim();
            const originalEmail = emailCell.textContent.trim();
            const originalCourse = courseCell.textContent.trim();
            
            // Create Role dropdown
            const roleSelect = document.createElement('select');
            roleSelect.className = 'form-select form-select-sm';
            roleSelect.innerHTML = `
                <option value="Admin" ${originalRole === 'Admin' ? 'selected' : ''}>Admin</option>
                <option value="Instructor" ${originalRole === 'Instructor' ? 'selected' : ''}>Instructor</option>
                <option value="Student" ${originalRole === 'Student' ? 'selected' : ''}>Student</option>
            `;
            roleCell.innerHTML = '';
            roleCell.appendChild(roleSelect);
            
            // Create Email input
            const emailInput = document.createElement('input');
            emailInput.type = 'email';
            emailInput.className = 'form-control form-control-sm';
            emailInput.value = originalEmail;
            emailCell.innerHTML = '';
            emailCell.appendChild(emailInput);
            
            // Create Course dropdown
            const courseSelect = document.createElement('select');
            courseSelect.className = 'form-select form-select-sm';
            
            // Get available courses from the filter dropdown
            const courseFilterOptions = document.getElementById('course').options;
            let courseOptions = '<option value="">N/A</option>';
            for (let i = 1; i < courseFilterOptions.length; i++) {
                const courseValue = courseFilterOptions[i].value;
                const courseText = courseFilterOptions[i].text;
                const selected = originalCourse === courseText ? 'selected' : '';
                courseOptions += `<option value="${courseValue}" ${selected}>${courseText}</option>`;
            }
            courseSelect.innerHTML = courseOptions;
            courseCell.innerHTML = '';
            courseCell.appendChild(courseSelect);
            
            // Change button to Save/Cancel
            btn.className = 'btn btn-sm btn-outline-success edit-btn';
            btn.innerHTML = '<i class="bi bi-check"></i> Save';
            
            // Add cancel button
            const cancelBtn = document.createElement('button');
            cancelBtn.className = 'btn btn-sm btn-outline-secondary cancel-edit-btn';
            cancelBtn.innerHTML = '<i class="bi bi-x"></i> Cancel';
            btn.parentNode.insertBefore(cancelBtn, btn.nextSibling);
            
            // Disable other action buttons while editing
            const actionButtons = row.querySelectorAll('.toggle-status-btn');
            actionButtons.forEach(b => b.disabled = true);
        }
    }
    
    // Handle cancel button
    if (e.target.closest('.cancel-edit-btn')) {
        const btn = e.target.closest('.cancel-edit-btn');
        const row = btn.closest('tr');
        
        // Reload the page to reset everything
        location.reload();
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