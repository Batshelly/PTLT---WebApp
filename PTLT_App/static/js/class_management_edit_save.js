document.addEventListener("DOMContentLoaded", function () {
    // ===== SEMESTER EDIT FUNCTIONALITY =====
    const editBtn = document.getElementById("edit-btn");
    const semesterForm = document.getElementById("semester-form");
    const semesterDisplay = document.getElementById("semester-display");
    const cancelBtn = document.getElementById("cancel-btn");

    if (editBtn && semesterForm && semesterDisplay) {
        editBtn.addEventListener("click", function() {
            semesterDisplay.style.display = "none";
            semesterForm.style.display = "block";
        });
    }

    if (cancelBtn && semesterForm && semesterDisplay) {
        cancelBtn.addEventListener("click", function() {
            semesterForm.style.display = "none";
            semesterDisplay.style.display = "block";
        });
    }

    // ===== EXISTING FUNCTIONALITY =====
    const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

    // Load instructors passed from Django template
    const instructorsData = JSON.parse(document.getElementById("instructor-list").textContent);
    const professors = instructorsData.map(i => `${i.first_name.trim()} ${i.last_name.trim()}`);

    // Helper to get CSRF token
    function getCSRFToken() {
        const token = document.querySelector('[name=csrfmiddlewaretoken]');
        return token ? token.value : '';
    }

    // Create Subject Form validation
    const createSubjectForm = document.getElementById("createSubjectForm");
    if (createSubjectForm) {
        createSubjectForm.addEventListener("submit", function(e) {
            const timeIn = document.getElementById("time_in").value;
            const timeOut = document.getElementById("time_out").value;

            if (timeOut <= timeIn) {
                e.preventDefault();
                alert("Time Out must be later than Time In.");
            }
        });
    }

    // Sync to Mobile Button
    const syncToMobileBtn = document.getElementById("syncToMobileBtn");
    if (syncToMobileBtn) {
        syncToMobileBtn.addEventListener("click", async function() {
            syncToMobileBtn.disabled = true;
            syncToMobileBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Preparing sync...';
            
            try {
                const response = await fetch('/api/trigger-mobile-sync/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCSRFToken()
                    }
                });
                
                const data = await response.json();
                
                if (data.status === 'success') {
                    let message = '✅ Sync triggered successfully!\n\n';
                    message += 'Master data now available for mobile download:\n';
                    message += `• ${data.data.accounts_available} user accounts\n`;
                    message += `• ${data.data.schedules_available} class schedules\n\n`;
                    message += 'Mobile apps will:\n';
                    message += '• Replace ALL mobile accounts with server data\n';
                    message += '• Update class schedules\n\n';
                    message += 'Open mobile app and press "Sync Now" to download!';
                    
                    alert(message);
                } else {
                    alert('❌ Sync failed: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                console.error('Sync error:', error);
                alert('❌ Sync failed: Network error');
            } finally {
                syncToMobileBtn.disabled = false;
                syncToMobileBtn.innerHTML = 'Sync to Mobile App';
            }
        });
    }

    // Toggle Edit/Save Button for class schedule table
    document.querySelectorAll('.toggle-edit-btn').forEach(button => {
        button.addEventListener('click', async function (e) {
            e.preventDefault();

            const row = button.closest('tr');
            const rowId = row.dataset.id;
            const isEditing = button.textContent.trim() === "Save";

            const profCell = row.querySelector('.professor');
            const timeInCell = row.querySelector('.timein');
            const timeOutCell = row.querySelector('.timeout');
            const dayCell = row.querySelector('.day');

            if (!isEditing) {
                const currentProf = profCell.textContent.trim();
                const currentTimeIn = timeInCell.textContent.trim();
                const currentTimeOut = timeOutCell.textContent.trim();
                const currentDay = dayCell.textContent.trim();

                let dropdownHTML = `<select class="form-select form-select-sm">`;

                dropdownHTML += professors.map(p => {
                    const selected = (p === currentProf) ? 'selected' : '';
                    return `<option value="${p}" ${selected}>${p}</option>`;
                }).join('');

                if (!professors.includes(currentProf) && currentProf !== "-") {
                    dropdownHTML = `<select class="form-select form-select-sm">
                        <option value="${currentProf}" selected>${currentProf}</option>` + dropdownHTML.replace('<select class="form-select form-select-sm">', '');
                }

                dropdownHTML += `</select>`;
                profCell.innerHTML = dropdownHTML;

                timeInCell.innerHTML = `<input type="time" class="form-control form-control-sm" value="${currentTimeIn}">`;
                timeOutCell.innerHTML = `<input type="time" class="form-control form-control-sm" value="${currentTimeOut}">`;

                dayCell.innerHTML = `<select class="form-select form-select-sm">
                    ${days.map(d =>
                        `<option value="${d}" ${d === currentDay ? 'selected' : ''}>${d}</option>`
                    ).join('')}
                </select>`;

                button.textContent = "Save";
                button.classList.replace("btn-outline-primary", "btn-outline-success");
            } else {
                const selectedProf = profCell.querySelector('select').value;
                const selectedTimeIn = timeInCell.querySelector('input').value;
                const selectedTimeOut = timeOutCell.querySelector('input').value;
                const selectedDay = dayCell.querySelector('select').value;

                if (selectedTimeOut <= selectedTimeIn) {
                    alert("Time Out must be later than Time In.");
                    return;
                }

                if (!confirm("Save changes?")) return;

                const response = await fetch(`/update_class_schedule/${rowId}/`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRFToken": getCSRFToken()
                    },
                    body: JSON.stringify({
                        professor_name: selectedProf,
                        time_in: selectedTimeIn,
                        time_out: selectedTimeOut,
                        day: selectedDay
                    })
                });

                if (response.ok) {
                    profCell.textContent = selectedProf;
                    timeInCell.textContent = selectedTimeIn;
                    timeOutCell.textContent = selectedTimeOut;
                    dayCell.textContent = selectedDay;

                    button.textContent = "Edit";
                    button.classList.replace("btn-outline-success", "btn-outline-primary");
                } else {
                    alert("Failed to save changes.");
                }
            }
        });
    });

    // Delete button for class schedule
    document.querySelectorAll('.delete-btn').forEach(button => {
        button.addEventListener('click', async function (e) {
            e.preventDefault();

            const row = button.closest('tr');
            const rowId = row.dataset.id;

            if (!confirm("Delete this class?")) return;

            const response = await fetch(`/delete_class_schedule/${rowId}/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken()
                }
            });

            if (response.ok) {
                row.remove();
            } else {
                alert("Failed to delete.");
            }
        });
    });

    // Import Class Schedule CSV
    const importBtn = document.getElementById("importClassBtn");
    const fileInput = document.getElementById("fileInput");

    if (importBtn && fileInput) {
        importBtn.addEventListener("click", function () {
            fileInput.click();
        });

        fileInput.addEventListener("change", async function (event) {
            const file = event.target.files[0];
            if (!file) return;

            const formData = new FormData();
            formData.append("csv_file", file);

            try {
                const response = await fetch("/import_class_schedule/", {
                    method: "POST",
                    headers: {
                        "X-CSRFToken": getCSRFToken()
                    },
                    body: formData
                });

                const data = await response.json();

                if (data.status === "ok") {
                    alert(`✅ Import completed successfully!\n${data.imported} class schedule(s) imported.`);
                    location.reload();
                } else if (data.status === "partial") {
                    let message = `⚠️ Import partially completed!\n\n`;
                    message += `✅ Successfully imported: ${data.imported} class schedule(s)\n`;
                    message += `⚠️ Skipped: ${data.skipped} class schedule(s)\n\n`;
                    message += `Issues found:\n`;
                    
                    const friendlyErrors = data.errors.map(error => {
                        if (error.includes("Professor") && error.includes("not found")) {
                            return "• Some instructors in your file don't exist in the system";
                        } else if (error.includes("Section") && error.includes("not found")) {
                            return "• Some course sections in your file don't exist in the system";
                        } else if (error.includes("Failed to save")) {
                            return "• Some data had formatting issues";
                        } else {
                            return "• " + error.split(":").pop().trim();
                        }
                    });
                    
                    const uniqueErrors = [...new Set(friendlyErrors)];
                    message += uniqueErrors.join("\n");
                    
                    alert(message);
                    if (data.imported > 0) {
                        location.reload();
                    }
                } else {
                    let message = `❌ Import failed!\n\n`;
                    message += `No class schedules were imported.\n\n`;
                    message += `Please check the following:\n`;
                    
                    const friendlyErrors = data.errors.map(error => {
                        if (error.includes("Professor") && error.includes("not found")) {
                            return "• Make sure all instructor IDs in your file exist in the system";
                        } else if (error.includes("Section") && error.includes("not found")) {
                            return "• Make sure all course section IDs in your file are valid";
                        } else if (error.includes("Failed to save")) {
                            return "• Check that your data is properly formatted (times, numbers, etc.)";
                        } else if (error.includes("Failed to read CSV")) {
                            return "• Make sure your file is a valid CSV format";
                        } else {
                            return "• " + error.split(":").pop().trim();
                        }
                    });
                    
                    const uniqueErrors = [...new Set(friendlyErrors)];
                    message += uniqueErrors.join("\n");
                    
                    alert(message);
                }
            } catch (err) {
                alert("⚠️ Error importing CSV: " + err);
            }
        });
    }

    // ===== ADD COURSE SECTION MODAL =====
    
    // Preview course section combination
    const courseNameInput = document.getElementById("courseName");
    const sectionNameInput = document.getElementById("sectionName");
    const previewSection = document.getElementById("previewSection");

    if (courseNameInput && sectionNameInput && previewSection) {
        function updatePreview() {
            const course = courseNameInput.value.trim();
            const section = sectionNameInput.value.trim();
            previewSection.textContent = (course && section) ? `${course} ${section}` : '-';
        }

        courseNameInput.addEventListener('input', updatePreview);
        sectionNameInput.addEventListener('input', updatePreview);
    }

    // Save new course section
    const saveSectionBtn = document.getElementById("saveSectionBtn");
    const addSectionForm = document.getElementById("addSectionForm");
    const courseSectionSelect = document.getElementById("courseSectionSelect");

    if (saveSectionBtn && addSectionForm) {
        saveSectionBtn.addEventListener("click", async function() {
            const courseName = courseNameInput.value.trim();
            const sectionName = sectionNameInput.value.trim();

            if (!courseName || !sectionName) {
                alert("Please fill in all fields.");
                return;
            }

            saveSectionBtn.disabled = true;
            saveSectionBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Saving...';

            try {
                const response = await fetch('/add_course_section/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCSRFToken()
                    },
                    body: JSON.stringify({
                        course_name: courseName,
                        section_name: sectionName
                    })
                });

                const data = await response.json();

                if (data.status === 'success') {
                    const newOption = document.createElement('option');
                    newOption.value = data.course_section;
                    newOption.textContent = data.course_section;
                    newOption.selected = true;
                    courseSectionSelect.appendChild(newOption);

                    const modal = bootstrap.Modal.getInstance(document.getElementById('addSectionModal'));
                    modal.hide();

                    addSectionForm.reset();
                    previewSection.textContent = '-';

                    alert(`✅ Successfully added: ${data.course_section}`);
                } else {
                    alert(`❌ Error: ${data.message}`);
                }
            } catch (error) {
                console.error('Error adding section:', error);
                alert('❌ Failed to add section. Please try again.');
            } finally {
                saveSectionBtn.disabled = false;
                saveSectionBtn.textContent = 'Save Section';
            }
        });
    }
        // Import Class Excel
    const importExcelBtn = document.getElementById("importClassExcelBtn");
    const excelFileInput = document.getElementById("excelFileInput");

    if (importExcelBtn && excelFileInput) {
        importExcelBtn.addEventListener("click", function () {
            excelFileInput.click();
        });

        excelFileInput.addEventListener("change", async function (event) {
            const file = event.target.files[0];
            if (!file) return;

            const formData = new FormData();
            formData.append("excel_file", file);

            importExcelBtn.disabled = true;
            importExcelBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Importing...';

            try {
                const response = await fetch("/import_class_excel/", {
                    method: "POST",
                    headers: {
                        "X-CSRFToken": getCSRFToken()
                    },
                    body: formData
                });

                const data = await response.json();

                if (data.status === "success") {
                    let message = `Successfully imported!\n\n`;
                    message += `Course: ${data.details.course_code} - ${data.details.course_title}\n`;
                    message += `Section: ${data.details.course_section}\n`;
                    message += `Schedule: ${data.details.day} ${data.details.time}\n\n`;
                    message += `Students created: ${data.details.students_created}\n`;
                    message += `Students skipped (already exist): ${data.details.students_skipped}\n`;
                    message += `Total students: ${data.details.total_students}`;
                    
                    alert(message);
                    location.reload();
                } else {
                    alert(`Import failed:\n${data.message}`);
                }
            } catch (err) {
                console.error('Excel import error:', err);
                alert(`Error importing Excel: ${err.message}`);
            } finally {
                importExcelBtn.disabled = false;
                importExcelBtn.innerHTML = 'Import from Excel';
                excelFileInput.value = '';
            }
        });
    }
}); // End of DOMContentLoaded