#!/bin/bash

# Find the line with "notification-email" and add the test notification button after the send-notifications form-check
sed -i '/id="send-notifications"/,/<\/div>/ {
  /<\/div>/a \
\                                    <div class="mt-3">\
\                                        <button id="test-notification-btn" type="button" class="btn btn-info btn-sm">\
\                                            <i class="fas fa-paper-plane me-1"></i> Test Notification\
\                                        </button>\
\                                        <small class="text-muted ms-2">Send a test email to verify settings</small>\
\                                    </div>
}' ./templates/email_automation.html

# Find the JavaScript section and add toggle function for notification method
sed -i '/toggleNotificationMethod/ {
    /.*/d
}' ./templates/email_automation.html

sed -i '/document.getElementById('\''reset-defaults-btn'\'').addEventListener('\''click'\'', resetToDefaults);/ a \
\            document.getElementById('\''enable-sendgrid'\'').addEventListener('\''change'\'', toggleNotificationMethod);\
\            document.getElementById('\''test-notification-btn'\'').addEventListener('\''click'\'', testNotification);
' ./templates/email_automation.html

# Add the toggleNotificationMethod and testNotification functions
sed -i '/function saveConfiguration()/ i \
\        function toggleNotificationMethod() {\
\            const useSendGrid = document.getElementById('\''enable-sendgrid'\'').checked;\
\            document.getElementById('\''sendgrid-settings'\'').style.display = useSendGrid ? '\''block'\'' : '\''none'\'';\
\            document.getElementById('\''smtp-settings'\'').style.display = useSendGrid ? '\''none'\'' : '\''block'\'';\
\        }\
\        \
\        function testNotification() {\
\            const recipient = document.getElementById('\''notification-email'\'').value;\
\            if (!recipient) {\
\                showAlert('\''danger'\'', '\''Please enter a notification email address'\'');\
\                return;\
\            }\
\            \
\            // Get SendGrid API key if using SendGrid\
\            let apiKey = "";\
\            const useSendGrid = document.getElementById('\''enable-sendgrid'\'') && document.getElementById('\''enable-sendgrid'\'').checked;\
\            \
\            if (useSendGrid) {\
\                apiKey = document.getElementById('\''sendgrid-api-key'\'').value;\
\                // Allow empty API key which will use environment variable\
\            }\
\            \
\            // Show loading state\
\            const button = document.getElementById('\''test-notification-btn'\'');\
\            const originalText = button.innerHTML;\
\            button.innerHTML = `<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Sending...`;\
\            button.disabled = true;\
\            \
\            // Make API request\
\            fetch('\''/api/email_automation/test_notification'\'', {\
\                method: '\''POST'\'',\
\                headers: {\
\                    '\''Content-Type'\'': '\''application/json'\''\
\                },\
\                body: JSON.stringify({\
\                    api_key: apiKey,\
\                    recipient: recipient,\
\                    sender_email: useSendGrid ? document.getElementById('\''sender-email'\'').value : null,\
\                    sender_name: useSendGrid ? document.getElementById('\''sender-name'\'').value : null\
\                })\
\            })\
\            .then(response => response.json())\
\            .then(data => {\
\                if (data.success) {\
\                    showAlert('\''success'\'', data.message);\
\                } else {\
\                    showAlert('\''danger'\'', data.message);\
\                }\
\                \
\                // Reset button\
\                button.innerHTML = originalText;\
\                button.disabled = false;\
\            })\
\            .catch(error => {\
\                console.error('\''Error testing notification:'\'', error);\
\                showAlert('\''danger'\'', `Error: ${error.message}`);\
\                \
\                // Reset button\
\                button.innerHTML = originalText;\
\                button.disabled = false;\
\            });\
\        }\
' ./templates/email_automation.html

# Add the SaveGrid settings to the populateConfigForm function
sed -i '/\/\/ SMTP settings/ i \
\            // SendGrid settings\
\            document.getElementById('\''enable-sendgrid'\'').checked = config.use_sendgrid !== false;\
\            document.getElementById('\''sendgrid-api-key'\'').value = config.sendgrid_api_key || '\'''\'';\
\            document.getElementById('\''sender-email'\'').value = config.sender_email || '\''noreply@speedefender.com'\'';\
\            document.getElementById('\''sender-name'\'').value = config.sender_name || '\''SpeeDefender'\'';\
\            \
\            // Initialize display based on notification method\
\            toggleNotificationMethod();\
' ./templates/email_automation.html

# Add SendGrid settings to the configuration object in saveConfiguration function
sed -i '/smtp_password:/ a \
\                // SendGrid settings\
\                use_sendgrid: document.getElementById('\''enable-sendgrid'\'').checked,\
\                sendgrid_api_key: document.getElementById('\''sendgrid-api-key'\'').value,\
\                sender_email: document.getElementById('\''sender-email'\'').value,\
\                sender_name: document.getElementById('\''sender-name'\'').value,\
' ./templates/email_automation.html

chmod +x temp_edit.sh
./temp_edit.sh
