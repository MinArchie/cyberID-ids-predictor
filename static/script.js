document.addEventListener('DOMContentLoaded', function() {
    const uploadBtn = document.getElementById('uploadBtn');
    const fileInput = document.getElementById('fileInput');
    
    uploadBtn.addEventListener('click', function() {
        fileInput.click();
    });
    
    fileInput.addEventListener('change', function(e) {
        if (e.target.files.length > 0) {
            const fileName = e.target.files[0].name;
            uploadLogFile(e.target.files[0]);

            const resultsContainer = document.getElementById('analysisResults');
            resultsContainer.innerHTML = `<div class="placeholder-text">Analyzing ${fileName}...</div>`;
            document.getElementById('last-updated').textContent = 'Just Now';
        }
    });
    
    const refreshButtons = document.querySelectorAll('.refresh-btn');
    refreshButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const card = this.closest('.card');
            const cardBody = card.querySelector('.card-body');
            cardBody.style.opacity = '0.5';
            setTimeout(() => {
                cardBody.style.opacity = '1';
                fetchDashboardData();
            }, 500);
        });
    });

    // Check if we have server-side data already
    if (window.serverData && window.serverData.hasResults) {
        // If we do, we don't need to re-render the results as they're already in the HTML
        document.getElementById('last-updated').textContent = 'Just Now';
    }
    
    fetchDashboardData();
    populateSecurityEvents();
});

function uploadLogFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    fetch('/api/analyze-log', {
        method: 'POST',
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        if (data.error) {
            console.error('Error:', data.error);
            document.getElementById('analysisResults').innerHTML = `<div class="error-text">${data.error}</div>`;
        } else {
            displayAnalysisResults(data);
        }
    })
    .catch(error => {
        console.error('Upload failed:', error);
        document.getElementById('analysisResults').innerHTML = `<div class="error-text">Error analyzing file.</div>`;
    });
}


function fetchDashboardData() {
    fetch('/api/dashboard-data')
        .then(res => res.json())
        .then(data => {
            updateCharts(data);
        })
        .catch(error => {
            console.error('Failed to load dashboard data:', error);
        });
}

function destroyChart(chartRef) {
    if (chartRef && typeof chartRef.destroy === 'function') {
        chartRef.destroy();
    }
}

function updateCharts(data) {
    const chartConfig = {
        plugins: {
            legend: {
                labels: {
                    color: '#e0e0e0',
                    font: {
                        family: "'Courier New', monospace",
                        size: 12
                    }
                }
            },
            tooltip: {
                backgroundColor: '#111722',
                titleColor: '#00ff9d',
                bodyColor: '#e0e0e0',
                borderColor: '#2a3042',
                borderWidth: 1,
                titleFont: {
                    family: "'Courier New', monospace"
                },
                bodyFont: {
                    family: "'Courier New', monospace"
                },
                displayColors: false
            }
        },
        scales: {
            x: {
                ticks: {
                    color: '#e0e0e0',
                    font: {
                        family: "'Courier New', monospace"
                    }
                },
                grid: {
                    color: 'rgba(42, 48, 66, 0.5)'
                }
            },
            y: {
                ticks: {
                    color: '#e0e0e0',
                    font: {
                        family: "'Courier New', monospace"
                    }
                },
                grid: {
                    color: 'rgba(42, 48, 66, 0.5)'
                }
            }
        },
        animation: {
            duration: 1000,
            easing: 'easeOutQuart'
        },
        responsive: true,
        maintainAspectRatio: false
    };
    
    //type of attack pie chart
    const attackCtx = document.getElementById('attackTypeChart').getContext('2d');
    destroyChart(window.attackChart);
    window.attackChart = new Chart(attackCtx, {
        type: 'pie',
        data: {
            labels: data.attack_type_stats.labels,
            datasets: [{
                data: data.attack_type_stats.data,
                backgroundColor: ['#6a994e', '#720026'],
                borderColor: '#111722',
                borderWidth: 2
            }]
        },
        options: {
            ...chartConfig,
            scales: undefined,
            plugins: {
                ...chartConfig.plugins,
                title: {
                    display: false
                }
            }
        }
    });
    
    //num_failed_login chart
    const loginCtx = document.getElementById('failedLoginChart').getContext('2d');
    destroyChart(window.loginChart);
    window.loginChart = new Chart(loginCtx, {
        type: 'bar',
        data: {
            labels: data.failed_login_stats.labels,
            datasets: [{
                label: 'Failed Login %',
                data: data.failed_login_stats.data,
                backgroundColor: ['#6a994e', '#720026'],
                borderColor: ['#00ff9d', '#ff3860'],
                borderWidth: 1
            }]
        },
        options: chartConfig
    });

    //protocol chart
    const protocolCtx = document.getElementById('protocolChart').getContext('2d');
    destroyChart(window.protocolChart);

    window.protocolChart = new Chart(protocolCtx, {
        type: 'bar',
        data: {
            labels: data.protocol_stats.labels,
            datasets: data.protocol_stats.datasets
        },
        options: {
            ...chartConfig,
            scales: {
                x: {
                    stacked: true,
                    ticks: {
                        color: '#e0e0e0',
                        font: {
                            family: "'Courier New', monospace"
                        }
                    },
                    grid: {
                        color: 'rgba(42, 48, 66, 0.5)'
                    }
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    ticks: {
                        color: '#e0e0e0',
                        font: {
                            family: "'Courier New', monospace"
                        }
                    },
                    grid: {
                        color: 'rgba(42, 48, 66, 0.5)'
                    }
                }
            }
        }
    });

    
    //service dist chart
    const serviceCtx = document.getElementById('serviceChart').getContext('2d');
    destroyChart(window.serviceChart);

    window.serviceChart = new Chart(serviceCtx, {
        type: 'bar',
        data: {
            labels: data.service_stats.labels,
            datasets: [
                {
                    label: 'Normal',
                    data: data.service_stats.normal,
                    backgroundColor: '#6a994e'
                },
                {
                    label: 'Abnormal',
                    data: data.service_stats.abnormal,
                    backgroundColor: '#720026'
                }
            ]
        },
        options: {
            ...chartConfig,
            indexAxis: 'y',
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        color: '#e0e0e0',
                        font: {
                            family: "'Courier New', monospace"
                        }
                    },
                    grid: {
                        color: 'rgba(42, 48, 66, 0.5)'
                    }
                },
                y: {
                    ticks: {
                        color: '#e0e0e0',
                        font: {
                            family: "'Courier New', monospace'"
                        }
                    },
                    grid: {
                        color: 'rgba(42, 48, 66, 0.5)'
                    }
                }
            }
        }
    });
}

// yeah ik this is fake
function populateSecurityEvents() {
    const eventsContainer = document.getElementById('securityEvents');
    
    const sampleEvents = [
        {
            message: 'Multiple failed login attempts detected from IP 192.168.1.45',
            timestamp: '2025-04-19 14:32:15',
            type: 'danger'
        },
        {
            message: 'Unusual SSH connection from unknown IP address 203.45.67.89',
            timestamp: '2025-04-19 14:25:03',
            type: 'danger'
        },
        {
            message: 'Firewall rule update: Added block for IP range 45.67.89.0/24',
            timestamp: '2025-04-19 14:20:47',
            type: 'normal'
        },
        {
            message: 'User account "admin" accessed sensitive file directory',
            timestamp: '2025-04-19 14:15:22',
            type: 'warning'
        },
        {
            message: 'System scan completed: 2 vulnerabilities detected',
            timestamp: '2025-04-19 14:10:05',
            type: 'warning'
        },
        {
            message: 'Service restarted: nginx web server',
            timestamp: '2025-04-19 14:05:33',
            type: 'normal'
        },
        {
            message: 'Database backup completed successfully',
            timestamp: '2025-04-19 14:00:00',
            type: 'normal'
        }
    ];
    
    eventsContainer.innerHTML = '';
    sampleEvents.forEach(event => {
        const eventElement = document.createElement('div');
        eventElement.className = `event-item ${event.type}`;
        eventElement.innerHTML = `
            <div class="event-message">${event.message}</div>
            <div class="event-timestamp">${event.timestamp}</div>
        `;
        eventsContainer.appendChild(eventElement);
    });
}

function displayAnalysisResults(results) {
    const resultsContainer = document.getElementById('analysisResults');
    const threatCount = results.filter(r => r.prediction === 'abnormal').length;
    document.getElementById('threats-count').textContent = threatCount.toString();

    resultsContainer.innerHTML = '';
    results.forEach(result => {
        const resultElement = document.createElement('div');
        resultElement.className = `analysis-item ${result.prediction}`;

        let html = `<div class="result-header">
            <strong>Prediction: ${result.prediction.toUpperCase()}</strong>
        </div>
        <div class="result-details">
            <span>Service: ${result.service}</span> |
            <span>Protocol: ${result.protocol_type}</span> |
            <span>Duration: ${result.duration}ms</span> |
            <span>Failed Logins: ${result.num_failed_logins}</span>
        </div>`;

        if (result.prediction === 'abnormal' && result.explanation) {
            html += `<div class="explanation-list">`;
            for (const [key, value] of Object.entries(result.explanation)) {
                html += `<div class="explanation-item">- ${value}</div>`;
            }
            html += `</div>`;
        }

        resultElement.innerHTML = html;
        resultsContainer.appendChild(resultElement);
    });
}
