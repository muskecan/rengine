/**
 * DataTables Responsive Configuration
 * This file configures DataTables defaults for responsive behavior across all tables
 */

// Wait for DataTables to be loaded
$(document).ready(function() {
    // Extend DataTables defaults with responsive options
    $.extend(true, $.fn.dataTable.defaults, {
        responsive: {
            details: {
                type: 'column',
                target: 'tr'
            }
        },
        // Responsive breakpoints matching Bootstrap 5
        // These determine when columns get hidden
        columnDefs: [
            {
                responsivePriority: 1,
                targets: 0 // First column always visible
            },
            {
                responsivePriority: 2,
                targets: 1 // Second column high priority
            },
            {
                responsivePriority: 10001,
                targets: '_all' // All other columns lower priority
            }
        ]
    });

    // Apply responsive class to all existing datatables
    $.fn.dataTable.ext.classes.sWrapper = 'dataTables_wrapper table-responsive';
    
    // Custom responsive breakpoints aligned with Bootstrap
    if ($.fn.dataTable.Responsive) {
        $.fn.dataTable.Responsive.breakpoints = [
            { name: 'xl', width: 1200 },
            { name: 'lg', width: 992 },
            { name: 'md', width: 768 },
            { name: 'sm', width: 576 },
            { name: 'xs', width: 0 }
        ];
    }
});

/**
 * Helper function to initialize a responsive DataTable
 * Use this for tables that need specific responsive configurations
 * 
 * @param {string} tableSelector - jQuery selector for the table
 * @param {object} options - Additional DataTable options to merge
 * @returns {DataTable} - The initialized DataTable instance
 */
function initResponsiveDataTable(tableSelector, options = {}) {
    const defaultOptions = {
        responsive: true,
        scrollX: false,
        autoWidth: false,
        dom: "<'row'<'col-12 col-md-6 mb-2'l><'col-12 col-md-6 mb-2'f>>" +
             "<'row'<'col-12'tr>>" +
             "<'row'<'col-12 col-md-5'i><'col-12 col-md-7'p>>",
        language: {
            search: "",
            searchPlaceholder: "Search...",
            lengthMenu: "Show _MENU_",
            info: "Showing _START_ to _END_ of _TOTAL_",
            infoEmpty: "No records",
            infoFiltered: "(filtered from _MAX_)",
            paginate: {
                first: '<i class="fe-chevrons-left"></i>',
                last: '<i class="fe-chevrons-right"></i>',
                previous: '<i class="fe-chevron-left"></i>',
                next: '<i class="fe-chevron-right"></i>'
            }
        },
        drawCallback: function() {
            // Add responsive class to pagination
            $(".dataTables_paginate > .pagination").addClass("pagination-rounded pagination-sm");
        }
    };

    // Merge options
    const mergedOptions = $.extend(true, {}, defaultOptions, options);
    
    return $(tableSelector).DataTable(mergedOptions);
}

/**
 * Reinitialize responsive features on window resize
 * Useful when tables are dynamically shown/hidden
 */
function recalculateResponsiveTables() {
    $.fn.dataTable.tables({ visible: true, api: true }).columns.adjust().responsive.recalc();
}

// Debounced resize handler for better performance
let resizeTimeout;
$(window).on('resize', function() {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(function() {
        recalculateResponsiveTables();
    }, 250);
});

// Recalculate when tabs are shown (Bootstrap tab events)
$(document).on('shown.bs.tab', function(e) {
    recalculateResponsiveTables();
});

// Recalculate when modals are shown
$(document).on('shown.bs.modal', function(e) {
    recalculateResponsiveTables();
});

// Recalculate when collapse elements are shown
$(document).on('shown.bs.collapse', function(e) {
    recalculateResponsiveTables();
});
