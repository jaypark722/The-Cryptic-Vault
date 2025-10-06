document.addEventListener('DOMContentLoaded', () => {
    const productTable = document.querySelector('#product-table');
    
    if (!productTable) {
        console.error("Error: Product table element with ID 'product-table' not found.");
        return;
    }

    let tableBody = productTable.querySelector('tbody');
    if (!tableBody) {
        tableBody = productTable.createTBody();
    }
    
    const displayKeys = [
        "Product ID",
        "Category", 
        "Product Name (Description)",
        "Vendor Name",
        "Price (BTC)"
    ];

    const urlParams = new URLSearchParams(window.location.search);
    const filterCat = urlParams.get('cat'); 
    const searchQuery = urlParams.get('q'); 

    const categoryMapping = {
        'guns': 'Weapons & Ammo',
        'pharma': 'Drugs & Pharmaceuticals',
        // Add other category mappings if needed for filtering
    };

    fetch('/static/data/products.json')
        .then(response => {
            if (!response.ok) {
                throw new Error(`Network response was not ok. Status: ${response.status}`);
            }
            return response.json();
        })
        .then(products => {
            let filteredProducts = products;

            // --- CRITICAL FILTER: Exclude system/internal products (like the coupon) ---
            filteredProducts = filteredProducts.filter(product => {
                return product["Product ID"] !== "COUPON-REDTEAM";
            });

            // --- FILTERING LOGIC ---
            
            // 1. Category Filter
            if (filterCat) {
                const targetCategoryName = categoryMapping[filterCat.toLowerCase()] || '';

                filteredProducts = filteredProducts.filter(product => {
                    const productCategory = product["Category"];
                    if (!productCategory) return false;

                    if (targetCategoryName && productCategory === targetCategoryName) {
                        return true;
                    }

                    return productCategory.toLowerCase().includes(filterCat.toLowerCase());
                });
            }
            
            // 2. Search Query Filter
            if (searchQuery) {
                const query = searchQuery.toLowerCase().trim();
                filteredProducts = filteredProducts.filter(product => {
                    // Search in Product ID, Name, Vendor Name, and Category
                    return product["Product ID"].toLowerCase().includes(query) ||
                               (product["Product Name (Description)"] && product["Product Name (Description)"].toLowerCase().includes(query)) ||
                               (product["Vendor Name"] && product["Vendor Name"].toLowerCase().includes(query)) ||
                               (product["Category"] && product["Category"].toLowerCase().includes(query));
                });
            }

            // --- Rendering Logic ---
            if (filteredProducts.length === 0) {
                 // Check if it's a specific search that resulted in zero results
                 let message = searchQuery ? `No listings found matching "${searchQuery}".` : 'No listings found for this category.';
                 tableBody.innerHTML = `<tr><td colspan="${displayKeys.length}" class="px-6 py-4 text-center">${message}</td></tr>`;
                 return;
            }

            tableBody.innerHTML = ''; 

            filteredProducts.forEach(product => {
                const row = tableBody.insertRow();
                displayKeys.forEach((key, index) => {
                    const cell = row.insertCell();
                    cell.className = 'px-6 py-4 whitespace-nowrap';
                    
                    const itemContent = product[key] || ''; 

                    if (key === "Product Name (Description)") {
                        // Make the Product Name (Description) clickable
                        const link = document.createElement('a');
                        link.href = `/product/${product["Product ID"]}`;
                        link.textContent = itemContent;
                        link.className = 'text-market-gold hover:text-white font-semibold';
                        cell.appendChild(link);
                    } else {
                        cell.textContent = itemContent; 
                    }
                });
            });
        })
        .catch(error => {
            console.error('Error loading or rendering product data:', error);
            if (tableBody) {
                tableBody.innerHTML = `<tr><td colspan="${displayKeys.length}" class="px-6 py-4 text-center text-red-500">Could not load product data.</td></tr>`;
            }
        });
});