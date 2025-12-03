// Client-side role-based navigation filtering
export default (function () {
  if (typeof window === 'undefined') return;

  let filterTimeout: any = null;

  function filterNavigation() {
    // Clear any pending filter operations
    if (filterTimeout) {
      clearTimeout(filterTimeout);
    }

    // Debounce to avoid excessive filtering
    filterTimeout = setTimeout(() => {
      const hasFullAccess = (window as any).__HAS_FULL_ACCESS__;
      const hasFlowchartsAccess = (window as any).__HAS_FLOWCHARTS_ACCESS__;

      // If user has full access, show everything
      if (hasFullAccess) return;

      // If user only has flowcharts access, hide other backend sections
      if (hasFlowchartsAccess && !hasFullAccess) {
        // Find all sidebar links and list items
        const allLinks = document.querySelectorAll('a[href*="/docs/"]');
        
        allLinks.forEach((link: any) => {
          const href = link.getAttribute('href') || '';
          
          // Determine if this should be hidden
          let shouldHide = false;
          
          // Hide all backend docs except flowcharts
          if (href.includes('/docs/backend/')) {
            if (!href.includes('/flowcharts')) {
              shouldHide = true;
            }
          }
          
          // Hide frontend docs
          if (href.includes('/docs/frontend/')) {
            shouldHide = true;
          }
          
          // Hide intro and other top-level docs
          if (href.includes('/docs/intro')) {
            shouldHide = true;
          }
          
          if (shouldHide) {
            // Hide the parent list item
            const listItem = link.closest('li');
            if (listItem) {
              listItem.style.display = 'none';
            }
            
            // Also hide the link itself
            link.style.display = 'none';
          }
        });

        // Hide category headers that don't have flowcharts
        const categories = document.querySelectorAll('.menu__list-item-collapsible');
        categories.forEach((category: any) => {
          const categoryLink = category.querySelector('a');
          if (categoryLink) {
            const href = categoryLink.getAttribute('href') || '';
            const text = categoryLink.textContent || '';
            
            // Hide non-flowcharts backend categories
            if ((href.includes('/docs/backend/') && !href.includes('/flowcharts')) ||
                text.toLowerCase().includes('db-panto-erd') ||
                text.toLowerCase().includes('documention-rules') ||
                text.toLowerCase().includes('system-overview') ||
                text.toLowerCase().includes('devices entity') ||
                text.toLowerCase().includes('accounts entity')) {
              category.style.display = 'none';
            }
            
            // Hide frontend category
            if (href.includes('/docs/frontend/') || text.toLowerCase().includes('frontend')) {
              category.style.display = 'none';
            }
          }
        });
      }
    }, 100);
  }

  // Run on page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', filterNavigation);
  } else {
    filterNavigation();
  }

  // Re-run when navigation changes (for SPA routing)
  const observer = new MutationObserver(filterNavigation);
  
  // Wait for body to be available
  const startObserving = () => {
    if (document.body) {
      observer.observe(document.body, {
        childList: true,
        subtree: true,
      });
    } else {
      setTimeout(startObserving, 100);
    }
  };
  
  startObserving();

  // Also run on route changes
  window.addEventListener('popstate', filterNavigation);
  window.addEventListener('hashchange', filterNavigation);
})();
