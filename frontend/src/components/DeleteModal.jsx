export default function DeleteModal({ show, onClose, onConfirm, domain, isDeleteAll = false, count = 0 }) {
  if (!show) return null;

  return (
    <div className={`modal-overlay ${show ? 'active' : ''}`} onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal delete-modal">
        <div className="delete-modal-content" style={{ textAlign: 'center', padding: '8px 0' }}>
          {/* Animated icon */}
          <div className="delete-icon-container">
            <div className="delete-icon-ring" />
            <div className="delete-icon-ring delay" />
            <div className="delete-icon">
              <span>{isDeleteAll ? '💣' : '🗑️'}</span>
            </div>
          </div>

          <h3 className="delete-title">
            {isDeleteAll ? 'Delete ALL Scans?' : 'Delete Scan?'}
          </h3>

          <p className="delete-description">
            {isDeleteAll ? (
              <>You are about to permanently delete <span className="delete-domain">{count}</span> scans.</>
            ) : (
              <>Are you sure you want to delete the scan for <span className="delete-domain">{domain}</span>?</>
            )}
          </p>

          <div className="delete-warning-box" style={{ textAlign: 'left' }}>
            <div className="delete-warning-header">
              <span>⚠️</span>
              <span>This action cannot be undone!</span>
            </div>
            <ul className="delete-items-list">
              {isDeleteAll && <li><span>🎯</span> All scan records will be removed</li>}
              <li><span>🌐</span> All subdomains will be {isDeleteAll ? 'deleted' : 'removed'}</li>
              <li><span>🔗</span> All endpoints will be deleted</li>
              <li><span>🔒</span> All vulnerability data will be lost</li>
            </ul>
          </div>
        </div>

        <div className="delete-modal-actions">
          <button type="button" className="btn-cancel" onClick={onClose}>
            <span>✕</span> Cancel
          </button>
          <button type="button" className="btn btn-danger" onClick={onConfirm}>
            <span>{isDeleteAll ? '💣' : '🗑️'}</span> {isDeleteAll ? 'Delete Everything' : 'Delete Scan'}
          </button>
        </div>
      </div>
    </div>
  );
}
