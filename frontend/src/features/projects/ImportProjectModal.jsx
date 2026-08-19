import React, { useState } from 'react';
import { X, GitBranch, FileArchive, UploadCloud, Loader2 } from 'lucide-react';

export default function ImportProjectModal({ isOpen, onClose, onImport }) {
  const [activeTab, setActiveTab] = useState('github'); // 'github' or 'zip'
  const [projectName, setProjectName] = useState('');
  const [description, setDescription] = useState('');
  
  // GitHub state
  const [installationId, setInstallationId] = useState('');
  const [owner, setOwner] = useState('');
  const [repo, setRepo] = useState('');
  const [branch, setBranch] = useState('main');
  
  // OAuth State
  const [githubToken, setGithubToken] = useState(null);
  const [repositories, setRepositories] = useState([]);
  const [isLoadingRepos, setIsLoadingRepos] = useState(false);
  
  // ZIP state
  const [selectedFile, setSelectedFile] = useState(null);
  
  const [isSubmitting, setIsSubmitting] = useState(false);

  React.useEffect(() => {
    const handleMessage = async (event) => {
      // In production, check event.origin to ensure security
      if (event.data?.type === 'github_oauth' && event.data?.token) {
        const token = event.data.token;
        setGithubToken(token);
        setIsLoadingRepos(true);
        try {
          const res = await fetch(`http://localhost:8000/api/github/user/repos?github_token=${token}`);
          if (res.ok) {
            const data = await res.json();
            setRepositories(data.repositories || []);
          } else {
            console.error("Backend error fetching repos:", await res.text());
            alert("Failed to fetch repositories. Ensure app has access to repos.");
          }
        } catch (e) {
          console.error("Failed to fetch repos", e);
          alert("Failed to reach backend to fetch repositories.");
        } finally {
          setIsLoadingRepos(false);
        }
      }
    };
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!projectName.trim()) {
      alert("Project name is required.");
      return;
    }

    setIsSubmitting(true);
    try {
      if (activeTab === 'github') {
        if (!installationId || !owner || !repo || !branch) {
          alert("All GitHub fields are required.");
          setIsSubmitting(false);
          return;
        }
        await onImport({
          type: 'github',
          project: { name: projectName, description },
          github: { installation_id: installationId, owner, repo, branch }
        });
      } else {
        if (!selectedFile) {
          alert("Please select a ZIP file to upload.");
          setIsSubmitting(false);
          return;
        }
        await onImport({
          type: 'zip',
          project: { name: projectName, description },
          file: selectedFile
        });
      }
      // Reset and close on success
      setProjectName('');
      setDescription('');
      setInstallationId('');
      setOwner('');
      setRepo('');
      setBranch('main');
      setSelectedFile(null);
      onClose();
    } catch (error) {
      alert(`Import failed: ${error.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0, 0, 0, 0.7)', backdropFilter: 'blur(4px)',
      display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 9999
    }}>
      <div className="glass-panel animate-fade-in" style={{
        width: '100%', maxWidth: '600px', background: 'var(--bg-card)',
        border: '1px solid rgba(0,0,0, 0.1)', padding: '0', display: 'flex', flexDirection: 'column',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.8)'
      }}>
        
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '24px', borderBottom: '1px solid rgba(0,0,0,0.05)' }}>
          <h2 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px' }}>
            <UploadCloud size={24} color="var(--primary)" /> Import Software Asset
          </h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '4px' }}>
            <X size={24} />
          </button>
        </div>

        {/* Content */}
        <div style={{ padding: '24px' }}>
          <div style={{ display: 'flex', gap: '12px', marginBottom: '24px' }}>
            <button
              type="button"
              className={`btn-secondary ${activeTab === 'github' ? 'active' : ''}`}
              onClick={() => setActiveTab('github')}
              style={{
                flex: 1, justifyContent: 'center', gap: '8px',
                background: activeTab === 'github' ? 'rgba(99,102,241,0.1)' : 'transparent',
                borderColor: activeTab === 'github' ? 'var(--primary)' : 'rgba(0,0,0,0.1)',
                color: 'var(--text-primary)'
              }}
            >
              <GitBranch size={18} /> GitHub Repository
            </button>
            <button
              type="button"
              className={`btn-secondary ${activeTab === 'zip' ? 'active' : ''}`}
              onClick={() => setActiveTab('zip')}
              style={{
                flex: 1, justifyContent: 'center', gap: '8px',
                background: activeTab === 'zip' ? 'rgba(99,102,241,0.1)' : 'transparent',
                borderColor: activeTab === 'zip' ? 'var(--primary)' : 'rgba(0,0,0,0.1)',
                color: 'var(--text-primary)'
              }}
            >
              <FileArchive size={18} /> Upload ZIP Archive
            </button>
          </div>

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {/* General Project Info */}
            <div style={{ display: 'flex', gap: '16px' }}>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Project Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Payment Gateway Service"
                  value={projectName}
                  onChange={e => setProjectName(e.target.value)}
                  style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
                />
              </div>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Description</label>
                <input
                  type="text"
                  placeholder="Optional brief description"
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                  style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
                />
              </div>
            </div>

            <hr style={{ border: 0, borderTop: '1px solid rgba(0,0,0,0.05)', margin: '4px 0' }} />

            {/* GitHub Specific Fields */}
            {activeTab === 'github' && (
              <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.9rem', fontWeight: 600 }}>GitHub Integration</span>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    {githubToken && <span style={{ fontSize: '0.8rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '4px' }}>✓ Connected</span>}
                    <button type="button" className="btn-secondary" style={{ padding: '6px 12px', fontSize: '0.75rem' }} onClick={() => window.open('http://localhost:8000/api/github/login', 'github-oauth', 'width=600,height=600')}>
                      <GitBranch size={14} /> Connect GitHub
                    </button>
                  </div>
                </div>
                
                {isLoadingRepos ? (
                  <div style={{ textAlign: 'center', padding: '20px', color: 'var(--text-muted)' }}>
                    <Loader2 size={24} className="animate-spin" style={{ margin: '0 auto 10px auto' }} />
                    <p style={{ fontSize: '0.85rem' }}>Fetching your repositories...</p>
                  </div>
                ) : repositories.length > 0 ? (
                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Select Repository *</label>
                    <select
                      required
                      onChange={(e) => {
                        const r = repositories[e.target.value];
                        if (r) {
                          setInstallationId(r.installation_id);
                          setOwner(r.owner);
                          setRepo(r.name);
                          setBranch(r.default_branch);
                          // Auto-fill project name if empty
                          if (!projectName) setProjectName(r.name);
                        }
                      }}
                      style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
                    >
                      <option value="">-- Choose a repository --</option>
                      {repositories.map((r, i) => (
                        <option key={i} value={i}>{r.full_name} (Branch: {r.default_branch})</option>
                      ))}
                    </select>
                    
                    <div style={{ marginTop: '16px', display: 'flex', gap: '16px', opacity: 0.6 }}>
                      <div style={{ flex: 1 }}>
                        <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Installation ID</label>
                        <input type="text" readOnly value={installationId} style={{ width: '100%', padding: '8px', borderRadius: '4px', background: 'transparent', border: '1px solid rgba(0,0,0,0.1)', color: 'var(--text-muted)' }} />
                      </div>
                      <div style={{ flex: 1 }}>
                        <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Branch</label>
                        <input type="text" readOnly value={branch} style={{ width: '100%', padding: '8px', borderRadius: '4px', background: 'transparent', border: '1px solid rgba(0,0,0,0.1)', color: 'var(--text-muted)' }} />
                      </div>
                    </div>
                  </div>
                ) : (
                  <>
                  <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Installation ID *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. 40123991"
                    value={installationId}
                    onChange={e => setInstallationId(e.target.value)}
                    style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
                  />
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>Required to fetch source code via the GitHub API.</p>
                </div>

                <div style={{ display: 'flex', gap: '16px' }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Repository Owner *</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. facebook"
                      value={owner}
                      onChange={e => setOwner(e.target.value)}
                      style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
                    />
                  </div>
                  <div style={{ flex: 1 }}>
                    <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Repository Name *</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. react"
                      value={repo}
                      onChange={e => setRepo(e.target.value)}
                      style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
                    />
                  </div>
                  <div style={{ flex: 0.5 }}>
                    <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Branch</label>
                    <input
                      type="text"
                      required
                      placeholder="main"
                      value={branch}
                      onChange={e => setBranch(e.target.value)}
                      style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
                    />
                  </div>
                </div>
                </>
                )}
              </div>
            )}

            {/* ZIP Specific Fields */}
            {activeTab === 'zip' && (
              <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <span style={{ fontSize: '0.9rem', fontWeight: 600 }}>Upload Source Code</span>
                
                <div style={{
                  border: '2px dashed var(--primary)', borderRadius: '8px', padding: '32px',
                  display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                  background: 'rgba(99, 102, 241, 0.05)', cursor: 'pointer', position: 'relative'
                }}>
                  <input 
                    type="file" 
                    accept=".zip"
                    onChange={(e) => setSelectedFile(e.target.files[0])}
                    style={{ position: 'absolute', inset: 0, opacity: 0, cursor: 'pointer' }}
                  />
                  <FileArchive size={48} color="var(--primary)" style={{ marginBottom: '16px', opacity: 0.8 }} />
                  <p style={{ margin: '0 0 8px 0', fontWeight: 600 }}>Drag and drop a .zip archive here</p>
                  <p style={{ margin: '0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Maximum file size: 50MB</p>
                  
                  {selectedFile && (
                    <div style={{ marginTop: '16px', padding: '8px 16px', background: 'var(--surface-color)', borderRadius: '4px', border: '1px solid var(--primary)', color: 'var(--primary)', fontSize: '0.85rem' }}>
                      Selected: <strong>{selectedFile.name}</strong> ({(selectedFile.size / 1024 / 1024).toFixed(2)} MB)
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Footer */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '16px', paddingTop: '20px', borderTop: '1px solid rgba(0,0,0,0.05)' }}>
              <button type="button" className="btn-secondary" onClick={onClose} disabled={isSubmitting}>
                Cancel
              </button>
              <button type="submit" className="btn-primary" disabled={isSubmitting}>
                {isSubmitting ? <span style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><Loader2 size={16} className="animate-spin" /> Importing...</span> : 'Import & Scan Asset'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
