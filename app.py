
    except:
        return "Error: index.html not found", 404

@app.route('/run-recon', methods=['POST'])
def run_recon():
    global log_queue, vuln_queue, scanning
    data = request.json
    domain = data.get('domain', 'example.com')
    log_queue = []
    vuln_queue = []
    scanning = True

    def execute():
        global log_queue, vuln_queue, scanning
        try:
            # Use absolute path to app.sh
            cmd = f"bash {APP_SHELL_SCRIPT} {domain}"
            log_queue.append(f"[*] Starting scan for {domain}...")
            log_queue.append(f"[*] Please wait for all steps...")
            
            process = subprocess.Popen(
                cmd, shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                line = line.rstrip('\n\r')
                if line:
                    log_queue.append(line)
                    
                    # Parse vulnerability markers for right panel
                    if ("###VULN###" in line) and ("###END###" in line):
                        vuln_queue.append(line)
                    
                time.sleep(0.01)
            
            process.wait()
        except Exception as e:
            log_queue.append(f"❌ ERROR: {str(e)}")
        finally:
            scanning = False
            vuln_queue.append("###DONE###")
    
    thread = threading.Thread(target=execute, daemon=True)
    thread.start()
    return jsonify({'status': 'started'})

@app.route('/logs')
def logs():
    def generate():
        global log_queue, vuln_queue, scanning
        sent_logs = 0
        sent_vulns = 0
        try:
            while scanning or sent_logs < len(log_queue) or sent_vulns < len(vuln_queue):
                while sent_logs < len(log_queue):
                    try:
                        yield f"data: {log_queue[sent_logs]}\n\n"
                        sent_logs += 1
                    except (BrokenPipeError, ConnectionError):
                        return
                
                while sent_vulns < len(vuln_queue):
                    try:
                        yield f"data: {vuln_queue[sent_vulns]}\n\n"
                        sent_vulns += 1
                    except (BrokenPipeError, ConnectionError):
                        return
                
                time.sleep(0.1)
        except GeneratorExit:
            return
    
    return Response(
        stream_with_context(generate()), 
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'scanning': scanning,
        'log_count': len(log_queue),
        'vuln_count': len(vuln_queue)
    })

if __name__ == '__main__':
    # Verify app.sh exists
    if not os.path.exists(APP_SHELL_SCRIPT):
        print(f"⚠️  WARNING: {APP_SHELL_SCRIPT} not found!")
        print(f"   Expected location: {SCRIPT_DIR}")
    
    print("=" * 60)
    print("🚀 Pentest Copilot running on http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=False, host='127.0.0.1', port=5000, threaded=True, use_reloader=False)
