def gallery_store():
    fn = request.files["pic"].filename
    request.files["pic"].save(f"/var/www/html/uploads/{fn}")
