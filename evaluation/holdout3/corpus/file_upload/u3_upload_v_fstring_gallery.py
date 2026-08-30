def gallery_put():
    fn = request.files["pic"].filename
    request.files["pic"].save(f"/var/www/html/gallery/{fn}")
