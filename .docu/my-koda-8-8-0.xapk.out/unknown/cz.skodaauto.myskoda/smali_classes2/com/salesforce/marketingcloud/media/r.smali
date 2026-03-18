.class public Lcom/salesforce/marketingcloud/media/r;
.super Lcom/salesforce/marketingcloud/media/v;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field private static final b:Ljava/lang/String;


# instance fields
.field private final a:Lcom/salesforce/marketingcloud/media/s;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "NetworkRequestHandler"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/media/r;->b:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/media/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/media/v;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/r;->a:Lcom/salesforce/marketingcloud/media/s;

    .line 5
    .line 6
    return-void
.end method

.method private a(Ljava/lang/String;Lcom/salesforce/marketingcloud/media/t;)Landroid/graphics/Bitmap;
    .locals 2

    .line 28
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/r;->a:Lcom/salesforce/marketingcloud/media/s;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/s;->a(Ljava/lang/String;)Ljava/io/InputStream;

    move-result-object p0

    const/4 p1, 0x0

    if-eqz p0, :cond_0

    .line 29
    :try_start_0
    invoke-static {p0, p2}, Lcom/salesforce/marketingcloud/media/v;->a(Ljava/io/InputStream;Lcom/salesforce/marketingcloud/media/t;)Landroid/graphics/Bitmap;

    move-result-object p1

    .line 30
    invoke-static {p0}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p0

    .line 31
    sget-object p2, Lcom/salesforce/marketingcloud/media/r;->b:Ljava/lang/String;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Failed to decode cache into Bitmap."

    invoke-static {p2, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    return-object p1
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/t;Lcom/salesforce/marketingcloud/media/v$a;)V
    .locals 4

    .line 4
    iget-object p1, p2, Lcom/salesforce/marketingcloud/media/t;->a:Landroid/net/Uri;

    invoke-virtual {p1}, Landroid/net/Uri;->toString()Ljava/lang/String;

    move-result-object p1

    .line 5
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/media/r;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/media/t;)Landroid/graphics/Bitmap;

    move-result-object v0

    if-eqz v0, :cond_0

    .line 6
    new-instance p0, Lcom/salesforce/marketingcloud/media/v$b;

    sget-object p1, Lcom/salesforce/marketingcloud/media/o$b;->d:Lcom/salesforce/marketingcloud/media/o$b;

    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/media/v$b;-><init>(Landroid/graphics/Bitmap;Lcom/salesforce/marketingcloud/media/o$b;)V

    invoke-interface {p3, p0}, Lcom/salesforce/marketingcloud/media/v$a;->a(Lcom/salesforce/marketingcloud/media/v$b;)V

    return-void

    :cond_0
    const/4 v0, 0x0

    .line 7
    new-array v1, v0, [Ljava/lang/Object;

    const-string v2, "Starting network request for image"

    const-string v3, "IMAGE"

    invoke-static {v3, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 v1, 0x1

    .line 8
    invoke-static {v1}, Ljava/net/HttpURLConnection;->setFollowRedirects(Z)V

    const/4 v1, 0x0

    .line 9
    :try_start_0
    new-instance v2, Ljava/net/URL;

    invoke-direct {v2, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v2

    invoke-static {v2}, Lcom/google/firebase/perf/network/FirebasePerfUrlConnection;->instrument(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/net/URLConnection;

    check-cast v2, Ljavax/net/ssl/HttpsURLConnection;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 10
    :try_start_1
    invoke-virtual {v2, v0}, Ljava/net/URLConnection;->setUseCaches(Z)V

    const/16 v0, 0x7530

    .line 11
    invoke-virtual {v2, v0}, Ljava/net/URLConnection;->setConnectTimeout(I)V

    .line 12
    const-string v0, "GET"

    invoke-virtual {v2, v0}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 13
    invoke-virtual {v2}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    move-result-object v0

    .line 14
    iget v1, p2, Lcom/salesforce/marketingcloud/media/t;->d:I

    invoke-static {v1}, Lcom/salesforce/marketingcloud/media/t$b;->c(I)Z

    move-result v1

    if-eqz v1, :cond_1

    .line 15
    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/InputStream;)[B

    move-result-object v1

    .line 16
    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V

    .line 17
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/r;->a:Lcom/salesforce/marketingcloud/media/s;

    new-instance v0, Ljava/io/ByteArrayInputStream;

    invoke-direct {v0, v1}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/media/s;->a(Ljava/lang/String;Ljava/io/InputStream;)V

    .line 18
    new-instance v0, Ljava/io/ByteArrayInputStream;

    invoke-direct {v0, v1}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    goto :goto_0

    :catchall_0
    move-exception p0

    move-object v1, v2

    goto :goto_2

    :catch_0
    move-exception p0

    move-object v1, v2

    goto :goto_1

    .line 19
    :cond_1
    :goto_0
    invoke-static {v0, p2}, Lcom/salesforce/marketingcloud/media/v;->a(Ljava/io/InputStream;Lcom/salesforce/marketingcloud/media/t;)Landroid/graphics/Bitmap;

    move-result-object p0

    .line 20
    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V

    .line 21
    new-instance p2, Lcom/salesforce/marketingcloud/media/v$b;

    sget-object v0, Lcom/salesforce/marketingcloud/media/o$b;->e:Lcom/salesforce/marketingcloud/media/o$b;

    invoke-direct {p2, p0, v0}, Lcom/salesforce/marketingcloud/media/v$b;-><init>(Landroid/graphics/Bitmap;Lcom/salesforce/marketingcloud/media/o$b;)V

    invoke-interface {p3, p2}, Lcom/salesforce/marketingcloud/media/v$a;->a(Lcom/salesforce/marketingcloud/media/v$b;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 22
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->disconnect()V

    return-void

    :catchall_1
    move-exception p0

    goto :goto_2

    :catch_1
    move-exception p0

    .line 23
    :goto_1
    :try_start_2
    const-string p2, "Image network error for URL: %s"

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-static {v3, p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 24
    invoke-interface {p3, p0}, Lcom/salesforce/marketingcloud/media/v$a;->a(Ljava/lang/Throwable;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    if-eqz v1, :cond_2

    .line 25
    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->disconnect()V

    :cond_2
    return-void

    :goto_2
    if-eqz v1, :cond_3

    .line 26
    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 27
    :cond_3
    throw p0
.end method

.method public a(Lcom/salesforce/marketingcloud/media/t;)Z
    .locals 3

    const/4 p0, 0x0

    .line 1
    :try_start_0
    iget-object p1, p1, Lcom/salesforce/marketingcloud/media/t;->a:Landroid/net/Uri;

    invoke-virtual {p1}, Landroid/net/Uri;->getScheme()Ljava/lang/String;

    move-result-object p1

    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    invoke-virtual {p1, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 2
    const-string v0, "http"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :cond_1

    const-string v0, "https"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    return p0

    :cond_1
    :goto_0
    const/4 p0, 0x1

    return p0

    :catch_0
    move-exception p1

    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/media/r;->b:Ljava/lang/String;

    new-array v1, p0, [Ljava/lang/Object;

    const-string v2, "Unable to get scheme from request."

    invoke-static {v0, p1, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return p0
.end method
