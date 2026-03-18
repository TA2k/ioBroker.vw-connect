.class public Lcom/salesforce/marketingcloud/media/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final d:I = 0x1400000


# instance fields
.field private final a:Ljava/io/File;

.field private final b:Ljava/lang/Object;

.field private c:Lcom/salesforce/marketingcloud/util/d;


# direct methods
.method public constructor <init>(Ljava/io/File;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/salesforce/marketingcloud/media/s;->b:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/s;->a:Ljava/io/File;

    .line 12
    .line 13
    return-void
.end method

.method private b()V
    .locals 6

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/s;->b:Ljava/lang/Object;

    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/s;->c:Lcom/salesforce/marketingcloud/util/d;

    if-nez v1, :cond_0

    .line 5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/s;->a:Ljava/io/File;

    const/4 v2, 0x1

    const-wide/32 v3, 0x1400000

    const/4 v5, 0x0

    invoke-static {v1, v5, v2, v3, v4}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/io/File;IIJ)Lcom/salesforce/marketingcloud/util/d;

    move-result-object v1

    iput-object v1, p0, Lcom/salesforce/marketingcloud/media/s;->c:Lcom/salesforce/marketingcloud/util/d;

    .line 6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/s;->b:Ljava/lang/Object;

    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 7
    :cond_0
    :goto_0
    monitor-exit v0

    return-void

    .line 8
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method private static c(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/util/j;->e(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public a(Ljava/lang/String;)Ljava/io/InputStream;
    .locals 1

    .line 12
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/media/s;->b()V

    .line 13
    invoke-static {p1}, Lcom/salesforce/marketingcloud/media/s;->c(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 14
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/s;->b:Ljava/lang/Object;

    monitor-enter v0

    .line 15
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/s;->c:Lcom/salesforce/marketingcloud/util/d;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/util/d;->b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/util/d$e;

    move-result-object p0

    if-eqz p0, :cond_0

    const/4 p1, 0x0

    .line 16
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/util/d$e;->a(I)Ljava/io/InputStream;

    move-result-object p0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_0
    const/4 p0, 0x0

    .line 17
    :goto_0
    monitor-exit v0

    return-object p0

    .line 18
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public a()V
    .locals 0

    .line 19
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/media/s;->b()V

    .line 20
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/s;->c:Lcom/salesforce/marketingcloud/util/d;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/util/d;->c()V

    return-void
.end method

.method public a(Ljava/lang/String;Ljava/io/InputStream;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/media/s;->b()V

    .line 2
    invoke-static {p1}, Lcom/salesforce/marketingcloud/media/s;->c(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/s;->b:Ljava/lang/Object;

    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/s;->c:Lcom/salesforce/marketingcloud/util/d;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/util/d$c;

    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 p1, 0x0

    .line 5
    :try_start_1
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/util/d$c;->c(I)Ljava/io/OutputStream;

    move-result-object p1

    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/InputStream;Ljava/io/OutputStream;)V

    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/util/d$c;->c()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 7
    :try_start_2
    invoke-static {p2}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V

    .line 8
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    goto :goto_0

    :catchall_1
    move-exception p0

    .line 9
    invoke-static {p2}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V

    .line 10
    throw p0

    .line 11
    :goto_0
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p0
.end method

.method public b(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/media/s;->b()V

    .line 2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/s;->c:Lcom/salesforce/marketingcloud/util/d;

    invoke-static {p1}, Lcom/salesforce/marketingcloud/media/s;->c(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/util/d;->d(Ljava/lang/String;)Z

    return-void
.end method
