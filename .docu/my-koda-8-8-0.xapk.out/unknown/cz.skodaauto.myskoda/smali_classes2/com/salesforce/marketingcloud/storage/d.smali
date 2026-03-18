.class public Lcom/salesforce/marketingcloud/storage/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field final a:Ljava/lang/Object;

.field final b:Ljava/io/File;

.field private final c:Ljava/lang/Object;

.field private final d:Landroid/content/Context;

.field private final e:Landroid/content/SharedPreferences;

.field private final f:Ljava/lang/String;

.field private final g:Lcom/salesforce/marketingcloud/internal/n;

.field private h:Ljava/lang/String;

.field private i:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/content/SharedPreferences;Ljava/lang/String;Lcom/salesforce/marketingcloud/internal/n;)V
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
    iput-object v0, p0, Lcom/salesforce/marketingcloud/storage/d;->a:Ljava/lang/Object;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lcom/salesforce/marketingcloud/storage/d;->c:Ljava/lang/Object;

    .line 17
    .line 18
    iput-object p1, p0, Lcom/salesforce/marketingcloud/storage/d;->d:Landroid/content/Context;

    .line 19
    .line 20
    iput-object p2, p0, Lcom/salesforce/marketingcloud/storage/d;->e:Landroid/content/SharedPreferences;

    .line 21
    .line 22
    iput-object p4, p0, Lcom/salesforce/marketingcloud/storage/d;->g:Lcom/salesforce/marketingcloud/internal/n;

    .line 23
    .line 24
    const/4 p2, 0x0

    .line 25
    iput-boolean p2, p0, Lcom/salesforce/marketingcloud/storage/d;->i:Z

    .line 26
    .line 27
    const-string p2, "_SFMC_PrivacyMode"

    .line 28
    .line 29
    invoke-static {p3, p2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    iput-object p2, p0, Lcom/salesforce/marketingcloud/storage/d;->f:Ljava/lang/String;

    .line 34
    .line 35
    new-instance p3, Ljava/io/File;

    .line 36
    .line 37
    invoke-virtual {p1}, Landroid/content/Context;->getNoBackupFilesDir()Ljava/io/File;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-direct {p3, p1, p2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    iput-object p3, p0, Lcom/salesforce/marketingcloud/storage/d;->b:Ljava/io/File;

    .line 45
    .line 46
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/storage/d;->c()V

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method private static a(Ljava/io/File;)Ljava/lang/String;
    .locals 5

    const/4 v0, 0x0

    .line 1
    :try_start_0
    new-instance v1, Ljava/io/FileInputStream;

    invoke-direct {v1, p0}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 2
    :try_start_1
    new-instance v2, Ljava/io/BufferedReader;

    new-instance v3, Ljava/io/InputStreamReader;

    sget-object v4, Lcom/salesforce/marketingcloud/util/j;->b:Ljava/nio/charset/Charset;

    invoke-direct {v3, v1, v4}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/nio/charset/Charset;)V

    invoke-direct {v2, v3}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    .line 3
    invoke-virtual {v2}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_2

    :catchall_1
    move-exception p0

    goto :goto_1

    :catch_0
    move-object v1, v0

    .line 4
    :catch_1
    :try_start_2
    sget-object v2, Lcom/salesforce/marketingcloud/storage/l;->f:Ljava/lang/String;

    const-string v3, "Failed to read gdpr mode from file: "

    invoke-virtual {p0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object p0

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    invoke-static {v2, v3, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 5
    :goto_0
    invoke-static {v1}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V

    return-object v0

    :catchall_2
    move-exception p0

    move-object v0, v1

    :goto_1
    move-object v1, v0

    .line 6
    :goto_2
    invoke-static {v1}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V

    .line 7
    throw p0
.end method

.method private a()V
    .locals 1

    .line 12
    :catch_0
    :goto_0
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/storage/d;->i:Z

    if-nez v0, :cond_0

    .line 13
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/d;->c:Ljava/lang/Object;

    invoke-virtual {v0}, Ljava/lang/Object;->wait()V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :cond_0
    return-void
.end method

.method private c()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/d;->c:Ljava/lang/Object;

    monitor-enter v0

    const/4 v1, 0x0

    .line 2
    :try_start_0
    iput-boolean v1, p0, Lcom/salesforce/marketingcloud/storage/d;->i:Z

    .line 3
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 4
    new-instance v0, Lcom/salesforce/marketingcloud/storage/d$a;

    const-string v1, "gdpr_file_load"

    invoke-direct {v0, p0, v1}, Lcom/salesforce/marketingcloud/storage/d$a;-><init>(Lcom/salesforce/marketingcloud/storage/d;Ljava/lang/String;)V

    .line 5
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    return-void

    :catchall_0
    move-exception p0

    .line 6
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p0
.end method


# virtual methods
.method public a(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/d;->c:Ljava/lang/Object;

    monitor-enter v0

    .line 9
    :try_start_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/storage/d;->a()V

    .line 10
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/d;->h:Ljava/lang/String;

    if-eqz p0, :cond_0

    move-object p1, p0

    :cond_0
    monitor-exit v0

    return-object p1

    :catchall_0
    move-exception p0

    .line 11
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public b()V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/d;->c:Ljava/lang/Object;

    monitor-enter v0

    .line 2
    :try_start_0
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/storage/d;->i:Z

    if-eqz v1, :cond_0

    .line 3
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    goto/16 :goto_2

    .line 4
    :cond_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/d;->b:Ljava/io/File;

    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/d;->b:Ljava/io/File;

    invoke-static {v0}, Lcom/salesforce/marketingcloud/storage/d;->a(Ljava/io/File;)Ljava/lang/String;

    move-result-object v0

    .line 7
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v2

    if-eqz v2, :cond_1

    goto :goto_1

    :cond_1
    move-object v1, v0

    goto :goto_1

    .line 8
    :cond_2
    sget-object v0, Lcom/salesforce/marketingcloud/storage/l;->f:Ljava/lang/String;

    const/4 v2, 0x0

    new-array v3, v2, [Ljava/lang/Object;

    const-string v4, "Checking SharedPreferences for gdpr mode"

    invoke-static {v0, v4, v3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    iget-object v3, p0, Lcom/salesforce/marketingcloud/storage/d;->e:Landroid/content/SharedPreferences;

    const-string v4, "cc_state"

    invoke-interface {v3, v4, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_3

    .line 10
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/d;->e:Landroid/content/SharedPreferences;

    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    const-string v2, "cc_state"

    invoke-interface {v0, v2}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    goto :goto_0

    .line 11
    :cond_3
    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "Checking pre-lollipop location for gdpr mode"

    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 12
    new-instance v0, Ljava/io/File;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/storage/d;->d:Landroid/content/Context;

    invoke-virtual {v2}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    move-result-object v2

    iget-object v3, p0, Lcom/salesforce/marketingcloud/storage/d;->f:Ljava/lang/String;

    invoke-direct {v0, v2, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 13
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    move-result v2

    if-eqz v2, :cond_4

    .line 14
    invoke-static {v0}, Lcom/salesforce/marketingcloud/storage/d;->a(Ljava/io/File;)Ljava/lang/String;

    move-result-object v1

    .line 15
    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/e;->b(Ljava/io/File;)V

    .line 16
    :cond_4
    :goto_0
    invoke-virtual {p0, v1}, Lcom/salesforce/marketingcloud/storage/d;->c(Ljava/lang/String;)V

    .line 17
    :goto_1
    iget-object v2, p0, Lcom/salesforce/marketingcloud/storage/d;->c:Ljava/lang/Object;

    monitor-enter v2

    .line 18
    :try_start_1
    iput-object v1, p0, Lcom/salesforce/marketingcloud/storage/d;->h:Ljava/lang/String;

    const/4 v0, 0x1

    .line 19
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/storage/d;->i:Z

    .line 20
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/d;->c:Ljava/lang/Object;

    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 21
    monitor-exit v2

    return-void

    :catchall_1
    move-exception p0

    .line 22
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    throw p0

    .line 23
    :goto_2
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p0
.end method

.method public b(Ljava/lang/String;)V
    .locals 4

    .line 24
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/d;->c:Ljava/lang/Object;

    monitor-enter v0

    .line 25
    :try_start_0
    sget-object v1, Lcom/salesforce/marketingcloud/storage/l;->f:Ljava/lang/String;

    const-string v2, "Updating gdpr mode: %s"

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v1, v2, v3}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    iput-object p1, p0, Lcom/salesforce/marketingcloud/storage/d;->h:Ljava/lang/String;

    .line 27
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/storage/d;->c(Ljava/lang/String;)V

    .line 28
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    .line 29
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public c(Ljava/lang/String;)V
    .locals 4

    .line 7
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/d;->g:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/storage/d$b;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "storing_gdpr"

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/storage/d$b;-><init>(Lcom/salesforce/marketingcloud/storage/d;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method
