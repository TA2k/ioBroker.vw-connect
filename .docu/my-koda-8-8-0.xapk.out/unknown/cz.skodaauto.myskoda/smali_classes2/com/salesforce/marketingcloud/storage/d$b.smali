.class Lcom/salesforce/marketingcloud/storage/d$b;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/storage/d;->c(Ljava/lang/String;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Ljava/lang/String;

.field final synthetic d:Lcom/salesforce/marketingcloud/storage/d;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/storage/d;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/storage/d$b;->d:Lcom/salesforce/marketingcloud/storage/d;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/storage/d$b;->c:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/d$b;->d:Lcom/salesforce/marketingcloud/storage/d;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/storage/d;->a:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    const/4 v1, 0x0

    .line 7
    :try_start_0
    new-instance v2, Ljava/io/FileOutputStream;

    .line 8
    .line 9
    iget-object v3, p0, Lcom/salesforce/marketingcloud/storage/d$b;->d:Lcom/salesforce/marketingcloud/storage/d;

    .line 10
    .line 11
    iget-object v3, v3, Lcom/salesforce/marketingcloud/storage/d;->b:Ljava/io/File;

    .line 12
    .line 13
    invoke-direct {v2, v3}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 14
    .line 15
    .line 16
    :try_start_1
    iget-object v1, p0, Lcom/salesforce/marketingcloud/storage/d$b;->c:Ljava/lang/String;

    .line 17
    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    sget-object v3, Lcom/salesforce/marketingcloud/util/j;->b:Ljava/nio/charset/Charset;

    .line 21
    .line 22
    invoke-virtual {v1, v3}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v1, 0x0

    .line 28
    new-array v1, v1, [B

    .line 29
    .line 30
    :goto_0
    invoke-virtual {v2, v1}, Ljava/io/FileOutputStream;->write([B)V

    .line 31
    .line 32
    .line 33
    sget-object v1, Lcom/salesforce/marketingcloud/storage/l;->f:Ljava/lang/String;

    .line 34
    .line 35
    const-string v3, "Gdpr mode [%s] written to file."

    .line 36
    .line 37
    iget-object v4, p0, Lcom/salesforce/marketingcloud/storage/d$b;->c:Ljava/lang/String;

    .line 38
    .line 39
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    invoke-static {v1, v3, v4}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 44
    .line 45
    .line 46
    goto :goto_2

    .line 47
    :catchall_0
    move-exception p0

    .line 48
    goto :goto_4

    .line 49
    :catch_0
    move-object v1, v2

    .line 50
    goto :goto_1

    .line 51
    :catchall_1
    move-exception p0

    .line 52
    goto :goto_3

    .line 53
    :catch_1
    :goto_1
    :try_start_2
    sget-object v2, Lcom/salesforce/marketingcloud/storage/l;->f:Ljava/lang/String;

    .line 54
    .line 55
    const-string v3, "Failed to write gdpr mode to file: "

    .line 56
    .line 57
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/d$b;->d:Lcom/salesforce/marketingcloud/storage/d;

    .line 58
    .line 59
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/d;->b:Ljava/io/File;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-static {v2, v3, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 70
    .line 71
    .line 72
    move-object v2, v1

    .line 73
    :goto_2
    :try_start_3
    invoke-static {v2}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V

    .line 74
    .line 75
    .line 76
    monitor-exit v0

    .line 77
    return-void

    .line 78
    :catchall_2
    move-exception p0

    .line 79
    goto :goto_5

    .line 80
    :goto_3
    move-object v2, v1

    .line 81
    :goto_4
    invoke-static {v2}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :goto_5
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 86
    throw p0
.end method
