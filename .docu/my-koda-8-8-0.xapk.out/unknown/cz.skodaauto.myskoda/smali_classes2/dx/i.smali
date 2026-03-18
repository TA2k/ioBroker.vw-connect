.class public final Ldx/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final j:Lcom/google/gson/j;


# instance fields
.field public final a:Ldx/k;

.field public final b:Lbu/c;

.field public final c:Laq/a;

.field public final d:La0/j;

.field public volatile e:Z

.field public f:Lcom/wultra/android/sslpinning/model/CachedData;

.field public g:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

.field public final h:Ljava/util/LinkedHashSet;

.field public final i:Landroid/os/Handler;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/google/gson/k;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/gson/k;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lcom/wultra/android/sslpinning/util/ByteArrayTypeAdapter;

    .line 7
    .line 8
    invoke-direct {v1}, Lcom/wultra/android/sslpinning/util/ByteArrayTypeAdapter;-><init>()V

    .line 9
    .line 10
    .line 11
    const-class v2, [B

    .line 12
    .line 13
    invoke-virtual {v0, v2, v1}, Lcom/google/gson/k;->b(Ljava/lang/Class;Lcom/google/gson/m;)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Lcom/wultra/android/sslpinning/util/DateTypeAdapter;

    .line 17
    .line 18
    invoke-direct {v1}, Lcom/wultra/android/sslpinning/util/DateTypeAdapter;-><init>()V

    .line 19
    .line 20
    .line 21
    const-class v2, Ljava/util/Date;

    .line 22
    .line 23
    invoke-virtual {v0, v2, v1}, Lcom/google/gson/k;->b(Ljava/lang/Class;Lcom/google/gson/m;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Lcom/google/gson/k;->a()Lcom/google/gson/j;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sput-object v0, Ldx/i;->j:Lcom/google/gson/j;

    .line 31
    .line 32
    return-void
.end method

.method public constructor <init>(Ldx/k;Lbu/c;Laq/a;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ldx/i;->a:Ldx/k;

    .line 5
    .line 6
    iput-object p2, p0, Ldx/i;->b:Lbu/c;

    .line 7
    .line 8
    iput-object p3, p0, Ldx/i;->c:Laq/a;

    .line 9
    .line 10
    const/4 p2, 0x0

    .line 11
    new-array p2, p2, [Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 12
    .line 13
    iput-object p2, p0, Ldx/i;->g:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 14
    .line 15
    new-instance p2, Ljava/util/LinkedHashSet;

    .line 16
    .line 17
    invoke-direct {p2}, Ljava/util/LinkedHashSet;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p2, p0, Ldx/i;->h:Ljava/util/LinkedHashSet;

    .line 21
    .line 22
    new-instance p2, Landroid/os/Handler;

    .line 23
    .line 24
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 25
    .line 26
    .line 27
    move-result-object p3

    .line 28
    invoke-direct {p2, p3}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 29
    .line 30
    .line 31
    iput-object p2, p0, Ldx/i;->i:Landroid/os/Handler;

    .line 32
    .line 33
    iget-object p2, p1, Ldx/k;->a:Ljava/net/URL;

    .line 34
    .line 35
    invoke-virtual {p2}, Ljava/net/URL;->getProtocol()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p3

    .line 39
    const-string v0, "http"

    .line 40
    .line 41
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p3

    .line 45
    if-eqz p3, :cond_0

    .line 46
    .line 47
    const-string p3, "CertStoreConfiguration: \'serviceUrl\' should point to \'https\' server."

    .line 48
    .line 49
    const-string v0, "Wultra-SSL-Pinning"

    .line 50
    .line 51
    invoke-static {v0, p3}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 52
    .line 53
    .line 54
    :cond_0
    iget-wide v0, p1, Ldx/k;->d:J

    .line 55
    .line 56
    const-wide/16 v2, 0x0

    .line 57
    .line 58
    cmp-long p3, v0, v2

    .line 59
    .line 60
    if-ltz p3, :cond_2

    .line 61
    .line 62
    iget-wide v0, p1, Ldx/k;->e:J

    .line 63
    .line 64
    cmp-long p1, v0, v2

    .line 65
    .line 66
    if-ltz p1, :cond_1

    .line 67
    .line 68
    new-instance p1, La0/j;

    .line 69
    .line 70
    const/16 p3, 0x1b

    .line 71
    .line 72
    invoke-direct {p1, p2, p3}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 73
    .line 74
    .line 75
    iput-object p1, p0, Ldx/i;->d:La0/j;

    .line 76
    .line 77
    return-void

    .line 78
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 79
    .line 80
    const-string p1, "CertStoreConfiguration: \'expirationUpdateThresholdMillis\' contains negative value."

    .line 81
    .line 82
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    throw p0

    .line 86
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 87
    .line 88
    const-string p1, "CertStoreConfiguration: \'periodicUpdateIntervalMillis\' contains negative value."

    .line 89
    .line 90
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw p0
.end method


# virtual methods
.method public final a(Lay0/n;Ljava/lang/String;)V
    .locals 4

    .line 1
    iget-object v0, p0, Ldx/i;->h:Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ldx/i;->h:Ljava/util/LinkedHashSet;

    .line 5
    .line 6
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    if-nez v2, :cond_0

    .line 21
    .line 22
    iget-object v2, p0, Ldx/i;->i:Landroid/os/Handler;

    .line 23
    .line 24
    new-instance v3, La8/z;

    .line 25
    .line 26
    invoke-direct {v3, p1, p2}, La8/z;-><init>(Lay0/n;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v2, v3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    new-instance p0, Ljava/lang/ClassCastException;

    .line 36
    .line 37
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 38
    .line 39
    .line 40
    throw p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 41
    :cond_1
    monitor-exit v0

    .line 42
    return-void

    .line 43
    :goto_1
    monitor-exit v0

    .line 44
    throw p0
.end method

.method public final b()V
    .locals 5

    .line 1
    iget-boolean v0, p0, Ldx/i;->e:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Ldx/i;->c:Laq/a;

    .line 6
    .line 7
    iget-object v0, v0, Laq/a;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lvv0/b;

    .line 10
    .line 11
    const-string v1, "default"

    .line 12
    .line 13
    invoke-interface {v0, v1}, Lvv0/b;->b(Ljava/lang/String;)[B

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const/4 v1, 0x0

    .line 18
    if-nez v0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    :try_start_0
    sget-object v2, Ldx/i;->j:Lcom/google/gson/j;

    .line 22
    .line 23
    new-instance v3, Ljava/lang/String;

    .line 24
    .line 25
    sget-object v4, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 26
    .line 27
    invoke-direct {v3, v0, v4}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 28
    .line 29
    .line 30
    const-class v0, Lcom/wultra/android/sslpinning/model/CachedData;

    .line 31
    .line 32
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    invoke-static {v0}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/Class;)Lcom/google/gson/reflect/TypeToken;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-virtual {v2, v3, v0}, Lcom/google/gson/j;->b(Ljava/lang/String;Lcom/google/gson/reflect/TypeToken;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    check-cast v0, Lcom/wultra/android/sslpinning/model/CachedData;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    .line 45
    move-object v1, v0

    .line 46
    goto :goto_0

    .line 47
    :catchall_0
    move-exception v0

    .line 48
    new-instance v2, Ljava/lang/StringBuilder;

    .line 49
    .line 50
    const-string v3, "Failed to parse stored fingerprint data: "

    .line 51
    .line 52
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    const-string v2, "message"

    .line 63
    .line 64
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    const-string v2, "Wultra-SSL-Pinning"

    .line 68
    .line 69
    invoke-static {v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 70
    .line 71
    .line 72
    :goto_0
    iput-object v1, p0, Ldx/i;->f:Lcom/wultra/android/sslpinning/model/CachedData;

    .line 73
    .line 74
    const/4 v0, 0x0

    .line 75
    new-array v0, v0, [Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 76
    .line 77
    iput-object v0, p0, Ldx/i;->g:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 78
    .line 79
    const/4 v0, 0x1

    .line 80
    iput-boolean v0, p0, Ldx/i;->e:Z

    .line 81
    .line 82
    :cond_1
    return-void
.end method

.method public final c(Lcom/wultra/android/sslpinning/model/CachedData;)V
    .locals 5

    .line 1
    sget-object v0, Ldx/i;->j:Lcom/google/gson/j;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const-class v1, Lcom/wultra/android/sslpinning/model/CachedData;

    .line 7
    .line 8
    new-instance v2, Ljava/io/StringWriter;

    .line 9
    .line 10
    invoke-direct {v2}, Ljava/io/StringWriter;-><init>()V

    .line 11
    .line 12
    .line 13
    :try_start_0
    new-instance v3, Lpu/b;

    .line 14
    .line 15
    invoke-direct {v3, v2}, Lpu/b;-><init>(Ljava/io/Writer;)V

    .line 16
    .line 17
    .line 18
    iget-object v4, v0, Lcom/google/gson/j;->g:Lcom/google/gson/i;

    .line 19
    .line 20
    invoke-virtual {v3, v4}, Lpu/b;->B(Lcom/google/gson/i;)V

    .line 21
    .line 22
    .line 23
    iget-boolean v4, v0, Lcom/google/gson/j;->f:Z

    .line 24
    .line 25
    iput-boolean v4, v3, Lpu/b;->l:Z

    .line 26
    .line 27
    const/4 v4, 0x2

    .line 28
    invoke-virtual {v3, v4}, Lpu/b;->E(I)V

    .line 29
    .line 30
    .line 31
    const/4 v4, 0x0

    .line 32
    iput-boolean v4, v3, Lpu/b;->n:Z

    .line 33
    .line 34
    invoke-virtual {v0, p1, v1, v3}, Lcom/google/gson/j;->e(Lcom/wultra/android/sslpinning/model/CachedData;Ljava/lang/Class;Lpu/b;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 35
    .line 36
    .line 37
    invoke-virtual {v2}, Ljava/io/StringWriter;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    const-string v0, "GSON.toJson(data)"

    .line 42
    .line 43
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    sget-object v0, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 47
    .line 48
    invoke-virtual {p1, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    const-string v0, "this as java.lang.String).getBytes(charset)"

    .line 53
    .line 54
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object p0, p0, Ldx/i;->c:Laq/a;

    .line 58
    .line 59
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p0, Lvv0/b;

    .line 62
    .line 63
    const-string v0, "default"

    .line 64
    .line 65
    invoke-interface {p0, v0, p1}, Lvv0/b;->a(Ljava/lang/String;[B)V

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :catch_0
    move-exception p0

    .line 70
    new-instance p1, Lcom/google/gson/o;

    .line 71
    .line 72
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 73
    .line 74
    .line 75
    throw p1
.end method
