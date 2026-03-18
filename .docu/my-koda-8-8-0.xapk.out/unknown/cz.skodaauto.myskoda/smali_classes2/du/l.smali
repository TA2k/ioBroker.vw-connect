.class public final Ldu/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final s:[I

.field public static final t:Ljava/util/regex/Pattern;


# instance fields
.field public final a:Ljava/util/LinkedHashSet;

.field public b:Z

.field public c:I

.field public d:Z

.field public e:Z

.field public f:Ljava/net/HttpURLConnection;

.field public g:Lc8/f;

.field public final h:Ljava/util/concurrent/ScheduledExecutorService;

.field public final i:Ldu/i;

.field public final j:Lsr/f;

.field public final k:Lht/d;

.field public final l:Ldu/c;

.field public final m:Landroid/content/Context;

.field public final n:Ljava/lang/String;

.field public final o:Ljava/util/Random;

.field public final p:Lto/a;

.field public final q:Ldu/n;

.field public final r:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    new-array v0, v0, [I

    .line 4
    .line 5
    fill-array-data v0, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v0, Ldu/l;->s:[I

    .line 9
    .line 10
    const-string v0, "^[^:]+:([0-9]+):(android|ios|web):([0-9a-f]+)"

    .line 11
    .line 12
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    sput-object v0, Ldu/l;->t:Ljava/util/regex/Pattern;

    .line 17
    .line 18
    return-void

    .line 19
    :array_0
    .array-data 4
        0x2
        0x4
        0x8
        0x10
        0x20
        0x40
        0x80
        0x100
    .end array-data
.end method

.method public constructor <init>(Lsr/f;Lht/d;Ldu/i;Ldu/c;Landroid/content/Context;Ljava/lang/String;Ljava/util/LinkedHashSet;Ldu/n;Ljava/util/concurrent/ScheduledExecutorService;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p7, p0, Ldu/l;->a:Ljava/util/LinkedHashSet;

    .line 5
    .line 6
    const/4 p7, 0x0

    .line 7
    iput-boolean p7, p0, Ldu/l;->b:Z

    .line 8
    .line 9
    iput-object p9, p0, Ldu/l;->h:Ljava/util/concurrent/ScheduledExecutorService;

    .line 10
    .line 11
    new-instance p9, Ljava/util/Random;

    .line 12
    .line 13
    invoke-direct {p9}, Ljava/util/Random;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p9, p0, Ldu/l;->o:Ljava/util/Random;

    .line 17
    .line 18
    invoke-virtual {p8}, Ldu/n;->c()Ldu/m;

    .line 19
    .line 20
    .line 21
    move-result-object p9

    .line 22
    iget p9, p9, Ldu/m;->a:I

    .line 23
    .line 24
    rsub-int/lit8 p9, p9, 0x8

    .line 25
    .line 26
    const/4 v0, 0x1

    .line 27
    invoke-static {p9, v0}, Ljava/lang/Math;->max(II)I

    .line 28
    .line 29
    .line 30
    move-result p9

    .line 31
    iput p9, p0, Ldu/l;->c:I

    .line 32
    .line 33
    sget-object p9, Lto/a;->a:Lto/a;

    .line 34
    .line 35
    iput-object p9, p0, Ldu/l;->p:Lto/a;

    .line 36
    .line 37
    iput-object p1, p0, Ldu/l;->j:Lsr/f;

    .line 38
    .line 39
    iput-object p3, p0, Ldu/l;->i:Ldu/i;

    .line 40
    .line 41
    iput-object p2, p0, Ldu/l;->k:Lht/d;

    .line 42
    .line 43
    iput-object p4, p0, Ldu/l;->l:Ldu/c;

    .line 44
    .line 45
    iput-object p5, p0, Ldu/l;->m:Landroid/content/Context;

    .line 46
    .line 47
    iput-object p6, p0, Ldu/l;->n:Ljava/lang/String;

    .line 48
    .line 49
    iput-object p8, p0, Ldu/l;->q:Ldu/n;

    .line 50
    .line 51
    iput-boolean p7, p0, Ldu/l;->d:Z

    .line 52
    .line 53
    iput-boolean p7, p0, Ldu/l;->e:Z

    .line 54
    .line 55
    new-instance p1, Ljava/lang/Object;

    .line 56
    .line 57
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 58
    .line 59
    .line 60
    iput-object p1, p0, Ldu/l;->r:Ljava/lang/Object;

    .line 61
    .line 62
    return-void
.end method

.method public static d(I)Z
    .locals 1

    .line 1
    const/16 v0, 0x198

    .line 2
    .line 3
    if-eq p0, v0, :cond_1

    .line 4
    .line 5
    const/16 v0, 0x1ad

    .line 6
    .line 7
    if-eq p0, v0, :cond_1

    .line 8
    .line 9
    const/16 v0, 0x1f6

    .line 10
    .line 11
    if-eq p0, v0, :cond_1

    .line 12
    .line 13
    const/16 v0, 0x1f7

    .line 14
    .line 15
    if-eq p0, v0, :cond_1

    .line 16
    .line 17
    const/16 v0, 0x1f8

    .line 18
    .line 19
    if-ne p0, v0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return p0

    .line 24
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 25
    return p0
.end method

.method public static f(Ljava/io/InputStream;)Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance v1, Ljava/io/BufferedReader;

    .line 7
    .line 8
    new-instance v2, Ljava/io/InputStreamReader;

    .line 9
    .line 10
    invoke-direct {v2, p0}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {v1, v2}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    .line 14
    .line 15
    .line 16
    :goto_0
    invoke-virtual {v1}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catch_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-nez p0, :cond_0

    .line 31
    .line 32
    const-string p0, "Unable to connect to the server, access is forbidden. HTTP status code: 403"

    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method


# virtual methods
.method public final declared-synchronized a()Z
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Ldu/l;->a:Ljava/util/LinkedHashSet;

    .line 3
    .line 4
    invoke-interface {v0}, Ljava/util/Set;->isEmpty()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    iget-boolean v0, p0, Ldu/l;->b:Z

    .line 11
    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    iget-boolean v0, p0, Ldu/l;->d:Z

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    iget-boolean v0, p0, Ldu/l;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    const/4 v0, 0x1

    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception v0

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    const/4 v0, 0x0

    .line 27
    :goto_0
    monitor-exit p0

    .line 28
    return v0

    .line 29
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 30
    throw v0
.end method

.method public final b(Ljava/io/InputStream;Ljava/io/InputStream;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ldu/l;->f:Ljava/net/HttpURLConnection;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean p0, p0, Ldu/l;->e:Z

    .line 6
    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 10
    .line 11
    .line 12
    :cond_0
    const-string p0, "Error closing connection stream."

    .line 13
    .line 14
    const-string v0, "FirebaseRemoteConfig"

    .line 15
    .line 16
    if-eqz p1, :cond_1

    .line 17
    .line 18
    :try_start_0
    invoke-virtual {p1}, Ljava/io/InputStream;->close()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catch_0
    move-exception p1

    .line 23
    invoke-static {v0, p0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 24
    .line 25
    .line 26
    :cond_1
    :goto_0
    if-eqz p2, :cond_2

    .line 27
    .line 28
    :try_start_1
    invoke-virtual {p2}, Ljava/io/InputStream;->close()V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 29
    .line 30
    .line 31
    goto :goto_1

    .line 32
    :catch_1
    move-exception p1

    .line 33
    invoke-static {v0, p0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 34
    .line 35
    .line 36
    :cond_2
    :goto_1
    return-void
.end method

.method public final c(Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 1
    iget-object p0, p0, Ldu/l;->j:Lsr/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lsr/f;->a()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lsr/f;->c:Lsr/i;

    .line 7
    .line 8
    iget-object p0, p0, Lsr/i;->b:Ljava/lang/String;

    .line 9
    .line 10
    sget-object v0, Ldu/l;->t:Ljava/util/regex/Pattern;

    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-virtual {p0}, Ljava/util/regex/Matcher;->matches()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    const/4 v0, 0x1

    .line 23
    invoke-virtual {p0, v0}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p0, 0x0

    .line 29
    :goto_0
    const-string v0, "/namespaces/"

    .line 30
    .line 31
    const-string v1, ":streamFetchInvalidations"

    .line 32
    .line 33
    const-string v2, "https://firebaseremoteconfigrealtime.googleapis.com/v1/projects/"

    .line 34
    .line 35
    invoke-static {v2, p0, v0, p1, v1}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method public final declared-synchronized e(J)V
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-virtual {p0}, Ldu/l;->a()Z

    .line 3
    .line 4
    .line 5
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    monitor-exit p0

    .line 9
    return-void

    .line 10
    :cond_0
    :try_start_1
    iget v0, p0, Ldu/l;->c:I

    .line 11
    .line 12
    if-lez v0, :cond_1

    .line 13
    .line 14
    add-int/lit8 v0, v0, -0x1

    .line 15
    .line 16
    iput v0, p0, Ldu/l;->c:I

    .line 17
    .line 18
    iget-object v0, p0, Ldu/l;->h:Ljava/util/concurrent/ScheduledExecutorService;

    .line 19
    .line 20
    new-instance v1, Laq/p;

    .line 21
    .line 22
    const/4 v2, 0x1

    .line 23
    invoke-direct {v1, p0, v2}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    sget-object v2, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 27
    .line 28
    invoke-interface {v0, v1, p1, p2, v2}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :catchall_0
    move-exception p1

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    iget-boolean p1, p0, Ldu/l;->e:Z

    .line 35
    .line 36
    if-nez p1, :cond_2

    .line 37
    .line 38
    new-instance p1, Lcu/c;

    .line 39
    .line 40
    const-string p2, "Unable to connect to the server. Check your connection and try again."

    .line 41
    .line 42
    invoke-direct {p1, p2}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0}, Ldu/l;->g()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 46
    .line 47
    .line 48
    :cond_2
    :goto_0
    monitor-exit p0

    .line 49
    return-void

    .line 50
    :goto_1
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 51
    throw p1
.end method

.method public final declared-synchronized g()V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Ldu/l;->a:Ljava/util/LinkedHashSet;

    .line 3
    .line 4
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    check-cast v1, Ldu/k;

    .line 19
    .line 20
    invoke-virtual {v1}, Ldu/k;->a()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception v0

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    monitor-exit p0

    .line 27
    return-void

    .line 28
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 29
    throw v0
.end method

.method public final declared-synchronized h()V
    .locals 5

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    new-instance v0, Ljava/util/Date;

    .line 3
    .line 4
    iget-object v1, p0, Ldu/l;->p:Lto/a;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 10
    .line 11
    .line 12
    move-result-wide v1

    .line 13
    invoke-direct {v0, v1, v2}, Ljava/util/Date;-><init>(J)V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Ldu/l;->q:Ldu/n;

    .line 17
    .line 18
    invoke-virtual {v1}, Ldu/n;->c()Ldu/m;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    iget-object v1, v1, Ldu/m;->b:Ljava/util/Date;

    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    .line 25
    .line 26
    .line 27
    move-result-wide v1

    .line 28
    invoke-virtual {v0}, Ljava/util/Date;->getTime()J

    .line 29
    .line 30
    .line 31
    move-result-wide v3

    .line 32
    sub-long/2addr v1, v3

    .line 33
    const-wide/16 v3, 0x0

    .line 34
    .line 35
    invoke-static {v3, v4, v1, v2}, Ljava/lang/Math;->max(JJ)J

    .line 36
    .line 37
    .line 38
    move-result-wide v0

    .line 39
    invoke-virtual {p0, v0, v1}, Ldu/l;->e(J)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    .line 41
    .line 42
    monitor-exit p0

    .line 43
    return-void

    .line 44
    :catchall_0
    move-exception v0

    .line 45
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 46
    throw v0
.end method

.method public final i(Ljava/net/HttpURLConnection;Ljava/lang/String;Ljava/lang/String;)V
    .locals 6

    .line 1
    const-string v0, "POST"

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "X-Goog-Firebase-Installations-Auth"

    .line 7
    .line 8
    invoke-virtual {p1, v0, p3}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p3, p0, Ldu/l;->j:Lsr/f;

    .line 12
    .line 13
    invoke-virtual {p3}, Lsr/f;->a()V

    .line 14
    .line 15
    .line 16
    iget-object v0, p3, Lsr/f;->c:Lsr/i;

    .line 17
    .line 18
    iget-object v1, v0, Lsr/i;->a:Ljava/lang/String;

    .line 19
    .line 20
    const-string v2, "X-Goog-Api-Key"

    .line 21
    .line 22
    invoke-virtual {p1, v2, v1}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Ldu/l;->m:Landroid/content/Context;

    .line 26
    .line 27
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    const-string v3, "X-Android-Package"

    .line 32
    .line 33
    invoke-virtual {p1, v3, v2}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string v2, "FirebaseRemoteConfig"

    .line 37
    .line 38
    const-string v3, "Could not get fingerprint hash for package: "

    .line 39
    .line 40
    const/4 v4, 0x0

    .line 41
    :try_start_0
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v5

    .line 45
    invoke-static {v1, v5}, Lto/b;->c(Landroid/content/Context;Ljava/lang/String;)[B

    .line 46
    .line 47
    .line 48
    move-result-object v5

    .line 49
    if-nez v5, :cond_0

    .line 50
    .line 51
    new-instance v5, Ljava/lang/StringBuilder;

    .line 52
    .line 53
    invoke-direct {v5, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    invoke-static {v2, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 68
    .line 69
    .line 70
    :goto_0
    move-object v1, v4

    .line 71
    goto :goto_1

    .line 72
    :cond_0
    invoke-static {v5}, Lto/b;->a([B)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v1
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 76
    goto :goto_1

    .line 77
    :catch_0
    new-instance v3, Ljava/lang/StringBuilder;

    .line 78
    .line 79
    const-string v5, "No such package: "

    .line 80
    .line 81
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    invoke-static {v2, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 96
    .line 97
    .line 98
    goto :goto_0

    .line 99
    :goto_1
    const-string v2, "X-Android-Cert"

    .line 100
    .line 101
    invoke-virtual {p1, v2, v1}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    const-string v1, "X-Google-GFE-Can-Retry"

    .line 105
    .line 106
    const-string v2, "yes"

    .line 107
    .line 108
    invoke-virtual {p1, v1, v2}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    const-string v1, "X-Accept-Response-Streaming"

    .line 112
    .line 113
    const-string v2, "true"

    .line 114
    .line 115
    invoke-virtual {p1, v1, v2}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    const-string v1, "Content-Type"

    .line 119
    .line 120
    const-string v2, "application/json"

    .line 121
    .line 122
    invoke-virtual {p1, v1, v2}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    const-string v1, "Accept"

    .line 126
    .line 127
    invoke-virtual {p1, v1, v2}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    new-instance v1, Ljava/util/HashMap;

    .line 131
    .line 132
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 133
    .line 134
    .line 135
    invoke-virtual {p3}, Lsr/f;->a()V

    .line 136
    .line 137
    .line 138
    iget-object v2, v0, Lsr/i;->b:Ljava/lang/String;

    .line 139
    .line 140
    sget-object v3, Ldu/l;->t:Ljava/util/regex/Pattern;

    .line 141
    .line 142
    invoke-virtual {v3, v2}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 143
    .line 144
    .line 145
    move-result-object v2

    .line 146
    invoke-virtual {v2}, Ljava/util/regex/Matcher;->matches()Z

    .line 147
    .line 148
    .line 149
    move-result v3

    .line 150
    if-eqz v3, :cond_1

    .line 151
    .line 152
    const/4 v3, 0x1

    .line 153
    invoke-virtual {v2, v3}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v4

    .line 157
    :cond_1
    const-string v2, "project"

    .line 158
    .line 159
    invoke-virtual {v1, v2, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    const-string v2, "namespace"

    .line 163
    .line 164
    iget-object v3, p0, Ldu/l;->n:Ljava/lang/String;

    .line 165
    .line 166
    invoke-virtual {v1, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    iget-object p0, p0, Ldu/l;->i:Ldu/i;

    .line 170
    .line 171
    iget-object p0, p0, Ldu/i;->g:Ldu/n;

    .line 172
    .line 173
    iget-object p0, p0, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 174
    .line 175
    const-string v2, "last_template_version"

    .line 176
    .line 177
    const-wide/16 v3, 0x0

    .line 178
    .line 179
    invoke-interface {p0, v2, v3, v4}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 180
    .line 181
    .line 182
    move-result-wide v2

    .line 183
    invoke-static {v2, v3}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    const-string v2, "lastKnownVersionNumber"

    .line 188
    .line 189
    invoke-virtual {v1, v2, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    invoke-virtual {p3}, Lsr/f;->a()V

    .line 193
    .line 194
    .line 195
    iget-object p0, v0, Lsr/i;->b:Ljava/lang/String;

    .line 196
    .line 197
    const-string p3, "appId"

    .line 198
    .line 199
    invoke-virtual {v1, p3, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    const-string p0, "sdkVersion"

    .line 203
    .line 204
    const-string p3, "23.0.1"

    .line 205
    .line 206
    invoke-virtual {v1, p0, p3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    const-string p0, "appInstanceId"

    .line 210
    .line 211
    invoke-virtual {v1, p0, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    new-instance p0, Lorg/json/JSONObject;

    .line 215
    .line 216
    invoke-direct {p0, v1}, Lorg/json/JSONObject;-><init>(Ljava/util/Map;)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {p0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object p0

    .line 223
    const-string p2, "utf-8"

    .line 224
    .line 225
    invoke-virtual {p0, p2}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    .line 226
    .line 227
    .line 228
    move-result-object p0

    .line 229
    new-instance p2, Ljava/io/BufferedOutputStream;

    .line 230
    .line 231
    invoke-virtual {p1}, Ljava/net/URLConnection;->getOutputStream()Ljava/io/OutputStream;

    .line 232
    .line 233
    .line 234
    move-result-object p1

    .line 235
    invoke-direct {p2, p1}, Ljava/io/BufferedOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 236
    .line 237
    .line 238
    invoke-virtual {p2, p0}, Ljava/io/OutputStream;->write([B)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {p2}, Ljava/io/OutputStream;->flush()V

    .line 242
    .line 243
    .line 244
    invoke-virtual {p2}, Ljava/io/OutputStream;->close()V

    .line 245
    .line 246
    .line 247
    return-void
.end method

.method public final declared-synchronized j(Ljava/net/HttpURLConnection;)Lc8/f;
    .locals 8

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    new-instance v5, Ldu/k;

    .line 3
    .line 4
    invoke-direct {v5, p0}, Ldu/k;-><init>(Ldu/l;)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lc8/f;

    .line 8
    .line 9
    iget-object v2, p0, Ldu/l;->i:Ldu/i;

    .line 10
    .line 11
    iget-object v3, p0, Ldu/l;->l:Ldu/c;

    .line 12
    .line 13
    iget-object v4, p0, Ldu/l;->a:Ljava/util/LinkedHashSet;

    .line 14
    .line 15
    iget-object v6, p0, Ldu/l;->h:Ljava/util/concurrent/ScheduledExecutorService;

    .line 16
    .line 17
    iget-object v7, p0, Ldu/l;->q:Ldu/n;

    .line 18
    .line 19
    move-object v1, p1

    .line 20
    invoke-direct/range {v0 .. v7}, Lc8/f;-><init>(Ljava/net/HttpURLConnection;Ldu/i;Ldu/c;Ljava/util/LinkedHashSet;Ldu/k;Ljava/util/concurrent/ScheduledExecutorService;Ldu/n;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    .line 23
    monitor-exit p0

    .line 24
    return-object v0

    .line 25
    :catchall_0
    move-exception v0

    .line 26
    move-object p1, v0

    .line 27
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 28
    throw p1
.end method

.method public final k(Ljava/util/Date;)V
    .locals 6

    .line 1
    iget-object v0, p0, Ldu/l;->q:Ldu/n;

    .line 2
    .line 3
    invoke-virtual {v0}, Ldu/n;->c()Ldu/m;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    iget v1, v1, Ldu/m;->a:I

    .line 8
    .line 9
    add-int/lit8 v1, v1, 0x1

    .line 10
    .line 11
    const/16 v2, 0x8

    .line 12
    .line 13
    if-ge v1, v2, :cond_0

    .line 14
    .line 15
    move v2, v1

    .line 16
    :cond_0
    sget-object v3, Ljava/util/concurrent/TimeUnit;->MINUTES:Ljava/util/concurrent/TimeUnit;

    .line 17
    .line 18
    add-int/lit8 v2, v2, -0x1

    .line 19
    .line 20
    sget-object v4, Ldu/l;->s:[I

    .line 21
    .line 22
    aget v2, v4, v2

    .line 23
    .line 24
    int-to-long v4, v2

    .line 25
    invoke-virtual {v3, v4, v5}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 26
    .line 27
    .line 28
    move-result-wide v2

    .line 29
    const-wide/16 v4, 0x2

    .line 30
    .line 31
    div-long v4, v2, v4

    .line 32
    .line 33
    iget-object p0, p0, Ldu/l;->o:Ljava/util/Random;

    .line 34
    .line 35
    long-to-int v2, v2

    .line 36
    invoke-virtual {p0, v2}, Ljava/util/Random;->nextInt(I)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    int-to-long v2, p0

    .line 41
    add-long/2addr v4, v2

    .line 42
    new-instance p0, Ljava/util/Date;

    .line 43
    .line 44
    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    .line 45
    .line 46
    .line 47
    move-result-wide v2

    .line 48
    add-long/2addr v2, v4

    .line 49
    invoke-direct {p0, v2, v3}, Ljava/util/Date;-><init>(J)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0, v1, p0}, Ldu/n;->e(ILjava/util/Date;)V

    .line 53
    .line 54
    .line 55
    return-void
.end method
