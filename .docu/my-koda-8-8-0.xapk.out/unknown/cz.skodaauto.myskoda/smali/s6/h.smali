.class public final Ls6/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final j:Ljava/lang/Object;

.field public static volatile k:Ls6/h;


# instance fields
.field public final a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

.field public final b:Landroidx/collection/g;

.field public volatile c:I

.field public final d:Landroid/os/Handler;

.field public final e:Lis/b;

.field public final f:Ls6/g;

.field public final g:Lrb0/a;

.field public final h:I

.field public final i:Ls6/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ls6/h;->j:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Ls6/p;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 10
    .line 11
    const/4 v1, 0x3

    .line 12
    iput v1, p0, Ls6/h;->c:I

    .line 13
    .line 14
    iget-object v1, p1, Lka/u;->b:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Ls6/g;

    .line 17
    .line 18
    iput-object v1, p0, Ls6/h;->f:Ls6/g;

    .line 19
    .line 20
    iget v2, p1, Lka/u;->a:I

    .line 21
    .line 22
    iput v2, p0, Ls6/h;->h:I

    .line 23
    .line 24
    iget-object p1, p1, Lka/u;->c:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p1, Ls6/c;

    .line 27
    .line 28
    iput-object p1, p0, Ls6/h;->i:Ls6/c;

    .line 29
    .line 30
    new-instance p1, Landroid/os/Handler;

    .line 31
    .line 32
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    invoke-direct {p1, v3}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 37
    .line 38
    .line 39
    iput-object p1, p0, Ls6/h;->d:Landroid/os/Handler;

    .line 40
    .line 41
    new-instance p1, Landroidx/collection/g;

    .line 42
    .line 43
    const/4 v3, 0x0

    .line 44
    invoke-direct {p1, v3}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    iput-object p1, p0, Ls6/h;->b:Landroidx/collection/g;

    .line 48
    .line 49
    new-instance p1, Lrb0/a;

    .line 50
    .line 51
    const/16 v3, 0xd

    .line 52
    .line 53
    invoke-direct {p1, v3}, Lrb0/a;-><init>(I)V

    .line 54
    .line 55
    .line 56
    iput-object p1, p0, Ls6/h;->g:Lrb0/a;

    .line 57
    .line 58
    new-instance p1, Lis/b;

    .line 59
    .line 60
    invoke-direct {p1, p0}, Lis/b;-><init>(Ls6/h;)V

    .line 61
    .line 62
    .line 63
    iput-object p1, p0, Ls6/h;->e:Lis/b;

    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    invoke-interface {v3}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 70
    .line 71
    .line 72
    if-nez v2, :cond_0

    .line 73
    .line 74
    const/4 v2, 0x0

    .line 75
    :try_start_0
    iput v2, p0, Ls6/h;->c:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :catchall_0
    move-exception p1

    .line 79
    iget-object p0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-interface {p0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 86
    .line 87
    .line 88
    throw p1

    .line 89
    :cond_0
    :goto_0
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 94
    .line 95
    .line 96
    invoke-virtual {p0}, Ls6/h;->c()I

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    if-nez v0, :cond_1

    .line 101
    .line 102
    :try_start_1
    new-instance v0, Ls6/d;

    .line 103
    .line 104
    invoke-direct {v0, p1}, Ls6/d;-><init>(Lis/b;)V

    .line 105
    .line 106
    .line 107
    invoke-interface {v1, v0}, Ls6/g;->a(Lkp/m7;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 108
    .line 109
    .line 110
    return-void

    .line 111
    :catchall_1
    move-exception p1

    .line 112
    invoke-virtual {p0, p1}, Ls6/h;->f(Ljava/lang/Throwable;)V

    .line 113
    .line 114
    .line 115
    :cond_1
    return-void
.end method

.method public static a()Ls6/h;
    .locals 4

    .line 1
    sget-object v0, Ls6/h;->j:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Ls6/h;->k:Ls6/h;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v2, 0x0

    .line 11
    :goto_0
    const-string v3, "EmojiCompat is not initialized.\n\nYou must initialize EmojiCompat prior to referencing the EmojiCompat instance.\n\nThe most likely cause of this error is disabling the EmojiCompatInitializer\neither explicitly in AndroidManifest.xml, or by including\nandroidx.emoji2:emoji2-bundled.\n\nAutomatic initialization is typically performed by EmojiCompatInitializer. If\nyou are not expecting to initialize EmojiCompat manually in your application,\nplease check to ensure it has not been removed from your APK\'s manifest. You can\ndo this in Android Studio using Build > Analyze APK.\n\nIn the APK Analyzer, ensure that the startup entry for\nEmojiCompatInitializer and InitializationProvider is present in\n AndroidManifest.xml. If it is missing or contains tools:node=\"remove\", and you\nintend to use automatic configuration, verify:\n\n  1. Your application does not include emoji2-bundled\n  2. All modules do not contain an exclusion manifest rule for\n     EmojiCompatInitializer or InitializationProvider. For more information\n     about manifest exclusions see the documentation for the androidx startup\n     library.\n\nIf you intend to use emoji2-bundled, please call EmojiCompat.init. You can\nlearn more in the documentation for BundledEmojiCompatConfig.\n\nIf you intended to perform manual configuration, it is recommended that you call\nEmojiCompat.init immediately on application startup.\n\nIf you still cannot resolve this issue, please open a bug with your specific\nconfiguration to help improve error message."

    .line 12
    .line 13
    invoke-static {v3, v2}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 14
    .line 15
    .line 16
    monitor-exit v0

    .line 17
    return-object v1

    .line 18
    :catchall_0
    move-exception v1

    .line 19
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    throw v1
.end method

.method public static d()Z
    .locals 1

    .line 1
    sget-object v0, Ls6/h;->k:Ls6/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    return v0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    return v0
.end method


# virtual methods
.method public final b(ILjava/lang/CharSequence;)I
    .locals 9

    .line 1
    invoke-virtual {p0}, Ls6/h;->c()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x1

    .line 7
    if-ne v0, v2, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move v2, v1

    .line 11
    :goto_0
    const-string v0, "Not initialized yet"

    .line 12
    .line 13
    invoke-static {v0, v2}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 14
    .line 15
    .line 16
    const-string v0, "charSequence cannot be null"

    .line 17
    .line 18
    invoke-static {p2, v0}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Ls6/h;->e:Lis/b;

    .line 22
    .line 23
    iget-object p0, p0, Lis/b;->b:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v2, p0

    .line 26
    check-cast v2, Lrn/i;

    .line 27
    .line 28
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    if-ltz p1, :cond_3

    .line 32
    .line 33
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-lt p1, p0, :cond_1

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    instance-of p0, p2, Landroid/text/Spanned;

    .line 41
    .line 42
    if-eqz p0, :cond_2

    .line 43
    .line 44
    move-object p0, p2

    .line 45
    check-cast p0, Landroid/text/Spanned;

    .line 46
    .line 47
    add-int/lit8 v0, p1, 0x1

    .line 48
    .line 49
    const-class v3, Ls6/u;

    .line 50
    .line 51
    invoke-interface {p0, p1, v0, v3}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    check-cast v0, [Ls6/u;

    .line 56
    .line 57
    array-length v3, v0

    .line 58
    if-lez v3, :cond_2

    .line 59
    .line 60
    aget-object p1, v0, v1

    .line 61
    .line 62
    invoke-interface {p0, p1}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    return p0

    .line 67
    :cond_2
    add-int/lit8 p0, p1, -0x10

    .line 68
    .line 69
    invoke-static {v1, p0}, Ljava/lang/Math;->max(II)I

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    add-int/lit8 v0, p1, 0x10

    .line 78
    .line 79
    invoke-static {p0, v0}, Ljava/lang/Math;->min(II)I

    .line 80
    .line 81
    .line 82
    move-result v5

    .line 83
    new-instance v8, Ls6/m;

    .line 84
    .line 85
    invoke-direct {v8, p1}, Ls6/m;-><init>(I)V

    .line 86
    .line 87
    .line 88
    const v6, 0x7fffffff

    .line 89
    .line 90
    .line 91
    const/4 v7, 0x1

    .line 92
    move-object v3, p2

    .line 93
    invoke-virtual/range {v2 .. v8}, Lrn/i;->x(Ljava/lang/CharSequence;IIIZLs6/l;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    check-cast p0, Ls6/m;

    .line 98
    .line 99
    iget p0, p0, Ls6/m;->e:I

    .line 100
    .line 101
    return p0

    .line 102
    :cond_3
    :goto_1
    const/4 p0, -0x1

    .line 103
    return p0
.end method

.method public final c()I
    .locals 1

    .line 1
    iget-object v0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->readLock()Ljava/util/concurrent/locks/Lock;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 8
    .line 9
    .line 10
    :try_start_0
    iget v0, p0, Ls6/h;->c:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    .line 12
    iget-object p0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->readLock()Ljava/util/concurrent/locks/Lock;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-interface {p0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 19
    .line 20
    .line 21
    return v0

    .line 22
    :catchall_0
    move-exception v0

    .line 23
    iget-object p0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->readLock()Ljava/util/concurrent/locks/Lock;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-interface {p0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 30
    .line 31
    .line 32
    throw v0
.end method

.method public final e()V
    .locals 4

    .line 1
    iget v0, p0, Ls6/h;->h:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-ne v0, v2, :cond_0

    .line 6
    .line 7
    move v0, v2

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v0, v1

    .line 10
    :goto_0
    const-string v3, "Set metadataLoadStrategy to LOAD_STRATEGY_MANUAL to execute manual loading"

    .line 11
    .line 12
    invoke-static {v3, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Ls6/h;->c()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-ne v0, v2, :cond_1

    .line 20
    .line 21
    return-void

    .line 22
    :cond_1
    iget-object v0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 29
    .line 30
    .line 31
    :try_start_0
    iget v0, p0, Ls6/h;->c:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 32
    .line 33
    if-nez v0, :cond_2

    .line 34
    .line 35
    iget-object p0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 36
    .line 37
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-interface {p0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_2
    :try_start_1
    iput v1, p0, Ls6/h;->c:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 46
    .line 47
    iget-object v0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Ls6/h;->e:Lis/b;

    .line 57
    .line 58
    iget-object v0, p0, Lis/b;->a:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Ls6/h;

    .line 61
    .line 62
    :try_start_2
    new-instance v1, Ls6/d;

    .line 63
    .line 64
    invoke-direct {v1, p0}, Ls6/d;-><init>(Lis/b;)V

    .line 65
    .line 66
    .line 67
    iget-object p0, v0, Ls6/h;->f:Ls6/g;

    .line 68
    .line 69
    invoke-interface {p0, v1}, Ls6/g;->a(Lkp/m7;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 70
    .line 71
    .line 72
    return-void

    .line 73
    :catchall_0
    move-exception p0

    .line 74
    invoke-virtual {v0, p0}, Ls6/h;->f(Ljava/lang/Throwable;)V

    .line 75
    .line 76
    .line 77
    return-void

    .line 78
    :catchall_1
    move-exception v0

    .line 79
    iget-object p0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-interface {p0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 86
    .line 87
    .line 88
    throw v0
.end method

.method public final f(Ljava/lang/Throwable;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    :try_start_0
    iput v1, p0, Ls6/h;->c:I

    .line 17
    .line 18
    iget-object v1, p0, Ls6/h;->b:Landroidx/collection/g;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Ls6/h;->b:Landroidx/collection/g;

    .line 24
    .line 25
    invoke-virtual {v1}, Landroidx/collection/g;->clear()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 35
    .line 36
    .line 37
    iget-object v1, p0, Ls6/h;->d:Landroid/os/Handler;

    .line 38
    .line 39
    new-instance v2, Lcom/google/android/material/datepicker/n;

    .line 40
    .line 41
    iget p0, p0, Ls6/h;->c:I

    .line 42
    .line 43
    invoke-direct {v2, v0, p0, p1}, Lcom/google/android/material/datepicker/n;-><init>(Ljava/util/List;ILjava/lang/Throwable;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v1, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :catchall_0
    move-exception p1

    .line 51
    iget-object p0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-interface {p0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 58
    .line 59
    .line 60
    throw p1
.end method

.method public final g(IIILjava/lang/CharSequence;)Ljava/lang/CharSequence;
    .locals 11

    .line 1
    invoke-virtual {p0}, Ls6/h;->c()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x1

    .line 7
    if-ne v0, v2, :cond_0

    .line 8
    .line 9
    move v0, v2

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v0, v1

    .line 12
    :goto_0
    const-string v3, "Not initialized yet"

    .line 13
    .line 14
    invoke-static {v3, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 15
    .line 16
    .line 17
    if-ltz p1, :cond_15

    .line 18
    .line 19
    if-ltz p2, :cond_14

    .line 20
    .line 21
    if-gt p1, p2, :cond_1

    .line 22
    .line 23
    move v0, v2

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move v0, v1

    .line 26
    :goto_1
    const-string v3, "start should be <= than end"

    .line 27
    .line 28
    invoke-static {v0, v3}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const/4 v0, 0x0

    .line 32
    if-nez p4, :cond_2

    .line 33
    .line 34
    return-object v0

    .line 35
    :cond_2
    invoke-interface {p4}, Ljava/lang/CharSequence;->length()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-gt p1, v3, :cond_3

    .line 40
    .line 41
    move v3, v2

    .line 42
    goto :goto_2

    .line 43
    :cond_3
    move v3, v1

    .line 44
    :goto_2
    const-string v4, "start should be < than charSequence length"

    .line 45
    .line 46
    invoke-static {v3, v4}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-interface {p4}, Ljava/lang/CharSequence;->length()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-gt p2, v3, :cond_4

    .line 54
    .line 55
    move v3, v2

    .line 56
    goto :goto_3

    .line 57
    :cond_4
    move v3, v1

    .line 58
    :goto_3
    const-string v4, "end should be < than charSequence length"

    .line 59
    .line 60
    invoke-static {v3, v4}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-interface {p4}, Ljava/lang/CharSequence;->length()I

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    if-eqz v3, :cond_5

    .line 68
    .line 69
    if-ne p1, p2, :cond_6

    .line 70
    .line 71
    :cond_5
    move-object v5, p4

    .line 72
    goto/16 :goto_d

    .line 73
    .line 74
    :cond_6
    if-eq p3, v2, :cond_7

    .line 75
    .line 76
    move v9, v1

    .line 77
    goto :goto_4

    .line 78
    :cond_7
    move v9, v2

    .line 79
    :goto_4
    iget-object p0, p0, Ls6/h;->e:Lis/b;

    .line 80
    .line 81
    iget-object p0, p0, Lis/b;->b:Ljava/lang/Object;

    .line 82
    .line 83
    move-object v4, p0

    .line 84
    check-cast v4, Lrn/i;

    .line 85
    .line 86
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    instance-of p0, p4, Ls6/s;

    .line 90
    .line 91
    if-eqz p0, :cond_8

    .line 92
    .line 93
    move-object p3, p4

    .line 94
    check-cast p3, Ls6/s;

    .line 95
    .line 96
    invoke-virtual {p3}, Ls6/s;->a()V

    .line 97
    .line 98
    .line 99
    :cond_8
    const-class p3, Ls6/u;

    .line 100
    .line 101
    if-nez p0, :cond_a

    .line 102
    .line 103
    :try_start_0
    instance-of v2, p4, Landroid/text/Spannable;

    .line 104
    .line 105
    if-eqz v2, :cond_9

    .line 106
    .line 107
    goto :goto_6

    .line 108
    :cond_9
    instance-of v2, p4, Landroid/text/Spanned;

    .line 109
    .line 110
    if-eqz v2, :cond_b

    .line 111
    .line 112
    move-object v2, p4

    .line 113
    check-cast v2, Landroid/text/Spanned;

    .line 114
    .line 115
    add-int/lit8 v3, p1, -0x1

    .line 116
    .line 117
    add-int/lit8 v5, p2, 0x1

    .line 118
    .line 119
    invoke-interface {v2, v3, v5, p3}, Landroid/text/Spanned;->nextSpanTransition(IILjava/lang/Class;)I

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    if-gt v2, p2, :cond_b

    .line 124
    .line 125
    new-instance v0, Ls6/v;

    .line 126
    .line 127
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 128
    .line 129
    .line 130
    iput-boolean v1, v0, Ls6/v;->d:Z

    .line 131
    .line 132
    new-instance v2, Landroid/text/SpannableString;

    .line 133
    .line 134
    invoke-direct {v2, p4}, Landroid/text/SpannableString;-><init>(Ljava/lang/CharSequence;)V

    .line 135
    .line 136
    .line 137
    iput-object v2, v0, Ls6/v;->e:Landroid/text/Spannable;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 138
    .line 139
    goto :goto_7

    .line 140
    :goto_5
    move-object v5, p4

    .line 141
    goto/16 :goto_c

    .line 142
    .line 143
    :catchall_0
    move-exception v0

    .line 144
    move-object p1, v0

    .line 145
    goto :goto_5

    .line 146
    :cond_a
    :goto_6
    :try_start_1
    new-instance v0, Ls6/v;

    .line 147
    .line 148
    move-object v2, p4

    .line 149
    check-cast v2, Landroid/text/Spannable;

    .line 150
    .line 151
    invoke-direct {v0, v2}, Ls6/v;-><init>(Landroid/text/Spannable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 152
    .line 153
    .line 154
    :cond_b
    :goto_7
    if-eqz v0, :cond_d

    .line 155
    .line 156
    :try_start_2
    iget-object v2, v0, Ls6/v;->e:Landroid/text/Spannable;

    .line 157
    .line 158
    invoke-interface {v2, p1, p2, p3}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object p3

    .line 162
    check-cast p3, [Ls6/u;

    .line 163
    .line 164
    if-eqz p3, :cond_d

    .line 165
    .line 166
    array-length v2, p3

    .line 167
    if-lez v2, :cond_d

    .line 168
    .line 169
    array-length v2, p3

    .line 170
    :goto_8
    if-ge v1, v2, :cond_d

    .line 171
    .line 172
    aget-object v3, p3, v1

    .line 173
    .line 174
    iget-object v5, v0, Ls6/v;->e:Landroid/text/Spannable;

    .line 175
    .line 176
    invoke-interface {v5, v3}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 177
    .line 178
    .line 179
    move-result v5

    .line 180
    iget-object v6, v0, Ls6/v;->e:Landroid/text/Spannable;

    .line 181
    .line 182
    invoke-interface {v6, v3}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    .line 183
    .line 184
    .line 185
    move-result v6

    .line 186
    if-eq v5, p2, :cond_c

    .line 187
    .line 188
    invoke-virtual {v0, v3}, Ls6/v;->removeSpan(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    :cond_c
    invoke-static {v5, p1}, Ljava/lang/Math;->min(II)I

    .line 192
    .line 193
    .line 194
    move-result p1

    .line 195
    invoke-static {v6, p2}, Ljava/lang/Math;->max(II)I

    .line 196
    .line 197
    .line 198
    move-result p2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 199
    add-int/lit8 v1, v1, 0x1

    .line 200
    .line 201
    goto :goto_8

    .line 202
    :cond_d
    move v6, p1

    .line 203
    move v7, p2

    .line 204
    if-eq v6, v7, :cond_e

    .line 205
    .line 206
    :try_start_3
    invoke-interface {p4}, Ljava/lang/CharSequence;->length()I

    .line 207
    .line 208
    .line 209
    move-result p1

    .line 210
    if-lt v6, p1, :cond_f

    .line 211
    .line 212
    :cond_e
    move-object v5, p4

    .line 213
    goto :goto_b

    .line 214
    :cond_f
    new-instance v10, Lvp/y1;

    .line 215
    .line 216
    iget-object p1, v4, Lrn/i;->e:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast p1, Lrb0/a;

    .line 219
    .line 220
    const/16 p2, 0x16

    .line 221
    .line 222
    const/4 p3, 0x0

    .line 223
    invoke-direct {v10, v0, p1, p3, p2}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 224
    .line 225
    .line 226
    const v8, 0x7fffffff

    .line 227
    .line 228
    .line 229
    move-object v5, p4

    .line 230
    :try_start_4
    invoke-virtual/range {v4 .. v10}, Lrn/i;->x(Ljava/lang/CharSequence;IIIZLs6/l;)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object p1

    .line 234
    check-cast p1, Ls6/v;

    .line 235
    .line 236
    if-eqz p1, :cond_11

    .line 237
    .line 238
    iget-object p1, p1, Ls6/v;->e:Landroid/text/Spannable;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 239
    .line 240
    if-eqz p0, :cond_10

    .line 241
    .line 242
    move-object p4, v5

    .line 243
    check-cast p4, Ls6/s;

    .line 244
    .line 245
    invoke-virtual {p4}, Ls6/s;->b()V

    .line 246
    .line 247
    .line 248
    :cond_10
    return-object p1

    .line 249
    :catchall_1
    move-exception v0

    .line 250
    :goto_9
    move-object p1, v0

    .line 251
    goto :goto_c

    .line 252
    :cond_11
    if-eqz p0, :cond_13

    .line 253
    .line 254
    :goto_a
    move-object p4, v5

    .line 255
    check-cast p4, Ls6/s;

    .line 256
    .line 257
    invoke-virtual {p4}, Ls6/s;->b()V

    .line 258
    .line 259
    .line 260
    return-object v5

    .line 261
    :catchall_2
    move-exception v0

    .line 262
    move-object v5, p4

    .line 263
    goto :goto_9

    .line 264
    :goto_b
    if-eqz p0, :cond_13

    .line 265
    .line 266
    goto :goto_a

    .line 267
    :goto_c
    if-eqz p0, :cond_12

    .line 268
    .line 269
    move-object p4, v5

    .line 270
    check-cast p4, Ls6/s;

    .line 271
    .line 272
    invoke-virtual {p4}, Ls6/s;->b()V

    .line 273
    .line 274
    .line 275
    :cond_12
    throw p1

    .line 276
    :cond_13
    :goto_d
    return-object v5

    .line 277
    :cond_14
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 278
    .line 279
    const-string p1, "end cannot be negative"

    .line 280
    .line 281
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    throw p0

    .line 285
    :cond_15
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 286
    .line 287
    const-string p1, "start cannot be negative"

    .line 288
    .line 289
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    throw p0
.end method

.method public final h(Ls6/f;)V
    .locals 4

    .line 1
    const-string v0, "initCallback cannot be null"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 13
    .line 14
    .line 15
    :try_start_0
    iget v0, p0, Ls6/h;->c:I

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    if-eq v0, v1, :cond_1

    .line 19
    .line 20
    iget v0, p0, Ls6/h;->c:I

    .line 21
    .line 22
    const/4 v1, 0x2

    .line 23
    if-ne v0, v1, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    iget-object v0, p0, Ls6/h;->b:Landroidx/collection/g;

    .line 27
    .line 28
    invoke-virtual {v0, p1}, Landroidx/collection/g;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    goto :goto_1

    .line 32
    :catchall_0
    move-exception p1

    .line 33
    goto :goto_2

    .line 34
    :cond_1
    :goto_0
    iget-object v0, p0, Ls6/h;->d:Landroid/os/Handler;

    .line 35
    .line 36
    new-instance v1, Lcom/google/android/material/datepicker/n;

    .line 37
    .line 38
    iget v2, p0, Ls6/h;->c:I

    .line 39
    .line 40
    filled-new-array {p1}, [Ls6/f;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-static {p1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    check-cast p1, Ljava/util/List;

    .line 49
    .line 50
    const/4 v3, 0x0

    .line 51
    invoke-direct {v1, p1, v2, v3}, Lcom/google/android/material/datepicker/n;-><init>(Ljava/util/List;ILjava/lang/Throwable;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 55
    .line 56
    .line 57
    :goto_1
    iget-object p0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 58
    .line 59
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-interface {p0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :goto_2
    iget-object p0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 68
    .line 69
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-interface {p0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 74
    .line 75
    .line 76
    throw p1
.end method

.method public final i(Landroid/view/inputmethod/EditorInfo;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Ls6/h;->c()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-ne v0, v1, :cond_3

    .line 7
    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    iget-object v0, p1, Landroid/view/inputmethod/EditorInfo;->extras:Landroid/os/Bundle;

    .line 12
    .line 13
    if-nez v0, :cond_1

    .line 14
    .line 15
    new-instance v0, Landroid/os/Bundle;

    .line 16
    .line 17
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object v0, p1, Landroid/view/inputmethod/EditorInfo;->extras:Landroid/os/Bundle;

    .line 21
    .line 22
    :cond_1
    iget-object p0, p0, Ls6/h;->e:Lis/b;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    iget-object v0, p1, Landroid/view/inputmethod/EditorInfo;->extras:Landroid/os/Bundle;

    .line 28
    .line 29
    iget-object p0, p0, Lis/b;->c:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lcom/google/firebase/messaging/w;

    .line 32
    .line 33
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, Lt6/b;

    .line 36
    .line 37
    const/4 v1, 0x4

    .line 38
    invoke-virtual {p0, v1}, Ld6/h0;->a(I)I

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    const/4 v2, 0x0

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    iget-object v3, p0, Ld6/h0;->g:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v3, Ljava/nio/ByteBuffer;

    .line 48
    .line 49
    iget p0, p0, Ld6/h0;->d:I

    .line 50
    .line 51
    add-int/2addr v1, p0

    .line 52
    invoke-virtual {v3, v1}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    goto :goto_0

    .line 57
    :cond_2
    move p0, v2

    .line 58
    :goto_0
    const-string v1, "android.support.text.emoji.emojiCompat_metadataVersion"

    .line 59
    .line 60
    invoke-virtual {v0, v1, p0}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 61
    .line 62
    .line 63
    iget-object p0, p1, Landroid/view/inputmethod/EditorInfo;->extras:Landroid/os/Bundle;

    .line 64
    .line 65
    const-string p1, "android.support.text.emoji.emojiCompat_replaceAll"

    .line 66
    .line 67
    invoke-virtual {p0, p1, v2}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 68
    .line 69
    .line 70
    :cond_3
    return-void
.end method
