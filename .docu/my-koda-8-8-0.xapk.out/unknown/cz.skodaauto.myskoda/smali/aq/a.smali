.class public final Laq/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/g;
.implements Laq/f;
.implements Laq/d;
.implements Lk0/c;
.implements Lc1/q;
.implements Ld6/c;
.implements Llo/l;
.implements Ll/w;
.implements Lh01/h;
.implements Lh1/l;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Laq/a;->d:I

    sparse-switch p1, :sswitch_data_0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, La0/j;

    const/4 v0, 0x3

    invoke-direct {p1, v0}, La0/j;-><init>(I)V

    iput-object p1, p0, Laq/a;->e:Ljava/lang/Object;

    return-void

    .line 2
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object p1

    .line 4
    invoke-static {p1}, Landroid/os/Handler;->createAsync(Landroid/os/Looper;)Landroid/os/Handler;

    move-result-object p1

    .line 5
    iput-object p1, p0, Laq/a;->e:Ljava/lang/Object;

    return-void

    .line 6
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    new-instance p1, Le3/a;

    invoke-direct {p1}, Le3/a;-><init>()V

    iput-object p1, p0, Laq/a;->e:Ljava/lang/Object;

    return-void

    .line 8
    :sswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object p1

    iput-object p1, p0, Laq/a;->e:Ljava/lang/Object;

    return-void

    .line 10
    :sswitch_3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void

    .line 11
    :sswitch_4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/concurrent/CountDownLatch;

    const/4 v0, 0x1

    invoke-direct {p1, v0}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    iput-object p1, p0, Laq/a;->e:Ljava/lang/Object;

    return-void

    :sswitch_data_0
    .sparse-switch
        0x1 -> :sswitch_4
        0x5 -> :sswitch_3
        0x9 -> :sswitch_2
        0x11 -> :sswitch_1
        0x14 -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(Landroid/content/ClipData;I)V
    .locals 1

    const/16 v0, 0xe

    iput v0, p0, Laq/a;->d:I

    .line 66
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 67
    invoke-static {p1, p2}, Lc4/a;->l(Landroid/content/ClipData;I)Landroid/view/ContentInfo$Builder;

    move-result-object p1

    iput-object p1, p0, Laq/a;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 3

    const/16 v0, 0xd

    iput v0, p0, Laq/a;->d:I

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    new-instance v0, Ler/i;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Ler/i;-><init>(Landroid/content/Context;Z)V

    .line 15
    sget-object p1, Lcr/i;->b:Let/d;

    invoke-static {p1}, Ler/g;->b(Ler/h;)Ler/g;

    move-result-object p1

    new-instance v1, Lip/v;

    invoke-direct {v1, v0}, Lip/v;-><init>(Ler/i;)V

    new-instance v2, Lvp/y1;

    invoke-direct {v2, v0, p1, v1}, Lvp/y1;-><init>(Ler/i;Ler/g;Lip/v;)V

    invoke-static {v2}, Ler/g;->b(Ler/h;)Ler/g;

    move-result-object p1

    new-instance v0, Lbu/c;

    const/16 v1, 0xd

    invoke-direct {v0, p1, v1}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    invoke-static {v0}, Ler/g;->b(Ler/h;)Ler/g;

    move-result-object p1

    iput-object p1, p0, Laq/a;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;I)V
    .locals 3

    const/16 v0, 0x15

    iput v0, p0, Laq/a;->d:I

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    .line 16
    const-string p2, "com.wultra.WultraCertStore"

    .line 17
    :cond_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    const-class p3, Lvv0/c;

    monitor-enter p3

    .line 19
    :try_start_0
    sget-object v0, Lvv0/c;->f:Lvv0/c;

    .line 20
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    .line 21
    invoke-virtual {v0, p1}, Lvv0/c;->b(Landroid/content/Context;)I

    move-result p1

    const/4 v2, 0x1

    if-gt v2, p1, :cond_2

    .line 22
    iget-object p1, v0, Lvv0/c;->a:Ljava/util/HashMap;

    .line 23
    invoke-virtual {p1, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lvv0/b;

    if-nez p1, :cond_1

    .line 24
    invoke-static {v1, v0, p2}, Llp/jc;->a(Landroid/content/Context;Lvv0/c;Ljava/lang/String;)Lvv0/b;

    move-result-object p1

    .line 25
    iget-object v0, v0, Lvv0/c;->a:Ljava/util/HashMap;

    .line 26
    invoke-virtual {v0, p2, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 27
    :cond_1
    :goto_0
    monitor-exit p3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    iput-object p1, p0, Laq/a;->e:Ljava/lang/Object;

    return-void

    .line 29
    :cond_2
    :try_start_1
    new-instance p0, Lb0/l;

    const-string p1, "Device doesn\'t support required level of keychain protection."

    .line 30
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 31
    throw p0

    .line 32
    :goto_1
    monitor-exit p3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p0
.end method

.method public constructor <init>(Landroid/os/Bundle;)V
    .locals 1

    const/16 v0, 0xc

    iput v0, p0, Laq/a;->d:I

    .line 59
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 60
    new-instance v0, Landroid/os/Bundle;

    invoke-direct {v0, p1}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    iput-object v0, p0, Laq/a;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/view/View;)V
    .locals 2

    const/16 v0, 0xf

    iput v0, p0, Laq/a;->d:I

    .line 50
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 51
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1e

    if-lt v0, v1, :cond_0

    .line 52
    new-instance v0, Ld6/a0;

    .line 53
    invoke-direct {v0, p1}, Ld6/y;-><init>(Landroid/view/View;)V

    .line 54
    iput-object p1, v0, Ld6/a0;->b:Landroid/view/View;

    .line 55
    iput-object v0, p0, Laq/a;->e:Ljava/lang/Object;

    goto :goto_0

    .line 56
    :cond_0
    new-instance v0, Ld6/y;

    invoke-direct {v0, p1}, Ld6/y;-><init>(Landroid/view/View;)V

    iput-object v0, p0, Laq/a;->e:Ljava/lang/Object;

    :goto_0
    return-void
.end method

.method public constructor <init>(Las/d;Ljava/util/concurrent/Executor;Ljava/util/concurrent/ScheduledExecutorService;)V
    .locals 0

    const/4 p1, 0x2

    iput p1, p0, Laq/a;->d:I

    .line 57
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 58
    iput-object p2, p0, Laq/a;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Le01/f;)V
    .locals 9

    const/16 v0, 0x16

    iput v0, p0, Laq/a;->d:I

    .line 61
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 62
    new-instance v1, Ljava/util/concurrent/ThreadPoolExecutor;

    .line 63
    sget-object v6, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 64
    new-instance v7, Ljava/util/concurrent/SynchronousQueue;

    invoke-direct {v7}, Ljava/util/concurrent/SynchronousQueue;-><init>()V

    const/4 v2, 0x0

    const v3, 0x7fffffff

    const-wide/16 v4, 0x3c

    move-object v8, p1

    .line 65
    invoke-direct/range {v1 .. v8}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;Ljava/util/concurrent/ThreadFactory;)V

    iput-object v1, p0, Laq/a;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 12
    iput p2, p0, Laq/a;->d:I

    iput-object p1, p0, Laq/a;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>([I[F[[F)V
    .locals 21

    move-object/from16 v0, p0

    move-object/from16 v1, p2

    const/4 v2, 0x7

    iput v2, v0, Laq/a;->d:I

    .line 33
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 34
    array-length v2, v1

    const/4 v3, 0x1

    sub-int/2addr v2, v3

    new-array v4, v2, [[Lc1/r;

    const/4 v5, 0x0

    move v7, v3

    move v8, v7

    move v6, v5

    :goto_0
    if-ge v6, v2, :cond_5

    .line 35
    aget v9, p1, v6

    const/4 v10, 0x3

    const/4 v11, 0x2

    if-eqz v9, :cond_0

    if-eq v9, v3, :cond_3

    if-eq v9, v11, :cond_2

    if-eq v9, v10, :cond_1

    const/4 v10, 0x4

    if-eq v9, v10, :cond_0

    const/4 v10, 0x5

    if-eq v9, v10, :cond_0

    move v13, v8

    goto :goto_3

    :cond_0
    move v13, v10

    goto :goto_3

    :cond_1
    if-ne v7, v3, :cond_3

    goto :goto_2

    :goto_1
    move v13, v7

    goto :goto_3

    :cond_2
    :goto_2
    move v7, v11

    goto :goto_1

    :cond_3
    move v7, v3

    goto :goto_1

    .line 36
    :goto_3
    aget-object v8, p3, v6

    add-int/lit8 v9, v6, 0x1

    .line 37
    aget-object v10, p3, v9

    .line 38
    aget v14, v1, v6

    .line 39
    aget v15, v1, v9

    .line 40
    array-length v12, v8

    div-int/2addr v12, v11

    array-length v3, v8

    rem-int/2addr v3, v11

    add-int/2addr v3, v12

    .line 41
    new-array v11, v3, [Lc1/r;

    move v12, v5

    :goto_4
    if-ge v12, v3, :cond_4

    mul-int/lit8 v16, v12, 0x2

    move/from16 v17, v12

    .line 42
    new-instance v12, Lc1/r;

    move/from16 v18, v16

    .line 43
    aget v16, v8, v18

    add-int/lit8 v19, v18, 0x1

    move/from16 v20, v17

    .line 44
    aget v17, v8, v19

    .line 45
    aget v18, v10, v18

    .line 46
    aget v19, v10, v19

    .line 47
    invoke-direct/range {v12 .. v19}, Lc1/r;-><init>(IFFFFFF)V

    aput-object v12, v11, v20

    add-int/lit8 v12, v20, 0x1

    goto :goto_4

    .line 48
    :cond_4
    aput-object v11, v4, v6

    move v6, v9

    move v8, v13

    const/4 v3, 0x1

    goto :goto_0

    .line 49
    :cond_5
    iput-object v4, v0, Laq/a;->e:Ljava/lang/Object;

    return-void
.end method

.method private final C(Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    return-void
.end method

.method public static G(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "gcm.n."

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 v0, 0x6

    .line 10
    invoke-virtual {p0, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :cond_0
    return-object p0
.end method

.method public static z(Landroid/os/Bundle;)Z
    .locals 4

    .line 1
    const-string v0, "gcm.n.e"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const-string v2, "1"

    .line 8
    .line 9
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-nez v1, :cond_1

    .line 14
    .line 15
    const-string v1, "gcm.n."

    .line 16
    .line 17
    const-string v3, "gcm.notification."

    .line 18
    .line 19
    invoke-virtual {v0, v1, v3}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-virtual {v2, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-eqz p0, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 p0, 0x0

    .line 35
    return p0

    .line 36
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 37
    return p0
.end method


# virtual methods
.method public A(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lg51/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lg51/a;

    .line 7
    .line 8
    iget v1, v0, Lg51/a;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lg51/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg51/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lg51/a;-><init>(Laq/a;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lg51/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg51/a;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    check-cast p1, Llx0/o;

    .line 40
    .line 41
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    const-string p1, "technology.cariad.cat.carkeykit.SKIP_COMPATIBILITY_CHECK"

    .line 56
    .line 57
    invoke-static {p1}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-eqz p1, :cond_3

    .line 62
    .line 63
    invoke-static {p1}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    if-ne p1, v3, :cond_3

    .line 68
    .line 69
    sget-object p1, Lx51/c;->o1:Lx51/b;

    .line 70
    .line 71
    invoke-static {p0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    new-instance v0, Lf2/h0;

    .line 76
    .line 77
    const/16 v1, 0x10

    .line 78
    .line 79
    invoke-direct {v0, v1}, Lf2/h0;-><init>(I)V

    .line 80
    .line 81
    .line 82
    const/4 v1, 0x6

    .line 83
    const/4 v2, 0x0

    .line 84
    invoke-static {p1, p0, v2, v0, v1}, Lx51/c;->f(Lx51/c;Ljava/lang/String;Ljava/lang/Exception;Lay0/a;I)V

    .line 85
    .line 86
    .line 87
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 88
    .line 89
    return-object p0

    .line 90
    :cond_3
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast p0, Lj51/h;

    .line 93
    .line 94
    iput v3, v0, Lg51/a;->f:I

    .line 95
    .line 96
    invoke-virtual {p0, v0}, Lj51/h;->c(Lrx0/c;)Ljava/io/Serializable;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    if-ne p0, v1, :cond_4

    .line 101
    .line 102
    return-object v1

    .line 103
    :cond_4
    return-object p0
.end method

.method public B(Ljava/lang/Exception;)V
    .locals 3

    .line 1
    const-string v0, "MediaCodecAudioRenderer"

    .line 2
    .line 3
    const-string v1, "Audio sink error"

    .line 4
    .line 5
    invoke-static {v0, v1, p1}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lc8/a0;

    .line 11
    .line 12
    iget-object p0, p0, Lc8/a0;->Q1:Lb81/d;

    .line 13
    .line 14
    iget-object v0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Landroid/os/Handler;

    .line 17
    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    new-instance v1, Lc8/i;

    .line 21
    .line 22
    const/16 v2, 0x8

    .line 23
    .line 24
    invoke-direct {v1, p0, p1, v2}, Lc8/i;-><init>(Lb81/d;Ljava/lang/Object;I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 28
    .line 29
    .line 30
    :cond_0
    return-void
.end method

.method public D()Landroid/os/Bundle;
    .locals 3

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Landroid/os/Bundle;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_2

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Ljava/lang/String;

    .line 29
    .line 30
    const-string v2, "google.c.a."

    .line 31
    .line 32
    invoke-virtual {v1, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-nez v2, :cond_0

    .line 37
    .line 38
    const-string v2, "from"

    .line 39
    .line 40
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    return-object v0
.end method

.method public E(Ld8/f;)V
    .locals 0

    .line 1
    return-void
.end method

.method public F(Ljava/lang/String;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public Q()V
    .locals 0

    .line 1
    return-void
.end method

.method public a()Lh01/p;
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    move-object v1, v0

    .line 3
    :goto_0
    iget-object v2, p0, Laq/a;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v2, Lh01/r;

    .line 6
    .line 7
    iget-object v2, v2, Lh01/r;->k:Lh01/o;

    .line 8
    .line 9
    iget-boolean v2, v2, Lh01/o;->t:Z

    .line 10
    .line 11
    if-nez v2, :cond_6

    .line 12
    .line 13
    :try_start_0
    iget-object v2, p0, Laq/a;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v2, Lh01/r;

    .line 16
    .line 17
    invoke-virtual {v2}, Lh01/r;->b()Lh01/u;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    invoke-interface {v2}, Lh01/u;->a()Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-nez v3, :cond_3

    .line 26
    .line 27
    invoke-interface {v2}, Lh01/u;->g()Lh01/t;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    iget-object v4, v3, Lh01/t;->b:Lh01/u;

    .line 32
    .line 33
    if-nez v4, :cond_0

    .line 34
    .line 35
    iget-object v4, v3, Lh01/t;->c:Ljava/lang/Throwable;

    .line 36
    .line 37
    if-nez v4, :cond_0

    .line 38
    .line 39
    const/4 v4, 0x1

    .line 40
    goto :goto_1

    .line 41
    :cond_0
    const/4 v4, 0x0

    .line 42
    :goto_1
    if-eqz v4, :cond_1

    .line 43
    .line 44
    invoke-interface {v2}, Lh01/u;->d()Lh01/t;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    goto :goto_2

    .line 49
    :catch_0
    move-exception v2

    .line 50
    goto :goto_3

    .line 51
    :cond_1
    :goto_2
    iget-object v4, v3, Lh01/t;->b:Lh01/u;

    .line 52
    .line 53
    iget-object v3, v3, Lh01/t;->c:Ljava/lang/Throwable;

    .line 54
    .line 55
    if-nez v3, :cond_2

    .line 56
    .line 57
    if-eqz v4, :cond_3

    .line 58
    .line 59
    iget-object v2, p0, Laq/a;->e:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v2, Lh01/r;

    .line 62
    .line 63
    iget-object v2, v2, Lh01/r;->p:Lmx0/l;

    .line 64
    .line 65
    invoke-virtual {v2, v4}, Lmx0/l;->addFirst(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_2
    throw v3

    .line 70
    :cond_3
    invoke-interface {v2}, Lh01/u;->b()Lh01/p;

    .line 71
    .line 72
    .line 73
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 74
    return-object p0

    .line 75
    :goto_3
    if-nez v1, :cond_4

    .line 76
    .line 77
    move-object v1, v2

    .line 78
    goto :goto_4

    .line 79
    :cond_4
    invoke-static {v1, v2}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 80
    .line 81
    .line 82
    :goto_4
    iget-object v2, p0, Laq/a;->e:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v2, Lh01/r;

    .line 85
    .line 86
    invoke-virtual {v2, v0}, Lh01/r;->a(Lh01/p;)Z

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    if-eqz v2, :cond_5

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_5
    throw v1

    .line 94
    :cond_6
    new-instance p0, Ljava/io/IOException;

    .line 95
    .line 96
    const-string v0, "Canceled"

    .line 97
    .line 98
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    throw p0
.end method

.method public b(Landroid/net/Uri;)V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/view/ContentInfo$Builder;

    .line 4
    .line 5
    invoke-static {p0, p1}, Lc4/a;->w(Landroid/view/ContentInfo$Builder;Landroid/net/Uri;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public build()Ld6/f;
    .locals 2

    .line 1
    new-instance v0, Ld6/f;

    .line 2
    .line 3
    new-instance v1, La0/j;

    .line 4
    .line 5
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroid/view/ContentInfo$Builder;

    .line 8
    .line 9
    invoke-static {p0}, Lc4/a;->m(Landroid/view/ContentInfo$Builder;)Landroid/view/ContentInfo;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-direct {v1, p0}, La0/j;-><init>(Landroid/view/ContentInfo;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {v0, v1}, Ld6/f;-><init>(Ld6/e;)V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method

.method public c(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Laq/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    check-cast p1, Ljava/lang/Void;

    .line 7
    .line 8
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lp0/e;

    .line 11
    .line 12
    invoke-virtual {p0}, Lp0/e;->run()V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_1
    check-cast p1, Ljava/lang/Void;

    .line 17
    .line 18
    return-void

    .line 19
    :pswitch_2
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public d(Ll/l;Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh/z;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lh/z;->v(Ll/l;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public e()Lh01/r;
    .locals 0

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh01/r;

    .line 4
    .line 5
    return-object p0
.end method

.method public f(Ll/l;)Z
    .locals 1

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh/z;

    .line 4
    .line 5
    iget-object p0, p0, Lh/z;->o:Landroid/view/Window;

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    const/16 v0, 0x6c

    .line 14
    .line 15
    invoke-interface {p0, v0, p1}, Landroid/view/Window$Callback;->onMenuOpened(ILandroid/view/Menu;)Z

    .line 16
    .line 17
    .line 18
    :cond_0
    const/4 p0, 0x1

    .line 19
    return p0
.end method

.method public g(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb81/d;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lb81/d;->g(F)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public get(I)Lc1/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lc1/b0;

    .line 4
    .line 5
    return-object p0
.end method

.method public h(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/view/ContentInfo$Builder;

    .line 4
    .line 5
    invoke-static {p0, p1}, Lc4/a;->v(Landroid/view/ContentInfo$Builder;I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public i(Ld8/f;)V
    .locals 0

    .line 1
    return-void
.end method

.method public j(FF)F
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public k()V
    .locals 1

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, La0/j;

    .line 4
    .line 5
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Laq/t;

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    invoke-virtual {p0, v0}, Laq/t;->q(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public l(Ljava/lang/String;)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string p1, "1"

    .line 6
    .line 7
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    if-nez p1, :cond_1

    .line 12
    .line 13
    invoke-static {p0}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    return p0

    .line 22
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 23
    return p0
.end method

.method public m()Lz7/a;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public n()Ld8/d;
    .locals 0

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ld8/d;

    .line 4
    .line 5
    return-object p0
.end method

.method public o(Lb0/d1;Ljava/util/ArrayList;ILjava/util/List;)Lf0/e;
    .locals 3

    .line 1
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-lt p3, v0, :cond_2

    .line 6
    .line 7
    iget-object p2, p1, Lb0/d1;->i:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p2, Ljava/util/Set;

    .line 10
    .line 11
    check-cast p4, Ljava/lang/Iterable;

    .line 12
    .line 13
    invoke-static {p2, p4}, Ljp/m1;->h(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    new-instance p3, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    const-string p4, "getFeatureListResolvedByPriority: features = "

    .line 20
    .line 21
    invoke-direct {p3, p4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string p4, ", useCases = "

    .line 28
    .line 29
    invoke-virtual {p3, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    iget-object p4, p1, Lb0/d1;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p4, Ljava/util/List;

    .line 35
    .line 36
    invoke-virtual {p3, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p3

    .line 43
    const-string p4, "DefaultFeatureGroupResolver"

    .line 44
    .line 45
    invoke-static {p4, p3}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p0, Lh0/z;

    .line 51
    .line 52
    new-instance p3, Ld0/c;

    .line 53
    .line 54
    invoke-direct {p3, p2}, Ld0/c;-><init>(Ljava/util/LinkedHashSet;)V

    .line 55
    .line 56
    .line 57
    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 58
    .line 59
    .line 60
    move-result-object p4

    .line 61
    :cond_0
    invoke-interface {p4}, Ljava/util/Iterator;->hasNext()Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    const-string v1, "CameraInfoInternal"

    .line 66
    .line 67
    if-eqz v0, :cond_1

    .line 68
    .line 69
    invoke-interface {p4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    check-cast v0, Lc0/a;

    .line 74
    .line 75
    invoke-virtual {v0, p1, p0}, Lc0/a;->b(Lb0/d1;Lh0/z;)Z

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    if-nez v2, :cond_0

    .line 80
    .line 81
    new-instance p0, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    const-string p1, " is not supported."

    .line 90
    .line 91
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-static {v1, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_1
    :try_start_0
    invoke-static {p0, p1, p3}, Lkp/ba;->a(Lh0/z;Lb0/d1;Ld0/c;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ll0/e; {:try_start_0 .. :try_end_0} :catch_0

    .line 103
    .line 104
    .line 105
    new-instance p0, Lf0/a;

    .line 106
    .line 107
    new-instance p1, Ld0/c;

    .line 108
    .line 109
    invoke-direct {p1, p2}, Ld0/c;-><init>(Ljava/util/LinkedHashSet;)V

    .line 110
    .line 111
    .line 112
    invoke-direct {p0, p1}, Lf0/a;-><init>(Ld0/c;)V

    .line 113
    .line 114
    .line 115
    return-object p0

    .line 116
    :catch_0
    move-exception p0

    .line 117
    const-string p1, "CameraInfoInternal.isResolvedFeatureGroupSupported failed"

    .line 118
    .line 119
    invoke-static {v1, p1, p0}, Ljp/v1;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 120
    .line 121
    .line 122
    :goto_0
    sget-object p0, Lf0/b;->a:Lf0/b;

    .line 123
    .line 124
    return-object p0

    .line 125
    :cond_2
    add-int/lit8 v0, p3, 0x1

    .line 126
    .line 127
    move-object v1, p4

    .line 128
    check-cast v1, Ljava/util/Collection;

    .line 129
    .line 130
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p3

    .line 134
    invoke-static {v1, p3}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 135
    .line 136
    .line 137
    move-result-object p3

    .line 138
    invoke-virtual {p0, p1, p2, v0, p3}, Laq/a;->o(Lb0/d1;Ljava/util/ArrayList;ILjava/util/List;)Lf0/e;

    .line 139
    .line 140
    .line 141
    move-result-object p3

    .line 142
    instance-of v1, p3, Lf0/a;

    .line 143
    .line 144
    if-eqz v1, :cond_3

    .line 145
    .line 146
    return-object p3

    .line 147
    :cond_3
    invoke-virtual {p0, p1, p2, v0, p4}, Laq/a;->o(Lb0/d1;Ljava/util/ArrayList;ILjava/util/List;)Lf0/e;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0
.end method

.method public onFailure(Ljava/lang/Exception;)V
    .locals 3

    .line 1
    iget v0, p0, Laq/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lbp/t;

    .line 9
    .line 10
    iget-object v0, p0, Lbp/t;->c:Lbp/u;

    .line 11
    .line 12
    iget-object v0, v0, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 13
    .line 14
    monitor-enter v0

    .line 15
    :try_start_0
    iget-object v1, p0, Lbp/t;->c:Lbp/u;

    .line 16
    .line 17
    iget-object v1, v1, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    if-ne v1, p0, :cond_0

    .line 24
    .line 25
    iget-object v1, p0, Lbp/t;->c:Lbp/u;

    .line 26
    .line 27
    iget-object v1, v1, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->remove()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    iget-object v1, p0, Lbp/t;->c:Lbp/u;

    .line 33
    .line 34
    const/4 v2, 0x0

    .line 35
    iput v2, v1, Lbp/u;->g:I

    .line 36
    .line 37
    iget-object v1, v1, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 38
    .line 39
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, Lbp/t;

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :catchall_0
    move-exception p0

    .line 47
    goto :goto_1

    .line 48
    :cond_0
    const/4 v1, 0x0

    .line 49
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 50
    iget-object p0, p0, Lbp/t;->b:Laq/k;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 53
    .line 54
    .line 55
    if-eqz v1, :cond_1

    .line 56
    .line 57
    invoke-virtual {v1}, Lbp/t;->a()V

    .line 58
    .line 59
    .line 60
    :cond_1
    return-void

    .line 61
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 62
    throw p0

    .line 63
    :pswitch_0
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 66
    .line 67
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 68
    .line 69
    .line 70
    return-void

    .line 71
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public p(Ljava/lang/String;)Ljava/lang/Integer;
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    :try_start_0
    invoke-static {p0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    return-object p0

    .line 20
    :catch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string v1, "Couldn\'t parse value of "

    .line 23
    .line 24
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-static {p1}, Laq/a;->G(Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string p1, "("

    .line 35
    .line 36
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string p0, ") into an int"

    .line 43
    .line 44
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const-string p1, "NotificationParams"

    .line 52
    .line 53
    invoke-static {p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 54
    .line 55
    .line 56
    :cond_0
    const/4 p0, 0x0

    .line 57
    return-object p0
.end method

.method public q(Ljava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p1, Lhg0/b;

    .line 2
    .line 3
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lgp/e;

    .line 6
    .line 7
    iget-object p0, p0, Lgp/e;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 8
    .line 9
    monitor-enter p0

    .line 10
    const/4 p1, 0x0

    .line 11
    :try_start_0
    iput-boolean p1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 12
    .line 13
    iget-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p1, Lis/b;

    .line 16
    .line 17
    iget-object p1, p1, Lis/b;->c:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p1, Llo/k;

    .line 20
    .line 21
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    if-eqz p1, :cond_0

    .line 23
    .line 24
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Lgp/a;

    .line 27
    .line 28
    const/16 v0, 0x989

    .line 29
    .line 30
    invoke-virtual {p0, p1, v0}, Lko/i;->d(Llo/k;I)Laq/t;

    .line 31
    .line 32
    .line 33
    :cond_0
    return-void

    .line 34
    :catchall_0
    move-exception p1

    .line 35
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    throw p1
.end method

.method public r(Ljava/lang/String;)Lorg/json/JSONArray;
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    :try_start_0
    new-instance v0, Lorg/json/JSONArray;

    .line 12
    .line 13
    invoke-direct {v0, p0}, Lorg/json/JSONArray;-><init>(Ljava/lang/String;)V
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :catch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    const-string v1, "Malformed JSON for key "

    .line 20
    .line 21
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-static {p1}, Laq/a;->G(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string p1, ": "

    .line 32
    .line 33
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string p0, ", falling back to default"

    .line 40
    .line 41
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    const-string p1, "NotificationParams"

    .line 49
    .line 50
    invoke-static {p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 51
    .line 52
    .line 53
    :cond_0
    const/4 p0, 0x0

    .line 54
    return-object p0
.end method

.method public s()V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setExtras(Landroid/os/Bundle;)V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/view/ContentInfo$Builder;

    .line 4
    .line 5
    invoke-static {p0, p1}, Lc4/a;->x(Landroid/view/ContentInfo$Builder;Landroid/os/Bundle;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public t()Lbn/c;
    .locals 2

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ll11/a;

    .line 4
    .line 5
    instance-of v0, p0, Lg11/q;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    check-cast p0, Lg11/q;

    .line 10
    .line 11
    iget-object p0, p0, Lg11/q;->b:Lg11/m;

    .line 12
    .line 13
    iget-object p0, p0, Lg11/m;->b:Ljava/util/ArrayList;

    .line 14
    .line 15
    new-instance v0, Lbn/c;

    .line 16
    .line 17
    const/4 v1, 0x4

    .line 18
    invoke-direct {v0, v1}, Lbn/c;-><init>(I)V

    .line 19
    .line 20
    .line 21
    iget-object v1, v0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-virtual {v1, p0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :cond_0
    new-instance p0, Lbn/c;

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    invoke-direct {p0, v0}, Lbn/c;-><init>(I)V

    .line 31
    .line 32
    .line 33
    return-object p0
.end method

.method public u(Landroid/content/res/Resources;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 7

    .line 1
    invoke-virtual {p0, p3}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    return-object v0

    .line 12
    :cond_0
    const-string v0, "_loc_key"

    .line 13
    .line 14
    invoke-virtual {p3, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-virtual {p0, v1}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    const/4 v3, 0x0

    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    return-object v3

    .line 30
    :cond_1
    const-string v2, "string"

    .line 31
    .line 32
    invoke-virtual {p1, v1, v2, p2}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 33
    .line 34
    .line 35
    move-result p2

    .line 36
    const-string v1, " Default value will be used."

    .line 37
    .line 38
    const-string v2, "NotificationParams"

    .line 39
    .line 40
    if-nez p2, :cond_2

    .line 41
    .line 42
    new-instance p0, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p3, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    invoke-static {p1}, Laq/a;->G(Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    const-string p1, " resource not found: "

    .line 59
    .line 60
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-static {v2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 74
    .line 75
    .line 76
    return-object v3

    .line 77
    :cond_2
    const-string v0, "_loc_args"

    .line 78
    .line 79
    invoke-virtual {p3, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-virtual {p0, v0}, Laq/a;->r(Ljava/lang/String;)Lorg/json/JSONArray;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    if-nez p0, :cond_3

    .line 88
    .line 89
    move-object v4, v3

    .line 90
    goto :goto_1

    .line 91
    :cond_3
    invoke-virtual {p0}, Lorg/json/JSONArray;->length()I

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    new-array v4, v0, [Ljava/lang/String;

    .line 96
    .line 97
    const/4 v5, 0x0

    .line 98
    :goto_0
    if-ge v5, v0, :cond_4

    .line 99
    .line 100
    invoke-virtual {p0, v5}, Lorg/json/JSONArray;->optString(I)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    aput-object v6, v4, v5

    .line 105
    .line 106
    add-int/lit8 v5, v5, 0x1

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_4
    :goto_1
    if-nez v4, :cond_5

    .line 110
    .line 111
    invoke-virtual {p1, p2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    return-object p0

    .line 116
    :cond_5
    :try_start_0
    invoke-virtual {p1, p2, v4}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p0
    :try_end_0
    .catch Ljava/util/MissingFormatArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 120
    return-object p0

    .line 121
    :catch_0
    move-exception p0

    .line 122
    new-instance p1, Ljava/lang/StringBuilder;

    .line 123
    .line 124
    const-string p2, "Missing format argument for "

    .line 125
    .line 126
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    invoke-static {p3}, Laq/a;->G(Ljava/lang/String;)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object p2

    .line 133
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    const-string p2, ": "

    .line 137
    .line 138
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    invoke-static {v4}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object p2

    .line 145
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    invoke-static {v2, p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 156
    .line 157
    .line 158
    return-object v3
.end method

.method public v()Ljava/util/UUID;
    .locals 0

    .line 1
    sget-object p0, Lt7/e;->a:Ljava/util/UUID;

    .line 2
    .line 3
    return-object p0
.end method

.method public w()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public x(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/os/Bundle;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    const-string v0, "gcm.n."

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-eqz v1, :cond_1

    .line 18
    .line 19
    invoke-virtual {p1, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-nez v1, :cond_0

    .line 24
    .line 25
    move-object v0, p1

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const-string v1, "gcm.notification."

    .line 28
    .line 29
    invoke-virtual {p1, v0, v1}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    :goto_0
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    move-object p1, v0

    .line 40
    :cond_1
    invoke-virtual {p0, p1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method

.method public y(Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    iget p1, p0, Laq/a;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lb0/o0;

    .line 10
    .line 11
    invoke-virtual {p0}, Lb0/b0;->close()V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method
