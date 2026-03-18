.class public final Lxl/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/content/ComponentCallbacks2;


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Ljava/lang/ref/WeakReference;

.field public final f:Lsl/e;

.field public volatile g:Z

.field public final h:Ljava/util/concurrent/atomic/AtomicBoolean;


# direct methods
.method public constructor <init>(Lil/j;Landroid/content/Context;Z)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lxl/f;->d:Landroid/content/Context;

    .line 5
    .line 6
    new-instance v0, Ljava/lang/ref/WeakReference;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lxl/f;->e:Ljava/lang/ref/WeakReference;

    .line 12
    .line 13
    if-eqz p3, :cond_1

    .line 14
    .line 15
    const-class p1, Landroid/net/ConnectivityManager;

    .line 16
    .line 17
    invoke-virtual {p2, p1}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    check-cast p1, Landroid/net/ConnectivityManager;

    .line 22
    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    const-string p3, "android.permission.ACCESS_NETWORK_STATE"

    .line 26
    .line 27
    invoke-static {p2, p3}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-nez p2, :cond_0

    .line 32
    .line 33
    :try_start_0
    new-instance p2, Lrn/i;

    .line 34
    .line 35
    invoke-direct {p2, p1, p0}, Lrn/i;-><init>(Landroid/net/ConnectivityManager;Lxl/f;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :catch_0
    new-instance p2, Lwq/f;

    .line 40
    .line 41
    const/16 p1, 0xd

    .line 42
    .line 43
    invoke-direct {p2, p1}, Lwq/f;-><init>(I)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    new-instance p2, Lwq/f;

    .line 48
    .line 49
    const/16 p1, 0xd

    .line 50
    .line 51
    invoke-direct {p2, p1}, Lwq/f;-><init>(I)V

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_1
    new-instance p2, Lwq/f;

    .line 56
    .line 57
    const/16 p1, 0xd

    .line 58
    .line 59
    invoke-direct {p2, p1}, Lwq/f;-><init>(I)V

    .line 60
    .line 61
    .line 62
    :goto_0
    iput-object p2, p0, Lxl/f;->f:Lsl/e;

    .line 63
    .line 64
    invoke-interface {p2}, Lsl/e;->d()Z

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    iput-boolean p1, p0, Lxl/f;->g:Z

    .line 69
    .line 70
    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 71
    .line 72
    const/4 p2, 0x0

    .line 73
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 74
    .line 75
    .line 76
    iput-object p1, p0, Lxl/f;->h:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 77
    .line 78
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lxl/f;->h:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    iget-object v0, p0, Lxl/f;->d:Landroid/content/Context;

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Landroid/content/Context;->unregisterComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lxl/f;->f:Lsl/e;

    .line 17
    .line 18
    invoke-interface {p0}, Lsl/e;->shutdown()V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final onConfigurationChanged(Landroid/content/res/Configuration;)V
    .locals 0

    .line 1
    iget-object p1, p0, Lxl/f;->e:Ljava/lang/ref/WeakReference;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    check-cast p1, Lil/j;

    .line 8
    .line 9
    if-nez p1, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lxl/f;->a()V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final onLowMemory()V
    .locals 1

    .line 1
    const/16 v0, 0x50

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lxl/f;->onTrimMemory(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onTrimMemory(I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lxl/f;->e:Ljava/lang/ref/WeakReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lil/j;

    .line 8
    .line 9
    if-eqz v0, :cond_2

    .line 10
    .line 11
    iget-object v0, v0, Lil/j;->b:Llx0/q;

    .line 12
    .line 13
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Lrl/c;

    .line 18
    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    iget-object v1, v0, Lrl/c;->a:Lrl/g;

    .line 22
    .line 23
    invoke-interface {v1, p1}, Lrl/g;->f(I)V

    .line 24
    .line 25
    .line 26
    iget-object v0, v0, Lrl/c;->b:Lhm/g;

    .line 27
    .line 28
    monitor-enter v0

    .line 29
    const/16 v1, 0xa

    .line 30
    .line 31
    if-lt p1, v1, :cond_0

    .line 32
    .line 33
    const/16 v1, 0x14

    .line 34
    .line 35
    if-eq p1, v1, :cond_0

    .line 36
    .line 37
    :try_start_0
    invoke-virtual {v0}, Lhm/g;->a()V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :catchall_0
    move-exception p0

    .line 42
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    throw p0

    .line 44
    :cond_0
    :goto_0
    monitor-exit v0

    .line 45
    :cond_1
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    const/4 p1, 0x0

    .line 49
    :goto_1
    if-nez p1, :cond_3

    .line 50
    .line 51
    invoke-virtual {p0}, Lxl/f;->a()V

    .line 52
    .line 53
    .line 54
    :cond_3
    return-void
.end method
