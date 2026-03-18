.class public final Lsm/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/app/Application$ActivityLifecycleCallbacks;


# instance fields
.field public final d:D

.field public final synthetic e:Lvv0/d;


# direct methods
.method public constructor <init>(Lvv0/d;Lyl/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lsm/a;->e:Lvv0/d;

    .line 5
    .line 6
    iget-object p1, p2, Lyl/r;->a:Lyl/o;

    .line 7
    .line 8
    sget-object p2, Lyl/n;->a:Ld8/c;

    .line 9
    .line 10
    iget-object p1, p1, Lyl/o;->b:Lmm/e;

    .line 11
    .line 12
    iget-object p1, p1, Lmm/e;->n:Lyl/i;

    .line 13
    .line 14
    sget-object p2, Lyl/n;->d:Ld8/c;

    .line 15
    .line 16
    iget-object p1, p1, Lyl/i;->a:Ljava/util/Map;

    .line 17
    .line 18
    invoke-interface {p1, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    if-nez p1, :cond_0

    .line 23
    .line 24
    const-wide/high16 p1, 0x3ff0000000000000L    # 1.0

    .line 25
    .line 26
    invoke-static {p1, p2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    :cond_0
    check-cast p1, Ljava/lang/Number;

    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/Number;->doubleValue()D

    .line 33
    .line 34
    .line 35
    move-result-wide p1

    .line 36
    iput-wide p1, p0, Lsm/a;->d:D

    .line 37
    .line 38
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;)V
    .locals 4

    .line 1
    iget-wide v0, p0, Lsm/a;->d:D

    .line 2
    .line 3
    const-wide/high16 v2, 0x3ff0000000000000L    # 1.0

    .line 4
    .line 5
    cmpg-double v2, v0, v2

    .line 6
    .line 7
    if-nez v2, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const-string v2, "null cannot be cast to non-null type android.app.Application"

    .line 15
    .line 16
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    check-cast p1, Landroid/app/Application;

    .line 20
    .line 21
    invoke-virtual {p1, p0}, Landroid/app/Application;->registerActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Lsm/a;->e:Lvv0/d;

    .line 25
    .line 26
    iget-object p1, p0, Lvv0/d;->b:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p1, Ljava/lang/ref/WeakReference;

    .line 29
    .line 30
    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    check-cast p1, Lyl/r;

    .line 35
    .line 36
    if-eqz p1, :cond_2

    .line 37
    .line 38
    invoke-virtual {p1}, Lyl/r;->c()Lhm/d;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    if-eqz p0, :cond_1

    .line 43
    .line 44
    iget-object p1, p0, Lhm/d;->c:Ljava/lang/Object;

    .line 45
    .line 46
    monitor-enter p1

    .line 47
    :try_start_0
    iget-object v2, p0, Lhm/d;->a:Lh6/j;

    .line 48
    .line 49
    iget-wide v2, v2, Lh6/j;->d:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 50
    .line 51
    monitor-exit p1

    .line 52
    long-to-double v2, v2

    .line 53
    mul-double/2addr v0, v2

    .line 54
    double-to-long v0, v0

    .line 55
    invoke-virtual {p0, v0, v1}, Lhm/d;->a(J)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :catchall_0
    move-exception p0

    .line 60
    monitor-exit p1

    .line 61
    throw p0

    .line 62
    :cond_1
    :goto_0
    return-void

    .line 63
    :cond_2
    invoke-virtual {p0}, Lvv0/d;->k()V

    .line 64
    .line 65
    .line 66
    return-void
.end method

.method public final b(Landroid/content/Context;)V
    .locals 4

    .line 1
    iget-wide v0, p0, Lsm/a;->d:D

    .line 2
    .line 3
    const-wide/high16 v2, 0x3ff0000000000000L    # 1.0

    .line 4
    .line 5
    cmpg-double v0, v0, v2

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const-string v0, "null cannot be cast to non-null type android.app.Application"

    .line 15
    .line 16
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    check-cast p1, Landroid/app/Application;

    .line 20
    .line 21
    invoke-virtual {p1, p0}, Landroid/app/Application;->unregisterActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Lsm/a;->e:Lvv0/d;

    .line 25
    .line 26
    iget-object p1, p0, Lvv0/d;->b:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p1, Ljava/lang/ref/WeakReference;

    .line 29
    .line 30
    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    check-cast p1, Lyl/r;

    .line 35
    .line 36
    if-eqz p1, :cond_2

    .line 37
    .line 38
    invoke-virtual {p1}, Lyl/r;->c()Lhm/d;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    if-eqz p0, :cond_1

    .line 43
    .line 44
    iget-object p1, p0, Lhm/d;->c:Ljava/lang/Object;

    .line 45
    .line 46
    monitor-enter p1

    .line 47
    :try_start_0
    iget-object v0, p0, Lhm/d;->a:Lh6/j;

    .line 48
    .line 49
    iget-wide v0, v0, Lh6/j;->d:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 50
    .line 51
    monitor-exit p1

    .line 52
    invoke-virtual {p0, v0, v1}, Lhm/d;->a(J)V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :catchall_0
    move-exception p0

    .line 57
    monitor-exit p1

    .line 58
    throw p0

    .line 59
    :cond_1
    :goto_0
    return-void

    .line 60
    :cond_2
    invoke-virtual {p0}, Lvv0/d;->k()V

    .line 61
    .line 62
    .line 63
    return-void
.end method

.method public final onActivityCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onActivityDestroyed(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onActivityPaused(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onActivityResumed(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onActivitySaveInstanceState(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onActivityStarted(Landroid/app/Activity;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lsm/a;->b(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final onActivityStopped(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method
