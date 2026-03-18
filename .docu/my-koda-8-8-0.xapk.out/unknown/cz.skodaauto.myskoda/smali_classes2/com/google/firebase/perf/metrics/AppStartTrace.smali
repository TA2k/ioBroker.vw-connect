.class public Lcom/google/firebase/perf/metrics/AppStartTrace;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/app/Application$ActivityLifecycleCallbacks;
.implements Landroidx/lifecycle/w;


# static fields
.field public static final A:J

.field public static final B:J

.field public static volatile C:Lcom/google/firebase/perf/metrics/AppStartTrace;

.field public static D:Ljava/util/concurrent/ThreadPoolExecutor;

.field public static final z:Lzt/h;


# instance fields
.field public d:Z

.field public final e:Lyt/h;

.field public final f:Lqt/a;

.field public final g:Lau/x;

.field public h:Landroid/app/Application;

.field public i:Z

.field public final j:Lzt/h;

.field public final k:Lzt/h;

.field public l:Lzt/h;

.field public m:Lzt/h;

.field public n:Lzt/h;

.field public o:Lzt/h;

.field public p:Lzt/h;

.field public q:Lzt/h;

.field public r:Lzt/h;

.field public s:Lzt/h;

.field public t:Lzt/h;

.field public u:Lwt/a;

.field public v:Z

.field public w:I

.field public final x:Ltt/b;

.field public y:Z


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lzt/h;

    .line 2
    .line 3
    invoke-direct {v0}, Lzt/h;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/firebase/perf/metrics/AppStartTrace;->z:Lzt/h;

    .line 7
    .line 8
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MINUTES:Ljava/util/concurrent/TimeUnit;

    .line 9
    .line 10
    const-wide/16 v1, 0x1

    .line 11
    .line 12
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toMicros(J)J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    sput-wide v0, Lcom/google/firebase/perf/metrics/AppStartTrace;->A:J

    .line 17
    .line 18
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 19
    .line 20
    const-wide/16 v1, 0x32

    .line 21
    .line 22
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toMicros(J)J

    .line 23
    .line 24
    .line 25
    move-result-wide v0

    .line 26
    sput-wide v0, Lcom/google/firebase/perf/metrics/AppStartTrace;->B:J

    .line 27
    .line 28
    return-void
.end method

.method public constructor <init>(Lyt/h;La61/a;Lqt/a;Ljava/util/concurrent/ThreadPoolExecutor;)V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 p2, 0x0

    .line 5
    iput-boolean p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->d:Z

    .line 6
    .line 7
    iput-boolean p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->i:Z

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    iput-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->l:Lzt/h;

    .line 11
    .line 12
    iput-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->m:Lzt/h;

    .line 13
    .line 14
    iput-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->n:Lzt/h;

    .line 15
    .line 16
    iput-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->o:Lzt/h;

    .line 17
    .line 18
    iput-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->p:Lzt/h;

    .line 19
    .line 20
    iput-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->q:Lzt/h;

    .line 21
    .line 22
    iput-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->r:Lzt/h;

    .line 23
    .line 24
    iput-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->s:Lzt/h;

    .line 25
    .line 26
    iput-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->t:Lzt/h;

    .line 27
    .line 28
    iput-boolean p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->v:Z

    .line 29
    .line 30
    iput p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->w:I

    .line 31
    .line 32
    new-instance v1, Ltt/b;

    .line 33
    .line 34
    invoke-direct {v1, p0}, Ltt/b;-><init>(Lcom/google/firebase/perf/metrics/AppStartTrace;)V

    .line 35
    .line 36
    .line 37
    iput-object v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->x:Ltt/b;

    .line 38
    .line 39
    iput-boolean p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->y:Z

    .line 40
    .line 41
    iput-object p1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->e:Lyt/h;

    .line 42
    .line 43
    iput-object p3, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->f:Lqt/a;

    .line 44
    .line 45
    sput-object p4, Lcom/google/firebase/perf/metrics/AppStartTrace;->D:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 46
    .line 47
    invoke-static {}, Lau/a0;->L()Lau/x;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    const-string p2, "_experiment_app_start_ttid"

    .line 52
    .line 53
    invoke-virtual {p1, p2}, Lau/x;->o(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iput-object p1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->g:Lau/x;

    .line 57
    .line 58
    invoke-static {}, Landroid/os/Process;->getStartElapsedRealtime()J

    .line 59
    .line 60
    .line 61
    move-result-wide p1

    .line 62
    sget-object p3, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 63
    .line 64
    invoke-virtual {p3, p1, p2}, Ljava/util/concurrent/TimeUnit;->toMicros(J)J

    .line 65
    .line 66
    .line 67
    move-result-wide p1

    .line 68
    invoke-static {}, Lzt/h;->m()J

    .line 69
    .line 70
    .line 71
    move-result-wide v1

    .line 72
    invoke-static {}, Lzt/h;->h()J

    .line 73
    .line 74
    .line 75
    move-result-wide v3

    .line 76
    sub-long v3, p1, v3

    .line 77
    .line 78
    add-long/2addr v3, v1

    .line 79
    new-instance p4, Lzt/h;

    .line 80
    .line 81
    invoke-direct {p4, v3, v4, p1, p2}, Lzt/h;-><init>(JJ)V

    .line 82
    .line 83
    .line 84
    iput-object p4, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->j:Lzt/h;

    .line 85
    .line 86
    invoke-static {}, Lsr/f;->c()Lsr/f;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    const-class p2, Lsr/a;

    .line 91
    .line 92
    invoke-virtual {p1, p2}, Lsr/f;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    check-cast p1, Lsr/a;

    .line 97
    .line 98
    if-eqz p1, :cond_0

    .line 99
    .line 100
    iget-wide p1, p1, Lsr/a;->b:J

    .line 101
    .line 102
    invoke-virtual {p3, p1, p2}, Ljava/util/concurrent/TimeUnit;->toMicros(J)J

    .line 103
    .line 104
    .line 105
    move-result-wide p1

    .line 106
    invoke-static {}, Lzt/h;->m()J

    .line 107
    .line 108
    .line 109
    move-result-wide p3

    .line 110
    invoke-static {}, Lzt/h;->h()J

    .line 111
    .line 112
    .line 113
    move-result-wide v0

    .line 114
    sub-long v0, p1, v0

    .line 115
    .line 116
    add-long/2addr v0, p3

    .line 117
    new-instance p3, Lzt/h;

    .line 118
    .line 119
    invoke-direct {p3, v0, v1, p1, p2}, Lzt/h;-><init>(JJ)V

    .line 120
    .line 121
    .line 122
    move-object v0, p3

    .line 123
    :cond_0
    iput-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->k:Lzt/h;

    .line 124
    .line 125
    return-void
.end method

.method public static c(Landroid/app/Application;)Z
    .locals 5

    .line 1
    const-string v0, "activity"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Landroid/app/ActivityManager;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_0
    invoke-virtual {v0}, Landroid/app/ActivityManager;->getRunningAppProcesses()Ljava/util/List;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    if-eqz v0, :cond_4

    .line 17
    .line 18
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    const-string v1, ":"

    .line 23
    .line 24
    invoke-static {p0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    check-cast v2, Landroid/app/ActivityManager$RunningAppProcessInfo;

    .line 43
    .line 44
    iget v3, v2, Landroid/app/ActivityManager$RunningAppProcessInfo;->importance:I

    .line 45
    .line 46
    const/16 v4, 0x64

    .line 47
    .line 48
    if-eq v3, v4, :cond_2

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    iget-object v3, v2, Landroid/app/ActivityManager$RunningAppProcessInfo;->processName:Ljava/lang/String;

    .line 52
    .line 53
    invoke-virtual {v3, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    if-nez v3, :cond_3

    .line 58
    .line 59
    iget-object v2, v2, Landroid/app/ActivityManager$RunningAppProcessInfo;->processName:Ljava/lang/String;

    .line 60
    .line 61
    invoke-virtual {v2, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-eqz v2, :cond_1

    .line 66
    .line 67
    :cond_3
    :goto_1
    const/4 p0, 0x1

    .line 68
    return p0

    .line 69
    :cond_4
    const/4 p0, 0x0

    .line 70
    return p0
.end method

.method public static setLauncherActivityOnCreateTime(Ljava/lang/String;)V
    .locals 0
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 1
    return-void
.end method

.method public static setLauncherActivityOnResumeTime(Ljava/lang/String;)V
    .locals 0
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 1
    return-void
.end method

.method public static setLauncherActivityOnStartTime(Ljava/lang/String;)V
    .locals 0
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final a()Lzt/h;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->k:Lzt/h;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    sget-object p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->z:Lzt/h;

    .line 7
    .line 8
    return-object p0
.end method

.method public final b()Lzt/h;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->j:Lzt/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->a()Lzt/h;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final d(Lau/x;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->r:Lzt/h;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->s:Lzt/h;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->t:Lzt/h;

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    sget-object v0, Lcom/google/firebase/perf/metrics/AppStartTrace;->D:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 15
    .line 16
    new-instance v1, Lno/nordicsemi/android/ble/o0;

    .line 17
    .line 18
    const/16 v2, 0xb

    .line 19
    .line 20
    invoke-direct {v1, v2, p0, p1}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v1}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->e()V

    .line 27
    .line 28
    .line 29
    :cond_1
    :goto_0
    return-void
.end method

.method public final declared-synchronized e()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->d:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return-void

    .line 8
    :cond_0
    :try_start_1
    sget-object v0, Landroidx/lifecycle/m0;->k:Landroidx/lifecycle/m0;

    .line 9
    .line 10
    iget-object v0, v0, Landroidx/lifecycle/m0;->i:Landroidx/lifecycle/z;

    .line 11
    .line 12
    invoke-virtual {v0, p0}, Landroidx/lifecycle/z;->d(Landroidx/lifecycle/w;)V

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->h:Landroid/app/Application;

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Landroid/app/Application;->unregisterActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    iput-boolean v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->d:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 22
    .line 23
    monitor-exit p0

    .line 24
    return-void

    .line 25
    :catchall_0
    move-exception v0

    .line 26
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 27
    throw v0
.end method

.method public final declared-synchronized onActivityCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 5

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->m:Lzt/h;

    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    if-nez p2, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 9
    .line 10
    const/16 v2, 0x22

    .line 11
    .line 12
    if-lt v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {p2}, Lzt/h;->j()J

    .line 15
    .line 16
    .line 17
    move-result-wide v1

    .line 18
    sget-wide v3, Lcom/google/firebase/perf/metrics/AppStartTrace;->B:J

    .line 19
    .line 20
    cmp-long p2, v1, v3

    .line 21
    .line 22
    if-lez p2, :cond_2

    .line 23
    .line 24
    :cond_1
    iput-boolean v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->v:Z

    .line 25
    .line 26
    :cond_2
    const/4 p2, 0x0

    .line 27
    iput-object p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->m:Lzt/h;

    .line 28
    .line 29
    :goto_0
    iget-boolean p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->v:Z

    .line 30
    .line 31
    if-nez p2, :cond_7

    .line 32
    .line 33
    iget-object p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->l:Lzt/h;

    .line 34
    .line 35
    if-eqz p2, :cond_3

    .line 36
    .line 37
    goto :goto_3

    .line 38
    :cond_3
    iget-boolean p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->y:Z

    .line 39
    .line 40
    if-nez p2, :cond_5

    .line 41
    .line 42
    iget-object p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->h:Landroid/app/Application;

    .line 43
    .line 44
    invoke-static {p2}, Lcom/google/firebase/perf/metrics/AppStartTrace;->c(Landroid/app/Application;)Z

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    if-eqz p2, :cond_4

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_4
    const/4 p2, 0x0

    .line 52
    goto :goto_2

    .line 53
    :catchall_0
    move-exception p1

    .line 54
    goto :goto_4

    .line 55
    :cond_5
    :goto_1
    move p2, v0

    .line 56
    :goto_2
    iput-boolean p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->y:Z

    .line 57
    .line 58
    new-instance p2, Ljava/lang/ref/WeakReference;

    .line 59
    .line 60
    invoke-direct {p2, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    new-instance p1, Lzt/h;

    .line 64
    .line 65
    invoke-direct {p1}, Lzt/h;-><init>()V

    .line 66
    .line 67
    .line 68
    iput-object p1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->l:Lzt/h;

    .line 69
    .line 70
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    iget-object p2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->l:Lzt/h;

    .line 75
    .line 76
    invoke-virtual {p1, p2}, Lzt/h;->k(Lzt/h;)J

    .line 77
    .line 78
    .line 79
    move-result-wide p1

    .line 80
    sget-wide v1, Lcom/google/firebase/perf/metrics/AppStartTrace;->A:J

    .line 81
    .line 82
    cmp-long p1, p1, v1

    .line 83
    .line 84
    if-lez p1, :cond_6

    .line 85
    .line 86
    iput-boolean v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->i:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 87
    .line 88
    :cond_6
    monitor-exit p0

    .line 89
    return-void

    .line 90
    :cond_7
    :goto_3
    monitor-exit p0

    .line 91
    return-void

    .line 92
    :goto_4
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 93
    throw p1
.end method

.method public final onActivityDestroyed(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onActivityPaused(Landroid/app/Activity;)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->v:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->i:Z

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->f:Lqt/a;

    .line 10
    .line 11
    invoke-virtual {v0}, Lqt/a;->f()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const v0, 0x1020002

    .line 19
    .line 20
    .line 21
    invoke-virtual {p1, v0}, Landroid/app/Activity;->findViewById(I)Landroid/view/View;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    if-eqz p1, :cond_1

    .line 26
    .line 27
    invoke-virtual {p1}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    iget-object p0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->x:Ltt/b;

    .line 32
    .line 33
    invoke-virtual {p1, p0}, Landroid/view/ViewTreeObserver;->removeOnDrawListener(Landroid/view/ViewTreeObserver$OnDrawListener;)V

    .line 34
    .line 35
    .line 36
    :cond_1
    :goto_0
    return-void
.end method

.method public final declared-synchronized onActivityResumed(Landroid/app/Activity;)V
    .locals 6

    .line 1
    const-string v0, "onResume(): "

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->v:Z

    .line 5
    .line 6
    if-nez v1, :cond_4

    .line 7
    .line 8
    iget-boolean v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->i:Z

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    goto/16 :goto_1

    .line 13
    .line 14
    :cond_0
    iget-object v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->f:Lqt/a;

    .line 15
    .line 16
    invoke-virtual {v1}, Lqt/a;->f()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    const v2, 0x1020002

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, v2}, Landroid/app/Activity;->findViewById(I)Landroid/view/View;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    if-eqz v2, :cond_1

    .line 30
    .line 31
    invoke-virtual {v2}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    iget-object v4, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->x:Ltt/b;

    .line 36
    .line 37
    invoke-virtual {v3, v4}, Landroid/view/ViewTreeObserver;->addOnDrawListener(Landroid/view/ViewTreeObserver$OnDrawListener;)V

    .line 38
    .line 39
    .line 40
    new-instance v3, Ltt/a;

    .line 41
    .line 42
    const/4 v4, 0x0

    .line 43
    invoke-direct {v3, p0, v4}, Ltt/a;-><init>(Lcom/google/firebase/perf/metrics/AppStartTrace;I)V

    .line 44
    .line 45
    .line 46
    new-instance v4, Lzt/b;

    .line 47
    .line 48
    invoke-direct {v4, v2, v3}, Lzt/b;-><init>(Landroid/view/View;Ltt/a;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v2}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    invoke-virtual {v3, v4}, Landroid/view/ViewTreeObserver;->addOnDrawListener(Landroid/view/ViewTreeObserver$OnDrawListener;)V

    .line 56
    .line 57
    .line 58
    new-instance v3, Ltt/a;

    .line 59
    .line 60
    const/4 v4, 0x1

    .line 61
    invoke-direct {v3, p0, v4}, Ltt/a;-><init>(Lcom/google/firebase/perf/metrics/AppStartTrace;I)V

    .line 62
    .line 63
    .line 64
    new-instance v4, Ltt/a;

    .line 65
    .line 66
    const/4 v5, 0x2

    .line 67
    invoke-direct {v4, p0, v5}, Ltt/a;-><init>(Lcom/google/firebase/perf/metrics/AppStartTrace;I)V

    .line 68
    .line 69
    .line 70
    new-instance v5, Lzt/e;

    .line 71
    .line 72
    invoke-direct {v5, v2, v3, v4}, Lzt/e;-><init>(Landroid/view/View;Ltt/a;Ltt/a;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v2}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    invoke-virtual {v2, v5}, Landroid/view/ViewTreeObserver;->addOnPreDrawListener(Landroid/view/ViewTreeObserver$OnPreDrawListener;)V

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :catchall_0
    move-exception p1

    .line 84
    goto :goto_2

    .line 85
    :cond_1
    :goto_0
    iget-object v2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->o:Lzt/h;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 86
    .line 87
    if-eqz v2, :cond_2

    .line 88
    .line 89
    monitor-exit p0

    .line 90
    return-void

    .line 91
    :cond_2
    :try_start_1
    new-instance v2, Ljava/lang/ref/WeakReference;

    .line 92
    .line 93
    invoke-direct {v2, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    new-instance v2, Lzt/h;

    .line 97
    .line 98
    invoke-direct {v2}, Lzt/h;-><init>()V

    .line 99
    .line 100
    .line 101
    iput-object v2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->o:Lzt/h;

    .line 102
    .line 103
    invoke-static {}, Lcom/google/firebase/perf/session/SessionManager;->getInstance()Lcom/google/firebase/perf/session/SessionManager;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    invoke-virtual {v2}, Lcom/google/firebase/perf/session/SessionManager;->perfSession()Lwt/a;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    iput-object v2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->u:Lwt/a;

    .line 112
    .line 113
    invoke-static {}, Lst/a;->d()Lst/a;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    new-instance v3, Ljava/lang/StringBuilder;

    .line 118
    .line 119
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const-string p1, ": "

    .line 134
    .line 135
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->a()Lzt/h;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    iget-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->o:Lzt/h;

    .line 143
    .line 144
    invoke-virtual {p1, v0}, Lzt/h;->k(Lzt/h;)J

    .line 145
    .line 146
    .line 147
    move-result-wide v4

    .line 148
    invoke-virtual {v3, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    const-string p1, " microseconds"

    .line 152
    .line 153
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object p1

    .line 160
    invoke-virtual {v2, p1}, Lst/a;->a(Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    sget-object p1, Lcom/google/firebase/perf/metrics/AppStartTrace;->D:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 164
    .line 165
    new-instance v0, Ltt/a;

    .line 166
    .line 167
    const/4 v2, 0x3

    .line 168
    invoke-direct {v0, p0, v2}, Ltt/a;-><init>(Lcom/google/firebase/perf/metrics/AppStartTrace;I)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {p1, v0}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 172
    .line 173
    .line 174
    if-nez v1, :cond_3

    .line 175
    .line 176
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->e()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 177
    .line 178
    .line 179
    :cond_3
    monitor-exit p0

    .line 180
    return-void

    .line 181
    :cond_4
    :goto_1
    monitor-exit p0

    .line 182
    return-void

    .line 183
    :goto_2
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 184
    throw p1
.end method

.method public final onActivitySaveInstanceState(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final declared-synchronized onActivityStarted(Landroid/app/Activity;)V
    .locals 0

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean p1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->v:Z

    .line 3
    .line 4
    if-nez p1, :cond_1

    .line 5
    .line 6
    iget-object p1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->n:Lzt/h;

    .line 7
    .line 8
    if-nez p1, :cond_1

    .line 9
    .line 10
    iget-boolean p1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->i:Z

    .line 11
    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    new-instance p1, Lzt/h;

    .line 16
    .line 17
    invoke-direct {p1}, Lzt/h;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->n:Lzt/h;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    monitor-exit p0

    .line 23
    return-void

    .line 24
    :catchall_0
    move-exception p1

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    :goto_0
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
    throw p1
.end method

.method public final onActivityStopped(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method

.method public onAppEnteredBackground()V
    .locals 3
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_STOP:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    iget-boolean v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->v:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->i:Z

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->q:Lzt/h;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance v0, Lzt/h;

    .line 15
    .line 16
    invoke-direct {v0}, Lzt/h;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->q:Lzt/h;

    .line 20
    .line 21
    invoke-static {}, Lau/a0;->L()Lau/x;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    const-string v1, "_experiment_firstBackgrounding"

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Lau/x;->o(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    iget-wide v1, v1, Lzt/h;->d:J

    .line 35
    .line 36
    invoke-virtual {v0, v1, v2}, Lau/x;->m(J)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iget-object v2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->q:Lzt/h;

    .line 44
    .line 45
    invoke-virtual {v1, v2}, Lzt/h;->k(Lzt/h;)J

    .line 46
    .line 47
    .line 48
    move-result-wide v1

    .line 49
    invoke-virtual {v0, v1, v2}, Lau/x;->n(J)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    check-cast v0, Lau/a0;

    .line 57
    .line 58
    iget-object p0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->g:Lau/x;

    .line 59
    .line 60
    invoke-virtual {p0, v0}, Lau/x;->k(Lau/a0;)V

    .line 61
    .line 62
    .line 63
    :cond_1
    :goto_0
    return-void
.end method

.method public onAppEnteredForeground()V
    .locals 3
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_START:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    iget-boolean v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->v:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->i:Z

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->p:Lzt/h;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance v0, Lzt/h;

    .line 15
    .line 16
    invoke-direct {v0}, Lzt/h;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->p:Lzt/h;

    .line 20
    .line 21
    invoke-static {}, Lau/a0;->L()Lau/x;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    const-string v1, "_experiment_firstForegrounding"

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Lau/x;->o(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    iget-wide v1, v1, Lzt/h;->d:J

    .line 35
    .line 36
    invoke-virtual {v0, v1, v2}, Lau/x;->m(J)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iget-object v2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->p:Lzt/h;

    .line 44
    .line 45
    invoke-virtual {v1, v2}, Lzt/h;->k(Lzt/h;)J

    .line 46
    .line 47
    .line 48
    move-result-wide v1

    .line 49
    invoke-virtual {v0, v1, v2}, Lau/x;->n(J)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    check-cast v0, Lau/a0;

    .line 57
    .line 58
    iget-object p0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->g:Lau/x;

    .line 59
    .line 60
    invoke-virtual {p0, v0}, Lau/x;->k(Lau/a0;)V

    .line 61
    .line 62
    .line 63
    :cond_1
    :goto_0
    return-void
.end method
