.class public final Lpt/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/app/Application$ActivityLifecycleCallbacks;


# static fields
.field public static final u:Lst/a;

.field public static volatile v:Lpt/c;


# instance fields
.field public final d:Ljava/util/WeakHashMap;

.field public final e:Ljava/util/WeakHashMap;

.field public final f:Ljava/util/WeakHashMap;

.field public final g:Ljava/util/WeakHashMap;

.field public final h:Ljava/util/HashMap;

.field public final i:Ljava/util/HashSet;

.field public final j:Ljava/util/HashSet;

.field public final k:Ljava/util/concurrent/atomic/AtomicInteger;

.field public final l:Lyt/h;

.field public final m:Lqt/a;

.field public final n:La61/a;

.field public final o:Z

.field public p:Lzt/h;

.field public q:Lzt/h;

.field public r:Lau/i;

.field public s:Z

.field public t:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lst/a;->d()Lst/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lpt/c;->u:Lst/a;

    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>(Lyt/h;La61/a;)V
    .locals 3

    .line 1
    invoke-static {}, Lqt/a;->e()Lqt/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lpt/f;->e:Lst/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    new-instance v1, Ljava/util/WeakHashMap;

    .line 11
    .line 12
    invoke-direct {v1}, Ljava/util/WeakHashMap;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object v1, p0, Lpt/c;->d:Ljava/util/WeakHashMap;

    .line 16
    .line 17
    new-instance v1, Ljava/util/WeakHashMap;

    .line 18
    .line 19
    invoke-direct {v1}, Ljava/util/WeakHashMap;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object v1, p0, Lpt/c;->e:Ljava/util/WeakHashMap;

    .line 23
    .line 24
    new-instance v1, Ljava/util/WeakHashMap;

    .line 25
    .line 26
    invoke-direct {v1}, Ljava/util/WeakHashMap;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object v1, p0, Lpt/c;->f:Ljava/util/WeakHashMap;

    .line 30
    .line 31
    new-instance v1, Ljava/util/WeakHashMap;

    .line 32
    .line 33
    invoke-direct {v1}, Ljava/util/WeakHashMap;-><init>()V

    .line 34
    .line 35
    .line 36
    iput-object v1, p0, Lpt/c;->g:Ljava/util/WeakHashMap;

    .line 37
    .line 38
    new-instance v1, Ljava/util/HashMap;

    .line 39
    .line 40
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 41
    .line 42
    .line 43
    iput-object v1, p0, Lpt/c;->h:Ljava/util/HashMap;

    .line 44
    .line 45
    new-instance v1, Ljava/util/HashSet;

    .line 46
    .line 47
    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    .line 48
    .line 49
    .line 50
    iput-object v1, p0, Lpt/c;->i:Ljava/util/HashSet;

    .line 51
    .line 52
    new-instance v1, Ljava/util/HashSet;

    .line 53
    .line 54
    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    .line 55
    .line 56
    .line 57
    iput-object v1, p0, Lpt/c;->j:Ljava/util/HashSet;

    .line 58
    .line 59
    new-instance v1, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 60
    .line 61
    const/4 v2, 0x0

    .line 62
    invoke-direct {v1, v2}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 63
    .line 64
    .line 65
    iput-object v1, p0, Lpt/c;->k:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 66
    .line 67
    sget-object v1, Lau/i;->g:Lau/i;

    .line 68
    .line 69
    iput-object v1, p0, Lpt/c;->r:Lau/i;

    .line 70
    .line 71
    iput-boolean v2, p0, Lpt/c;->s:Z

    .line 72
    .line 73
    const/4 v1, 0x1

    .line 74
    iput-boolean v1, p0, Lpt/c;->t:Z

    .line 75
    .line 76
    iput-object p1, p0, Lpt/c;->l:Lyt/h;

    .line 77
    .line 78
    iput-object p2, p0, Lpt/c;->n:La61/a;

    .line 79
    .line 80
    iput-object v0, p0, Lpt/c;->m:Lqt/a;

    .line 81
    .line 82
    iput-boolean v1, p0, Lpt/c;->o:Z

    .line 83
    .line 84
    return-void
.end method

.method public static a()Lpt/c;
    .locals 5

    .line 1
    sget-object v0, Lpt/c;->v:Lpt/c;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    const-class v0, Lpt/c;

    .line 6
    .line 7
    monitor-enter v0

    .line 8
    :try_start_0
    sget-object v1, Lpt/c;->v:Lpt/c;

    .line 9
    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    new-instance v1, Lpt/c;

    .line 13
    .line 14
    sget-object v2, Lyt/h;->v:Lyt/h;

    .line 15
    .line 16
    new-instance v3, La61/a;

    .line 17
    .line 18
    const/16 v4, 0x1c

    .line 19
    .line 20
    invoke-direct {v3, v4}, La61/a;-><init>(I)V

    .line 21
    .line 22
    .line 23
    invoke-direct {v1, v2, v3}, Lpt/c;-><init>(Lyt/h;La61/a;)V

    .line 24
    .line 25
    .line 26
    sput-object v1, Lpt/c;->v:Lpt/c;

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catchall_0
    move-exception v1

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    :goto_0
    monitor-exit v0

    .line 32
    goto :goto_2

    .line 33
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    throw v1

    .line 35
    :cond_1
    :goto_2
    sget-object v0, Lpt/c;->v:Lpt/c;

    .line 36
    .line 37
    return-object v0
.end method


# virtual methods
.method public final b(Ljava/lang/String;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lpt/c;->h:Ljava/util/HashMap;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lpt/c;->h:Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-virtual {v1, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    check-cast v1, Ljava/lang/Long;

    .line 11
    .line 12
    const-wide/16 v2, 0x1

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Lpt/c;->h:Ljava/util/HashMap;

    .line 17
    .line 18
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {p0, p1, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catchall_0
    move-exception p0

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    iget-object p0, p0, Lpt/c;->h:Ljava/util/HashMap;

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 31
    .line 32
    .line 33
    move-result-wide v4

    .line 34
    add-long/2addr v4, v2

    .line 35
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    invoke-virtual {p0, p1, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    :goto_0
    monitor-exit v0

    .line 43
    return-void

    .line 44
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    throw p0
.end method

.method public final c()V
    .locals 4

    .line 1
    iget-object v0, p0, Lpt/c;->j:Ljava/util/HashSet;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lpt/c;->j:Ljava/util/HashSet;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lpt/a;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    :try_start_1
    sget-object v1, Lot/b;->b:Lst/a;

    .line 25
    .line 26
    invoke-static {}, Lsr/f;->c()Lsr/f;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    const-class v2, Lot/b;

    .line 31
    .line 32
    invoke-virtual {v1, v2}, Lsr/f;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Lot/b;
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :catch_0
    move-exception v1

    .line 40
    :try_start_2
    sget-object v2, Lot/c;->a:Lst/a;

    .line 41
    .line 42
    const-string v3, "FirebaseApp is not initialized. Firebase Performance will not be collecting any performance metrics until initialized. %s"

    .line 43
    .line 44
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-virtual {v2, v3, v1}, Lst/a;->g(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :catchall_0
    move-exception p0

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    monitor-exit v0

    .line 55
    return-void

    .line 56
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 57
    throw p0
.end method

.method public final d(Landroid/app/Activity;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lpt/c;->g:Ljava/util/WeakHashMap;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lcom/google/firebase/perf/metrics/Trace;

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-virtual {v0, p1}, Ljava/util/WeakHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lpt/c;->e:Ljava/util/WeakHashMap;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Lpt/f;

    .line 22
    .line 23
    iget-object v0, p0, Lpt/f;->b:Lbu/c;

    .line 24
    .line 25
    iget-object v2, p0, Lpt/f;->c:Ljava/util/HashMap;

    .line 26
    .line 27
    sget-object v3, Lpt/f;->e:Lst/a;

    .line 28
    .line 29
    iget-boolean v4, p0, Lpt/f;->d:Z

    .line 30
    .line 31
    if-nez v4, :cond_1

    .line 32
    .line 33
    const-string p0, "Cannot stop because no recording was started"

    .line 34
    .line 35
    invoke-virtual {v3, p0}, Lst/a;->a(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    new-instance p0, Lzt/d;

    .line 39
    .line 40
    invoke-direct {p0}, Lzt/d;-><init>()V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    invoke-virtual {v2}, Ljava/util/HashMap;->isEmpty()Z

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-nez v4, :cond_2

    .line 49
    .line 50
    const-string v4, "Sub-recordings are still ongoing! Sub-recordings should be stopped first before stopping Activity screen trace."

    .line 51
    .line 52
    invoke-virtual {v3, v4}, Lst/a;->a(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v2}, Ljava/util/HashMap;->clear()V

    .line 56
    .line 57
    .line 58
    :cond_2
    invoke-virtual {p0}, Lpt/f;->a()Lzt/d;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    :try_start_0
    iget-object v4, p0, Lpt/f;->a:Landroid/app/Activity;

    .line 63
    .line 64
    invoke-virtual {v0, v4}, Lbu/c;->x(Landroid/app/Activity;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :catch_0
    move-exception v2

    .line 69
    instance-of v4, v2, Ljava/lang/NullPointerException;

    .line 70
    .line 71
    if-nez v4, :cond_4

    .line 72
    .line 73
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    const-string v4, "View not hardware accelerated. Unable to collect FrameMetrics. %s"

    .line 82
    .line 83
    invoke-virtual {v3, v4, v2}, Lst/a;->g(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    new-instance v2, Lzt/d;

    .line 87
    .line 88
    invoke-direct {v2}, Lzt/d;-><init>()V

    .line 89
    .line 90
    .line 91
    :goto_0
    iget-object v0, v0, Lbu/c;->e:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast v0, Lio/o;

    .line 94
    .line 95
    iget-object v3, v0, Lio/o;->e:Ljava/lang/Object;

    .line 96
    .line 97
    const/16 v3, 0x9

    .line 98
    .line 99
    new-array v3, v3, [Landroid/util/SparseIntArray;

    .line 100
    .line 101
    iput-object v3, v0, Lio/o;->e:Ljava/lang/Object;

    .line 102
    .line 103
    const/4 v0, 0x0

    .line 104
    iput-boolean v0, p0, Lpt/f;->d:Z

    .line 105
    .line 106
    move-object p0, v2

    .line 107
    :goto_1
    invoke-virtual {p0}, Lzt/d;->b()Z

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    if-nez v0, :cond_3

    .line 112
    .line 113
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    invoke-virtual {p0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    sget-object p1, Lpt/c;->u:Lst/a;

    .line 126
    .line 127
    const-string v0, "Failed to record frame data for %s."

    .line 128
    .line 129
    invoke-virtual {p1, v0, p0}, Lst/a;->g(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    return-void

    .line 133
    :cond_3
    invoke-virtual {p0}, Lzt/d;->a()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    check-cast p0, Ltt/d;

    .line 138
    .line 139
    invoke-static {v1, p0}, Lzt/g;->a(Lcom/google/firebase/perf/metrics/Trace;Ltt/d;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v1}, Lcom/google/firebase/perf/metrics/Trace;->stop()V

    .line 143
    .line 144
    .line 145
    return-void

    .line 146
    :cond_4
    throw v2
.end method

.method public final e(Ljava/lang/String;Lzt/h;Lzt/h;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lpt/c;->m:Lqt/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Lqt/a;->o()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    invoke-static {}, Lau/a0;->L()Lau/x;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {v0, p1}, Lau/x;->o(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-wide v1, p2, Lzt/h;->d:J

    .line 18
    .line 19
    invoke-virtual {v0, v1, v2}, Lau/x;->m(J)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p2, p3}, Lzt/h;->k(Lzt/h;)J

    .line 23
    .line 24
    .line 25
    move-result-wide p1

    .line 26
    invoke-virtual {v0, p1, p2}, Lau/x;->n(J)V

    .line 27
    .line 28
    .line 29
    invoke-static {}, Lcom/google/firebase/perf/session/SessionManager;->getInstance()Lcom/google/firebase/perf/session/SessionManager;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p1}, Lcom/google/firebase/perf/session/SessionManager;->perfSession()Lwt/a;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-virtual {p1}, Lwt/a;->h()Lau/w;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-virtual {v0}, Lcom/google/protobuf/n;->j()V

    .line 42
    .line 43
    .line 44
    iget-object p2, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 45
    .line 46
    check-cast p2, Lau/a0;

    .line 47
    .line 48
    invoke-static {p2, p1}, Lau/a0;->x(Lau/a0;Lau/w;)V

    .line 49
    .line 50
    .line 51
    iget-object p1, p0, Lpt/c;->k:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 52
    .line 53
    const/4 p2, 0x0

    .line 54
    invoke-virtual {p1, p2}, Ljava/util/concurrent/atomic/AtomicInteger;->getAndSet(I)I

    .line 55
    .line 56
    .line 57
    move-result p1

    .line 58
    iget-object p2, p0, Lpt/c;->h:Ljava/util/HashMap;

    .line 59
    .line 60
    monitor-enter p2

    .line 61
    :try_start_0
    iget-object p3, p0, Lpt/c;->h:Ljava/util/HashMap;

    .line 62
    .line 63
    invoke-virtual {v0}, Lcom/google/protobuf/n;->j()V

    .line 64
    .line 65
    .line 66
    iget-object v1, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 67
    .line 68
    check-cast v1, Lau/a0;

    .line 69
    .line 70
    invoke-static {v1}, Lau/a0;->t(Lau/a0;)Lcom/google/protobuf/i0;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-virtual {v1, p3}, Lcom/google/protobuf/i0;->putAll(Ljava/util/Map;)V

    .line 75
    .line 76
    .line 77
    if-eqz p1, :cond_1

    .line 78
    .line 79
    const-string p3, "_tsns"

    .line 80
    .line 81
    int-to-long v1, p1

    .line 82
    invoke-virtual {v0, v1, v2, p3}, Lau/x;->l(JLjava/lang/String;)V

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :catchall_0
    move-exception p0

    .line 87
    goto :goto_1

    .line 88
    :cond_1
    :goto_0
    iget-object p1, p0, Lpt/c;->h:Ljava/util/HashMap;

    .line 89
    .line 90
    invoke-virtual {p1}, Ljava/util/HashMap;->clear()V

    .line 91
    .line 92
    .line 93
    monitor-exit p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 94
    iget-object p0, p0, Lpt/c;->l:Lyt/h;

    .line 95
    .line 96
    invoke-virtual {v0}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    check-cast p1, Lau/a0;

    .line 101
    .line 102
    sget-object p2, Lau/i;->h:Lau/i;

    .line 103
    .line 104
    invoke-virtual {p0, p1, p2}, Lyt/h;->c(Lau/a0;Lau/i;)V

    .line 105
    .line 106
    .line 107
    return-void

    .line 108
    :goto_1
    :try_start_1
    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 109
    throw p0
.end method

.method public final f(Landroid/app/Activity;)V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lpt/c;->o:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lpt/c;->m:Lqt/a;

    .line 6
    .line 7
    invoke-virtual {v0}, Lqt/a;->o()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    new-instance v0, Lpt/f;

    .line 14
    .line 15
    invoke-direct {v0, p1}, Lpt/f;-><init>(Landroid/app/Activity;)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lpt/c;->e:Ljava/util/WeakHashMap;

    .line 19
    .line 20
    invoke-virtual {v1, p1, v0}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    instance-of v1, p1, Landroidx/fragment/app/o0;

    .line 24
    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    new-instance v1, Lpt/e;

    .line 28
    .line 29
    iget-object v2, p0, Lpt/c;->n:La61/a;

    .line 30
    .line 31
    iget-object v3, p0, Lpt/c;->l:Lyt/h;

    .line 32
    .line 33
    invoke-direct {v1, v2, v3, p0, v0}, Lpt/e;-><init>(La61/a;Lyt/h;Lpt/c;Lpt/f;)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lpt/c;->f:Ljava/util/WeakHashMap;

    .line 37
    .line 38
    invoke-virtual {p0, p1, v1}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    check-cast p1, Landroidx/fragment/app/o0;

    .line 42
    .line 43
    invoke-virtual {p1}, Landroidx/fragment/app/o0;->getSupportFragmentManager()Landroidx/fragment/app/j1;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    iget-object p0, p0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 48
    .line 49
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 53
    .line 54
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 55
    .line 56
    new-instance p1, Landroidx/fragment/app/w0;

    .line 57
    .line 58
    invoke-direct {p1, v1}, Landroidx/fragment/app/w0;-><init>(Lpt/e;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0, p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    :cond_0
    return-void
.end method

.method public final g(Lau/i;)V
    .locals 3

    .line 1
    iput-object p1, p0, Lpt/c;->r:Lau/i;

    .line 2
    .line 3
    iget-object p1, p0, Lpt/c;->i:Ljava/util/HashSet;

    .line 4
    .line 5
    monitor-enter p1

    .line 6
    :try_start_0
    iget-object v0, p0, Lpt/c;->i:Ljava/util/HashSet;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_1

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    check-cast v1, Ljava/lang/ref/WeakReference;

    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Lpt/b;

    .line 29
    .line 30
    if-eqz v1, :cond_0

    .line 31
    .line 32
    iget-object v2, p0, Lpt/c;->r:Lau/i;

    .line 33
    .line 34
    invoke-interface {v1, v2}, Lpt/b;->onUpdateAppState(Lau/i;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :catchall_0
    move-exception p0

    .line 39
    goto :goto_1

    .line 40
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->remove()V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    monitor-exit p1

    .line 45
    return-void

    .line 46
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 47
    throw p0
.end method

.method public final onActivityCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lpt/c;->f(Landroid/app/Activity;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final onActivityDestroyed(Landroid/app/Activity;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lpt/c;->e:Ljava/util/WeakHashMap;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/WeakHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lpt/c;->f:Ljava/util/WeakHashMap;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/util/WeakHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_2

    .line 13
    .line 14
    move-object v0, p1

    .line 15
    check-cast v0, Landroidx/fragment/app/o0;

    .line 16
    .line 17
    invoke-virtual {v0}, Landroidx/fragment/app/o0;->getSupportFragmentManager()Landroidx/fragment/app/j1;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iget-object p0, p0, Lpt/c;->f:Ljava/util/WeakHashMap;

    .line 22
    .line 23
    invoke-virtual {p0, p1}, Ljava/util/WeakHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Landroidx/fragment/app/e1;

    .line 28
    .line 29
    iget-object p1, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 30
    .line 31
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const-string v0, "cb"

    .line 35
    .line 36
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-object v0, p1, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 40
    .line 41
    check-cast v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 42
    .line 43
    monitor-enter v0

    .line 44
    :try_start_0
    iget-object v1, p1, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 45
    .line 46
    check-cast v1, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 47
    .line 48
    invoke-virtual {v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->size()I

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    const/4 v2, 0x0

    .line 53
    :goto_0
    if-ge v2, v1, :cond_1

    .line 54
    .line 55
    iget-object v3, p1, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 56
    .line 57
    check-cast v3, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 58
    .line 59
    invoke-virtual {v3, v2}, Ljava/util/concurrent/CopyOnWriteArrayList;->get(I)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    check-cast v3, Landroidx/fragment/app/w0;

    .line 64
    .line 65
    iget-object v3, v3, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 66
    .line 67
    if-ne v3, p0, :cond_0

    .line 68
    .line 69
    iget-object p0, p1, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 70
    .line 71
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 72
    .line 73
    invoke-virtual {p0, v2}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(I)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :catchall_0
    move-exception p0

    .line 78
    goto :goto_2

    .line 79
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_1
    :goto_1
    monitor-exit v0

    .line 83
    return-void

    .line 84
    :goto_2
    monitor-exit v0

    .line 85
    throw p0

    .line 86
    :cond_2
    return-void
.end method

.method public final onActivityPaused(Landroid/app/Activity;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final declared-synchronized onActivityResumed(Landroid/app/Activity;)V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lpt/c;->d:Ljava/util/WeakHashMap;

    .line 3
    .line 4
    invoke-virtual {v0}, Ljava/util/WeakHashMap;->isEmpty()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    iget-object v0, p0, Lpt/c;->n:La61/a;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    new-instance v0, Lzt/h;

    .line 16
    .line 17
    invoke-direct {v0}, Lzt/h;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lpt/c;->p:Lzt/h;

    .line 21
    .line 22
    iget-object v0, p0, Lpt/c;->d:Ljava/util/WeakHashMap;

    .line 23
    .line 24
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 25
    .line 26
    invoke-virtual {v0, p1, v1}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    iget-boolean p1, p0, Lpt/c;->t:Z

    .line 30
    .line 31
    if-eqz p1, :cond_0

    .line 32
    .line 33
    sget-object p1, Lau/i;->f:Lau/i;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lpt/c;->g(Lau/i;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0}, Lpt/c;->c()V

    .line 39
    .line 40
    .line 41
    const/4 p1, 0x0

    .line 42
    iput-boolean p1, p0, Lpt/c;->t:Z

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catchall_0
    move-exception p1

    .line 46
    goto :goto_1

    .line 47
    :cond_0
    const-string p1, "_bs"

    .line 48
    .line 49
    iget-object v0, p0, Lpt/c;->q:Lzt/h;

    .line 50
    .line 51
    iget-object v1, p0, Lpt/c;->p:Lzt/h;

    .line 52
    .line 53
    invoke-virtual {p0, p1, v0, v1}, Lpt/c;->e(Ljava/lang/String;Lzt/h;Lzt/h;)V

    .line 54
    .line 55
    .line 56
    sget-object p1, Lau/i;->f:Lau/i;

    .line 57
    .line 58
    invoke-virtual {p0, p1}, Lpt/c;->g(Lau/i;)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_1
    iget-object v0, p0, Lpt/c;->d:Ljava/util/WeakHashMap;

    .line 63
    .line 64
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 65
    .line 66
    invoke-virtual {v0, p1, v1}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 67
    .line 68
    .line 69
    :goto_0
    monitor-exit p0

    .line 70
    return-void

    .line 71
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 72
    throw p1
.end method

.method public final onActivitySaveInstanceState(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final declared-synchronized onActivityStarted(Landroid/app/Activity;)V
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lpt/c;->o:Z

    .line 3
    .line 4
    if-eqz v0, :cond_1

    .line 5
    .line 6
    iget-object v0, p0, Lpt/c;->m:Lqt/a;

    .line 7
    .line 8
    invoke-virtual {v0}, Lqt/a;->o()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    iget-object v0, p0, Lpt/c;->e:Ljava/util/WeakHashMap;

    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/util/WeakHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {p0, p1}, Lpt/c;->f(Landroid/app/Activity;)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catchall_0
    move-exception p1

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    :goto_0
    iget-object v0, p0, Lpt/c;->e:Ljava/util/WeakHashMap;

    .line 29
    .line 30
    invoke-virtual {v0, p1}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    check-cast v0, Lpt/f;

    .line 35
    .line 36
    invoke-virtual {v0}, Lpt/f;->b()V

    .line 37
    .line 38
    .line 39
    new-instance v0, Lcom/google/firebase/perf/metrics/Trace;

    .line 40
    .line 41
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    const-string v2, "_st_"

    .line 50
    .line 51
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    iget-object v2, p0, Lpt/c;->l:Lyt/h;

    .line 56
    .line 57
    iget-object v3, p0, Lpt/c;->n:La61/a;

    .line 58
    .line 59
    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/firebase/perf/metrics/Trace;-><init>(Ljava/lang/String;Lyt/h;La61/a;Lpt/c;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v0}, Lcom/google/firebase/perf/metrics/Trace;->start()V

    .line 63
    .line 64
    .line 65
    iget-object v1, p0, Lpt/c;->g:Ljava/util/WeakHashMap;

    .line 66
    .line 67
    invoke-virtual {v1, p1, v0}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 68
    .line 69
    .line 70
    :cond_1
    monitor-exit p0

    .line 71
    return-void

    .line 72
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 73
    throw p1
.end method

.method public final declared-synchronized onActivityStopped(Landroid/app/Activity;)V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lpt/c;->o:Z

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lpt/c;->d(Landroid/app/Activity;)V

    .line 7
    .line 8
    .line 9
    goto :goto_0

    .line 10
    :catchall_0
    move-exception p1

    .line 11
    goto :goto_1

    .line 12
    :cond_0
    :goto_0
    iget-object v0, p0, Lpt/c;->d:Ljava/util/WeakHashMap;

    .line 13
    .line 14
    invoke-virtual {v0, p1}, Ljava/util/WeakHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    iget-object v0, p0, Lpt/c;->d:Ljava/util/WeakHashMap;

    .line 21
    .line 22
    invoke-virtual {v0, p1}, Ljava/util/WeakHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    iget-object p1, p0, Lpt/c;->d:Ljava/util/WeakHashMap;

    .line 26
    .line 27
    invoke-virtual {p1}, Ljava/util/WeakHashMap;->isEmpty()Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    iget-object p1, p0, Lpt/c;->n:La61/a;

    .line 34
    .line 35
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    new-instance p1, Lzt/h;

    .line 39
    .line 40
    invoke-direct {p1}, Lzt/h;-><init>()V

    .line 41
    .line 42
    .line 43
    iput-object p1, p0, Lpt/c;->q:Lzt/h;

    .line 44
    .line 45
    const-string v0, "_fs"

    .line 46
    .line 47
    iget-object v1, p0, Lpt/c;->p:Lzt/h;

    .line 48
    .line 49
    invoke-virtual {p0, v0, v1, p1}, Lpt/c;->e(Ljava/lang/String;Lzt/h;Lzt/h;)V

    .line 50
    .line 51
    .line 52
    sget-object p1, Lau/i;->g:Lau/i;

    .line 53
    .line 54
    invoke-virtual {p0, p1}, Lpt/c;->g(Lau/i;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 55
    .line 56
    .line 57
    :cond_1
    monitor-exit p0

    .line 58
    return-void

    .line 59
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 60
    throw p1
.end method
