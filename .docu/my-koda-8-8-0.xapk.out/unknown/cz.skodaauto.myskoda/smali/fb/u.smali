.class public final Lfb/u;
.super Lkp/g6;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static k:Lfb/u;

.field public static l:Lfb/u;

.field public static final m:Ljava/lang/Object;


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Leb/b;

.field public final c:Landroidx/work/impl/WorkDatabase;

.field public final d:Lob/a;

.field public final e:Ljava/util/List;

.field public final f:Lfb/e;

.field public final g:Lj1/a;

.field public h:Z

.field public i:Landroid/content/BroadcastReceiver$PendingResult;

.field public final j:Lkb/i;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "WorkManagerImpl"

    .line 2
    .line 3
    invoke-static {v0}, Leb/w;->f(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    sput-object v0, Lfb/u;->k:Lfb/u;

    .line 8
    .line 9
    sput-object v0, Lfb/u;->l:Lfb/u;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lfb/u;->m:Ljava/lang/Object;

    .line 17
    .line 18
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Leb/b;Lob/a;Landroidx/work/impl/WorkDatabase;Ljava/util/List;Lfb/e;Lkb/i;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lfb/u;->h:Z

    .line 6
    .line 7
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-virtual {p1}, Landroid/content/Context;->isDeviceProtectedStorage()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-nez v1, :cond_2

    .line 16
    .line 17
    new-instance v1, Leb/w;

    .line 18
    .line 19
    iget v2, p2, Leb/b;->h:I

    .line 20
    .line 21
    invoke-direct {v1, v2}, Leb/w;-><init>(I)V

    .line 22
    .line 23
    .line 24
    sget-object v2, Leb/w;->b:Ljava/lang/Object;

    .line 25
    .line 26
    monitor-enter v2

    .line 27
    :try_start_0
    sget-object v3, Leb/w;->c:Leb/w;

    .line 28
    .line 29
    if-nez v3, :cond_0

    .line 30
    .line 31
    sput-object v1, Leb/w;->c:Leb/w;

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    goto/16 :goto_1

    .line 36
    .line 37
    :cond_0
    :goto_0
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    iput-object p1, p0, Lfb/u;->a:Landroid/content/Context;

    .line 39
    .line 40
    iput-object p3, p0, Lfb/u;->d:Lob/a;

    .line 41
    .line 42
    iput-object p4, p0, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 43
    .line 44
    iput-object p6, p0, Lfb/u;->f:Lfb/e;

    .line 45
    .line 46
    iput-object p7, p0, Lfb/u;->j:Lkb/i;

    .line 47
    .line 48
    iput-object p2, p0, Lfb/u;->b:Leb/b;

    .line 49
    .line 50
    iput-object p5, p0, Lfb/u;->e:Ljava/util/List;

    .line 51
    .line 52
    iget-object p7, p3, Lob/a;->b:Lvy0/x;

    .line 53
    .line 54
    const-string v1, "getTaskCoroutineDispatcher(...)"

    .line 55
    .line 56
    invoke-static {p7, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-static {p7}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 60
    .line 61
    .line 62
    move-result-object p7

    .line 63
    new-instance v1, Lj1/a;

    .line 64
    .line 65
    const/16 v2, 0x14

    .line 66
    .line 67
    invoke-direct {v1, p4, v2}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 68
    .line 69
    .line 70
    iput-object v1, p0, Lfb/u;->g:Lj1/a;

    .line 71
    .line 72
    iget-object v1, p3, Lob/a;->a:Lla/a0;

    .line 73
    .line 74
    sget-object v3, Lfb/i;->a:Ljava/lang/String;

    .line 75
    .line 76
    new-instance v3, Lfb/h;

    .line 77
    .line 78
    invoke-direct {v3, v1, p5, p2, p4}, Lfb/h;-><init>(Ljava/util/concurrent/Executor;Ljava/util/List;Leb/b;Landroidx/work/impl/WorkDatabase;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p6, v3}, Lfb/e;->a(Lfb/b;)V

    .line 82
    .line 83
    .line 84
    new-instance p5, Lnb/b;

    .line 85
    .line 86
    invoke-direct {p5, p1, p0}, Lnb/b;-><init>(Landroid/content/Context;Lfb/u;)V

    .line 87
    .line 88
    .line 89
    iget-object p0, p3, Lob/a;->a:Lla/a0;

    .line 90
    .line 91
    invoke-virtual {p0, p5}, Lla/a0;->execute(Ljava/lang/Runnable;)V

    .line 92
    .line 93
    .line 94
    sget-object p0, Lfb/n;->a:Ljava/lang/String;

    .line 95
    .line 96
    invoke-static {p1, p2}, Lnb/g;->a(Landroid/content/Context;Leb/b;)Z

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    if-eqz p0, :cond_1

    .line 101
    .line 102
    invoke-virtual {p4}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    iget-object p0, p0, Lmb/s;->a:Lla/u;

    .line 107
    .line 108
    const-string p2, "workspec"

    .line 109
    .line 110
    filled-new-array {p2}, [Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p2

    .line 114
    new-instance p3, Lm40/e;

    .line 115
    .line 116
    const/16 p4, 0x10

    .line 117
    .line 118
    invoke-direct {p3, p4}, Lm40/e;-><init>(I)V

    .line 119
    .line 120
    .line 121
    invoke-static {p0, v0, p2, p3}, Ljp/ga;->a(Lla/u;Z[Ljava/lang/String;Lay0/k;)Lna/j;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    new-instance p2, Lfb/m;

    .line 126
    .line 127
    const/4 p3, 0x4

    .line 128
    const/4 p4, 0x0

    .line 129
    invoke-direct {p2, p3, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 130
    .line 131
    .line 132
    new-instance p3, Llb0/y;

    .line 133
    .line 134
    invoke-direct {p3, v2, p0, p2}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    const/4 p0, -0x1

    .line 138
    invoke-static {p3, p0}, Lyy0/u;->g(Lyy0/i;I)Lyy0/i;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-static {p0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    new-instance p2, Lc/m;

    .line 147
    .line 148
    const/4 p3, 0x2

    .line 149
    invoke-direct {p2, p1, p4, p3}, Lc/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 150
    .line 151
    .line 152
    new-instance p1, Lne0/n;

    .line 153
    .line 154
    const/4 p3, 0x5

    .line 155
    invoke-direct {p1, p0, p2, p3}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 156
    .line 157
    .line 158
    invoke-static {p1, p7}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 159
    .line 160
    .line 161
    :cond_1
    return-void

    .line 162
    :goto_1
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 163
    throw p0

    .line 164
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 165
    .line 166
    const-string p1, "Cannot initialize WorkManager in direct boot mode"

    .line 167
    .line 168
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    throw p0
.end method

.method public static f(Landroid/content/Context;)Lfb/u;
    .locals 2

    .line 1
    sget-object v0, Lfb/u;->m:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    monitor-enter v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 5
    :try_start_1
    sget-object v1, Lfb/u;->k:Lfb/u;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    monitor-exit v0

    .line 10
    goto :goto_0

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    goto :goto_1

    .line 13
    :cond_0
    sget-object v1, Lfb/u;->l:Lfb/u;

    .line 14
    .line 15
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 16
    :goto_0
    if-eqz v1, :cond_1

    .line 17
    .line 18
    :try_start_2
    monitor-exit v0

    .line 19
    return-object v1

    .line 20
    :catchall_1
    move-exception p0

    .line 21
    goto :goto_2

    .line 22
    :cond_1
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 23
    .line 24
    .line 25
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string v1, "WorkManager is not initialized properly.  You have explicitly disabled WorkManagerInitializer in your manifest, have not manually called WorkManager#initialize at this point, and your Application does not implement Configuration.Provider."

    .line 28
    .line 29
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 33
    :goto_1
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 34
    :try_start_4
    throw p0

    .line 35
    :goto_2
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 36
    throw p0
.end method


# virtual methods
.method public final g()V
    .locals 2

    .line 1
    sget-object v0, Lfb/u;->m:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    const/4 v1, 0x1

    .line 5
    :try_start_0
    iput-boolean v1, p0, Lfb/u;->h:Z

    .line 6
    .line 7
    iget-object v1, p0, Lfb/u;->i:Landroid/content/BroadcastReceiver$PendingResult;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v1}, Landroid/content/BroadcastReceiver$PendingResult;->finish()V

    .line 12
    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    iput-object v1, p0, Lfb/u;->i:Landroid/content/BroadcastReceiver$PendingResult;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    :goto_0
    monitor-exit v0

    .line 21
    return-void

    .line 22
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    throw p0
.end method

.method public final h()V
    .locals 4

    .line 1
    iget-object v0, p0, Lfb/u;->b:Leb/b;

    .line 2
    .line 3
    iget-object v0, v0, Leb/b;->m:Leb/j;

    .line 4
    .line 5
    const-string v1, "ReschedulingWork"

    .line 6
    .line 7
    new-instance v2, Lfb/t;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-direct {v2, p0, v3}, Lfb/t;-><init>(Lfb/u;I)V

    .line 11
    .line 12
    .line 13
    const-string p0, "<this>"

    .line 14
    .line 15
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-static {}, Lab/a;->a()Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    :try_start_0
    invoke-static {v1}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    :cond_0
    invoke-virtual {v2}, Lfb/t;->invoke()Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    .line 33
    .line 34
    if-eqz p0, :cond_1

    .line 35
    .line 36
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 37
    .line 38
    .line 39
    :cond_1
    return-void

    .line 40
    :catchall_0
    move-exception v0

    .line 41
    if-eqz p0, :cond_2

    .line 42
    .line 43
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 44
    .line 45
    .line 46
    :cond_2
    throw v0
.end method
