.class public Lcom/google/firebase/perf/FirebasePerfRegistrar;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


# annotations
.annotation build Landroidx/annotation/Keep;
.end annotation


# static fields
.field private static final EARLY_LIBRARY_NAME:Ljava/lang/String; = "fire-perf-early"

.field private static final LIBRARY_NAME:Ljava/lang/String; = "fire-perf"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Lin/z1;)Lot/b;
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/firebase/perf/FirebasePerfRegistrar;->providesFirebasePerformance(Lgs/c;)Lot/b;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Lgs/s;Lin/z1;)Lot/a;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/firebase/perf/FirebasePerfRegistrar;->lambda$getComponents$0(Lgs/s;Lgs/c;)Lot/a;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static lambda$getComponents$0(Lgs/s;Lgs/c;)Lot/a;
    .locals 14

    .line 1
    new-instance v0, Lot/a;

    .line 2
    .line 3
    const-class v1, Lsr/f;

    .line 4
    .line 5
    invoke-interface {p1, v1}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Lsr/f;

    .line 10
    .line 11
    const-class v2, Lsr/a;

    .line 12
    .line 13
    invoke-interface {p1, v2}, Lgs/c;->f(Ljava/lang/Class;)Lgt/b;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-interface {v2}, Lgt/b;->get()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Lsr/a;

    .line 22
    .line 23
    invoke-interface {p1, p0}, Lgs/c;->b(Lgs/s;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ljava/util/concurrent/Executor;

    .line 28
    .line 29
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Lsr/f;->a()V

    .line 33
    .line 34
    .line 35
    iget-object p1, v1, Lsr/f;->a:Landroid/content/Context;

    .line 36
    .line 37
    invoke-static {}, Lqt/a;->e()Lqt/a;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    sget-object v3, Lqt/a;->d:Lst/a;

    .line 45
    .line 46
    invoke-static {p1}, Ljp/m1;->d(Landroid/content/Context;)Z

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    iput-boolean v4, v3, Lst/a;->b:Z

    .line 51
    .line 52
    iget-object v1, v1, Lqt/a;->c:Lqt/v;

    .line 53
    .line 54
    invoke-virtual {v1, p1}, Lqt/v;->c(Landroid/content/Context;)V

    .line 55
    .line 56
    .line 57
    invoke-static {}, Lpt/c;->a()Lpt/c;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    monitor-enter v1

    .line 62
    :try_start_0
    iget-boolean v3, v1, Lpt/c;->s:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 63
    .line 64
    const/4 v4, 0x1

    .line 65
    if-eqz v3, :cond_0

    .line 66
    .line 67
    monitor-exit v1

    .line 68
    goto :goto_1

    .line 69
    :cond_0
    :try_start_1
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    instance-of v5, v3, Landroid/app/Application;

    .line 74
    .line 75
    if-eqz v5, :cond_1

    .line 76
    .line 77
    check-cast v3, Landroid/app/Application;

    .line 78
    .line 79
    invoke-virtual {v3, v1}, Landroid/app/Application;->registerActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    .line 80
    .line 81
    .line 82
    iput-boolean v4, v1, Lpt/c;->s:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :catchall_0
    move-exception v0

    .line 86
    move-object p0, v0

    .line 87
    goto/16 :goto_c

    .line 88
    .line 89
    :cond_1
    :goto_0
    monitor-exit v1

    .line 90
    :goto_1
    new-instance v3, Lot/c;

    .line 91
    .line 92
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 93
    .line 94
    .line 95
    iget-object v5, v1, Lpt/c;->j:Ljava/util/HashSet;

    .line 96
    .line 97
    monitor-enter v5

    .line 98
    :try_start_2
    iget-object v1, v1, Lpt/c;->j:Ljava/util/HashSet;

    .line 99
    .line 100
    invoke-virtual {v1, v3}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    monitor-exit v5
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 104
    if-eqz v2, :cond_9

    .line 105
    .line 106
    sget-object v1, Lcom/google/firebase/perf/metrics/AppStartTrace;->C:Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 107
    .line 108
    if-eqz v1, :cond_2

    .line 109
    .line 110
    sget-object v1, Lcom/google/firebase/perf/metrics/AppStartTrace;->C:Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 111
    .line 112
    goto :goto_5

    .line 113
    :cond_2
    sget-object v1, Lyt/h;->v:Lyt/h;

    .line 114
    .line 115
    new-instance v2, La61/a;

    .line 116
    .line 117
    const/16 v3, 0x1c

    .line 118
    .line 119
    invoke-direct {v2, v3}, La61/a;-><init>(I)V

    .line 120
    .line 121
    .line 122
    sget-object v3, Lcom/google/firebase/perf/metrics/AppStartTrace;->C:Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 123
    .line 124
    if-nez v3, :cond_4

    .line 125
    .line 126
    const-class v3, Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 127
    .line 128
    monitor-enter v3

    .line 129
    :try_start_3
    sget-object v5, Lcom/google/firebase/perf/metrics/AppStartTrace;->C:Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 130
    .line 131
    if-nez v5, :cond_3

    .line 132
    .line 133
    new-instance v5, Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 134
    .line 135
    invoke-static {}, Lqt/a;->e()Lqt/a;

    .line 136
    .line 137
    .line 138
    move-result-object v6

    .line 139
    new-instance v7, Ljava/util/concurrent/ThreadPoolExecutor;

    .line 140
    .line 141
    sget-wide v8, Lcom/google/firebase/perf/metrics/AppStartTrace;->A:J

    .line 142
    .line 143
    const-wide/16 v10, 0xa

    .line 144
    .line 145
    add-long/2addr v10, v8

    .line 146
    sget-object v12, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 147
    .line 148
    new-instance v13, Ljava/util/concurrent/LinkedBlockingQueue;

    .line 149
    .line 150
    invoke-direct {v13}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>()V

    .line 151
    .line 152
    .line 153
    const/4 v8, 0x0

    .line 154
    const/4 v9, 0x1

    .line 155
    invoke-direct/range {v7 .. v13}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;)V

    .line 156
    .line 157
    .line 158
    invoke-direct {v5, v1, v2, v6, v7}, Lcom/google/firebase/perf/metrics/AppStartTrace;-><init>(Lyt/h;La61/a;Lqt/a;Ljava/util/concurrent/ThreadPoolExecutor;)V

    .line 159
    .line 160
    .line 161
    sput-object v5, Lcom/google/firebase/perf/metrics/AppStartTrace;->C:Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 162
    .line 163
    goto :goto_2

    .line 164
    :catchall_1
    move-exception v0

    .line 165
    move-object p0, v0

    .line 166
    goto :goto_3

    .line 167
    :cond_3
    :goto_2
    monitor-exit v3

    .line 168
    goto :goto_4

    .line 169
    :goto_3
    monitor-exit v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 170
    throw p0

    .line 171
    :cond_4
    :goto_4
    sget-object v1, Lcom/google/firebase/perf/metrics/AppStartTrace;->C:Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 172
    .line 173
    :goto_5
    monitor-enter v1

    .line 174
    :try_start_4
    iget-boolean v2, v1, Lcom/google/firebase/perf/metrics/AppStartTrace;->d:Z
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 175
    .line 176
    if-eqz v2, :cond_5

    .line 177
    .line 178
    monitor-exit v1

    .line 179
    goto :goto_9

    .line 180
    :cond_5
    :try_start_5
    sget-object v2, Landroidx/lifecycle/m0;->k:Landroidx/lifecycle/m0;

    .line 181
    .line 182
    iget-object v2, v2, Landroidx/lifecycle/m0;->i:Landroidx/lifecycle/z;

    .line 183
    .line 184
    invoke-virtual {v2, v1}, Landroidx/lifecycle/z;->a(Landroidx/lifecycle/w;)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 188
    .line 189
    .line 190
    move-result-object p1

    .line 191
    instance-of v2, p1, Landroid/app/Application;

    .line 192
    .line 193
    if-eqz v2, :cond_8

    .line 194
    .line 195
    move-object v2, p1

    .line 196
    check-cast v2, Landroid/app/Application;

    .line 197
    .line 198
    invoke-virtual {v2, v1}, Landroid/app/Application;->registerActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    .line 199
    .line 200
    .line 201
    iget-boolean v2, v1, Lcom/google/firebase/perf/metrics/AppStartTrace;->y:Z

    .line 202
    .line 203
    if-nez v2, :cond_7

    .line 204
    .line 205
    move-object v2, p1

    .line 206
    check-cast v2, Landroid/app/Application;

    .line 207
    .line 208
    invoke-static {v2}, Lcom/google/firebase/perf/metrics/AppStartTrace;->c(Landroid/app/Application;)Z

    .line 209
    .line 210
    .line 211
    move-result v2

    .line 212
    if-eqz v2, :cond_6

    .line 213
    .line 214
    goto :goto_6

    .line 215
    :cond_6
    const/4 v2, 0x0

    .line 216
    goto :goto_7

    .line 217
    :cond_7
    :goto_6
    move v2, v4

    .line 218
    :goto_7
    iput-boolean v2, v1, Lcom/google/firebase/perf/metrics/AppStartTrace;->y:Z

    .line 219
    .line 220
    iput-boolean v4, v1, Lcom/google/firebase/perf/metrics/AppStartTrace;->d:Z

    .line 221
    .line 222
    check-cast p1, Landroid/app/Application;

    .line 223
    .line 224
    iput-object p1, v1, Lcom/google/firebase/perf/metrics/AppStartTrace;->h:Landroid/app/Application;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 225
    .line 226
    goto :goto_8

    .line 227
    :catchall_2
    move-exception v0

    .line 228
    move-object p0, v0

    .line 229
    goto :goto_a

    .line 230
    :cond_8
    :goto_8
    monitor-exit v1

    .line 231
    :goto_9
    new-instance p1, Laq/p;

    .line 232
    .line 233
    const/16 v2, 0x17

    .line 234
    .line 235
    invoke-direct {p1, v1, v2}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 236
    .line 237
    .line 238
    invoke-interface {p0, p1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 239
    .line 240
    .line 241
    goto :goto_b

    .line 242
    :goto_a
    :try_start_6
    monitor-exit v1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 243
    throw p0

    .line 244
    :cond_9
    :goto_b
    invoke-static {}, Lcom/google/firebase/perf/session/SessionManager;->getInstance()Lcom/google/firebase/perf/session/SessionManager;

    .line 245
    .line 246
    .line 247
    move-result-object p0

    .line 248
    invoke-virtual {p0}, Lcom/google/firebase/perf/session/SessionManager;->initializeGaugeCollection()V

    .line 249
    .line 250
    .line 251
    return-object v0

    .line 252
    :catchall_3
    move-exception v0

    .line 253
    move-object p0, v0

    .line 254
    :try_start_7
    monitor-exit v5
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 255
    throw p0

    .line 256
    :goto_c
    :try_start_8
    monitor-exit v1
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 257
    throw p0
.end method

.method private static providesFirebasePerformance(Lgs/c;)Lot/b;
    .locals 11

    .line 1
    const-class v0, Lot/a;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 7
    .line 8
    const-class v0, Lsr/f;

    .line 9
    .line 10
    invoke-interface {p0, v0}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    move-object v2, v0

    .line 15
    check-cast v2, Lsr/f;

    .line 16
    .line 17
    const-class v0, Lht/d;

    .line 18
    .line 19
    invoke-interface {p0, v0}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    move-object v3, v0

    .line 24
    check-cast v3, Lht/d;

    .line 25
    .line 26
    const-class v0, Lcu/j;

    .line 27
    .line 28
    invoke-interface {p0, v0}, Lgs/c;->f(Ljava/lang/Class;)Lgt/b;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    const-class v0, Lon/f;

    .line 33
    .line 34
    invoke-interface {p0, v0}, Lgs/c;->f(Ljava/lang/Class;)Lgt/b;

    .line 35
    .line 36
    .line 37
    move-result-object v5

    .line 38
    const/16 v6, 0x1b

    .line 39
    .line 40
    invoke-direct/range {v1 .. v6}, Lcom/google/firebase/messaging/w;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 41
    .line 42
    .line 43
    new-instance v3, Lrt/a;

    .line 44
    .line 45
    const/4 p0, 0x0

    .line 46
    invoke-direct {v3, v1, p0}, Lrt/a;-><init>(Lcom/google/firebase/messaging/w;I)V

    .line 47
    .line 48
    .line 49
    new-instance v4, Lj1/a;

    .line 50
    .line 51
    const/16 p0, 0x1b

    .line 52
    .line 53
    invoke-direct {v4, v1, p0}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 54
    .line 55
    .line 56
    new-instance v5, Lpv/g;

    .line 57
    .line 58
    const/4 p0, 0x5

    .line 59
    invoke-direct {v5, v1, p0}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    .line 60
    .line 61
    .line 62
    new-instance v6, Lrt/a;

    .line 63
    .line 64
    const/4 p0, 0x1

    .line 65
    invoke-direct {v6, v1, p0}, Lrt/a;-><init>(Lcom/google/firebase/messaging/w;I)V

    .line 66
    .line 67
    .line 68
    new-instance v7, Ldv/a;

    .line 69
    .line 70
    invoke-direct {v7, v1}, Ldv/a;-><init>(Lcom/google/firebase/messaging/w;)V

    .line 71
    .line 72
    .line 73
    new-instance v8, La61/a;

    .line 74
    .line 75
    invoke-direct {v8, v1}, La61/a;-><init>(Lcom/google/firebase/messaging/w;)V

    .line 76
    .line 77
    .line 78
    new-instance v9, Let/d;

    .line 79
    .line 80
    const/16 p0, 0xd

    .line 81
    .line 82
    invoke-direct {v9, v1, p0}, Let/d;-><init>(Ljava/lang/Object;I)V

    .line 83
    .line 84
    .line 85
    new-instance v2, Lss/b;

    .line 86
    .line 87
    const/16 v10, 0xa

    .line 88
    .line 89
    invoke-direct/range {v2 .. v10}, Lss/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 90
    .line 91
    .line 92
    new-instance p0, Lrv0/a;

    .line 93
    .line 94
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 95
    .line 96
    .line 97
    sget-object v0, Lrv0/a;->f:Ljava/lang/Object;

    .line 98
    .line 99
    iput-object v0, p0, Lrv0/a;->e:Ljava/lang/Object;

    .line 100
    .line 101
    iput-object v2, p0, Lrv0/a;->d:Lss/b;

    .line 102
    .line 103
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    check-cast p0, Lot/b;

    .line 108
    .line 109
    return-object p0
.end method


# virtual methods
.method public getComponents()Ljava/util/List;
    .locals 7
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lgs/b;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance p0, Lgs/s;

    .line 2
    .line 3
    const-class v0, Lyr/d;

    .line 4
    .line 5
    const-class v1, Ljava/util/concurrent/Executor;

    .line 6
    .line 7
    invoke-direct {p0, v0, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 8
    .line 9
    .line 10
    const-class v0, Lot/b;

    .line 11
    .line 12
    invoke-static {v0}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const-string v1, "fire-perf"

    .line 17
    .line 18
    iput-object v1, v0, Lgs/a;->a:Ljava/lang/String;

    .line 19
    .line 20
    const-class v2, Lsr/f;

    .line 21
    .line 22
    invoke-static {v2}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    invoke-virtual {v0, v3}, Lgs/a;->a(Lgs/k;)V

    .line 27
    .line 28
    .line 29
    new-instance v3, Lgs/k;

    .line 30
    .line 31
    const/4 v4, 0x1

    .line 32
    const-class v5, Lcu/j;

    .line 33
    .line 34
    invoke-direct {v3, v4, v4, v5}, Lgs/k;-><init>(IILjava/lang/Class;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0, v3}, Lgs/a;->a(Lgs/k;)V

    .line 38
    .line 39
    .line 40
    const-class v3, Lht/d;

    .line 41
    .line 42
    invoke-static {v3}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    invoke-virtual {v0, v3}, Lgs/a;->a(Lgs/k;)V

    .line 47
    .line 48
    .line 49
    new-instance v3, Lgs/k;

    .line 50
    .line 51
    const-class v5, Lon/f;

    .line 52
    .line 53
    invoke-direct {v3, v4, v4, v5}, Lgs/k;-><init>(IILjava/lang/Class;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0, v3}, Lgs/a;->a(Lgs/k;)V

    .line 57
    .line 58
    .line 59
    const-class v3, Lot/a;

    .line 60
    .line 61
    invoke-static {v3}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    invoke-virtual {v0, v5}, Lgs/a;->a(Lgs/k;)V

    .line 66
    .line 67
    .line 68
    new-instance v5, Lj9/d;

    .line 69
    .line 70
    const/16 v6, 0x11

    .line 71
    .line 72
    invoke-direct {v5, v6}, Lj9/d;-><init>(I)V

    .line 73
    .line 74
    .line 75
    iput-object v5, v0, Lgs/a;->f:Lgs/e;

    .line 76
    .line 77
    invoke-virtual {v0}, Lgs/a;->b()Lgs/b;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-static {v3}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    const-string v5, "fire-perf-early"

    .line 86
    .line 87
    iput-object v5, v3, Lgs/a;->a:Ljava/lang/String;

    .line 88
    .line 89
    invoke-static {v2}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    invoke-virtual {v3, v2}, Lgs/a;->a(Lgs/k;)V

    .line 94
    .line 95
    .line 96
    const-class v2, Lsr/a;

    .line 97
    .line 98
    invoke-static {v2}, Lgs/k;->a(Ljava/lang/Class;)Lgs/k;

    .line 99
    .line 100
    .line 101
    move-result-object v2

    .line 102
    invoke-virtual {v3, v2}, Lgs/a;->a(Lgs/k;)V

    .line 103
    .line 104
    .line 105
    new-instance v2, Lgs/k;

    .line 106
    .line 107
    const/4 v5, 0x0

    .line 108
    invoke-direct {v2, p0, v4, v5}, Lgs/k;-><init>(Lgs/s;II)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v3, v2}, Lgs/a;->a(Lgs/k;)V

    .line 112
    .line 113
    .line 114
    const/4 v2, 0x2

    .line 115
    invoke-virtual {v3, v2}, Lgs/a;->c(I)V

    .line 116
    .line 117
    .line 118
    new-instance v2, Lcom/google/firebase/messaging/p;

    .line 119
    .line 120
    const/4 v4, 0x3

    .line 121
    invoke-direct {v2, p0, v4}, Lcom/google/firebase/messaging/p;-><init>(Lgs/s;I)V

    .line 122
    .line 123
    .line 124
    iput-object v2, v3, Lgs/a;->f:Lgs/e;

    .line 125
    .line 126
    invoke-virtual {v3}, Lgs/a;->b()Lgs/b;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    const-string v2, "22.0.2"

    .line 131
    .line 132
    invoke-static {v1, v2}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    filled-new-array {v0, p0, v1}, [Lgs/b;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    return-object p0
.end method
