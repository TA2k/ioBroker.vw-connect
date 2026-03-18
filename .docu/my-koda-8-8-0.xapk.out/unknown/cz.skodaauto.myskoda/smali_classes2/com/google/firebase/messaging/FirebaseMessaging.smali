.class public Lcom/google/firebase/messaging/FirebaseMessaging;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final j:J

.field public static k:La0/j;

.field public static l:Lgt/b;

.field public static m:Ljava/util/concurrent/ScheduledThreadPoolExecutor;


# instance fields
.field public final a:Lsr/f;

.field public final b:Landroid/content/Context;

.field public final c:Lin/z1;

.field public final d:Lcom/google/firebase/messaging/j;

.field public final e:La8/b;

.field public final f:Ljava/util/concurrent/ScheduledThreadPoolExecutor;

.field public final g:Ljava/util/concurrent/ThreadPoolExecutor;

.field public final h:Lcom/google/firebase/messaging/r;

.field public i:Z


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Ljava/util/concurrent/TimeUnit;->HOURS:Ljava/util/concurrent/TimeUnit;

    .line 2
    .line 3
    const-wide/16 v1, 0x8

    .line 4
    .line 5
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toSeconds(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    sput-wide v0, Lcom/google/firebase/messaging/FirebaseMessaging;->j:J

    .line 10
    .line 11
    new-instance v0, Lcom/google/firebase/messaging/l;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-direct {v0, v1}, Lcom/google/firebase/messaging/l;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lcom/google/firebase/messaging/FirebaseMessaging;->l:Lgt/b;

    .line 18
    .line 19
    return-void
.end method

.method public constructor <init>(Lsr/f;Lgt/b;Lgt/b;Lht/d;Lgt/b;Ldt/c;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    new-instance v2, Lcom/google/firebase/messaging/r;

    .line 6
    .line 7
    invoke-virtual {v1}, Lsr/f;->a()V

    .line 8
    .line 9
    .line 10
    iget-object v3, v1, Lsr/f;->a:Landroid/content/Context;

    .line 11
    .line 12
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    const/4 v4, 0x0

    .line 16
    iput v4, v2, Lcom/google/firebase/messaging/r;->b:I

    .line 17
    .line 18
    iput-object v3, v2, Lcom/google/firebase/messaging/r;->c:Ljava/lang/Object;

    .line 19
    .line 20
    new-instance v5, Lin/z1;

    .line 21
    .line 22
    new-instance v6, Lio/b;

    .line 23
    .line 24
    invoke-virtual {v1}, Lsr/f;->a()V

    .line 25
    .line 26
    .line 27
    iget-object v7, v1, Lsr/f;->a:Landroid/content/Context;

    .line 28
    .line 29
    invoke-direct {v6, v7}, Lio/b;-><init>(Landroid/content/Context;)V

    .line 30
    .line 31
    .line 32
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 33
    .line 34
    .line 35
    iput-object v1, v5, Lin/z1;->a:Ljava/lang/Object;

    .line 36
    .line 37
    iput-object v2, v5, Lin/z1;->b:Ljava/lang/Object;

    .line 38
    .line 39
    iput-object v6, v5, Lin/z1;->c:Ljava/lang/Object;

    .line 40
    .line 41
    move-object/from16 v6, p2

    .line 42
    .line 43
    iput-object v6, v5, Lin/z1;->d:Ljava/lang/Object;

    .line 44
    .line 45
    move-object/from16 v6, p3

    .line 46
    .line 47
    iput-object v6, v5, Lin/z1;->e:Ljava/lang/Object;

    .line 48
    .line 49
    move-object/from16 v6, p4

    .line 50
    .line 51
    iput-object v6, v5, Lin/z1;->f:Ljava/lang/Object;

    .line 52
    .line 53
    new-instance v6, Luo/a;

    .line 54
    .line 55
    const-string v7, "Firebase-Messaging-Task"

    .line 56
    .line 57
    invoke-direct {v6, v7}, Luo/a;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-static {v6}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor(Ljava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ExecutorService;

    .line 61
    .line 62
    .line 63
    move-result-object v6

    .line 64
    new-instance v7, Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    .line 65
    .line 66
    new-instance v8, Luo/a;

    .line 67
    .line 68
    const-string v9, "Firebase-Messaging-Init"

    .line 69
    .line 70
    invoke-direct {v8, v9}, Luo/a;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    const/4 v9, 0x1

    .line 74
    invoke-direct {v7, v9, v8}, Ljava/util/concurrent/ScheduledThreadPoolExecutor;-><init>(ILjava/util/concurrent/ThreadFactory;)V

    .line 75
    .line 76
    .line 77
    new-instance v10, Ljava/util/concurrent/ThreadPoolExecutor;

    .line 78
    .line 79
    sget-object v15, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 80
    .line 81
    new-instance v16, Ljava/util/concurrent/LinkedBlockingQueue;

    .line 82
    .line 83
    invoke-direct/range {v16 .. v16}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>()V

    .line 84
    .line 85
    .line 86
    new-instance v8, Luo/a;

    .line 87
    .line 88
    const-string v11, "Firebase-Messaging-File-Io"

    .line 89
    .line 90
    invoke-direct {v8, v11}, Luo/a;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    const/4 v11, 0x0

    .line 94
    const/4 v12, 0x1

    .line 95
    const-wide/16 v13, 0x1e

    .line 96
    .line 97
    move-object/from16 v17, v8

    .line 98
    .line 99
    invoke-direct/range {v10 .. v17}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;Ljava/util/concurrent/ThreadFactory;)V

    .line 100
    .line 101
    .line 102
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 103
    .line 104
    .line 105
    iput-boolean v4, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->i:Z

    .line 106
    .line 107
    sput-object p5, Lcom/google/firebase/messaging/FirebaseMessaging;->l:Lgt/b;

    .line 108
    .line 109
    iput-object v1, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Lsr/f;

    .line 110
    .line 111
    new-instance v8, La8/b;

    .line 112
    .line 113
    move-object/from16 v11, p6

    .line 114
    .line 115
    invoke-direct {v8, v0, v11}, La8/b;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;Ldt/c;)V

    .line 116
    .line 117
    .line 118
    iput-object v8, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->e:La8/b;

    .line 119
    .line 120
    invoke-virtual {v1}, Lsr/f;->a()V

    .line 121
    .line 122
    .line 123
    iget-object v8, v1, Lsr/f;->a:Landroid/content/Context;

    .line 124
    .line 125
    iput-object v8, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 126
    .line 127
    new-instance v11, Lcom/google/firebase/messaging/k;

    .line 128
    .line 129
    invoke-direct {v11}, Lcom/google/firebase/messaging/k;-><init>()V

    .line 130
    .line 131
    .line 132
    iput-object v2, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->h:Lcom/google/firebase/messaging/r;

    .line 133
    .line 134
    iput-object v5, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->c:Lin/z1;

    .line 135
    .line 136
    new-instance v12, Lcom/google/firebase/messaging/j;

    .line 137
    .line 138
    invoke-direct {v12, v6}, Lcom/google/firebase/messaging/j;-><init>(Ljava/util/concurrent/ExecutorService;)V

    .line 139
    .line 140
    .line 141
    iput-object v12, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->d:Lcom/google/firebase/messaging/j;

    .line 142
    .line 143
    iput-object v7, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->f:Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    .line 144
    .line 145
    iput-object v10, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->g:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 146
    .line 147
    invoke-virtual {v1}, Lsr/f;->a()V

    .line 148
    .line 149
    .line 150
    instance-of v1, v3, Landroid/app/Application;

    .line 151
    .line 152
    if-eqz v1, :cond_0

    .line 153
    .line 154
    check-cast v3, Landroid/app/Application;

    .line 155
    .line 156
    invoke-virtual {v3, v11}, Landroid/app/Application;->registerActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    .line 157
    .line 158
    .line 159
    goto :goto_0

    .line 160
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 161
    .line 162
    const-string v6, "Context "

    .line 163
    .line 164
    invoke-direct {v1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    const-string v3, " was not an application, can\'t register for lifecycle callbacks. Some notification events may be dropped as a result."

    .line 171
    .line 172
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v1

    .line 179
    const-string v3, "FirebaseMessaging"

    .line 180
    .line 181
    invoke-static {v3, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 182
    .line 183
    .line 184
    :goto_0
    new-instance v1, Lcom/google/firebase/messaging/n;

    .line 185
    .line 186
    invoke-direct {v1, v0, v4}, Lcom/google/firebase/messaging/n;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;I)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v7, v1}, Ljava/util/concurrent/ScheduledThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 190
    .line 191
    .line 192
    new-instance v1, Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    .line 193
    .line 194
    new-instance v3, Luo/a;

    .line 195
    .line 196
    const-string v6, "Firebase-Messaging-Topics-Io"

    .line 197
    .line 198
    invoke-direct {v3, v6}, Luo/a;-><init>(Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    invoke-direct {v1, v9, v3}, Ljava/util/concurrent/ScheduledThreadPoolExecutor;-><init>(ILjava/util/concurrent/ThreadFactory;)V

    .line 202
    .line 203
    .line 204
    sget v3, Lcom/google/firebase/messaging/d0;->j:I

    .line 205
    .line 206
    new-instance v3, Lcom/google/firebase/messaging/c0;

    .line 207
    .line 208
    move-object/from16 p4, v0

    .line 209
    .line 210
    move-object/from16 p3, v1

    .line 211
    .line 212
    move-object/from16 p5, v2

    .line 213
    .line 214
    move-object/from16 p1, v3

    .line 215
    .line 216
    move-object/from16 p6, v5

    .line 217
    .line 218
    move-object/from16 p2, v8

    .line 219
    .line 220
    invoke-direct/range {p1 .. p6}, Lcom/google/firebase/messaging/c0;-><init>(Landroid/content/Context;Ljava/util/concurrent/ScheduledThreadPoolExecutor;Lcom/google/firebase/messaging/FirebaseMessaging;Lcom/google/firebase/messaging/r;Lin/z1;)V

    .line 221
    .line 222
    .line 223
    move-object/from16 v2, p1

    .line 224
    .line 225
    invoke-static {v1, v2}, Ljp/l1;->c(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;)Laq/t;

    .line 226
    .line 227
    .line 228
    move-result-object v1

    .line 229
    new-instance v2, Lcom/google/firebase/messaging/o;

    .line 230
    .line 231
    invoke-direct {v2, v0, v4}, Lcom/google/firebase/messaging/o;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;I)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v1, v7, v2}, Laq/t;->d(Ljava/util/concurrent/Executor;Laq/g;)Laq/t;

    .line 235
    .line 236
    .line 237
    new-instance v1, Lcom/google/firebase/messaging/n;

    .line 238
    .line 239
    invoke-direct {v1, v0, v9}, Lcom/google/firebase/messaging/n;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;I)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {v7, v1}, Ljava/util/concurrent/ScheduledThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 243
    .line 244
    .line 245
    return-void
.end method

.method public static b(Ljava/lang/Runnable;J)V
    .locals 4

    .line 1
    const-class v0, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lcom/google/firebase/messaging/FirebaseMessaging;->m:Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    new-instance v1, Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    .line 9
    .line 10
    new-instance v2, Luo/a;

    .line 11
    .line 12
    const-string v3, "TAG"

    .line 13
    .line 14
    invoke-direct {v2, v3}, Luo/a;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const/4 v3, 0x1

    .line 18
    invoke-direct {v1, v3, v2}, Ljava/util/concurrent/ScheduledThreadPoolExecutor;-><init>(ILjava/util/concurrent/ThreadFactory;)V

    .line 19
    .line 20
    .line 21
    sput-object v1, Lcom/google/firebase/messaging/FirebaseMessaging;->m:Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    :goto_0
    sget-object v1, Lcom/google/firebase/messaging/FirebaseMessaging;->m:Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    .line 27
    .line 28
    sget-object v2, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 29
    .line 30
    invoke-virtual {v1, p0, p1, p2, v2}, Ljava/util/concurrent/ScheduledThreadPoolExecutor;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    .line 31
    .line 32
    .line 33
    monitor-exit v0

    .line 34
    return-void

    .line 35
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    throw p0
.end method

.method public static declared-synchronized c()Lcom/google/firebase/messaging/FirebaseMessaging;
    .locals 2

    .line 1
    const-class v0, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-static {}, Lsr/f;->c()Lsr/f;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    invoke-static {v1}, Lcom/google/firebase/messaging/FirebaseMessaging;->getInstance(Lsr/f;)Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 9
    .line 10
    .line 11
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    monitor-exit v0

    .line 13
    return-object v1

    .line 14
    :catchall_0
    move-exception v1

    .line 15
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 16
    throw v1
.end method

.method public static declared-synchronized d(Landroid/content/Context;)La0/j;
    .locals 2

    .line 1
    const-class v0, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lcom/google/firebase/messaging/FirebaseMessaging;->k:La0/j;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    new-instance v1, La0/j;

    .line 9
    .line 10
    invoke-direct {v1, p0}, La0/j;-><init>(Landroid/content/Context;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lcom/google/firebase/messaging/FirebaseMessaging;->k:La0/j;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    :goto_0
    sget-object p0, Lcom/google/firebase/messaging/FirebaseMessaging;->k:La0/j;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    monitor-exit v0

    .line 21
    return-object p0

    .line 22
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 23
    throw p0
.end method

.method public static declared-synchronized getInstance(Lsr/f;)Lcom/google/firebase/messaging/FirebaseMessaging;
    .locals 2
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 1
    const-class v0, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    const-class v1, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lsr/f;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 11
    .line 12
    const-string v1, "Firebase Messaging component is not present"

    .line 13
    .line 14
    invoke-static {p0, v1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    .line 16
    .line 17
    monitor-exit v0

    .line 18
    return-object p0

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 21
    throw p0
.end method


# virtual methods
.method public final a()Ljava/lang/String;
    .locals 7

    .line 1
    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->g()Lcom/google/firebase/messaging/x;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0, v0}, Lcom/google/firebase/messaging/FirebaseMessaging;->k(Lcom/google/firebase/messaging/x;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    iget-object p0, v0, Lcom/google/firebase/messaging/x;->a:Ljava/lang/String;

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    iget-object v1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Lsr/f;

    .line 15
    .line 16
    invoke-static {v1}, Lcom/google/firebase/messaging/r;->c(Lsr/f;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    iget-object v2, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->d:Lcom/google/firebase/messaging/j;

    .line 21
    .line 22
    const-string v3, "Making new request for: "

    .line 23
    .line 24
    const-string v4, "Joining ongoing request for: "

    .line 25
    .line 26
    monitor-enter v2

    .line 27
    :try_start_0
    iget-object v5, v2, Lcom/google/firebase/messaging/j;->b:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v5, Landroidx/collection/f;

    .line 30
    .line 31
    invoke-interface {v5, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    check-cast v5, Laq/j;

    .line 36
    .line 37
    const/4 v6, 0x3

    .line 38
    if-eqz v5, :cond_2

    .line 39
    .line 40
    const-string p0, "FirebaseMessaging"

    .line 41
    .line 42
    invoke-static {p0, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_1

    .line 47
    .line 48
    const-string p0, "FirebaseMessaging"

    .line 49
    .line 50
    new-instance v0, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    invoke-direct {v0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    invoke-static {p0, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :catchall_0
    move-exception p0

    .line 67
    goto :goto_2

    .line 68
    :cond_1
    :goto_0
    monitor-exit v2

    .line 69
    goto :goto_1

    .line 70
    :cond_2
    :try_start_1
    const-string v4, "FirebaseMessaging"

    .line 71
    .line 72
    invoke-static {v4, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    if-eqz v4, :cond_3

    .line 77
    .line 78
    const-string v4, "FirebaseMessaging"

    .line 79
    .line 80
    new-instance v5, Ljava/lang/StringBuilder;

    .line 81
    .line 82
    invoke-direct {v5, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    invoke-static {v4, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 93
    .line 94
    .line 95
    :cond_3
    iget-object v3, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->c:Lin/z1;

    .line 96
    .line 97
    iget-object v4, v3, Lin/z1;->a:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v4, Lsr/f;

    .line 100
    .line 101
    invoke-static {v4}, Lcom/google/firebase/messaging/r;->c(Lsr/f;)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v4

    .line 105
    const-string v5, "*"

    .line 106
    .line 107
    new-instance v6, Landroid/os/Bundle;

    .line 108
    .line 109
    invoke-direct {v6}, Landroid/os/Bundle;-><init>()V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v3, v4, v5, v6}, Lin/z1;->d0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Laq/t;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    invoke-virtual {v3, v4}, Lin/z1;->y(Laq/t;)Laq/t;

    .line 117
    .line 118
    .line 119
    move-result-object v3

    .line 120
    iget-object v4, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->g:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 121
    .line 122
    new-instance v5, Lbb/i;

    .line 123
    .line 124
    const/4 v6, 0x1

    .line 125
    invoke-direct {v5, p0, v1, v0, v6}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v3, v4, v5}, Laq/t;->j(Ljava/util/concurrent/Executor;Laq/i;)Laq/t;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    iget-object v0, v2, Lcom/google/firebase/messaging/j;->a:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast v0, Ljava/util/concurrent/Executor;

    .line 135
    .line 136
    new-instance v3, La0/h;

    .line 137
    .line 138
    const/16 v4, 0x8

    .line 139
    .line 140
    invoke-direct {v3, v4, v2, v1}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {p0, v0, v3}, Laq/t;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 144
    .line 145
    .line 146
    move-result-object v5

    .line 147
    iget-object p0, v2, Lcom/google/firebase/messaging/j;->b:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast p0, Landroidx/collection/f;

    .line 150
    .line 151
    invoke-interface {p0, v1, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 152
    .line 153
    .line 154
    monitor-exit v2

    .line 155
    :goto_1
    :try_start_2
    invoke-static {v5}, Ljp/l1;->a(Laq/j;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    check-cast p0, Ljava/lang/String;
    :try_end_2
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_2 .. :try_end_2} :catch_0
    .catch Ljava/lang/InterruptedException; {:try_start_2 .. :try_end_2} :catch_0

    .line 160
    .line 161
    return-object p0

    .line 162
    :catch_0
    move-exception p0

    .line 163
    new-instance v0, Ljava/io/IOException;

    .line 164
    .line 165
    invoke-direct {v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/Throwable;)V

    .line 166
    .line 167
    .line 168
    throw v0

    .line 169
    :goto_2
    :try_start_3
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 170
    throw p0
.end method

.method public final e()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Lsr/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lsr/f;->a()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lsr/f;->b:Ljava/lang/String;

    .line 7
    .line 8
    const-string v1, "[DEFAULT]"

    .line 9
    .line 10
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const-string p0, ""

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    invoke-virtual {p0}, Lsr/f;->d()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public final f()Laq/t;
    .locals 3

    .line 1
    new-instance v0, Laq/k;

    .line 2
    .line 3
    invoke-direct {v0}, Laq/k;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lcom/google/firebase/messaging/m;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-direct {v1, p0, v0, v2}, Lcom/google/firebase/messaging/m;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;Laq/k;I)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->f:Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    .line 13
    .line 14
    invoke-virtual {p0, v1}, Ljava/util/concurrent/ScheduledThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 15
    .line 16
    .line 17
    iget-object p0, v0, Laq/k;->a:Laq/t;

    .line 18
    .line 19
    return-object p0
.end method

.method public final g()Lcom/google/firebase/messaging/x;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 2
    .line 3
    invoke-static {v0}, Lcom/google/firebase/messaging/FirebaseMessaging;->d(Landroid/content/Context;)La0/j;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->e()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    iget-object p0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Lsr/f;

    .line 12
    .line 13
    invoke-static {p0}, Lcom/google/firebase/messaging/r;->c(Lsr/f;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    monitor-enter v0

    .line 18
    :try_start_0
    iget-object v2, v0, La0/j;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v2, Landroid/content/SharedPreferences;

    .line 21
    .line 22
    invoke-static {v1, p0}, La0/j;->U(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    const/4 v1, 0x0

    .line 27
    invoke-interface {v2, p0, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {p0}, Lcom/google/firebase/messaging/x;->b(Ljava/lang/String;)Lcom/google/firebase/messaging/x;

    .line 32
    .line 33
    .line 34
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    monitor-exit v0

    .line 36
    return-object p0

    .line 37
    :catchall_0
    move-exception p0

    .line 38
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 39
    throw p0
.end method

.method public final h()V
    .locals 6

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->c:Lin/z1;

    .line 2
    .line 3
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lio/b;

    .line 6
    .line 7
    iget-object v1, v0, Lio/b;->c:Lc1/m2;

    .line 8
    .line 9
    invoke-virtual {v1}, Lc1/m2;->q()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    const v2, 0xe5ee4e0

    .line 14
    .line 15
    .line 16
    if-lt v1, v2, :cond_0

    .line 17
    .line 18
    iget-object v0, v0, Lio/b;->b:Landroid/content/Context;

    .line 19
    .line 20
    invoke-static {v0}, Lio/o;->d(Landroid/content/Context;)Lio/o;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    sget-object v1, Landroid/os/Bundle;->EMPTY:Landroid/os/Bundle;

    .line 25
    .line 26
    new-instance v2, Lio/n;

    .line 27
    .line 28
    monitor-enter v0

    .line 29
    :try_start_0
    iget v3, v0, Lio/o;->d:I

    .line 30
    .line 31
    add-int/lit8 v4, v3, 0x1

    .line 32
    .line 33
    iput v4, v0, Lio/o;->d:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    .line 35
    monitor-exit v0

    .line 36
    const/4 v4, 0x1

    .line 37
    const/4 v5, 0x5

    .line 38
    invoke-direct {v2, v3, v5, v1, v4}, Lio/n;-><init>(IILandroid/os/Bundle;I)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0, v2}, Lio/o;->e(Lio/n;)Laq/t;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sget-object v1, Lio/h;->f:Lio/h;

    .line 46
    .line 47
    sget-object v2, Lio/d;->f:Lio/d;

    .line 48
    .line 49
    invoke-virtual {v0, v1, v2}, Laq/t;->m(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    goto :goto_0

    .line 54
    :catchall_0
    move-exception p0

    .line 55
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 56
    throw p0

    .line 57
    :cond_0
    new-instance v0, Ljava/io/IOException;

    .line 58
    .line 59
    const-string v1, "SERVICE_NOT_AVAILABLE"

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-static {v0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    :goto_0
    iget-object v1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->f:Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    .line 69
    .line 70
    new-instance v2, Lcom/google/firebase/messaging/o;

    .line 71
    .line 72
    const/4 v3, 0x1

    .line 73
    invoke-direct {v2, p0, v3}, Lcom/google/firebase/messaging/o;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;I)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v0, v1, v2}, Laq/t;->d(Ljava/util/concurrent/Executor;Laq/g;)Laq/t;

    .line 77
    .line 78
    .line 79
    return-void
.end method

.method public final i()Z
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 2
    .line 3
    invoke-static {v0}, Ljp/ke;->e(Landroid/content/Context;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Landroid/os/Binder;->getCallingUid()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    iget v2, v2, Landroid/content/pm/ApplicationInfo;->uid:I

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    const-string v4, "FirebaseMessaging"

    .line 18
    .line 19
    if-ne v1, v2, :cond_3

    .line 20
    .line 21
    const-class v1, Landroid/app/NotificationManager;

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Landroid/app/NotificationManager;

    .line 28
    .line 29
    invoke-virtual {v0}, Landroid/app/NotificationManager;->getNotificationDelegate()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    const-string v1, "com.google.android.gms"

    .line 34
    .line 35
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_2

    .line 40
    .line 41
    const/4 v0, 0x3

    .line 42
    invoke-static {v4, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-eqz v0, :cond_0

    .line 47
    .line 48
    const-string v0, "GMS core is set for proxying"

    .line 49
    .line 50
    invoke-static {v4, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 51
    .line 52
    .line 53
    :cond_0
    iget-object p0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Lsr/f;

    .line 54
    .line 55
    const-class v0, Lwr/b;

    .line 56
    .line 57
    invoke-virtual {p0, v0}, Lsr/f;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    if-eqz p0, :cond_1

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    invoke-static {}, Ljp/je;->a()Z

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    if-eqz p0, :cond_2

    .line 69
    .line 70
    sget-object p0, Lcom/google/firebase/messaging/FirebaseMessaging;->l:Lgt/b;

    .line 71
    .line 72
    if-eqz p0, :cond_2

    .line 73
    .line 74
    :goto_0
    const/4 p0, 0x1

    .line 75
    return p0

    .line 76
    :cond_2
    return v3

    .line 77
    :cond_3
    new-instance p0, Ljava/lang/StringBuilder;

    .line 78
    .line 79
    const-string v1, "error retrieving notification delegate for package "

    .line 80
    .line 81
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    invoke-static {v4, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 96
    .line 97
    .line 98
    return v3
.end method

.method public final declared-synchronized j(J)V
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    const-wide/16 v0, 0x2

    .line 3
    .line 4
    mul-long/2addr v0, p1

    .line 5
    const-wide/16 v2, 0x1e

    .line 6
    .line 7
    :try_start_0
    invoke-static {v2, v3, v0, v1}, Ljava/lang/Math;->max(JJ)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    sget-wide v2, Lcom/google/firebase/messaging/FirebaseMessaging;->j:J

    .line 12
    .line 13
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->min(JJ)J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    new-instance v2, Lcom/google/firebase/messaging/z;

    .line 18
    .line 19
    invoke-direct {v2, p0, v0, v1}, Lcom/google/firebase/messaging/z;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;J)V

    .line 20
    .line 21
    .line 22
    invoke-static {v2, p1, p2}, Lcom/google/firebase/messaging/FirebaseMessaging;->b(Ljava/lang/Runnable;J)V

    .line 23
    .line 24
    .line 25
    const/4 p1, 0x1

    .line 26
    iput-boolean p1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->i:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    .line 28
    monitor-exit p0

    .line 29
    return-void

    .line 30
    :catchall_0
    move-exception p1

    .line 31
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 32
    throw p1
.end method

.method public final k(Lcom/google/firebase/messaging/x;)Z
    .locals 6

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->h:Lcom/google/firebase/messaging/r;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/firebase/messaging/r;->b()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    iget-wide v2, p1, Lcom/google/firebase/messaging/x;->c:J

    .line 14
    .line 15
    sget-wide v4, Lcom/google/firebase/messaging/x;->d:J

    .line 16
    .line 17
    add-long/2addr v2, v4

    .line 18
    cmp-long v0, v0, v2

    .line 19
    .line 20
    if-gtz v0, :cond_1

    .line 21
    .line 22
    iget-object p1, p1, Lcom/google/firebase/messaging/x;->b:Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-nez p0, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 p0, 0x0

    .line 32
    return p0

    .line 33
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 34
    return p0
.end method
