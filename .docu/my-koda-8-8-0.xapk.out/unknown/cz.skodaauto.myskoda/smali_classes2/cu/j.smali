.class public final Lcu/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lfu/a;


# static fields
.field public static final j:Ljava/util/Random;

.field public static final k:Ljava/util/HashMap;


# instance fields
.field public final a:Ljava/util/HashMap;

.field public final b:Landroid/content/Context;

.field public final c:Ljava/util/concurrent/ScheduledExecutorService;

.field public final d:Lsr/f;

.field public final e:Lht/d;

.field public final f:Ltr/c;

.field public final g:Lgt/b;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/util/HashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/Random;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/Random;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcu/j;->j:Ljava/util/Random;

    .line 7
    .line 8
    new-instance v0, Ljava/util/HashMap;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lcu/j;->k:Ljava/util/HashMap;

    .line 14
    .line 15
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/util/concurrent/ScheduledExecutorService;Lsr/f;Lht/d;Ltr/c;Lgt/b;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcu/j;->a:Ljava/util/HashMap;

    .line 10
    .line 11
    new-instance v0, Ljava/util/HashMap;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lcu/j;->i:Ljava/util/HashMap;

    .line 17
    .line 18
    iput-object p1, p0, Lcu/j;->b:Landroid/content/Context;

    .line 19
    .line 20
    iput-object p2, p0, Lcu/j;->c:Ljava/util/concurrent/ScheduledExecutorService;

    .line 21
    .line 22
    iput-object p3, p0, Lcu/j;->d:Lsr/f;

    .line 23
    .line 24
    iput-object p4, p0, Lcu/j;->e:Lht/d;

    .line 25
    .line 26
    iput-object p5, p0, Lcu/j;->f:Ltr/c;

    .line 27
    .line 28
    iput-object p6, p0, Lcu/j;->g:Lgt/b;

    .line 29
    .line 30
    invoke-virtual {p3}, Lsr/f;->a()V

    .line 31
    .line 32
    .line 33
    iget-object p3, p3, Lsr/f;->c:Lsr/i;

    .line 34
    .line 35
    iget-object p3, p3, Lsr/i;->b:Ljava/lang/String;

    .line 36
    .line 37
    iput-object p3, p0, Lcu/j;->h:Ljava/lang/String;

    .line 38
    .line 39
    sget-object p3, Lcu/i;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 40
    .line 41
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    check-cast p1, Landroid/app/Application;

    .line 46
    .line 47
    sget-object p3, Lcu/i;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 48
    .line 49
    invoke-virtual {p3}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p4

    .line 53
    if-nez p4, :cond_2

    .line 54
    .line 55
    new-instance p4, Lcu/i;

    .line 56
    .line 57
    invoke-direct {p4}, Ljava/lang/Object;-><init>()V

    .line 58
    .line 59
    .line 60
    :cond_0
    const/4 p5, 0x0

    .line 61
    invoke-virtual {p3, p5, p4}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result p5

    .line 65
    if-eqz p5, :cond_1

    .line 66
    .line 67
    invoke-static {p1}, Llo/d;->b(Landroid/app/Application;)V

    .line 68
    .line 69
    .line 70
    sget-object p1, Llo/d;->h:Llo/d;

    .line 71
    .line 72
    invoke-virtual {p1, p4}, Llo/d;->a(Llo/c;)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_1
    invoke-virtual {p3}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p5

    .line 80
    if-eqz p5, :cond_0

    .line 81
    .line 82
    :cond_2
    :goto_0
    new-instance p1, Lbm/x;

    .line 83
    .line 84
    const/4 p3, 0x1

    .line 85
    invoke-direct {p1, p0, p3}, Lbm/x;-><init>(Ljava/lang/Object;I)V

    .line 86
    .line 87
    .line 88
    invoke-static {p2, p1}, Ljp/l1;->c(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;)Laq/t;

    .line 89
    .line 90
    .line 91
    return-void
.end method


# virtual methods
.method public final declared-synchronized a(Ljava/lang/String;)Lcu/b;
    .locals 14

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    const-string v0, "fetch"

    .line 3
    .line 4
    invoke-virtual {p0, p1, v0}, Lcu/j;->c(Ljava/lang/String;Ljava/lang/String;)Ldu/c;

    .line 5
    .line 6
    .line 7
    move-result-object v7

    .line 8
    const-string v0, "activate"

    .line 9
    .line 10
    invoke-virtual {p0, p1, v0}, Lcu/j;->c(Ljava/lang/String;Ljava/lang/String;)Ldu/c;

    .line 11
    .line 12
    .line 13
    move-result-object v8

    .line 14
    const-string v0, "defaults"

    .line 15
    .line 16
    invoke-virtual {p0, p1, v0}, Lcu/j;->c(Ljava/lang/String;Ljava/lang/String;)Ldu/c;

    .line 17
    .line 18
    .line 19
    move-result-object v9

    .line 20
    iget-object v0, p0, Lcu/j;->b:Landroid/content/Context;

    .line 21
    .line 22
    iget-object v1, p0, Lcu/j;->h:Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 23
    .line 24
    :try_start_1
    new-instance v2, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    const-string v3, "frc_"

    .line 27
    .line 28
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string v1, "_"

    .line 35
    .line 36
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v1, "_settings"

    .line 43
    .line 44
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    const/4 v2, 0x0

    .line 52
    invoke-virtual {v0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    new-instance v12, Ldu/n;

    .line 57
    .line 58
    invoke-direct {v12, v0}, Ldu/n;-><init>(Landroid/content/SharedPreferences;)V

    .line 59
    .line 60
    .line 61
    new-instance v11, Ldu/j;

    .line 62
    .line 63
    iget-object v0, p0, Lcu/j;->c:Ljava/util/concurrent/ScheduledExecutorService;

    .line 64
    .line 65
    invoke-direct {v11, v0, v8, v9}, Ldu/j;-><init>(Ljava/util/concurrent/Executor;Ldu/c;Ldu/c;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 66
    .line 67
    .line 68
    :try_start_2
    iget-object v0, p0, Lcu/j;->d:Lsr/f;

    .line 69
    .line 70
    iget-object v1, p0, Lcu/j;->g:Lgt/b;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 71
    .line 72
    :try_start_3
    invoke-virtual {v0}, Lsr/f;->a()V

    .line 73
    .line 74
    .line 75
    iget-object v0, v0, Lsr/f;->b:Ljava/lang/String;

    .line 76
    .line 77
    const-string v2, "[DEFAULT]"

    .line 78
    .line 79
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_4

    .line 83
    if-eqz v0, :cond_0

    .line 84
    .line 85
    :try_start_4
    const-string v0, "firebase"

    .line 86
    .line 87
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-eqz v0, :cond_0

    .line 92
    .line 93
    new-instance v0, Lb81/a;

    .line 94
    .line 95
    invoke-direct {v0, v1}, Lb81/a;-><init>(Lgt/b;)V

    .line 96
    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_0
    const/4 v0, 0x0

    .line 100
    :goto_0
    if-eqz v0, :cond_1

    .line 101
    .line 102
    new-instance v1, Lcu/h;

    .line 103
    .line 104
    invoke-direct {v1, v0}, Lcu/h;-><init>(Lb81/a;)V

    .line 105
    .line 106
    .line 107
    iget-object v2, v11, Ldu/j;->a:Ljava/util/HashSet;

    .line 108
    .line 109
    monitor-enter v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 110
    :try_start_5
    iget-object v0, v11, Ldu/j;->a:Ljava/util/HashSet;

    .line 111
    .line 112
    invoke-virtual {v0, v1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    monitor-exit v2

    .line 116
    goto :goto_2

    .line 117
    :catchall_0
    move-exception v0

    .line 118
    move-object p1, v0

    .line 119
    monitor-exit v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 120
    :try_start_6
    throw p1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 121
    :goto_1
    move-object v1, p0

    .line 122
    goto :goto_5

    .line 123
    :catchall_1
    move-exception v0

    .line 124
    move-object p1, v0

    .line 125
    goto :goto_1

    .line 126
    :cond_1
    :goto_2
    :try_start_7
    new-instance v0, Lb81/b;

    .line 127
    .line 128
    const/4 v1, 0x5

    .line 129
    const/4 v2, 0x0

    .line 130
    invoke-direct {v0, v1, v2}, Lb81/b;-><init>(IZ)V

    .line 131
    .line 132
    .line 133
    iput-object v8, v0, Lb81/b;->e:Ljava/lang/Object;

    .line 134
    .line 135
    iput-object v9, v0, Lb81/b;->f:Ljava/lang/Object;

    .line 136
    .line 137
    new-instance v13, Lcom/google/firebase/messaging/w;

    .line 138
    .line 139
    iget-object v1, p0, Lcu/j;->c:Ljava/util/concurrent/ScheduledExecutorService;

    .line 140
    .line 141
    const/16 v2, 0xa

    .line 142
    .line 143
    const/4 v3, 0x0

    .line 144
    invoke-direct {v13, v2, v3}, Lcom/google/firebase/messaging/w;-><init>(IZ)V

    .line 145
    .line 146
    .line 147
    new-instance v2, Ljava/util/concurrent/ConcurrentHashMap;

    .line 148
    .line 149
    invoke-direct {v2}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 150
    .line 151
    .line 152
    invoke-static {v2}, Ljava/util/Collections;->newSetFromMap(Ljava/util/Map;)Ljava/util/Set;

    .line 153
    .line 154
    .line 155
    move-result-object v2

    .line 156
    iput-object v2, v13, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 157
    .line 158
    iput-object v8, v13, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 159
    .line 160
    iput-object v0, v13, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 161
    .line 162
    iput-object v1, v13, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_4

    .line 163
    .line 164
    :try_start_8
    iget-object v2, p0, Lcu/j;->d:Lsr/f;

    .line 165
    .line 166
    iget-object v4, p0, Lcu/j;->e:Lht/d;

    .line 167
    .line 168
    iget-object v5, p0, Lcu/j;->f:Ltr/c;

    .line 169
    .line 170
    iget-object v6, p0, Lcu/j;->c:Ljava/util/concurrent/ScheduledExecutorService;

    .line 171
    .line 172
    invoke-virtual {p0, p1, v7, v12}, Lcu/j;->d(Ljava/lang/String;Ldu/c;Ldu/n;)Ldu/i;

    .line 173
    .line 174
    .line 175
    move-result-object v10
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 176
    move-object v1, p0

    .line 177
    move-object v3, p1

    .line 178
    :try_start_9
    invoke-virtual/range {v1 .. v13}, Lcu/j;->b(Lsr/f;Ljava/lang/String;Lht/d;Ltr/c;Ljava/util/concurrent/Executor;Ldu/c;Ldu/c;Ldu/c;Ldu/i;Ldu/j;Ldu/n;Lcom/google/firebase/messaging/w;)Lcu/b;

    .line 179
    .line 180
    .line 181
    move-result-object p0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 182
    monitor-exit v1

    .line 183
    return-object p0

    .line 184
    :catchall_2
    move-exception v0

    .line 185
    :goto_3
    move-object p1, v0

    .line 186
    goto :goto_5

    .line 187
    :catchall_3
    move-exception v0

    .line 188
    move-object v1, p0

    .line 189
    goto :goto_3

    .line 190
    :goto_4
    move-object p1, p0

    .line 191
    goto :goto_5

    .line 192
    :catchall_4
    move-exception v0

    .line 193
    move-object v1, p0

    .line 194
    move-object p0, v0

    .line 195
    goto :goto_4

    .line 196
    :goto_5
    :try_start_a
    monitor-exit v1
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_2

    .line 197
    throw p1
.end method

.method public final declared-synchronized b(Lsr/f;Ljava/lang/String;Lht/d;Ltr/c;Ljava/util/concurrent/Executor;Ldu/c;Ldu/c;Ldu/c;Ldu/i;Ldu/j;Ldu/n;Lcom/google/firebase/messaging/w;)Lcu/b;
    .locals 13

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lcu/j;->a:Ljava/util/HashMap;

    .line 3
    .line 4
    invoke-virtual {v0, p2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    new-instance v9, Lcu/b;

    .line 11
    .line 12
    iget-object v10, p0, Lcu/j;->b:Landroid/content/Context;

    .line 13
    .line 14
    const-string v0, "firebase"

    .line 15
    .line 16
    invoke-virtual {p2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {p1}, Lsr/f;->a()V

    .line 23
    .line 24
    .line 25
    iget-object v0, p1, Lsr/f;->b:Ljava/lang/String;

    .line 26
    .line 27
    const-string v1, "[DEFAULT]"

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    move-object/from16 v11, p4

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 v0, 0x0

    .line 39
    move-object v11, v0

    .line 40
    :goto_0
    iget-object v5, p0, Lcu/j;->b:Landroid/content/Context;

    .line 41
    .line 42
    monitor-enter p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    :try_start_1
    new-instance v0, Lvp/y1;

    .line 44
    .line 45
    iget-object v8, p0, Lcu/j;->c:Ljava/util/concurrent/ScheduledExecutorService;

    .line 46
    .line 47
    move-object v1, p1

    .line 48
    move-object v6, p2

    .line 49
    move-object/from16 v2, p3

    .line 50
    .line 51
    move-object/from16 v4, p7

    .line 52
    .line 53
    move-object/from16 v3, p9

    .line 54
    .line 55
    move-object/from16 v7, p11

    .line 56
    .line 57
    invoke-direct/range {v0 .. v8}, Lvp/y1;-><init>(Lsr/f;Lht/d;Ldu/i;Ldu/c;Landroid/content/Context;Ljava/lang/String;Ldu/n;Ljava/util/concurrent/ScheduledExecutorService;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 58
    .line 59
    .line 60
    :try_start_2
    monitor-exit p0

    .line 61
    move-object/from16 v4, p5

    .line 62
    .line 63
    move-object/from16 v5, p6

    .line 64
    .line 65
    move-object/from16 v6, p7

    .line 66
    .line 67
    move-object/from16 v7, p8

    .line 68
    .line 69
    move-object/from16 v8, p9

    .line 70
    .line 71
    move-object/from16 v12, p12

    .line 72
    .line 73
    move-object v1, v9

    .line 74
    move-object v2, v10

    .line 75
    move-object v3, v11

    .line 76
    move-object/from16 v9, p10

    .line 77
    .line 78
    move-object/from16 v10, p11

    .line 79
    .line 80
    move-object v11, v0

    .line 81
    invoke-direct/range {v1 .. v12}, Lcu/b;-><init>(Landroid/content/Context;Ltr/c;Ljava/util/concurrent/Executor;Ldu/c;Ldu/c;Ldu/c;Ldu/i;Ldu/j;Ldu/n;Lvp/y1;Lcom/google/firebase/messaging/w;)V

    .line 82
    .line 83
    .line 84
    invoke-virtual/range {p7 .. p7}, Ldu/c;->b()Laq/j;

    .line 85
    .line 86
    .line 87
    invoke-virtual/range {p8 .. p8}, Ldu/c;->b()Laq/j;

    .line 88
    .line 89
    .line 90
    invoke-virtual/range {p6 .. p6}, Ldu/c;->b()Laq/j;

    .line 91
    .line 92
    .line 93
    iget-object v0, p0, Lcu/j;->a:Ljava/util/HashMap;

    .line 94
    .line 95
    invoke-virtual {v0, p2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    sget-object v0, Lcu/j;->k:Ljava/util/HashMap;

    .line 99
    .line 100
    invoke-virtual {v0, p2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 101
    .line 102
    .line 103
    goto :goto_1

    .line 104
    :catchall_0
    move-exception v0

    .line 105
    move-object p1, v0

    .line 106
    goto :goto_2

    .line 107
    :catchall_1
    move-exception v0

    .line 108
    move-object p1, v0

    .line 109
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 110
    :try_start_4
    throw p1

    .line 111
    :cond_1
    :goto_1
    iget-object v0, p0, Lcu/j;->a:Ljava/util/HashMap;

    .line 112
    .line 113
    invoke-virtual {v0, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    check-cast p1, Lcu/b;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 118
    .line 119
    monitor-exit p0

    .line 120
    return-object p1

    .line 121
    :goto_2
    :try_start_5
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 122
    throw p1
.end method

.method public final c(Ljava/lang/String;Ljava/lang/String;)Ldu/c;
    .locals 4

    .line 1
    iget-object v0, p0, Lcu/j;->h:Ljava/lang/String;

    .line 2
    .line 3
    const-string v1, "frc_"

    .line 4
    .line 5
    const-string v2, "_"

    .line 6
    .line 7
    const-string v3, "_"

    .line 8
    .line 9
    invoke-static {v1, v0, v2, p1, v3}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    const-string v0, ".json"

    .line 14
    .line 15
    invoke-static {p1, p2, v0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iget-object p2, p0, Lcu/j;->c:Ljava/util/concurrent/ScheduledExecutorService;

    .line 20
    .line 21
    iget-object p0, p0, Lcu/j;->b:Landroid/content/Context;

    .line 22
    .line 23
    sget-object v0, Ldu/o;->c:Ljava/util/HashMap;

    .line 24
    .line 25
    const-class v0, Ldu/o;

    .line 26
    .line 27
    monitor-enter v0

    .line 28
    :try_start_0
    sget-object v1, Ldu/o;->c:Ljava/util/HashMap;

    .line 29
    .line 30
    invoke-virtual {v1, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-nez v2, :cond_0

    .line 35
    .line 36
    new-instance v2, Ldu/o;

    .line 37
    .line 38
    invoke-direct {v2, p0, p1}, Ldu/o;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v1, p1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catchall_0
    move-exception p0

    .line 46
    goto :goto_3

    .line 47
    :cond_0
    :goto_0
    invoke-virtual {v1, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Ldu/o;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 52
    .line 53
    monitor-exit v0

    .line 54
    sget-object p1, Ldu/c;->d:Ljava/util/HashMap;

    .line 55
    .line 56
    const-class p1, Ldu/c;

    .line 57
    .line 58
    monitor-enter p1

    .line 59
    :try_start_1
    iget-object v0, p0, Ldu/o;->b:Ljava/lang/String;

    .line 60
    .line 61
    sget-object v1, Ldu/c;->d:Ljava/util/HashMap;

    .line 62
    .line 63
    invoke-virtual {v1, v0}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    if-nez v2, :cond_1

    .line 68
    .line 69
    new-instance v2, Ldu/c;

    .line 70
    .line 71
    invoke-direct {v2, p2, p0}, Ldu/c;-><init>(Ljava/util/concurrent/Executor;Ldu/o;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v1, v0, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :catchall_1
    move-exception p0

    .line 79
    goto :goto_2

    .line 80
    :cond_1
    :goto_1
    invoke-virtual {v1, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    check-cast p0, Ldu/c;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 85
    .line 86
    monitor-exit p1

    .line 87
    return-object p0

    .line 88
    :goto_2
    :try_start_2
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 89
    throw p0

    .line 90
    :goto_3
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 91
    throw p0
.end method

.method public final declared-synchronized d(Ljava/lang/String;Ldu/c;Ldu/n;)Ldu/i;
    .locals 21

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v9, p3

    .line 4
    .line 5
    monitor-enter p0

    .line 6
    :try_start_0
    new-instance v2, Ldu/i;

    .line 7
    .line 8
    iget-object v3, v1, Lcu/j;->e:Lht/d;

    .line 9
    .line 10
    iget-object v0, v1, Lcu/j;->d:Lsr/f;

    .line 11
    .line 12
    invoke-virtual {v0}, Lsr/f;->a()V

    .line 13
    .line 14
    .line 15
    iget-object v0, v0, Lsr/f;->b:Ljava/lang/String;

    .line 16
    .line 17
    const-string v4, "[DEFAULT]"

    .line 18
    .line 19
    invoke-virtual {v0, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    iget-object v0, v1, Lcu/j;->g:Lgt/b;

    .line 26
    .line 27
    :goto_0
    move-object v4, v0

    .line 28
    goto :goto_1

    .line 29
    :catchall_0
    move-exception v0

    .line 30
    goto :goto_2

    .line 31
    :cond_0
    new-instance v0, Lcom/google/firebase/messaging/l;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    invoke-direct {v0, v4}, Lcom/google/firebase/messaging/l;-><init>(I)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :goto_1
    iget-object v5, v1, Lcu/j;->c:Ljava/util/concurrent/ScheduledExecutorService;

    .line 39
    .line 40
    sget-object v6, Lcu/j;->j:Ljava/util/Random;

    .line 41
    .line 42
    iget-object v0, v1, Lcu/j;->d:Lsr/f;

    .line 43
    .line 44
    invoke-virtual {v0}, Lsr/f;->a()V

    .line 45
    .line 46
    .line 47
    iget-object v0, v0, Lsr/f;->c:Lsr/i;

    .line 48
    .line 49
    iget-object v13, v0, Lsr/i;->a:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v0, v1, Lcu/j;->d:Lsr/f;

    .line 52
    .line 53
    invoke-virtual {v0}, Lsr/f;->a()V

    .line 54
    .line 55
    .line 56
    iget-object v0, v0, Lsr/f;->c:Lsr/i;

    .line 57
    .line 58
    iget-object v12, v0, Lsr/i;->b:Ljava/lang/String;

    .line 59
    .line 60
    new-instance v8, Lcom/google/firebase/remoteconfig/internal/ConfigFetchHttpClient;

    .line 61
    .line 62
    iget-object v11, v1, Lcu/j;->b:Landroid/content/Context;

    .line 63
    .line 64
    iget-object v0, v9, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 65
    .line 66
    const-string v7, "fetch_timeout_in_seconds"

    .line 67
    .line 68
    const-wide/16 v14, 0x3c

    .line 69
    .line 70
    invoke-interface {v0, v7, v14, v15}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 71
    .line 72
    .line 73
    move-result-wide v16

    .line 74
    iget-object v0, v9, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 75
    .line 76
    const-string v7, "fetch_timeout_in_seconds"

    .line 77
    .line 78
    invoke-interface {v0, v7, v14, v15}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 79
    .line 80
    .line 81
    move-result-wide v14

    .line 82
    move-wide/from16 v19, v16

    .line 83
    .line 84
    move-wide/from16 v17, v14

    .line 85
    .line 86
    move-wide/from16 v15, v19

    .line 87
    .line 88
    move-object/from16 v14, p1

    .line 89
    .line 90
    move-object v10, v8

    .line 91
    invoke-direct/range {v10 .. v18}, Lcom/google/firebase/remoteconfig/internal/ConfigFetchHttpClient;-><init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JJ)V

    .line 92
    .line 93
    .line 94
    move-object v8, v10

    .line 95
    iget-object v10, v1, Lcu/j;->i:Ljava/util/HashMap;

    .line 96
    .line 97
    move-object/from16 v7, p2

    .line 98
    .line 99
    invoke-direct/range {v2 .. v10}, Ldu/i;-><init>(Lht/d;Lgt/b;Ljava/util/concurrent/Executor;Ljava/util/Random;Ldu/c;Lcom/google/firebase/remoteconfig/internal/ConfigFetchHttpClient;Ldu/n;Ljava/util/HashMap;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 100
    .line 101
    .line 102
    monitor-exit p0

    .line 103
    return-object v2

    .line 104
    :goto_2
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 105
    throw v0
.end method
