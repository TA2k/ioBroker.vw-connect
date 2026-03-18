.class public final synthetic Lio/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/16 v0, 0xd

    iput v0, p0, Lio/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p4, p0, Lio/i;->d:I

    iput-object p1, p0, Lio/i;->e:Ljava/lang/Object;

    iput-object p2, p0, Lio/i;->f:Ljava/lang/Object;

    iput-object p3, p0, Lio/i;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;I)V
    .locals 0

    .line 3
    iput p5, p0, Lio/i;->d:I

    iput-object p1, p0, Lio/i;->g:Ljava/lang/Object;

    iput-object p2, p0, Lio/i;->e:Ljava/lang/Object;

    iput-object p4, p0, Lio/i;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkp/la;Lvp/y1;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lio/i;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lio/i;->e:Ljava/lang/Object;

    iput-object p2, p0, Lio/i;->f:Ljava/lang/Object;

    iput-object p3, p0, Lio/i;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/d3;Ljava/util/concurrent/atomic/AtomicReference;Lvp/f4;)V
    .locals 1

    const/16 v0, 0x9

    iput v0, p0, Lio/i;->d:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lio/i;->e:Ljava/lang/Object;

    iput-object p3, p0, Lio/i;->f:Ljava/lang/Object;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lio/i;->g:Ljava/lang/Object;

    return-void
.end method

.method private final a()V
    .locals 9

    .line 1
    const-string v0, "Failed to get app instance id"

    .line 2
    .line 3
    iget-object v1, p0, Lio/i;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lcom/google/android/gms/internal/measurement/m0;

    .line 6
    .line 7
    iget-object v2, p0, Lio/i;->g:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v2, Lvp/d3;

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    :try_start_0
    iget-object v4, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v4, Lvp/g1;

    .line 15
    .line 16
    iget-object v5, v4, Lvp/g1;->h:Lvp/w0;

    .line 17
    .line 18
    iget-object v6, v4, Lvp/g1;->i:Lvp/p0;

    .line 19
    .line 20
    invoke-static {v5}, Lvp/g1;->g(Lap0/o;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v5}, Lvp/w0;->h0()Lvp/s1;

    .line 24
    .line 25
    .line 26
    move-result-object v7

    .line 27
    sget-object v8, Lvp/r1;->f:Lvp/r1;

    .line 28
    .line 29
    invoke-virtual {v7, v8}, Lvp/s1;->i(Lvp/r1;)Z

    .line 30
    .line 31
    .line 32
    move-result v7

    .line 33
    if-nez v7, :cond_0

    .line 34
    .line 35
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, v6, Lvp/p0;->o:Lvp/n0;

    .line 39
    .line 40
    const-string v6, "Analytics storage consent denied; will not get app instance id"

    .line 41
    .line 42
    invoke-virtual {p0, v6}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    iget-object p0, v4, Lvp/g1;->p:Lvp/j2;

    .line 46
    .line 47
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 48
    .line 49
    .line 50
    iget-object p0, p0, Lvp/j2;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 51
    .line 52
    invoke-virtual {p0, v3}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-static {v5}, Lvp/g1;->g(Lap0/o;)V

    .line 56
    .line 57
    .line 58
    iget-object p0, v5, Lvp/w0;->k:La8/b;

    .line 59
    .line 60
    invoke-virtual {p0, v3}, La8/b;->u(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    goto :goto_4

    .line 66
    :catch_0
    move-exception p0

    .line 67
    goto :goto_2

    .line 68
    :cond_0
    iget-object v7, v2, Lvp/d3;->h:Lvp/c0;

    .line 69
    .line 70
    if-nez v7, :cond_1

    .line 71
    .line 72
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 73
    .line 74
    .line 75
    iget-object p0, v6, Lvp/p0;->j:Lvp/n0;

    .line 76
    .line 77
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 78
    .line 79
    .line 80
    :goto_0
    iget-object p0, v4, Lvp/g1;->l:Lvp/d4;

    .line 81
    .line 82
    :goto_1
    invoke-static {p0}, Lvp/g1;->g(Lap0/o;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p0, v3, v1}, Lvp/d4;->I0(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V

    .line 86
    .line 87
    .line 88
    return-void

    .line 89
    :cond_1
    :try_start_1
    iget-object p0, p0, Lio/i;->e:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast p0, Lvp/f4;

    .line 92
    .line 93
    invoke-interface {v7, p0}, Lvp/c0;->u(Lvp/f4;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    if-eqz v3, :cond_2

    .line 98
    .line 99
    iget-object p0, v4, Lvp/g1;->p:Lvp/j2;

    .line 100
    .line 101
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 102
    .line 103
    .line 104
    iget-object p0, p0, Lvp/j2;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 105
    .line 106
    invoke-virtual {p0, v3}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    invoke-static {v5}, Lvp/g1;->g(Lap0/o;)V

    .line 110
    .line 111
    .line 112
    iget-object p0, v5, Lvp/w0;->k:La8/b;

    .line 113
    .line 114
    invoke-virtual {p0, v3}, La8/b;->u(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    :cond_2
    invoke-virtual {v2}, Lvp/d3;->n0()V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 118
    .line 119
    .line 120
    goto :goto_3

    .line 121
    :goto_2
    :try_start_2
    iget-object v4, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v4, Lvp/g1;

    .line 124
    .line 125
    iget-object v4, v4, Lvp/g1;->i:Lvp/p0;

    .line 126
    .line 127
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 128
    .line 129
    .line 130
    iget-object v4, v4, Lvp/p0;->j:Lvp/n0;

    .line 131
    .line 132
    invoke-virtual {v4, p0, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 133
    .line 134
    .line 135
    :goto_3
    iget-object p0, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast p0, Lvp/g1;

    .line 138
    .line 139
    iget-object p0, p0, Lvp/g1;->l:Lvp/d4;

    .line 140
    .line 141
    goto :goto_1

    .line 142
    :goto_4
    iget-object v0, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v0, Lvp/g1;

    .line 145
    .line 146
    iget-object v0, v0, Lvp/g1;->l:Lvp/d4;

    .line 147
    .line 148
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v0, v3, v1}, Lvp/d4;->I0(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V

    .line 152
    .line 153
    .line 154
    throw p0
.end method


# virtual methods
.method public final run()V
    .locals 37

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget v0, v1, Lio/i;->d:I

    .line 4
    .line 5
    const/4 v2, 0x5

    .line 6
    const/4 v3, 0x2

    .line 7
    const/4 v4, 0x3

    .line 8
    const/4 v5, 0x4

    .line 9
    const/4 v6, 0x0

    .line 10
    const/4 v7, 0x1

    .line 11
    const/4 v8, 0x0

    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    :try_start_0
    iget-object v0, v1, Lio/i;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lz5/d;

    .line 18
    .line 19
    invoke-virtual {v0}, Lz5/d;->call()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v8
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 23
    :catch_0
    iget-object v0, v1, Lio/i;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v0, Lp0/d;

    .line 26
    .line 27
    iget-object v1, v1, Lio/i;->g:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v1, Landroid/os/Handler;

    .line 30
    .line 31
    new-instance v2, Lk0/g;

    .line 32
    .line 33
    const/16 v3, 0x18

    .line 34
    .line 35
    invoke-direct {v2, v3, v0, v8}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :pswitch_0
    iget-object v0, v1, Lio/i;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v0, Lpv/g;

    .line 45
    .line 46
    iget-object v2, v1, Lio/i;->f:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v2, Lvp/p0;

    .line 49
    .line 50
    iget-object v1, v1, Lio/i;->g:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v1, Landroid/app/job/JobParameters;

    .line 53
    .line 54
    iget-object v2, v2, Lvp/p0;->r:Lvp/n0;

    .line 55
    .line 56
    const-string v3, "AppMeasurementJobService processed last upload request."

    .line 57
    .line 58
    invoke-virtual {v2, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iget-object v0, v0, Lpv/g;->e:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v0, Landroid/app/Service;

    .line 64
    .line 65
    check-cast v0, Lvp/g3;

    .line 66
    .line 67
    invoke-interface {v0, v1}, Lvp/g3;->c(Landroid/app/job/JobParameters;)V

    .line 68
    .line 69
    .line 70
    return-void

    .line 71
    :pswitch_1
    iget-object v0, v1, Lio/i;->e:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v0, Lvp/d3;

    .line 74
    .line 75
    iget-object v2, v1, Lio/i;->f:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v2, Lvp/f4;

    .line 78
    .line 79
    iget-object v1, v1, Lio/i;->g:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v1, Lvp/e;

    .line 82
    .line 83
    iget-object v3, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v3, Lvp/g1;

    .line 86
    .line 87
    iget-object v4, v0, Lvp/d3;->h:Lvp/c0;

    .line 88
    .line 89
    if-nez v4, :cond_0

    .line 90
    .line 91
    iget-object v0, v3, Lvp/g1;->i:Lvp/p0;

    .line 92
    .line 93
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 94
    .line 95
    .line 96
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 97
    .line 98
    const-string v1, "[sgtm] Discarding data. Failed to update batch upload status."

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_0
    :try_start_1
    invoke-interface {v4, v2, v1}, Lvp/c0;->l(Lvp/f4;Lvp/e;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v0}, Lvp/d3;->n0()V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_1

    .line 108
    .line 109
    .line 110
    goto :goto_0

    .line 111
    :catch_1
    move-exception v0

    .line 112
    iget-object v2, v3, Lvp/g1;->i:Lvp/p0;

    .line 113
    .line 114
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 115
    .line 116
    .line 117
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 118
    .line 119
    iget-wide v3, v1, Lvp/e;->d:J

    .line 120
    .line 121
    const-string v1, "[sgtm] Failed to update batch upload status, rowId, exception"

    .line 122
    .line 123
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 124
    .line 125
    .line 126
    move-result-object v3

    .line 127
    invoke-virtual {v2, v3, v0, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    :goto_0
    return-void

    .line 131
    :pswitch_2
    invoke-direct {v1}, Lio/i;->a()V

    .line 132
    .line 133
    .line 134
    return-void

    .line 135
    :pswitch_3
    iget-object v0, v1, Lio/i;->e:Ljava/lang/Object;

    .line 136
    .line 137
    move-object v6, v0

    .line 138
    check-cast v6, Ljava/util/concurrent/atomic/AtomicReference;

    .line 139
    .line 140
    monitor-enter v6

    .line 141
    :try_start_2
    iget-object v0, v1, Lio/i;->g:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast v0, Lvp/d3;

    .line 144
    .line 145
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v2, Lvp/g1;

    .line 148
    .line 149
    iget-object v3, v2, Lvp/g1;->h:Lvp/w0;

    .line 150
    .line 151
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v3}, Lvp/w0;->h0()Lvp/s1;

    .line 155
    .line 156
    .line 157
    move-result-object v3

    .line 158
    sget-object v4, Lvp/r1;->f:Lvp/r1;

    .line 159
    .line 160
    invoke-virtual {v3, v4}, Lvp/s1;->i(Lvp/r1;)Z

    .line 161
    .line 162
    .line 163
    move-result v3

    .line 164
    if-nez v3, :cond_1

    .line 165
    .line 166
    iget-object v3, v2, Lvp/g1;->i:Lvp/p0;

    .line 167
    .line 168
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 169
    .line 170
    .line 171
    iget-object v3, v3, Lvp/p0;->o:Lvp/n0;

    .line 172
    .line 173
    const-string v4, "Analytics storage consent denied; will not get app instance id"

    .line 174
    .line 175
    invoke-virtual {v3, v4}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 179
    .line 180
    check-cast v0, Lvp/g1;

    .line 181
    .line 182
    iget-object v0, v0, Lvp/g1;->p:Lvp/j2;

    .line 183
    .line 184
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 185
    .line 186
    .line 187
    iget-object v0, v0, Lvp/j2;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 188
    .line 189
    invoke-virtual {v0, v8}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    iget-object v0, v2, Lvp/g1;->h:Lvp/w0;

    .line 193
    .line 194
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 195
    .line 196
    .line 197
    iget-object v0, v0, Lvp/w0;->k:La8/b;

    .line 198
    .line 199
    invoke-virtual {v0, v8}, La8/b;->u(Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v6, v8}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V
    :try_end_2
    .catch Landroid/os/RemoteException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 203
    .line 204
    .line 205
    :goto_1
    :try_start_3
    invoke-virtual {v6}, Ljava/lang/Object;->notify()V

    .line 206
    .line 207
    .line 208
    monitor-exit v6
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 209
    goto :goto_4

    .line 210
    :catchall_0
    move-exception v0

    .line 211
    goto :goto_6

    .line 212
    :catchall_1
    move-exception v0

    .line 213
    goto :goto_5

    .line 214
    :catch_2
    move-exception v0

    .line 215
    goto :goto_2

    .line 216
    :cond_1
    :try_start_4
    iget-object v3, v0, Lvp/d3;->h:Lvp/c0;

    .line 217
    .line 218
    if-nez v3, :cond_2

    .line 219
    .line 220
    iget-object v0, v2, Lvp/g1;->i:Lvp/p0;

    .line 221
    .line 222
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 223
    .line 224
    .line 225
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 226
    .line 227
    const-string v2, "Failed to get app instance id"

    .line 228
    .line 229
    invoke-virtual {v0, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    goto :goto_1

    .line 233
    :cond_2
    iget-object v4, v1, Lio/i;->f:Ljava/lang/Object;

    .line 234
    .line 235
    check-cast v4, Lvp/f4;

    .line 236
    .line 237
    invoke-interface {v3, v4}, Lvp/c0;->u(Lvp/f4;)Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v3

    .line 241
    invoke-virtual {v6, v3}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    invoke-virtual {v6}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v3

    .line 248
    check-cast v3, Ljava/lang/String;

    .line 249
    .line 250
    if-eqz v3, :cond_3

    .line 251
    .line 252
    iget-object v4, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast v4, Lvp/g1;

    .line 255
    .line 256
    iget-object v4, v4, Lvp/g1;->p:Lvp/j2;

    .line 257
    .line 258
    invoke-static {v4}, Lvp/g1;->i(Lvp/b0;)V

    .line 259
    .line 260
    .line 261
    iget-object v4, v4, Lvp/j2;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 262
    .line 263
    invoke-virtual {v4, v3}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    iget-object v2, v2, Lvp/g1;->h:Lvp/w0;

    .line 267
    .line 268
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 269
    .line 270
    .line 271
    iget-object v2, v2, Lvp/w0;->k:La8/b;

    .line 272
    .line 273
    invoke-virtual {v2, v3}, La8/b;->u(Ljava/lang/String;)V

    .line 274
    .line 275
    .line 276
    :cond_3
    invoke-virtual {v0}, Lvp/d3;->n0()V
    :try_end_4
    .catch Landroid/os/RemoteException; {:try_start_4 .. :try_end_4} :catch_2
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 277
    .line 278
    .line 279
    :try_start_5
    iget-object v0, v1, Lio/i;->e:Ljava/lang/Object;

    .line 280
    .line 281
    check-cast v0, Ljava/util/concurrent/atomic/AtomicReference;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 282
    .line 283
    goto :goto_3

    .line 284
    :goto_2
    :try_start_6
    iget-object v2, v1, Lio/i;->g:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast v2, Lvp/d3;

    .line 287
    .line 288
    iget-object v2, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 289
    .line 290
    check-cast v2, Lvp/g1;

    .line 291
    .line 292
    iget-object v2, v2, Lvp/g1;->i:Lvp/p0;

    .line 293
    .line 294
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 295
    .line 296
    .line 297
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 298
    .line 299
    const-string v3, "Failed to get app instance id"

    .line 300
    .line 301
    invoke-virtual {v2, v0, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 302
    .line 303
    .line 304
    :try_start_7
    iget-object v0, v1, Lio/i;->e:Ljava/lang/Object;

    .line 305
    .line 306
    check-cast v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 307
    .line 308
    :goto_3
    invoke-virtual {v0}, Ljava/lang/Object;->notify()V

    .line 309
    .line 310
    .line 311
    monitor-exit v6

    .line 312
    :goto_4
    return-void

    .line 313
    :goto_5
    iget-object v1, v1, Lio/i;->e:Ljava/lang/Object;

    .line 314
    .line 315
    check-cast v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 316
    .line 317
    invoke-virtual {v1}, Ljava/lang/Object;->notify()V

    .line 318
    .line 319
    .line 320
    throw v0

    .line 321
    :goto_6
    monitor-exit v6
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 322
    throw v0

    .line 323
    :pswitch_4
    iget-object v0, v1, Lio/i;->e:Ljava/lang/Object;

    .line 324
    .line 325
    check-cast v0, Lvp/m1;

    .line 326
    .line 327
    iget-object v6, v1, Lio/i;->f:Ljava/lang/Object;

    .line 328
    .line 329
    check-cast v6, Lvp/f4;

    .line 330
    .line 331
    iget-object v1, v1, Lio/i;->g:Ljava/lang/Object;

    .line 332
    .line 333
    check-cast v1, Lvp/e;

    .line 334
    .line 335
    iget-object v9, v0, Lvp/m1;->c:Lvp/z3;

    .line 336
    .line 337
    invoke-virtual {v9}, Lvp/z3;->B()V

    .line 338
    .line 339
    .line 340
    iget-object v6, v6, Lvp/f4;->d:Ljava/lang/String;

    .line 341
    .line 342
    invoke-static {v6}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 343
    .line 344
    .line 345
    iget-object v10, v9, Lvp/z3;->H:Ljava/util/HashMap;

    .line 346
    .line 347
    invoke-virtual {v9}, Lvp/z3;->f()Lvp/e1;

    .line 348
    .line 349
    .line 350
    move-result-object v0

    .line 351
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 352
    .line 353
    .line 354
    invoke-virtual {v9}, Lvp/z3;->k0()V

    .line 355
    .line 356
    .line 357
    iget-object v11, v9, Lvp/z3;->f:Lvp/n;

    .line 358
    .line 359
    invoke-static {v11}, Lvp/z3;->T(Lvp/u3;)V

    .line 360
    .line 361
    .line 362
    iget-wide v13, v1, Lvp/e;->d:J

    .line 363
    .line 364
    move-object/from16 p0, v9

    .line 365
    .line 366
    iget-wide v8, v1, Lvp/e;->f:J

    .line 367
    .line 368
    invoke-virtual {v11}, Lap0/o;->a0()V

    .line 369
    .line 370
    .line 371
    invoke-virtual {v11}, Lvp/u3;->b0()V

    .line 372
    .line 373
    .line 374
    :try_start_8
    invoke-virtual {v11}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 375
    .line 376
    .line 377
    move-result-object v15

    .line 378
    const-string v16, "upload_queue"

    .line 379
    .line 380
    const-string v27, "rowId"

    .line 381
    .line 382
    const-string v28, "app_id"

    .line 383
    .line 384
    const-string v29, "measurement_batch"

    .line 385
    .line 386
    const-string v30, "upload_uri"

    .line 387
    .line 388
    const-string v31, "upload_headers"

    .line 389
    .line 390
    const-string v32, "upload_type"

    .line 391
    .line 392
    const-string v33, "retry_count"

    .line 393
    .line 394
    const-string v34, "creation_timestamp"

    .line 395
    .line 396
    const-string v35, "associated_row_id"

    .line 397
    .line 398
    const-string v36, "last_upload_timestamp"

    .line 399
    .line 400
    filled-new-array/range {v27 .. v36}, [Ljava/lang/String;

    .line 401
    .line 402
    .line 403
    move-result-object v17

    .line 404
    const-string v18, "rowId=?"

    .line 405
    .line 406
    invoke-static {v13, v14}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 407
    .line 408
    .line 409
    move-result-object v0

    .line 410
    filled-new-array {v0}, [Ljava/lang/String;

    .line 411
    .line 412
    .line 413
    move-result-object v19

    .line 414
    const-string v23, "1"

    .line 415
    .line 416
    const/16 v20, 0x0

    .line 417
    .line 418
    const/16 v21, 0x0

    .line 419
    .line 420
    const/16 v22, 0x0

    .line 421
    .line 422
    invoke-virtual/range {v15 .. v23}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 423
    .line 424
    .line 425
    move-result-object v12
    :try_end_8
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_8 .. :try_end_8} :catch_5
    .catchall {:try_start_8 .. :try_end_8} :catchall_4

    .line 426
    :try_start_9
    invoke-interface {v12}, Landroid/database/Cursor;->moveToFirst()Z

    .line 427
    .line 428
    .line 429
    move-result v0

    .line 430
    if-nez v0, :cond_4

    .line 431
    .line 432
    goto/16 :goto_b

    .line 433
    .line 434
    :cond_4
    invoke-interface {v12, v7}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 435
    .line 436
    .line 437
    move-result-object v0

    .line 438
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 439
    .line 440
    .line 441
    invoke-interface {v12, v3}, Landroid/database/Cursor;->getBlob(I)[B

    .line 442
    .line 443
    .line 444
    move-result-object v15

    .line 445
    invoke-interface {v12, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 446
    .line 447
    .line 448
    move-result-object v16

    .line 449
    invoke-interface {v12, v5}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 450
    .line 451
    .line 452
    move-result-object v17

    .line 453
    invoke-interface {v12, v2}, Landroid/database/Cursor;->getInt(I)I

    .line 454
    .line 455
    .line 456
    move-result v18

    .line 457
    const/4 v2, 0x6

    .line 458
    invoke-interface {v12, v2}, Landroid/database/Cursor;->getInt(I)I

    .line 459
    .line 460
    .line 461
    move-result v19

    .line 462
    const/4 v2, 0x7

    .line 463
    invoke-interface {v12, v2}, Landroid/database/Cursor;->getLong(I)J

    .line 464
    .line 465
    .line 466
    move-result-wide v20

    .line 467
    const/16 v2, 0x8

    .line 468
    .line 469
    invoke-interface {v12, v2}, Landroid/database/Cursor;->getLong(I)J

    .line 470
    .line 471
    .line 472
    move-result-wide v22

    .line 473
    const/16 v2, 0x9

    .line 474
    .line 475
    invoke-interface {v12, v2}, Landroid/database/Cursor;->getLong(I)J

    .line 476
    .line 477
    .line 478
    move-result-wide v24
    :try_end_9
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_9 .. :try_end_9} :catch_4
    .catchall {:try_start_9 .. :try_end_9} :catchall_3

    .line 479
    move-object v2, v12

    .line 480
    move-object v12, v0

    .line 481
    :try_start_a
    invoke-virtual/range {v11 .. v25}, Lvp/n;->B0(Ljava/lang/String;J[BLjava/lang/String;Ljava/lang/String;IIJJJ)Lvp/a4;

    .line 482
    .line 483
    .line 484
    move-result-object v0
    :try_end_a
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_a .. :try_end_a} :catch_3
    .catchall {:try_start_a .. :try_end_a} :catchall_2

    .line 485
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 486
    .line 487
    .line 488
    goto :goto_c

    .line 489
    :catchall_2
    move-exception v0

    .line 490
    goto :goto_7

    .line 491
    :catch_3
    move-exception v0

    .line 492
    goto :goto_a

    .line 493
    :catchall_3
    move-exception v0

    .line 494
    move-object v2, v12

    .line 495
    goto :goto_7

    .line 496
    :catch_4
    move-exception v0

    .line 497
    move-object v2, v12

    .line 498
    goto :goto_a

    .line 499
    :goto_7
    move-object v8, v2

    .line 500
    goto/16 :goto_11

    .line 501
    .line 502
    :catchall_4
    move-exception v0

    .line 503
    goto :goto_8

    .line 504
    :catch_5
    move-exception v0

    .line 505
    goto :goto_9

    .line 506
    :goto_8
    const/4 v8, 0x0

    .line 507
    goto/16 :goto_11

    .line 508
    .line 509
    :goto_9
    const/4 v2, 0x0

    .line 510
    :goto_a
    :try_start_b
    iget-object v3, v11, Lap0/o;->e:Ljava/lang/Object;

    .line 511
    .line 512
    check-cast v3, Lvp/g1;

    .line 513
    .line 514
    iget-object v3, v3, Lvp/g1;->i:Lvp/p0;

    .line 515
    .line 516
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 517
    .line 518
    .line 519
    iget-object v3, v3, Lvp/p0;->j:Lvp/n0;

    .line 520
    .line 521
    const-string v11, "Error to querying MeasurementBatch from upload_queue. rowId"

    .line 522
    .line 523
    invoke-static {v13, v14}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 524
    .line 525
    .line 526
    move-result-object v12

    .line 527
    invoke-virtual {v3, v12, v0, v11}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_2

    .line 528
    .line 529
    .line 530
    move-object v12, v2

    .line 531
    :goto_b
    if-eqz v12, :cond_5

    .line 532
    .line 533
    invoke-interface {v12}, Landroid/database/Cursor;->close()V

    .line 534
    .line 535
    .line 536
    :cond_5
    const/4 v0, 0x0

    .line 537
    :goto_c
    if-nez v0, :cond_6

    .line 538
    .line 539
    invoke-virtual/range {p0 .. p0}, Lvp/z3;->d()Lvp/p0;

    .line 540
    .line 541
    .line 542
    move-result-object v0

    .line 543
    iget-object v0, v0, Lvp/p0;->m:Lvp/n0;

    .line 544
    .line 545
    invoke-static {v13, v14}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 546
    .line 547
    .line 548
    move-result-object v1

    .line 549
    const-string v2, "[sgtm] Queued batch doesn\'t exist. appId, rowId"

    .line 550
    .line 551
    invoke-virtual {v0, v6, v1, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 552
    .line 553
    .line 554
    goto/16 :goto_10

    .line 555
    .line 556
    :cond_6
    iget-object v0, v0, Lvp/a4;->c:Ljava/lang/String;

    .line 557
    .line 558
    iget v2, v1, Lvp/e;->e:I

    .line 559
    .line 560
    if-ne v2, v7, :cond_9

    .line 561
    .line 562
    invoke-virtual {v10, v0}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 563
    .line 564
    .line 565
    move-result v1

    .line 566
    if-eqz v1, :cond_7

    .line 567
    .line 568
    invoke-virtual {v10, v0}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 569
    .line 570
    .line 571
    :cond_7
    move-object/from16 v3, p0

    .line 572
    .line 573
    iget-object v0, v3, Lvp/z3;->f:Lvp/n;

    .line 574
    .line 575
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 576
    .line 577
    .line 578
    invoke-static {v13, v14}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 579
    .line 580
    .line 581
    move-result-object v1

    .line 582
    invoke-virtual {v0, v1}, Lvp/n;->h0(Ljava/lang/Long;)V

    .line 583
    .line 584
    .line 585
    invoke-virtual {v3}, Lvp/z3;->d()Lvp/p0;

    .line 586
    .line 587
    .line 588
    move-result-object v0

    .line 589
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 590
    .line 591
    const-string v2, "[sgtm] queued batch deleted after successful client upload. appId, rowId"

    .line 592
    .line 593
    invoke-virtual {v0, v6, v1, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 594
    .line 595
    .line 596
    const-wide/16 v0, 0x0

    .line 597
    .line 598
    cmp-long v0, v8, v0

    .line 599
    .line 600
    if-lez v0, :cond_c

    .line 601
    .line 602
    iget-object v0, v3, Lvp/z3;->f:Lvp/n;

    .line 603
    .line 604
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 605
    .line 606
    .line 607
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 608
    .line 609
    check-cast v1, Lvp/g1;

    .line 610
    .line 611
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 612
    .line 613
    .line 614
    invoke-virtual {v0}, Lvp/u3;->b0()V

    .line 615
    .line 616
    .line 617
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 618
    .line 619
    .line 620
    move-result-object v2

    .line 621
    new-instance v4, Landroid/content/ContentValues;

    .line 622
    .line 623
    invoke-direct {v4}, Landroid/content/ContentValues;-><init>()V

    .line 624
    .line 625
    .line 626
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 627
    .line 628
    .line 629
    move-result-object v7

    .line 630
    const-string v10, "upload_type"

    .line 631
    .line 632
    invoke-virtual {v4, v10, v7}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 633
    .line 634
    .line 635
    iget-object v7, v1, Lvp/g1;->n:Lto/a;

    .line 636
    .line 637
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 638
    .line 639
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 640
    .line 641
    .line 642
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 643
    .line 644
    .line 645
    move-result-wide v10

    .line 646
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 647
    .line 648
    .line 649
    move-result-object v7

    .line 650
    const-string v10, "creation_timestamp"

    .line 651
    .line 652
    invoke-virtual {v4, v10, v7}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 653
    .line 654
    .line 655
    :try_start_c
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 656
    .line 657
    .line 658
    move-result-object v0

    .line 659
    const-string v7, "upload_queue"

    .line 660
    .line 661
    const-string v10, "rowid=? AND app_id=? AND upload_type=?"

    .line 662
    .line 663
    invoke-static {v8, v9}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 664
    .line 665
    .line 666
    move-result-object v11

    .line 667
    invoke-static {v5}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 668
    .line 669
    .line 670
    move-result-object v5

    .line 671
    filled-new-array {v11, v6, v5}, [Ljava/lang/String;

    .line 672
    .line 673
    .line 674
    move-result-object v5

    .line 675
    invoke-virtual {v0, v7, v4, v10, v5}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    .line 676
    .line 677
    .line 678
    move-result v0

    .line 679
    int-to-long v4, v0

    .line 680
    const-wide/16 v10, 0x1

    .line 681
    .line 682
    cmp-long v0, v4, v10

    .line 683
    .line 684
    if-eqz v0, :cond_8

    .line 685
    .line 686
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 687
    .line 688
    .line 689
    iget-object v0, v1, Lvp/p0;->m:Lvp/n0;

    .line 690
    .line 691
    const-string v4, "Google Signal pending batch not updated. appId, rowId"

    .line 692
    .line 693
    invoke-virtual {v0, v6, v2, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_c
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_c .. :try_end_c} :catch_6

    .line 694
    .line 695
    .line 696
    goto :goto_d

    .line 697
    :catch_6
    move-exception v0

    .line 698
    goto :goto_e

    .line 699
    :cond_8
    :goto_d
    invoke-virtual {v3}, Lvp/z3;->d()Lvp/p0;

    .line 700
    .line 701
    .line 702
    move-result-object v0

    .line 703
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 704
    .line 705
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 706
    .line 707
    .line 708
    move-result-object v1

    .line 709
    const-string v2, "[sgtm] queued Google Signal batch updated. appId, signalRowId"

    .line 710
    .line 711
    invoke-virtual {v0, v6, v1, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 712
    .line 713
    .line 714
    invoke-virtual {v3, v6}, Lvp/z3;->t(Ljava/lang/String;)V

    .line 715
    .line 716
    .line 717
    goto :goto_10

    .line 718
    :goto_e
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 719
    .line 720
    .line 721
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 722
    .line 723
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 724
    .line 725
    .line 726
    move-result-object v2

    .line 727
    const-string v3, "Failed to update google Signal pending batch. appid, rowId"

    .line 728
    .line 729
    invoke-virtual {v1, v3, v6, v2, v0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 730
    .line 731
    .line 732
    throw v0

    .line 733
    :cond_9
    move-object/from16 v3, p0

    .line 734
    .line 735
    if-ne v2, v4, :cond_b

    .line 736
    .line 737
    invoke-virtual {v10, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 738
    .line 739
    .line 740
    move-result-object v2

    .line 741
    check-cast v2, Lvp/y3;

    .line 742
    .line 743
    if-nez v2, :cond_a

    .line 744
    .line 745
    new-instance v2, Lvp/y3;

    .line 746
    .line 747
    invoke-direct {v2, v3}, Lvp/y3;-><init>(Lvp/z3;)V

    .line 748
    .line 749
    .line 750
    invoke-virtual {v10, v0, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 751
    .line 752
    .line 753
    goto :goto_f

    .line 754
    :cond_a
    iget v4, v2, Lvp/y3;->b:I

    .line 755
    .line 756
    add-int/2addr v4, v7

    .line 757
    iput v4, v2, Lvp/y3;->b:I

    .line 758
    .line 759
    invoke-virtual {v2}, Lvp/y3;->a()J

    .line 760
    .line 761
    .line 762
    move-result-wide v4

    .line 763
    iput-wide v4, v2, Lvp/y3;->c:J

    .line 764
    .line 765
    :goto_f
    invoke-virtual {v3}, Lvp/z3;->l()Lto/a;

    .line 766
    .line 767
    .line 768
    move-result-object v4

    .line 769
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 770
    .line 771
    .line 772
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 773
    .line 774
    .line 775
    move-result-wide v4

    .line 776
    iget-wide v7, v2, Lvp/y3;->c:J

    .line 777
    .line 778
    sub-long/2addr v7, v4

    .line 779
    invoke-virtual {v3}, Lvp/z3;->d()Lvp/p0;

    .line 780
    .line 781
    .line 782
    move-result-object v2

    .line 783
    iget-object v2, v2, Lvp/p0;->r:Lvp/n0;

    .line 784
    .line 785
    const-wide/16 v4, 0x3e8

    .line 786
    .line 787
    div-long/2addr v7, v4

    .line 788
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 789
    .line 790
    .line 791
    move-result-object v4

    .line 792
    const-string v5, "[sgtm] Putting sGTM server in backoff mode. appId, destination, nextRetryInSeconds"

    .line 793
    .line 794
    invoke-virtual {v2, v5, v6, v0, v4}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 795
    .line 796
    .line 797
    :cond_b
    iget-object v0, v3, Lvp/z3;->f:Lvp/n;

    .line 798
    .line 799
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 800
    .line 801
    .line 802
    iget-wide v1, v1, Lvp/e;->d:J

    .line 803
    .line 804
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 805
    .line 806
    .line 807
    move-result-object v1

    .line 808
    invoke-virtual {v0, v1}, Lvp/n;->m0(Ljava/lang/Long;)V

    .line 809
    .line 810
    .line 811
    invoke-virtual {v3}, Lvp/z3;->d()Lvp/p0;

    .line 812
    .line 813
    .line 814
    move-result-object v0

    .line 815
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 816
    .line 817
    const-string v2, "[sgtm] increased batch retry count after failed client upload. appId, rowId"

    .line 818
    .line 819
    invoke-virtual {v0, v6, v1, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 820
    .line 821
    .line 822
    :cond_c
    :goto_10
    return-void

    .line 823
    :goto_11
    if-eqz v8, :cond_d

    .line 824
    .line 825
    invoke-interface {v8}, Landroid/database/Cursor;->close()V

    .line 826
    .line 827
    .line 828
    :cond_d
    throw v0

    .line 829
    :pswitch_5
    iget-object v0, v1, Lio/i;->f:Ljava/lang/Object;

    .line 830
    .line 831
    check-cast v0, Lvp/f4;

    .line 832
    .line 833
    iget-object v2, v1, Lio/i;->g:Ljava/lang/Object;

    .line 834
    .line 835
    check-cast v2, Lvp/m1;

    .line 836
    .line 837
    iget-object v2, v2, Lvp/m1;->c:Lvp/z3;

    .line 838
    .line 839
    invoke-virtual {v2}, Lvp/z3;->B()V

    .line 840
    .line 841
    .line 842
    iget-object v1, v1, Lio/i;->e:Ljava/lang/Object;

    .line 843
    .line 844
    check-cast v1, Lvp/b4;

    .line 845
    .line 846
    invoke-virtual {v1}, Lvp/b4;->h()Ljava/lang/Object;

    .line 847
    .line 848
    .line 849
    move-result-object v3

    .line 850
    if-nez v3, :cond_e

    .line 851
    .line 852
    iget-object v1, v1, Lvp/b4;->e:Ljava/lang/String;

    .line 853
    .line 854
    invoke-virtual {v2, v1, v0}, Lvp/z3;->W(Ljava/lang/String;Lvp/f4;)V

    .line 855
    .line 856
    .line 857
    goto :goto_12

    .line 858
    :cond_e
    invoke-virtual {v2, v1, v0}, Lvp/z3;->V(Lvp/b4;Lvp/f4;)V

    .line 859
    .line 860
    .line 861
    :goto_12
    return-void

    .line 862
    :pswitch_6
    iget-object v0, v1, Lio/i;->g:Ljava/lang/Object;

    .line 863
    .line 864
    check-cast v0, Lvp/m1;

    .line 865
    .line 866
    iget-object v2, v0, Lvp/m1;->c:Lvp/z3;

    .line 867
    .line 868
    invoke-virtual {v2}, Lvp/z3;->B()V

    .line 869
    .line 870
    .line 871
    iget-object v0, v0, Lvp/m1;->c:Lvp/z3;

    .line 872
    .line 873
    iget-object v2, v1, Lio/i;->e:Ljava/lang/Object;

    .line 874
    .line 875
    check-cast v2, Lvp/t;

    .line 876
    .line 877
    iget-object v1, v1, Lio/i;->f:Ljava/lang/Object;

    .line 878
    .line 879
    check-cast v1, Ljava/lang/String;

    .line 880
    .line 881
    invoke-virtual {v0, v1, v2}, Lvp/z3;->c(Ljava/lang/String;Lvp/t;)V

    .line 882
    .line 883
    .line 884
    return-void

    .line 885
    :pswitch_7
    iget-object v0, v1, Lio/i;->e:Ljava/lang/Object;

    .line 886
    .line 887
    check-cast v0, Lvp/t;

    .line 888
    .line 889
    iget-object v2, v1, Lio/i;->f:Ljava/lang/Object;

    .line 890
    .line 891
    check-cast v2, Lvp/f4;

    .line 892
    .line 893
    iget-object v1, v1, Lio/i;->g:Ljava/lang/Object;

    .line 894
    .line 895
    check-cast v1, Lvp/m1;

    .line 896
    .line 897
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 898
    .line 899
    .line 900
    iget-object v1, v1, Lvp/m1;->c:Lvp/z3;

    .line 901
    .line 902
    const-string v3, "_cmp"

    .line 903
    .line 904
    iget-object v4, v0, Lvp/t;->d:Ljava/lang/String;

    .line 905
    .line 906
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 907
    .line 908
    .line 909
    move-result v3

    .line 910
    if-eqz v3, :cond_11

    .line 911
    .line 912
    iget-object v10, v0, Lvp/t;->e:Lvp/s;

    .line 913
    .line 914
    if-eqz v10, :cond_11

    .line 915
    .line 916
    iget-object v3, v10, Lvp/s;->d:Landroid/os/Bundle;

    .line 917
    .line 918
    invoke-virtual {v3}, Landroid/os/BaseBundle;->size()I

    .line 919
    .line 920
    .line 921
    move-result v4

    .line 922
    if-nez v4, :cond_f

    .line 923
    .line 924
    goto :goto_13

    .line 925
    :cond_f
    const-string v4, "_cis"

    .line 926
    .line 927
    invoke-virtual {v3, v4}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 928
    .line 929
    .line 930
    move-result-object v3

    .line 931
    const-string v4, "referrer broadcast"

    .line 932
    .line 933
    invoke-virtual {v4, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 934
    .line 935
    .line 936
    move-result v4

    .line 937
    if-nez v4, :cond_10

    .line 938
    .line 939
    const-string v4, "referrer API"

    .line 940
    .line 941
    invoke-virtual {v4, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 942
    .line 943
    .line 944
    move-result v3

    .line 945
    if-eqz v3, :cond_11

    .line 946
    .line 947
    :cond_10
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 948
    .line 949
    .line 950
    move-result-object v3

    .line 951
    iget-object v3, v3, Lvp/p0;->p:Lvp/n0;

    .line 952
    .line 953
    invoke-virtual {v0}, Lvp/t;->toString()Ljava/lang/String;

    .line 954
    .line 955
    .line 956
    move-result-object v4

    .line 957
    const-string v5, "Event has been filtered "

    .line 958
    .line 959
    invoke-virtual {v3, v4, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 960
    .line 961
    .line 962
    new-instance v8, Lvp/t;

    .line 963
    .line 964
    iget-object v11, v0, Lvp/t;->f:Ljava/lang/String;

    .line 965
    .line 966
    iget-wide v12, v0, Lvp/t;->g:J

    .line 967
    .line 968
    const-string v9, "_cmpx"

    .line 969
    .line 970
    invoke-direct/range {v8 .. v13}, Lvp/t;-><init>(Ljava/lang/String;Lvp/s;Ljava/lang/String;J)V

    .line 971
    .line 972
    .line 973
    move-object v0, v8

    .line 974
    :cond_11
    :goto_13
    iget-object v3, v0, Lvp/t;->d:Ljava/lang/String;

    .line 975
    .line 976
    iget-object v4, v1, Lvp/z3;->d:Lvp/a1;

    .line 977
    .line 978
    iget-object v5, v1, Lvp/z3;->j:Lvp/s0;

    .line 979
    .line 980
    invoke-static {v4}, Lvp/z3;->T(Lvp/u3;)V

    .line 981
    .line 982
    .line 983
    iget-object v6, v2, Lvp/f4;->d:Ljava/lang/String;

    .line 984
    .line 985
    invoke-static {v6}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 986
    .line 987
    .line 988
    move-result v8

    .line 989
    if-eqz v8, :cond_12

    .line 990
    .line 991
    const/4 v8, 0x0

    .line 992
    goto :goto_14

    .line 993
    :cond_12
    iget-object v4, v4, Lvp/a1;->n:Lrl/e;

    .line 994
    .line 995
    invoke-virtual {v4, v6}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 996
    .line 997
    .line 998
    move-result-object v4

    .line 999
    move-object v8, v4

    .line 1000
    check-cast v8, Lcom/google/android/gms/internal/measurement/e0;

    .line 1001
    .line 1002
    :goto_14
    if-eqz v8, :cond_16

    .line 1003
    .line 1004
    :try_start_d
    iget-object v4, v8, Lcom/google/android/gms/internal/measurement/e0;->c:Lgw0/c;

    .line 1005
    .line 1006
    invoke-static {v5}, Lvp/z3;->T(Lvp/u3;)V

    .line 1007
    .line 1008
    .line 1009
    iget-object v6, v0, Lvp/t;->e:Lvp/s;

    .line 1010
    .line 1011
    invoke-virtual {v6}, Lvp/s;->A0()Landroid/os/Bundle;

    .line 1012
    .line 1013
    .line 1014
    move-result-object v6

    .line 1015
    invoke-static {v6, v7}, Lvp/s0;->Q0(Landroid/os/Bundle;Z)Ljava/util/HashMap;

    .line 1016
    .line 1017
    .line 1018
    move-result-object v6

    .line 1019
    sget-object v7, Lvp/t1;->c:[Ljava/lang/String;

    .line 1020
    .line 1021
    sget-object v9, Lvp/t1;->a:[Ljava/lang/String;

    .line 1022
    .line 1023
    invoke-static {v7, v3, v9}, Lvp/t1;->g([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;

    .line 1024
    .line 1025
    .line 1026
    move-result-object v7

    .line 1027
    if-eqz v7, :cond_13

    .line 1028
    .line 1029
    goto :goto_15

    .line 1030
    :cond_13
    move-object v7, v3

    .line 1031
    :goto_15
    new-instance v9, Lcom/google/android/gms/internal/measurement/b;

    .line 1032
    .line 1033
    iget-wide v10, v0, Lvp/t;->g:J

    .line 1034
    .line 1035
    invoke-direct {v9, v7, v10, v11, v6}, Lcom/google/android/gms/internal/measurement/b;-><init>(Ljava/lang/String;JLjava/util/HashMap;)V

    .line 1036
    .line 1037
    .line 1038
    invoke-virtual {v8, v9}, Lcom/google/android/gms/internal/measurement/e0;->a(Lcom/google/android/gms/internal/measurement/b;)Z

    .line 1039
    .line 1040
    .line 1041
    move-result v6
    :try_end_d
    .catch Lcom/google/android/gms/internal/measurement/q0; {:try_start_d .. :try_end_d} :catch_7

    .line 1042
    if-nez v6, :cond_14

    .line 1043
    .line 1044
    goto/16 :goto_18

    .line 1045
    .line 1046
    :cond_14
    iget-object v6, v4, Lgw0/c;->f:Ljava/lang/Object;

    .line 1047
    .line 1048
    check-cast v6, Lcom/google/android/gms/internal/measurement/b;

    .line 1049
    .line 1050
    iget-object v7, v4, Lgw0/c;->e:Ljava/lang/Object;

    .line 1051
    .line 1052
    check-cast v7, Lcom/google/android/gms/internal/measurement/b;

    .line 1053
    .line 1054
    invoke-virtual {v6, v7}, Lcom/google/android/gms/internal/measurement/b;->equals(Ljava/lang/Object;)Z

    .line 1055
    .line 1056
    .line 1057
    move-result v6

    .line 1058
    if-nez v6, :cond_15

    .line 1059
    .line 1060
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 1061
    .line 1062
    .line 1063
    move-result-object v0

    .line 1064
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 1065
    .line 1066
    const-string v6, "EES edited event"

    .line 1067
    .line 1068
    invoke-virtual {v0, v3, v6}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1069
    .line 1070
    .line 1071
    invoke-static {v5}, Lvp/z3;->T(Lvp/u3;)V

    .line 1072
    .line 1073
    .line 1074
    iget-object v0, v4, Lgw0/c;->f:Ljava/lang/Object;

    .line 1075
    .line 1076
    check-cast v0, Lcom/google/android/gms/internal/measurement/b;

    .line 1077
    .line 1078
    invoke-static {v0}, Lvp/s0;->e0(Lcom/google/android/gms/internal/measurement/b;)Lvp/t;

    .line 1079
    .line 1080
    .line 1081
    move-result-object v0

    .line 1082
    invoke-virtual {v1}, Lvp/z3;->B()V

    .line 1083
    .line 1084
    .line 1085
    invoke-virtual {v1, v0, v2}, Lvp/z3;->g(Lvp/t;Lvp/f4;)V

    .line 1086
    .line 1087
    .line 1088
    goto :goto_16

    .line 1089
    :cond_15
    invoke-virtual {v1}, Lvp/z3;->B()V

    .line 1090
    .line 1091
    .line 1092
    invoke-virtual {v1, v0, v2}, Lvp/z3;->g(Lvp/t;Lvp/f4;)V

    .line 1093
    .line 1094
    .line 1095
    :goto_16
    iget-object v0, v4, Lgw0/c;->g:Ljava/lang/Object;

    .line 1096
    .line 1097
    check-cast v0, Ljava/util/ArrayList;

    .line 1098
    .line 1099
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1100
    .line 1101
    .line 1102
    move-result v0

    .line 1103
    if-nez v0, :cond_17

    .line 1104
    .line 1105
    iget-object v0, v4, Lgw0/c;->g:Ljava/lang/Object;

    .line 1106
    .line 1107
    check-cast v0, Ljava/util/ArrayList;

    .line 1108
    .line 1109
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1110
    .line 1111
    .line 1112
    move-result-object v0

    .line 1113
    :goto_17
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1114
    .line 1115
    .line 1116
    move-result v3

    .line 1117
    if-eqz v3, :cond_17

    .line 1118
    .line 1119
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1120
    .line 1121
    .line 1122
    move-result-object v3

    .line 1123
    check-cast v3, Lcom/google/android/gms/internal/measurement/b;

    .line 1124
    .line 1125
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 1126
    .line 1127
    .line 1128
    move-result-object v4

    .line 1129
    iget-object v4, v4, Lvp/p0;->r:Lvp/n0;

    .line 1130
    .line 1131
    iget-object v6, v3, Lcom/google/android/gms/internal/measurement/b;->a:Ljava/lang/String;

    .line 1132
    .line 1133
    const-string v7, "EES logging created event"

    .line 1134
    .line 1135
    invoke-virtual {v4, v6, v7}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1136
    .line 1137
    .line 1138
    invoke-static {v5}, Lvp/z3;->T(Lvp/u3;)V

    .line 1139
    .line 1140
    .line 1141
    invoke-static {v3}, Lvp/s0;->e0(Lcom/google/android/gms/internal/measurement/b;)Lvp/t;

    .line 1142
    .line 1143
    .line 1144
    move-result-object v3

    .line 1145
    invoke-virtual {v1}, Lvp/z3;->B()V

    .line 1146
    .line 1147
    .line 1148
    invoke-virtual {v1, v3, v2}, Lvp/z3;->g(Lvp/t;Lvp/f4;)V

    .line 1149
    .line 1150
    .line 1151
    goto :goto_17

    .line 1152
    :catch_7
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 1153
    .line 1154
    .line 1155
    move-result-object v4

    .line 1156
    iget-object v4, v4, Lvp/p0;->j:Lvp/n0;

    .line 1157
    .line 1158
    iget-object v5, v2, Lvp/f4;->e:Ljava/lang/String;

    .line 1159
    .line 1160
    const-string v6, "EES error. appId, eventName"

    .line 1161
    .line 1162
    invoke-virtual {v4, v5, v3, v6}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 1163
    .line 1164
    .line 1165
    :goto_18
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 1166
    .line 1167
    .line 1168
    move-result-object v4

    .line 1169
    iget-object v4, v4, Lvp/p0;->r:Lvp/n0;

    .line 1170
    .line 1171
    const-string v5, "EES was not applied to event"

    .line 1172
    .line 1173
    invoke-virtual {v4, v3, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1174
    .line 1175
    .line 1176
    invoke-virtual {v1}, Lvp/z3;->B()V

    .line 1177
    .line 1178
    .line 1179
    invoke-virtual {v1, v0, v2}, Lvp/z3;->g(Lvp/t;Lvp/f4;)V

    .line 1180
    .line 1181
    .line 1182
    goto :goto_19

    .line 1183
    :cond_16
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 1184
    .line 1185
    .line 1186
    move-result-object v3

    .line 1187
    iget-object v3, v3, Lvp/p0;->r:Lvp/n0;

    .line 1188
    .line 1189
    iget-object v4, v2, Lvp/f4;->d:Ljava/lang/String;

    .line 1190
    .line 1191
    const-string v5, "EES not loaded for"

    .line 1192
    .line 1193
    invoke-virtual {v3, v4, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1194
    .line 1195
    .line 1196
    invoke-virtual {v1}, Lvp/z3;->B()V

    .line 1197
    .line 1198
    .line 1199
    invoke-virtual {v1, v0, v2}, Lvp/z3;->g(Lvp/t;Lvp/f4;)V

    .line 1200
    .line 1201
    .line 1202
    :cond_17
    :goto_19
    return-void

    .line 1203
    :pswitch_8
    iget-object v0, v1, Lio/i;->f:Ljava/lang/Object;

    .line 1204
    .line 1205
    check-cast v0, Lvp/f4;

    .line 1206
    .line 1207
    iget-object v2, v1, Lio/i;->g:Ljava/lang/Object;

    .line 1208
    .line 1209
    check-cast v2, Lvp/m1;

    .line 1210
    .line 1211
    iget-object v2, v2, Lvp/m1;->c:Lvp/z3;

    .line 1212
    .line 1213
    invoke-virtual {v2}, Lvp/z3;->B()V

    .line 1214
    .line 1215
    .line 1216
    iget-object v1, v1, Lio/i;->e:Ljava/lang/Object;

    .line 1217
    .line 1218
    check-cast v1, Lvp/f;

    .line 1219
    .line 1220
    iget-object v3, v1, Lvp/f;->f:Lvp/b4;

    .line 1221
    .line 1222
    invoke-virtual {v3}, Lvp/b4;->h()Ljava/lang/Object;

    .line 1223
    .line 1224
    .line 1225
    move-result-object v3

    .line 1226
    if-nez v3, :cond_18

    .line 1227
    .line 1228
    invoke-virtual {v2, v1, v0}, Lvp/z3;->Z(Lvp/f;Lvp/f4;)V

    .line 1229
    .line 1230
    .line 1231
    goto :goto_1a

    .line 1232
    :cond_18
    invoke-virtual {v2, v1, v0}, Lvp/z3;->Y(Lvp/f;Lvp/f4;)V

    .line 1233
    .line 1234
    .line 1235
    :goto_1a
    return-void

    .line 1236
    :pswitch_9
    iget-object v0, v1, Lio/i;->g:Ljava/lang/Object;

    .line 1237
    .line 1238
    check-cast v0, Lts/b;

    .line 1239
    .line 1240
    iget-object v2, v1, Lio/i;->e:Ljava/lang/Object;

    .line 1241
    .line 1242
    check-cast v2, Lms/a;

    .line 1243
    .line 1244
    iget-object v1, v1, Lio/i;->f:Ljava/lang/Object;

    .line 1245
    .line 1246
    check-cast v1, Laq/k;

    .line 1247
    .line 1248
    invoke-virtual {v0, v2, v1}, Lts/b;->b(Lms/a;Laq/k;)V

    .line 1249
    .line 1250
    .line 1251
    iget-object v1, v0, Lts/b;->i:Lb81/d;

    .line 1252
    .line 1253
    iget-object v1, v1, Lb81/d;->f:Ljava/lang/Object;

    .line 1254
    .line 1255
    check-cast v1, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 1256
    .line 1257
    invoke-virtual {v1, v6}, Ljava/util/concurrent/atomic/AtomicInteger;->set(I)V

    .line 1258
    .line 1259
    .line 1260
    const-wide v5, 0x40ed4c0000000000L    # 60000.0

    .line 1261
    .line 1262
    .line 1263
    .line 1264
    .line 1265
    iget-wide v7, v0, Lts/b;->a:D

    .line 1266
    .line 1267
    div-double/2addr v5, v7

    .line 1268
    iget-wide v7, v0, Lts/b;->b:D

    .line 1269
    .line 1270
    invoke-virtual {v0}, Lts/b;->a()I

    .line 1271
    .line 1272
    .line 1273
    move-result v0

    .line 1274
    int-to-double v0, v0

    .line 1275
    invoke-static {v7, v8, v0, v1}, Ljava/lang/Math;->pow(DD)D

    .line 1276
    .line 1277
    .line 1278
    move-result-wide v0

    .line 1279
    mul-double/2addr v0, v5

    .line 1280
    const-wide v5, 0x414b774000000000L    # 3600000.0

    .line 1281
    .line 1282
    .line 1283
    .line 1284
    .line 1285
    invoke-static {v5, v6, v0, v1}, Ljava/lang/Math;->min(DD)D

    .line 1286
    .line 1287
    .line 1288
    move-result-wide v0

    .line 1289
    new-instance v3, Ljava/lang/StringBuilder;

    .line 1290
    .line 1291
    const-string v5, "Delay for: "

    .line 1292
    .line 1293
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1294
    .line 1295
    .line 1296
    sget-object v5, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 1297
    .line 1298
    const-string v6, "%.2f"

    .line 1299
    .line 1300
    const-wide v7, 0x408f400000000000L    # 1000.0

    .line 1301
    .line 1302
    .line 1303
    .line 1304
    .line 1305
    div-double v7, v0, v7

    .line 1306
    .line 1307
    invoke-static {v7, v8}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1308
    .line 1309
    .line 1310
    move-result-object v7

    .line 1311
    filled-new-array {v7}, [Ljava/lang/Object;

    .line 1312
    .line 1313
    .line 1314
    move-result-object v7

    .line 1315
    invoke-static {v5, v6, v7}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 1316
    .line 1317
    .line 1318
    move-result-object v5

    .line 1319
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1320
    .line 1321
    .line 1322
    const-string v5, " s for report: "

    .line 1323
    .line 1324
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1325
    .line 1326
    .line 1327
    iget-object v2, v2, Lms/a;->b:Ljava/lang/String;

    .line 1328
    .line 1329
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1330
    .line 1331
    .line 1332
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1333
    .line 1334
    .line 1335
    move-result-object v2

    .line 1336
    const-string v3, "FirebaseCrashlytics"

    .line 1337
    .line 1338
    invoke-static {v3, v4}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1339
    .line 1340
    .line 1341
    move-result v4

    .line 1342
    if-eqz v4, :cond_19

    .line 1343
    .line 1344
    const/4 v4, 0x0

    .line 1345
    invoke-static {v3, v2, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1346
    .line 1347
    .line 1348
    :cond_19
    double-to-long v0, v0

    .line 1349
    :try_start_e
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V
    :try_end_e
    .catch Ljava/lang/InterruptedException; {:try_start_e .. :try_end_e} :catch_8

    .line 1350
    .line 1351
    .line 1352
    :catch_8
    return-void

    .line 1353
    :pswitch_a
    iget-object v0, v1, Lio/i;->e:Ljava/lang/Object;

    .line 1354
    .line 1355
    move-object v4, v0

    .line 1356
    check-cast v4, Lvy0/l;

    .line 1357
    .line 1358
    :try_start_f
    iget-object v0, v4, Lvy0/l;->h:Lpx0/g;

    .line 1359
    .line 1360
    sget-object v2, Lpx0/c;->d:Lpx0/c;

    .line 1361
    .line 1362
    invoke-interface {v0, v2}, Lpx0/g;->minusKey(Lpx0/f;)Lpx0/g;

    .line 1363
    .line 1364
    .line 1365
    move-result-object v0

    .line 1366
    new-instance v2, Lh7/z;

    .line 1367
    .line 1368
    iget-object v3, v1, Lio/i;->f:Ljava/lang/Object;

    .line 1369
    .line 1370
    check-cast v3, Lla/u;

    .line 1371
    .line 1372
    iget-object v1, v1, Lio/i;->g:Ljava/lang/Object;

    .line 1373
    .line 1374
    move-object v5, v1

    .line 1375
    check-cast v5, Lew/f;

    .line 1376
    .line 1377
    const/4 v6, 0x0

    .line 1378
    move-object v1, v2

    .line 1379
    const/16 v2, 0x9

    .line 1380
    .line 1381
    invoke-direct/range {v1 .. v6}, Lh7/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1382
    .line 1383
    .line 1384
    invoke-static {v0, v1}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_5

    .line 1385
    .line 1386
    .line 1387
    goto :goto_1b

    .line 1388
    :catchall_5
    move-exception v0

    .line 1389
    invoke-virtual {v4, v0}, Lvy0/l;->c(Ljava/lang/Throwable;)Z

    .line 1390
    .line 1391
    .line 1392
    :goto_1b
    return-void

    .line 1393
    :pswitch_b
    iget-object v0, v1, Lio/i;->e:Ljava/lang/Object;

    .line 1394
    .line 1395
    check-cast v0, Lkp/la;

    .line 1396
    .line 1397
    iget-object v2, v1, Lio/i;->f:Ljava/lang/Object;

    .line 1398
    .line 1399
    check-cast v2, Lvp/y1;

    .line 1400
    .line 1401
    sget-object v3, Lkp/k7;->e:Lkp/k7;

    .line 1402
    .line 1403
    iget-object v1, v1, Lio/i;->g:Ljava/lang/Object;

    .line 1404
    .line 1405
    check-cast v1, Ljava/lang/String;

    .line 1406
    .line 1407
    iget-object v4, v2, Lvp/y1;->e:Ljava/lang/Object;

    .line 1408
    .line 1409
    check-cast v4, Lil/g;

    .line 1410
    .line 1411
    iput-object v3, v4, Lil/g;->f:Ljava/lang/Object;

    .line 1412
    .line 1413
    iget-object v3, v4, Lil/g;->e:Ljava/lang/Object;

    .line 1414
    .line 1415
    check-cast v3, Lkp/l9;

    .line 1416
    .line 1417
    if-eqz v3, :cond_1a

    .line 1418
    .line 1419
    iget-object v3, v3, Lkp/l9;->d:Ljava/lang/String;

    .line 1420
    .line 1421
    sget v4, Lkp/r2;->a:I

    .line 1422
    .line 1423
    if-eqz v3, :cond_1a

    .line 1424
    .line 1425
    invoke-virtual {v3}, Ljava/lang/String;->isEmpty()Z

    .line 1426
    .line 1427
    .line 1428
    move-result v4

    .line 1429
    if-eqz v4, :cond_1b

    .line 1430
    .line 1431
    :cond_1a
    const-string v3, "NA"

    .line 1432
    .line 1433
    :cond_1b
    new-instance v4, Ljp/uf;

    .line 1434
    .line 1435
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 1436
    .line 1437
    .line 1438
    iget-object v8, v0, Lkp/la;->a:Ljava/lang/String;

    .line 1439
    .line 1440
    iput-object v8, v4, Ljp/uf;->a:Ljava/lang/Object;

    .line 1441
    .line 1442
    iget-object v8, v0, Lkp/la;->b:Ljava/lang/String;

    .line 1443
    .line 1444
    iput-object v8, v4, Ljp/uf;->b:Ljava/lang/Object;

    .line 1445
    .line 1446
    const-class v8, Lkp/la;

    .line 1447
    .line 1448
    monitor-enter v8

    .line 1449
    :try_start_10
    sget-object v9, Lkp/la;->j:Lkp/ua;
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_6

    .line 1450
    .line 1451
    if-eqz v9, :cond_1c

    .line 1452
    .line 1453
    monitor-exit v8

    .line 1454
    goto :goto_1e

    .line 1455
    :cond_1c
    :try_start_11
    invoke-static {}, Landroid/content/res/Resources;->getSystem()Landroid/content/res/Resources;

    .line 1456
    .line 1457
    .line 1458
    move-result-object v9

    .line 1459
    invoke-virtual {v9}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 1460
    .line 1461
    .line 1462
    move-result-object v9

    .line 1463
    invoke-virtual {v9}, Landroid/content/res/Configuration;->getLocales()Landroid/os/LocaleList;

    .line 1464
    .line 1465
    .line 1466
    move-result-object v9

    .line 1467
    new-instance v10, Ly5/c;

    .line 1468
    .line 1469
    new-instance v11, Ly5/d;

    .line 1470
    .line 1471
    invoke-direct {v11, v9}, Ly5/d;-><init>(Landroid/os/LocaleList;)V

    .line 1472
    .line 1473
    .line 1474
    invoke-direct {v10, v11}, Ly5/c;-><init>(Ly5/d;)V

    .line 1475
    .line 1476
    .line 1477
    new-array v5, v5, [Ljava/lang/Object;

    .line 1478
    .line 1479
    move v9, v6

    .line 1480
    :goto_1c
    invoke-virtual {v10}, Ly5/c;->c()I

    .line 1481
    .line 1482
    .line 1483
    move-result v11

    .line 1484
    if-ge v6, v11, :cond_20

    .line 1485
    .line 1486
    invoke-virtual {v10, v6}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 1487
    .line 1488
    .line 1489
    move-result-object v11

    .line 1490
    sget-object v12, Lfv/c;->a:Lb81/b;

    .line 1491
    .line 1492
    invoke-virtual {v11}, Ljava/util/Locale;->toLanguageTag()Ljava/lang/String;

    .line 1493
    .line 1494
    .line 1495
    move-result-object v11

    .line 1496
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1497
    .line 1498
    .line 1499
    add-int/lit8 v12, v9, 0x1

    .line 1500
    .line 1501
    array-length v13, v5

    .line 1502
    if-ge v13, v12, :cond_1f

    .line 1503
    .line 1504
    shr-int/lit8 v14, v13, 0x1

    .line 1505
    .line 1506
    add-int/2addr v13, v14

    .line 1507
    add-int/2addr v13, v7

    .line 1508
    if-ge v13, v12, :cond_1d

    .line 1509
    .line 1510
    invoke-static {v9}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 1511
    .line 1512
    .line 1513
    move-result v13

    .line 1514
    add-int/2addr v13, v13

    .line 1515
    :cond_1d
    if-gez v13, :cond_1e

    .line 1516
    .line 1517
    const v13, 0x7fffffff

    .line 1518
    .line 1519
    .line 1520
    :cond_1e
    invoke-static {v5, v13}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1521
    .line 1522
    .line 1523
    move-result-object v5

    .line 1524
    :cond_1f
    aput-object v11, v5, v9

    .line 1525
    .line 1526
    add-int/lit8 v6, v6, 0x1

    .line 1527
    .line 1528
    move v9, v12

    .line 1529
    goto :goto_1c

    .line 1530
    :catchall_6
    move-exception v0

    .line 1531
    goto :goto_20

    .line 1532
    :cond_20
    sget-object v6, Lkp/sa;->e:Lkp/qa;

    .line 1533
    .line 1534
    if-nez v9, :cond_21

    .line 1535
    .line 1536
    sget-object v5, Lkp/ua;->h:Lkp/ua;

    .line 1537
    .line 1538
    move-object v9, v5

    .line 1539
    goto :goto_1d

    .line 1540
    :cond_21
    new-instance v6, Lkp/ua;

    .line 1541
    .line 1542
    invoke-direct {v6, v5, v9}, Lkp/ua;-><init>([Ljava/lang/Object;I)V

    .line 1543
    .line 1544
    .line 1545
    move-object v9, v6

    .line 1546
    :goto_1d
    sput-object v9, Lkp/la;->j:Lkp/ua;
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_6

    .line 1547
    .line 1548
    monitor-exit v8

    .line 1549
    :goto_1e
    iput-object v9, v4, Ljp/uf;->k:Ljava/util/RandomAccess;

    .line 1550
    .line 1551
    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 1552
    .line 1553
    iput-object v5, v4, Ljp/uf;->g:Ljava/lang/Object;

    .line 1554
    .line 1555
    iput-object v3, v4, Ljp/uf;->d:Ljava/lang/Object;

    .line 1556
    .line 1557
    iput-object v1, v4, Ljp/uf;->c:Ljava/lang/Object;

    .line 1558
    .line 1559
    iget-object v1, v0, Lkp/la;->f:Laq/t;

    .line 1560
    .line 1561
    invoke-virtual {v1}, Laq/t;->i()Z

    .line 1562
    .line 1563
    .line 1564
    move-result v1

    .line 1565
    if-eqz v1, :cond_22

    .line 1566
    .line 1567
    iget-object v1, v0, Lkp/la;->f:Laq/t;

    .line 1568
    .line 1569
    invoke-virtual {v1}, Laq/t;->g()Ljava/lang/Object;

    .line 1570
    .line 1571
    .line 1572
    move-result-object v1

    .line 1573
    check-cast v1, Ljava/lang/String;

    .line 1574
    .line 1575
    goto :goto_1f

    .line 1576
    :cond_22
    iget-object v1, v0, Lkp/la;->d:Lfv/i;

    .line 1577
    .line 1578
    invoke-virtual {v1}, Lfv/i;->a()Ljava/lang/String;

    .line 1579
    .line 1580
    .line 1581
    move-result-object v1

    .line 1582
    :goto_1f
    iput-object v1, v4, Ljp/uf;->e:Ljava/lang/Object;

    .line 1583
    .line 1584
    const/16 v1, 0xa

    .line 1585
    .line 1586
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1587
    .line 1588
    .line 1589
    move-result-object v1

    .line 1590
    iput-object v1, v4, Ljp/uf;->i:Ljava/io/Serializable;

    .line 1591
    .line 1592
    iget v1, v0, Lkp/la;->h:I

    .line 1593
    .line 1594
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1595
    .line 1596
    .line 1597
    move-result-object v1

    .line 1598
    iput-object v1, v4, Ljp/uf;->j:Ljava/lang/Object;

    .line 1599
    .line 1600
    iput-object v4, v2, Lvp/y1;->f:Ljava/lang/Object;

    .line 1601
    .line 1602
    iget-object v0, v0, Lkp/la;->c:Lkp/ka;

    .line 1603
    .line 1604
    invoke-virtual {v0, v2}, Lkp/ka;->a(Lvp/y1;)V

    .line 1605
    .line 1606
    .line 1607
    return-void

    .line 1608
    :goto_20
    :try_start_12
    monitor-exit v8
    :try_end_12
    .catchall {:try_start_12 .. :try_end_12} :catchall_6

    .line 1609
    throw v0

    .line 1610
    :pswitch_c
    iget-object v0, v1, Lio/i;->f:Ljava/lang/Object;

    .line 1611
    .line 1612
    check-cast v0, Lio/a;

    .line 1613
    .line 1614
    iget-object v4, v0, Lio/a;->d:Landroid/content/Intent;

    .line 1615
    .line 1616
    const-string v5, "google.message_id"

    .line 1617
    .line 1618
    invoke-virtual {v4, v5}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 1619
    .line 1620
    .line 1621
    move-result-object v5

    .line 1622
    if-nez v5, :cond_23

    .line 1623
    .line 1624
    const-string v5, "message_id"

    .line 1625
    .line 1626
    invoke-virtual {v4, v5}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 1627
    .line 1628
    .line 1629
    move-result-object v5

    .line 1630
    :cond_23
    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1631
    .line 1632
    .line 1633
    move-result v4

    .line 1634
    if-eqz v4, :cond_24

    .line 1635
    .line 1636
    const/16 v26, 0x0

    .line 1637
    .line 1638
    invoke-static/range {v26 .. v26}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 1639
    .line 1640
    .line 1641
    move-result-object v0

    .line 1642
    goto :goto_22

    .line 1643
    :cond_24
    const/16 v26, 0x0

    .line 1644
    .line 1645
    new-instance v4, Landroid/os/Bundle;

    .line 1646
    .line 1647
    invoke-direct {v4}, Landroid/os/Bundle;-><init>()V

    .line 1648
    .line 1649
    .line 1650
    iget-object v5, v0, Lio/a;->d:Landroid/content/Intent;

    .line 1651
    .line 1652
    const-string v8, "google.message_id"

    .line 1653
    .line 1654
    invoke-virtual {v5, v8}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 1655
    .line 1656
    .line 1657
    move-result-object v8

    .line 1658
    if-nez v8, :cond_25

    .line 1659
    .line 1660
    const-string v8, "message_id"

    .line 1661
    .line 1662
    invoke-virtual {v5, v8}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 1663
    .line 1664
    .line 1665
    move-result-object v8

    .line 1666
    :cond_25
    const-string v5, "google.message_id"

    .line 1667
    .line 1668
    invoke-virtual {v4, v5, v8}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 1669
    .line 1670
    .line 1671
    iget-object v0, v0, Lio/a;->d:Landroid/content/Intent;

    .line 1672
    .line 1673
    const-string v5, "google.product_id"

    .line 1674
    .line 1675
    invoke-virtual {v0, v5}, Landroid/content/Intent;->hasExtra(Ljava/lang/String;)Z

    .line 1676
    .line 1677
    .line 1678
    move-result v8

    .line 1679
    if-eqz v8, :cond_26

    .line 1680
    .line 1681
    invoke-virtual {v0, v5, v6}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 1682
    .line 1683
    .line 1684
    move-result v0

    .line 1685
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1686
    .line 1687
    .line 1688
    move-result-object v8

    .line 1689
    goto :goto_21

    .line 1690
    :cond_26
    move-object/from16 v8, v26

    .line 1691
    .line 1692
    :goto_21
    if-eqz v8, :cond_27

    .line 1693
    .line 1694
    const-string v0, "google.product_id"

    .line 1695
    .line 1696
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 1697
    .line 1698
    .line 1699
    move-result v5

    .line 1700
    invoke-virtual {v4, v0, v5}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 1701
    .line 1702
    .line 1703
    :cond_27
    iget-object v0, v1, Lio/i;->e:Ljava/lang/Object;

    .line 1704
    .line 1705
    check-cast v0, Landroid/content/Context;

    .line 1706
    .line 1707
    const-string v5, "supports_message_handled"

    .line 1708
    .line 1709
    invoke-virtual {v4, v5, v7}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 1710
    .line 1711
    .line 1712
    invoke-static {v0}, Lio/o;->d(Landroid/content/Context;)Lio/o;

    .line 1713
    .line 1714
    .line 1715
    move-result-object v5

    .line 1716
    new-instance v0, Lio/n;

    .line 1717
    .line 1718
    monitor-enter v5

    .line 1719
    :try_start_13
    iget v7, v5, Lio/o;->d:I

    .line 1720
    .line 1721
    add-int/lit8 v8, v7, 0x1

    .line 1722
    .line 1723
    iput v8, v5, Lio/o;->d:I
    :try_end_13
    .catchall {:try_start_13 .. :try_end_13} :catchall_7

    .line 1724
    .line 1725
    monitor-exit v5

    .line 1726
    invoke-direct {v0, v7, v3, v4, v6}, Lio/n;-><init>(IILandroid/os/Bundle;I)V

    .line 1727
    .line 1728
    .line 1729
    invoke-virtual {v5, v0}, Lio/o;->e(Lio/n;)Laq/t;

    .line 1730
    .line 1731
    .line 1732
    move-result-object v0

    .line 1733
    :goto_22
    iget-object v1, v1, Lio/i;->g:Ljava/lang/Object;

    .line 1734
    .line 1735
    check-cast v1, Ljava/util/concurrent/CountDownLatch;

    .line 1736
    .line 1737
    sget-object v3, Lio/h;->e:Lio/h;

    .line 1738
    .line 1739
    new-instance v4, Lh6/e;

    .line 1740
    .line 1741
    invoke-direct {v4, v1, v2}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 1742
    .line 1743
    .line 1744
    invoke-virtual {v0, v3, v4}, Laq/t;->b(Ljava/util/concurrent/Executor;Laq/e;)Laq/t;

    .line 1745
    .line 1746
    .line 1747
    return-void

    .line 1748
    :catchall_7
    move-exception v0

    .line 1749
    :try_start_14
    monitor-exit v5
    :try_end_14
    .catchall {:try_start_14 .. :try_end_14} :catchall_7

    .line 1750
    throw v0

    .line 1751
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
