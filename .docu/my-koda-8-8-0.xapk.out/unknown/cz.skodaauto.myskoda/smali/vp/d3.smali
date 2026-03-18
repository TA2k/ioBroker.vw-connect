.class public final Lvp/d3;
.super Lvp/b0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:Lvp/c3;

.field public h:Lvp/c0;

.field public volatile i:Ljava/lang/Boolean;

.field public final j:Lvp/a3;

.field public k:Ljava/util/concurrent/ScheduledExecutorService;

.field public final l:Lg1/i3;

.field public final m:Ljava/util/ArrayList;

.field public final n:Lvp/a3;


# direct methods
.method public constructor <init>(Lvp/g1;)V
    .locals 2

    .line 1
    invoke-direct {p0, p1}, Lvp/b0;-><init>(Lvp/g1;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lvp/d3;->m:Ljava/util/ArrayList;

    .line 10
    .line 11
    new-instance v0, Lg1/i3;

    .line 12
    .line 13
    iget-object v1, p1, Lvp/g1;->n:Lto/a;

    .line 14
    .line 15
    invoke-direct {v0, v1}, Lg1/i3;-><init>(Lto/a;)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lvp/d3;->l:Lg1/i3;

    .line 19
    .line 20
    new-instance v0, Lvp/c3;

    .line 21
    .line 22
    invoke-direct {v0, p0}, Lvp/c3;-><init>(Lvp/d3;)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lvp/d3;->g:Lvp/c3;

    .line 26
    .line 27
    new-instance v0, Lvp/a3;

    .line 28
    .line 29
    const/4 v1, 0x0

    .line 30
    invoke-direct {v0, p0, p1, v1}, Lvp/a3;-><init>(Lvp/d3;Lvp/g1;I)V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Lvp/d3;->j:Lvp/a3;

    .line 34
    .line 35
    new-instance v0, Lvp/a3;

    .line 36
    .line 37
    const/4 v1, 0x1

    .line 38
    invoke-direct {v0, p0, p1, v1}, Lvp/a3;-><init>(Lvp/d3;Lvp/g1;I)V

    .line 39
    .line 40
    .line 41
    iput-object v0, p0, Lvp/d3;->n:Lvp/a3;

    .line 42
    .line 43
    return-void
.end method


# virtual methods
.method public final d0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final e0(Ljava/util/concurrent/atomic/AtomicReference;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 5
    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-virtual {p0, v0}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    new-instance v1, Lio/i;

    .line 13
    .line 14
    invoke-direct {v1, p0, p1, v0}, Lio/i;-><init>(Lvp/d3;Ljava/util/concurrent/atomic/AtomicReference;Lvp/f4;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, v1}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final f0(Landroid/os/Bundle;)V
    .locals 7

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 5
    .line 6
    .line 7
    new-instance v4, Lvp/s;

    .line 8
    .line 9
    invoke-direct {v4, p1}, Lvp/s;-><init>(Landroid/os/Bundle;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lvp/d3;->m0()V

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lvp/g1;

    .line 18
    .line 19
    iget-object v1, v0, Lvp/g1;->g:Lvp/h;

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    sget-object v3, Lvp/z;->b1:Lvp/y;

    .line 23
    .line 24
    invoke-virtual {v1, v2, v3}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    const/4 v2, 0x0

    .line 29
    if-eqz v1, :cond_2

    .line 30
    .line 31
    invoke-virtual {v0}, Lvp/g1;->n()Lvp/j0;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v1, Lvp/g1;

    .line 38
    .line 39
    iget-object v3, v1, Lvp/g1;->l:Lvp/d4;

    .line 40
    .line 41
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 42
    .line 43
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 44
    .line 45
    .line 46
    invoke-static {v4}, Lvp/d4;->E0(Landroid/os/Parcelable;)[B

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    if-nez v3, :cond_0

    .line 51
    .line 52
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 53
    .line 54
    .line 55
    iget-object v0, v1, Lvp/p0;->k:Lvp/n0;

    .line 56
    .line 57
    const-string v1, "Null default event parameters; not writing to database"

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    :goto_0
    move v0, v2

    .line 63
    goto :goto_1

    .line 64
    :cond_0
    array-length v5, v3

    .line 65
    const/high16 v6, 0x20000

    .line 66
    .line 67
    if-le v5, v6, :cond_1

    .line 68
    .line 69
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 70
    .line 71
    .line 72
    iget-object v0, v1, Lvp/p0;->k:Lvp/n0;

    .line 73
    .line 74
    const-string v1, "Default event parameters too long for local database. Sending directly to service"

    .line 75
    .line 76
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_1
    const/4 v1, 0x4

    .line 81
    invoke-virtual {v0, v1, v3}, Lvp/j0;->h0(I[B)Z

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    :goto_1
    if-eqz v0, :cond_2

    .line 86
    .line 87
    const/4 v0, 0x1

    .line 88
    move v3, v0

    .line 89
    goto :goto_2

    .line 90
    :cond_2
    move v3, v2

    .line 91
    :goto_2
    invoke-virtual {p0, v2}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    new-instance v0, Lvp/a2;

    .line 96
    .line 97
    move-object v1, p0

    .line 98
    move-object v5, p1

    .line 99
    invoke-direct/range {v0 .. v5}, Lvp/a2;-><init>(Lvp/d3;Lvp/f4;ZLvp/s;Landroid/os/Bundle;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v1, v0}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 103
    .line 104
    .line 105
    return-void
.end method

.method public final g0()V
    .locals 11

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lvp/d3;->r0()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    goto/16 :goto_1

    .line 14
    .line 15
    :cond_0
    invoke-virtual {p0}, Lvp/d3;->h0()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const/4 v1, 0x1

    .line 20
    if-nez v0, :cond_4

    .line 21
    .line 22
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Lvp/g1;

    .line 25
    .line 26
    iget-object v2, v0, Lvp/g1;->g:Lvp/h;

    .line 27
    .line 28
    invoke-virtual {v2}, Lvp/h;->d0()Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-nez v2, :cond_3

    .line 33
    .line 34
    iget-object v2, v0, Lvp/g1;->d:Landroid/content/Context;

    .line 35
    .line 36
    invoke-virtual {v2}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    new-instance v3, Landroid/content/Intent;

    .line 41
    .line 42
    invoke-direct {v3}, Landroid/content/Intent;-><init>()V

    .line 43
    .line 44
    .line 45
    iget-object v4, v0, Lvp/g1;->d:Landroid/content/Context;

    .line 46
    .line 47
    const-string v5, "com.google.android.gms.measurement.AppMeasurementService"

    .line 48
    .line 49
    invoke-virtual {v3, v4, v5}, Landroid/content/Intent;->setClassName(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    const/high16 v4, 0x10000

    .line 54
    .line 55
    invoke-virtual {v2, v3, v4}, Landroid/content/pm/PackageManager;->queryIntentServices(Landroid/content/Intent;I)Ljava/util/List;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    if-eqz v2, :cond_2

    .line 60
    .line 61
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-nez v2, :cond_2

    .line 66
    .line 67
    new-instance v2, Landroid/content/Intent;

    .line 68
    .line 69
    const-string v3, "com.google.android.gms.measurement.START"

    .line 70
    .line 71
    invoke-direct {v2, v3}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    new-instance v3, Landroid/content/ComponentName;

    .line 75
    .line 76
    iget-object v0, v0, Lvp/g1;->d:Landroid/content/Context;

    .line 77
    .line 78
    const-string v4, "com.google.android.gms.measurement.AppMeasurementService"

    .line 79
    .line 80
    invoke-direct {v3, v0, v4}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v2, v3}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;

    .line 84
    .line 85
    .line 86
    iget-object p0, p0, Lvp/d3;->g:Lvp/c3;

    .line 87
    .line 88
    iget-object v0, p0, Lvp/c3;->c:Lvp/d3;

    .line 89
    .line 90
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 91
    .line 92
    .line 93
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Lvp/g1;

    .line 96
    .line 97
    iget-object v0, v0, Lvp/g1;->d:Landroid/content/Context;

    .line 98
    .line 99
    invoke-static {}, Lso/a;->b()Lso/a;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    monitor-enter p0

    .line 104
    :try_start_0
    iget-boolean v4, p0, Lvp/c3;->a:Z

    .line 105
    .line 106
    if-eqz v4, :cond_1

    .line 107
    .line 108
    iget-object v0, p0, Lvp/c3;->c:Lvp/d3;

    .line 109
    .line 110
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast v0, Lvp/g1;

    .line 113
    .line 114
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 115
    .line 116
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 117
    .line 118
    .line 119
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 120
    .line 121
    const-string v1, "Connection attempt already in progress"

    .line 122
    .line 123
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    monitor-exit p0

    .line 127
    return-void

    .line 128
    :catchall_0
    move-exception v0

    .line 129
    goto :goto_0

    .line 130
    :cond_1
    iget-object v4, p0, Lvp/c3;->c:Lvp/d3;

    .line 131
    .line 132
    iget-object v5, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast v5, Lvp/g1;

    .line 135
    .line 136
    iget-object v5, v5, Lvp/g1;->i:Lvp/p0;

    .line 137
    .line 138
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 139
    .line 140
    .line 141
    iget-object v5, v5, Lvp/p0;->r:Lvp/n0;

    .line 142
    .line 143
    const-string v6, "Using local app measurement service"

    .line 144
    .line 145
    invoke-virtual {v5, v6}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    iput-boolean v1, p0, Lvp/c3;->a:Z

    .line 149
    .line 150
    iget-object v1, v4, Lvp/d3;->g:Lvp/c3;

    .line 151
    .line 152
    const/16 v4, 0x81

    .line 153
    .line 154
    invoke-virtual {v3, v0, v2, v1, v4}, Lso/a;->a(Landroid/content/Context;Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z

    .line 155
    .line 156
    .line 157
    monitor-exit p0

    .line 158
    return-void

    .line 159
    :goto_0
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 160
    throw v0

    .line 161
    :cond_2
    iget-object p0, v0, Lvp/g1;->i:Lvp/p0;

    .line 162
    .line 163
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 164
    .line 165
    .line 166
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 167
    .line 168
    const-string v0, "Unable to use remote or local measurement implementation. Please register the AppMeasurementService service in the app manifest"

    .line 169
    .line 170
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    :cond_3
    :goto_1
    return-void

    .line 174
    :cond_4
    iget-object v8, p0, Lvp/d3;->g:Lvp/c3;

    .line 175
    .line 176
    iget-object p0, v8, Lvp/c3;->c:Lvp/d3;

    .line 177
    .line 178
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 179
    .line 180
    .line 181
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast p0, Lvp/g1;

    .line 184
    .line 185
    iget-object v3, p0, Lvp/g1;->d:Landroid/content/Context;

    .line 186
    .line 187
    monitor-enter v8

    .line 188
    :try_start_1
    iget-boolean p0, v8, Lvp/c3;->a:Z

    .line 189
    .line 190
    if-eqz p0, :cond_5

    .line 191
    .line 192
    iget-object p0, v8, Lvp/c3;->c:Lvp/d3;

    .line 193
    .line 194
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 195
    .line 196
    check-cast p0, Lvp/g1;

    .line 197
    .line 198
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 199
    .line 200
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 201
    .line 202
    .line 203
    iget-object p0, p0, Lvp/p0;->r:Lvp/n0;

    .line 204
    .line 205
    const-string v0, "Connection attempt already in progress"

    .line 206
    .line 207
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    monitor-exit v8

    .line 211
    return-void

    .line 212
    :catchall_1
    move-exception v0

    .line 213
    move-object p0, v0

    .line 214
    goto/16 :goto_3

    .line 215
    .line 216
    :cond_5
    iget-object p0, v8, Lvp/c3;->b:Lvp/l0;

    .line 217
    .line 218
    if-eqz p0, :cond_7

    .line 219
    .line 220
    iget-object p0, v8, Lvp/c3;->b:Lvp/l0;

    .line 221
    .line 222
    invoke-virtual {p0}, Lno/e;->b()Z

    .line 223
    .line 224
    .line 225
    move-result p0

    .line 226
    if-nez p0, :cond_6

    .line 227
    .line 228
    iget-object p0, v8, Lvp/c3;->b:Lvp/l0;

    .line 229
    .line 230
    invoke-virtual {p0}, Lno/e;->isConnected()Z

    .line 231
    .line 232
    .line 233
    move-result p0

    .line 234
    if-eqz p0, :cond_7

    .line 235
    .line 236
    :cond_6
    iget-object p0, v8, Lvp/c3;->c:Lvp/d3;

    .line 237
    .line 238
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 239
    .line 240
    check-cast p0, Lvp/g1;

    .line 241
    .line 242
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 243
    .line 244
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 245
    .line 246
    .line 247
    iget-object p0, p0, Lvp/p0;->r:Lvp/n0;

    .line 248
    .line 249
    const-string v0, "Already awaiting connection attempt"

    .line 250
    .line 251
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    monitor-exit v8

    .line 255
    return-void

    .line 256
    :cond_7
    new-instance v2, Lvp/l0;

    .line 257
    .line 258
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 259
    .line 260
    .line 261
    move-result-object v4

    .line 262
    invoke-static {v3}, Lno/n0;->a(Landroid/content/Context;)Lno/n0;

    .line 263
    .line 264
    .line 265
    move-result-object v5

    .line 266
    sget-object v6, Ljo/f;->b:Ljo/f;

    .line 267
    .line 268
    const/16 v7, 0x5d

    .line 269
    .line 270
    const/4 v10, 0x0

    .line 271
    move-object v9, v8

    .line 272
    invoke-direct/range {v2 .. v10}, Lno/e;-><init>(Landroid/content/Context;Landroid/os/Looper;Lno/n0;Ljo/f;ILno/b;Lno/c;Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    iput-object v2, v8, Lvp/c3;->b:Lvp/l0;

    .line 276
    .line 277
    iget-object p0, v8, Lvp/c3;->c:Lvp/d3;

    .line 278
    .line 279
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 280
    .line 281
    check-cast p0, Lvp/g1;

    .line 282
    .line 283
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 284
    .line 285
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 286
    .line 287
    .line 288
    iget-object p0, p0, Lvp/p0;->r:Lvp/n0;

    .line 289
    .line 290
    const-string v0, "Connecting to remote service"

    .line 291
    .line 292
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    iput-boolean v1, v8, Lvp/c3;->a:Z

    .line 296
    .line 297
    iget-object p0, v8, Lvp/c3;->b:Lvp/l0;

    .line 298
    .line 299
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 300
    .line 301
    .line 302
    iget-object p0, v8, Lvp/c3;->b:Lvp/l0;

    .line 303
    .line 304
    iget-object v0, p0, Lno/e;->e:Ljo/f;

    .line 305
    .line 306
    iget-object v2, p0, Lno/e;->c:Landroid/content/Context;

    .line 307
    .line 308
    const v3, 0xbdfcb8

    .line 309
    .line 310
    .line 311
    invoke-virtual {v0, v2, v3}, Ljo/f;->c(Landroid/content/Context;I)I

    .line 312
    .line 313
    .line 314
    move-result v0

    .line 315
    if-eqz v0, :cond_8

    .line 316
    .line 317
    const/4 v2, 0x0

    .line 318
    invoke-virtual {p0, v1, v2}, Lno/e;->B(ILandroid/os/IInterface;)V

    .line 319
    .line 320
    .line 321
    new-instance v1, Lno/n;

    .line 322
    .line 323
    invoke-direct {v1, p0}, Lno/n;-><init>(Ljava/lang/Object;)V

    .line 324
    .line 325
    .line 326
    invoke-virtual {p0, v1, v0, v2}, Lno/e;->y(Lno/d;ILandroid/app/PendingIntent;)V

    .line 327
    .line 328
    .line 329
    goto :goto_2

    .line 330
    :cond_8
    new-instance v0, Lno/n;

    .line 331
    .line 332
    invoke-direct {v0, p0}, Lno/n;-><init>(Ljava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    invoke-virtual {p0, v0}, Lno/e;->e(Lno/d;)V

    .line 336
    .line 337
    .line 338
    :goto_2
    monitor-exit v8

    .line 339
    return-void

    .line 340
    :goto_3
    monitor-exit v8
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 341
    throw p0
.end method

.method public final h0()Z
    .locals 9

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lvp/d3;->i:Ljava/lang/Boolean;

    .line 8
    .line 9
    if-nez v0, :cond_d

    .line 10
    .line 11
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lvp/g1;

    .line 20
    .line 21
    iget-object v1, v0, Lvp/g1;->h:Lvp/w0;

    .line 22
    .line 23
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1}, Lap0/o;->a0()V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    const-string v3, "use_service"

    .line 34
    .line 35
    invoke-interface {v2, v3}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    const/4 v4, 0x0

    .line 40
    if-nez v2, :cond_0

    .line 41
    .line 42
    const/4 v1, 0x0

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    invoke-virtual {v1}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-interface {v1, v3, v4}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    :goto_0
    const/4 v2, 0x1

    .line 57
    if-eqz v1, :cond_1

    .line 58
    .line 59
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 60
    .line 61
    .line 62
    move-result v5

    .line 63
    if-eqz v5, :cond_1

    .line 64
    .line 65
    goto/16 :goto_6

    .line 66
    .line 67
    :cond_1
    iget-object v5, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v5, Lvp/g1;

    .line 70
    .line 71
    invoke-virtual {v5}, Lvp/g1;->q()Lvp/h0;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    invoke-virtual {v5}, Lvp/b0;->b0()V

    .line 76
    .line 77
    .line 78
    iget v5, v5, Lvp/h0;->q:I

    .line 79
    .line 80
    if-ne v5, v2, :cond_2

    .line 81
    .line 82
    :goto_1
    move v4, v2

    .line 83
    goto/16 :goto_4

    .line 84
    .line 85
    :cond_2
    iget-object v5, v0, Lvp/g1;->i:Lvp/p0;

    .line 86
    .line 87
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 88
    .line 89
    .line 90
    iget-object v5, v5, Lvp/p0;->r:Lvp/n0;

    .line 91
    .line 92
    const-string v6, "Checking service availability"

    .line 93
    .line 94
    invoke-virtual {v5, v6}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    iget-object v5, v0, Lvp/g1;->l:Lvp/d4;

    .line 98
    .line 99
    invoke-static {v5}, Lvp/g1;->g(Lap0/o;)V

    .line 100
    .line 101
    .line 102
    iget-object v5, v5, Lap0/o;->e:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v5, Lvp/g1;

    .line 105
    .line 106
    sget-object v6, Ljo/f;->b:Ljo/f;

    .line 107
    .line 108
    iget-object v5, v5, Lvp/g1;->d:Landroid/content/Context;

    .line 109
    .line 110
    const v7, 0xbdfcb8

    .line 111
    .line 112
    .line 113
    invoke-virtual {v6, v5, v7}, Ljo/f;->c(Landroid/content/Context;I)I

    .line 114
    .line 115
    .line 116
    move-result v5

    .line 117
    if-eqz v5, :cond_a

    .line 118
    .line 119
    if-eq v5, v2, :cond_9

    .line 120
    .line 121
    const/4 v6, 0x2

    .line 122
    if-eq v5, v6, :cond_6

    .line 123
    .line 124
    const/4 v1, 0x3

    .line 125
    if-eq v5, v1, :cond_5

    .line 126
    .line 127
    const/16 v1, 0x9

    .line 128
    .line 129
    if-eq v5, v1, :cond_4

    .line 130
    .line 131
    const/16 v1, 0x12

    .line 132
    .line 133
    if-eq v5, v1, :cond_3

    .line 134
    .line 135
    iget-object v1, v0, Lvp/g1;->i:Lvp/p0;

    .line 136
    .line 137
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 138
    .line 139
    .line 140
    iget-object v1, v1, Lvp/p0;->m:Lvp/n0;

    .line 141
    .line 142
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 143
    .line 144
    .line 145
    move-result-object v2

    .line 146
    const-string v5, "Unexpected service status"

    .line 147
    .line 148
    invoke-virtual {v1, v2, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    :goto_2
    move v2, v4

    .line 152
    goto/16 :goto_4

    .line 153
    .line 154
    :cond_3
    iget-object v1, v0, Lvp/g1;->i:Lvp/p0;

    .line 155
    .line 156
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 157
    .line 158
    .line 159
    iget-object v1, v1, Lvp/p0;->m:Lvp/n0;

    .line 160
    .line 161
    const-string v4, "Service updating"

    .line 162
    .line 163
    invoke-virtual {v1, v4}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    goto :goto_1

    .line 167
    :cond_4
    iget-object v1, v0, Lvp/g1;->i:Lvp/p0;

    .line 168
    .line 169
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 170
    .line 171
    .line 172
    iget-object v1, v1, Lvp/p0;->m:Lvp/n0;

    .line 173
    .line 174
    const-string v2, "Service invalid"

    .line 175
    .line 176
    invoke-virtual {v1, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    goto :goto_2

    .line 180
    :cond_5
    iget-object v1, v0, Lvp/g1;->i:Lvp/p0;

    .line 181
    .line 182
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 183
    .line 184
    .line 185
    iget-object v1, v1, Lvp/p0;->m:Lvp/n0;

    .line 186
    .line 187
    const-string v2, "Service disabled"

    .line 188
    .line 189
    invoke-virtual {v1, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    goto :goto_2

    .line 193
    :cond_6
    iget-object v5, v0, Lvp/g1;->i:Lvp/p0;

    .line 194
    .line 195
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 196
    .line 197
    .line 198
    iget-object v5, v5, Lvp/p0;->q:Lvp/n0;

    .line 199
    .line 200
    const-string v6, "Service container out of date"

    .line 201
    .line 202
    invoke-virtual {v5, v6}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    iget-object v5, v0, Lvp/g1;->l:Lvp/d4;

    .line 206
    .line 207
    invoke-static {v5}, Lvp/g1;->g(Lap0/o;)V

    .line 208
    .line 209
    .line 210
    invoke-virtual {v5}, Lvp/d4;->G0()I

    .line 211
    .line 212
    .line 213
    move-result v5

    .line 214
    const/16 v6, 0x4423

    .line 215
    .line 216
    if-ge v5, v6, :cond_7

    .line 217
    .line 218
    goto :goto_4

    .line 219
    :cond_7
    if-nez v1, :cond_8

    .line 220
    .line 221
    goto :goto_3

    .line 222
    :cond_8
    move v2, v4

    .line 223
    :goto_3
    move v8, v4

    .line 224
    move v4, v2

    .line 225
    move v2, v8

    .line 226
    goto :goto_4

    .line 227
    :cond_9
    iget-object v1, v0, Lvp/g1;->i:Lvp/p0;

    .line 228
    .line 229
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 230
    .line 231
    .line 232
    iget-object v1, v1, Lvp/p0;->r:Lvp/n0;

    .line 233
    .line 234
    const-string v5, "Service missing"

    .line 235
    .line 236
    invoke-virtual {v1, v5}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 237
    .line 238
    .line 239
    goto :goto_4

    .line 240
    :cond_a
    iget-object v1, v0, Lvp/g1;->i:Lvp/p0;

    .line 241
    .line 242
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 243
    .line 244
    .line 245
    iget-object v1, v1, Lvp/p0;->r:Lvp/n0;

    .line 246
    .line 247
    const-string v4, "Service available"

    .line 248
    .line 249
    invoke-virtual {v1, v4}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    goto/16 :goto_1

    .line 253
    .line 254
    :goto_4
    if-nez v4, :cond_b

    .line 255
    .line 256
    iget-object v1, v0, Lvp/g1;->g:Lvp/h;

    .line 257
    .line 258
    invoke-virtual {v1}, Lvp/h;->d0()Z

    .line 259
    .line 260
    .line 261
    move-result v1

    .line 262
    if-eqz v1, :cond_b

    .line 263
    .line 264
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 265
    .line 266
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 267
    .line 268
    .line 269
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 270
    .line 271
    const-string v1, "No way to upload. Consider using the full version of Analytics"

    .line 272
    .line 273
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 274
    .line 275
    .line 276
    goto :goto_5

    .line 277
    :cond_b
    if-eqz v2, :cond_c

    .line 278
    .line 279
    iget-object v0, v0, Lvp/g1;->h:Lvp/w0;

    .line 280
    .line 281
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 285
    .line 286
    .line 287
    invoke-virtual {v0}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 292
    .line 293
    .line 294
    move-result-object v0

    .line 295
    invoke-interface {v0, v3, v4}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 296
    .line 297
    .line 298
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 299
    .line 300
    .line 301
    :cond_c
    :goto_5
    move v2, v4

    .line 302
    :goto_6
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 303
    .line 304
    .line 305
    move-result-object v0

    .line 306
    iput-object v0, p0, Lvp/d3;->i:Ljava/lang/Boolean;

    .line 307
    .line 308
    :cond_d
    iget-object p0, p0, Lvp/d3;->i:Ljava/lang/Boolean;

    .line 309
    .line 310
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 311
    .line 312
    .line 313
    move-result p0

    .line 314
    return p0
.end method

.method public final i0()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lvp/d3;->g:Lvp/c3;

    .line 8
    .line 9
    iget-object v1, v0, Lvp/c3;->b:Lvp/l0;

    .line 10
    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    iget-object v1, v0, Lvp/c3;->b:Lvp/l0;

    .line 14
    .line 15
    invoke-virtual {v1}, Lno/e;->isConnected()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-nez v1, :cond_0

    .line 20
    .line 21
    iget-object v1, v0, Lvp/c3;->b:Lvp/l0;

    .line 22
    .line 23
    invoke-virtual {v1}, Lno/e;->b()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_1

    .line 28
    .line 29
    :cond_0
    iget-object v1, v0, Lvp/c3;->b:Lvp/l0;

    .line 30
    .line 31
    invoke-virtual {v1}, Lno/e;->disconnect()V

    .line 32
    .line 33
    .line 34
    :cond_1
    const/4 v1, 0x0

    .line 35
    iput-object v1, v0, Lvp/c3;->b:Lvp/l0;

    .line 36
    .line 37
    :try_start_0
    invoke-static {}, Lso/a;->b()Lso/a;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    iget-object v3, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v3, Lvp/g1;

    .line 44
    .line 45
    iget-object v3, v3, Lvp/g1;->d:Landroid/content/Context;

    .line 46
    .line 47
    invoke-virtual {v2, v3, v0}, Lso/a;->c(Landroid/content/Context;Landroid/content/ServiceConnection;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 48
    .line 49
    .line 50
    :catch_0
    iput-object v1, p0, Lvp/d3;->h:Lvp/c0;

    .line 51
    .line 52
    return-void
.end method

.method public final j0()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lvp/d3;->h0()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lvp/g1;

    .line 16
    .line 17
    iget-object p0, p0, Lvp/g1;->l:Lvp/d4;

    .line 18
    .line 19
    invoke-static {p0}, Lvp/g1;->g(Lap0/o;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lvp/d4;->G0()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    sget-object v0, Lvp/z;->J0:Lvp/y;

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    invoke-virtual {v0, v1}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    check-cast v0, Ljava/lang/Integer;

    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-lt p0, v0, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 p0, 0x0

    .line 43
    return p0

    .line 44
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 45
    return p0
.end method

.method public final k0()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lvp/d3;->h0()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lvp/g1;

    .line 16
    .line 17
    iget-object p0, p0, Lvp/g1;->l:Lvp/d4;

    .line 18
    .line 19
    invoke-static {p0}, Lvp/g1;->g(Lap0/o;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lvp/d4;->G0()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    const v0, 0x3ae30

    .line 27
    .line 28
    .line 29
    if-lt p0, v0, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 p0, 0x0

    .line 33
    return p0

    .line 34
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 35
    return p0
.end method

.method public final l0(Landroid/content/ComponentName;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lvp/d3;->h:Lvp/c0;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput-object v0, p0, Lvp/d3;->h:Lvp/c0;

    .line 10
    .line 11
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lvp/g1;

    .line 14
    .line 15
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 16
    .line 17
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 18
    .line 19
    .line 20
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 21
    .line 22
    const-string v1, "Disconnected from device MeasurementService"

    .line 23
    .line 24
    invoke-virtual {v0, p1, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Lvp/d3;->g0()V

    .line 31
    .line 32
    .line 33
    :cond_0
    return-void
.end method

.method public final m0()V
    .locals 0

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final n0()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lvp/d3;->l:Lg1/i3;

    .line 5
    .line 6
    iget-object v1, v0, Lg1/i3;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Lto/a;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 14
    .line 15
    .line 16
    move-result-wide v1

    .line 17
    iput-wide v1, v0, Lg1/i3;->e:J

    .line 18
    .line 19
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Lvp/g1;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    sget-object v0, Lvp/z;->Y:Lvp/y;

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    invoke-virtual {v0, v1}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    check-cast v0, Ljava/lang/Long;

    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 36
    .line 37
    .line 38
    move-result-wide v0

    .line 39
    iget-object p0, p0, Lvp/d3;->j:Lvp/a3;

    .line 40
    .line 41
    invoke-virtual {p0, v0, v1}, Lvp/o;->b(J)V

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public final o0(Ljava/lang/Runnable;)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/d3;->r0()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-interface {p1}, Ljava/lang/Runnable;->run()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget-object v0, p0, Lvp/d3;->m:Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    int-to-long v1, v1

    .line 21
    iget-object v3, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v3, Lvp/g1;

    .line 24
    .line 25
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    const-wide/16 v4, 0x3e8

    .line 29
    .line 30
    cmp-long v1, v1, v4

    .line 31
    .line 32
    if-ltz v1, :cond_1

    .line 33
    .line 34
    iget-object p0, v3, Lvp/g1;->i:Lvp/p0;

    .line 35
    .line 36
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 40
    .line 41
    const-string p1, "Discarding data. Max runnable queue size reached"

    .line 42
    .line 43
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    iget-object p1, p0, Lvp/d3;->n:Lvp/a3;

    .line 51
    .line 52
    const-wide/32 v0, 0xea60

    .line 53
    .line 54
    .line 55
    invoke-virtual {p1, v0, v1}, Lvp/o;->b(J)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p0}, Lvp/d3;->g0()V

    .line 59
    .line 60
    .line 61
    return-void
.end method

.method public final p0()V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Lvp/g1;

    .line 7
    .line 8
    iget-object v1, v0, Lvp/g1;->i:Lvp/p0;

    .line 9
    .line 10
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 11
    .line 12
    .line 13
    iget-object v1, v1, Lvp/p0;->r:Lvp/n0;

    .line 14
    .line 15
    iget-object v2, p0, Lvp/d3;->m:Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    const-string v4, "Processing queued up service tasks"

    .line 26
    .line 27
    invoke-virtual {v1, v3, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    if-eqz v3, :cond_0

    .line 39
    .line 40
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    check-cast v3, Ljava/lang/Runnable;

    .line 45
    .line 46
    :try_start_0
    invoke-interface {v3}, Ljava/lang/Runnable;->run()V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catch_0
    move-exception v3

    .line 51
    iget-object v4, v0, Lvp/g1;->i:Lvp/p0;

    .line 52
    .line 53
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 54
    .line 55
    .line 56
    iget-object v4, v4, Lvp/p0;->j:Lvp/n0;

    .line 57
    .line 58
    const-string v5, "Task exception while flushing queue"

    .line 59
    .line 60
    invoke-virtual {v4, v3, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_0
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 65
    .line 66
    .line 67
    iget-object p0, p0, Lvp/d3;->n:Lvp/a3;

    .line 68
    .line 69
    invoke-virtual {p0}, Lvp/o;->c()V

    .line 70
    .line 71
    .line 72
    return-void
.end method

.method public final q0(Z)Lvp/f4;
    .locals 9

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lvp/g1;->q()Lvp/h0;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    const/4 v1, 0x0

    .line 13
    if-eqz p1, :cond_7

    .line 14
    .line 15
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 16
    .line 17
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Lvp/g1;

    .line 23
    .line 24
    iget-object p1, p0, Lvp/g1;->h:Lvp/w0;

    .line 25
    .line 26
    invoke-static {p1}, Lvp/g1;->g(Lap0/o;)V

    .line 27
    .line 28
    .line 29
    iget-object p1, p1, Lvp/w0;->i:Lgb/d;

    .line 30
    .line 31
    if-nez p1, :cond_0

    .line 32
    .line 33
    goto/16 :goto_4

    .line 34
    .line 35
    :cond_0
    iget-object p0, p0, Lvp/g1;->h:Lvp/w0;

    .line 36
    .line 37
    invoke-static {p0}, Lvp/g1;->g(Lap0/o;)V

    .line 38
    .line 39
    .line 40
    iget-object p0, p0, Lvp/w0;->i:Lgb/d;

    .line 41
    .line 42
    iget-object p1, p0, Lgb/d;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p1, Lvp/w0;

    .line 45
    .line 46
    invoke-virtual {p1}, Lap0/o;->a0()V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p1}, Lap0/o;->a0()V

    .line 50
    .line 51
    .line 52
    iget-object v2, p0, Lgb/d;->e:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v2, Lvp/w0;

    .line 55
    .line 56
    invoke-virtual {v2}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    iget-object v3, p0, Lgb/d;->b:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v3, Ljava/lang/String;

    .line 63
    .line 64
    const-wide/16 v4, 0x0

    .line 65
    .line 66
    invoke-interface {v2, v3, v4, v5}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 67
    .line 68
    .line 69
    move-result-wide v2

    .line 70
    cmp-long v6, v2, v4

    .line 71
    .line 72
    if-nez v6, :cond_1

    .line 73
    .line 74
    invoke-virtual {p0}, Lgb/d;->d()V

    .line 75
    .line 76
    .line 77
    move-wide v2, v4

    .line 78
    goto :goto_0

    .line 79
    :cond_1
    iget-object v6, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v6, Lvp/g1;

    .line 82
    .line 83
    iget-object v6, v6, Lvp/g1;->n:Lto/a;

    .line 84
    .line 85
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 86
    .line 87
    .line 88
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 89
    .line 90
    .line 91
    move-result-wide v6

    .line 92
    sub-long/2addr v2, v6

    .line 93
    invoke-static {v2, v3}, Ljava/lang/Math;->abs(J)J

    .line 94
    .line 95
    .line 96
    move-result-wide v2

    .line 97
    :goto_0
    iget-wide v6, p0, Lgb/d;->a:J

    .line 98
    .line 99
    cmp-long v8, v2, v6

    .line 100
    .line 101
    if-gez v8, :cond_2

    .line 102
    .line 103
    :goto_1
    move-object p0, v1

    .line 104
    goto :goto_3

    .line 105
    :cond_2
    add-long/2addr v6, v6

    .line 106
    cmp-long v2, v2, v6

    .line 107
    .line 108
    if-lez v2, :cond_3

    .line 109
    .line 110
    invoke-virtual {p0}, Lgb/d;->d()V

    .line 111
    .line 112
    .line 113
    goto :goto_1

    .line 114
    :cond_3
    iget-object v2, p0, Lgb/d;->d:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast v2, Ljava/lang/String;

    .line 117
    .line 118
    invoke-virtual {p1}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 119
    .line 120
    .line 121
    move-result-object v3

    .line 122
    invoke-interface {v3, v2, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    iget-object v3, p0, Lgb/d;->c:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v3, Ljava/lang/String;

    .line 129
    .line 130
    invoke-virtual {p1}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    invoke-interface {p1, v3, v4, v5}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 135
    .line 136
    .line 137
    move-result-wide v6

    .line 138
    invoke-virtual {p0}, Lgb/d;->d()V

    .line 139
    .line 140
    .line 141
    if-eqz v2, :cond_5

    .line 142
    .line 143
    cmp-long p0, v6, v4

    .line 144
    .line 145
    if-gtz p0, :cond_4

    .line 146
    .line 147
    goto :goto_2

    .line 148
    :cond_4
    new-instance p0, Landroid/util/Pair;

    .line 149
    .line 150
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    invoke-direct {p0, v2, p1}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_5
    :goto_2
    sget-object p0, Lvp/w0;->D:Landroid/util/Pair;

    .line 159
    .line 160
    :goto_3
    if-eqz p0, :cond_7

    .line 161
    .line 162
    sget-object p1, Lvp/w0;->D:Landroid/util/Pair;

    .line 163
    .line 164
    if-ne p0, p1, :cond_6

    .line 165
    .line 166
    goto :goto_4

    .line 167
    :cond_6
    iget-object p1, p0, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 168
    .line 169
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    iget-object p0, p0, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 174
    .line 175
    check-cast p0, Ljava/lang/String;

    .line 176
    .line 177
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    add-int/lit8 v1, v1, 0x1

    .line 186
    .line 187
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 188
    .line 189
    .line 190
    move-result v2

    .line 191
    new-instance v3, Ljava/lang/StringBuilder;

    .line 192
    .line 193
    add-int/2addr v1, v2

    .line 194
    invoke-direct {v3, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 195
    .line 196
    .line 197
    const-string v1, ":"

    .line 198
    .line 199
    invoke-static {v3, p1, v1, p0}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v1

    .line 203
    :cond_7
    :goto_4
    invoke-virtual {v0, v1}, Lvp/h0;->e0(Ljava/lang/String;)Lvp/f4;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    return-object p0
.end method

.method public final r0()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lvp/d3;->h:Lvp/c0;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final s0(Lvp/c0;Loo/a;Lvp/f4;)V
    .locals 66

    .line 1
    move-object/from16 v2, p2

    .line 2
    .line 3
    invoke-virtual/range {p0 .. p0}, Lvp/x;->a0()V

    .line 4
    .line 5
    .line 6
    invoke-virtual/range {p0 .. p0}, Lvp/b0;->b0()V

    .line 7
    .line 8
    .line 9
    invoke-virtual/range {p0 .. p0}, Lvp/d3;->m0()V

    .line 10
    .line 11
    .line 12
    move-object/from16 v0, p0

    .line 13
    .line 14
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 15
    .line 16
    move-object v3, v0

    .line 17
    check-cast v3, Lvp/g1;

    .line 18
    .line 19
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    iget-object v4, v3, Lvp/g1;->d:Landroid/content/Context;

    .line 23
    .line 24
    iget-object v5, v3, Lvp/g1;->i:Lvp/p0;

    .line 25
    .line 26
    iget-object v6, v3, Lvp/g1;->n:Lto/a;

    .line 27
    .line 28
    iget-object v7, v3, Lvp/g1;->g:Lvp/h;

    .line 29
    .line 30
    const/16 v9, 0x64

    .line 31
    .line 32
    move-object/from16 v10, p3

    .line 33
    .line 34
    move v0, v9

    .line 35
    const/4 v11, 0x0

    .line 36
    :goto_0
    const/16 v12, 0x3e9

    .line 37
    .line 38
    if-ge v11, v12, :cond_26

    .line 39
    .line 40
    if-ne v0, v9, :cond_26

    .line 41
    .line 42
    new-instance v12, Ljava/util/ArrayList;

    .line 43
    .line 44
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v3}, Lvp/g1;->n()Lvp/j0;

    .line 48
    .line 49
    .line 50
    move-result-object v13

    .line 51
    const-string v14, "Error reading entries from local database"

    .line 52
    .line 53
    const-string v15, "entry"

    .line 54
    .line 55
    move/from16 p0, v9

    .line 56
    .line 57
    const-string v9, "type"

    .line 58
    .line 59
    const-string v8, "rowid"

    .line 60
    .line 61
    iget-object v0, v13, Lap0/o;->e:Ljava/lang/Object;

    .line 62
    .line 63
    move-object/from16 v17, v6

    .line 64
    .line 65
    move-object v6, v0

    .line 66
    check-cast v6, Lvp/g1;

    .line 67
    .line 68
    invoke-virtual {v13}, Lvp/x;->a0()V

    .line 69
    .line 70
    .line 71
    iget-boolean v0, v13, Lvp/j0;->h:Z

    .line 72
    .line 73
    move/from16 p3, v11

    .line 74
    .line 75
    const-wide/16 v18, 0x0

    .line 76
    .line 77
    if-eqz v0, :cond_0

    .line 78
    .line 79
    move-object/from16 v20, v3

    .line 80
    .line 81
    move-object/from16 v21, v4

    .line 82
    .line 83
    move-object/from16 v22, v5

    .line 84
    .line 85
    :goto_1
    const/4 v8, 0x0

    .line 86
    :goto_2
    const/4 v11, 0x0

    .line 87
    goto/16 :goto_3a

    .line 88
    .line 89
    :cond_0
    new-instance v11, Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 92
    .line 93
    .line 94
    iget-object v0, v13, Lap0/o;->e:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v0, Lvp/g1;

    .line 97
    .line 98
    iget-object v0, v0, Lvp/g1;->d:Landroid/content/Context;

    .line 99
    .line 100
    move-object/from16 v20, v3

    .line 101
    .line 102
    const-string v3, "google_app_measurement_local.db"

    .line 103
    .line 104
    invoke-virtual {v0, v3}, Landroid/content/Context;->getDatabasePath(Ljava/lang/String;)Ljava/io/File;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    if-eqz v0, :cond_18

    .line 113
    .line 114
    const/4 v3, 0x5

    .line 115
    move-object/from16 v21, v4

    .line 116
    .line 117
    move-object/from16 v22, v5

    .line 118
    .line 119
    const/4 v4, 0x0

    .line 120
    move v5, v3

    .line 121
    :goto_3
    if-ge v4, v3, :cond_17

    .line 122
    .line 123
    const/4 v3, 0x1

    .line 124
    :try_start_0
    invoke-virtual {v13}, Lvp/j0;->g0()Landroid/database/sqlite/SQLiteDatabase;

    .line 125
    .line 126
    .line 127
    move-result-object v24
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_0 .. :try_end_0} :catch_38
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_0 .. :try_end_0} :catch_37
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_36
    .catchall {:try_start_0 .. :try_end_0} :catchall_c

    .line 128
    if-nez v24, :cond_1

    .line 129
    .line 130
    :try_start_1
    iput-boolean v3, v13, Lvp/j0;->h:Z

    .line 131
    .line 132
    goto :goto_1

    .line 133
    :catchall_0
    move-exception v0

    .line 134
    move-object/from16 v4, v24

    .line 135
    .line 136
    goto/16 :goto_30

    .line 137
    .line 138
    :catch_0
    move-exception v0

    .line 139
    move/from16 v36, v4

    .line 140
    .line 141
    :goto_4
    move-object/from16 v37, v8

    .line 142
    .line 143
    move-object/from16 v26, v15

    .line 144
    .line 145
    move-object/from16 v4, v24

    .line 146
    .line 147
    const/4 v8, 0x0

    .line 148
    const/16 v23, 0x5

    .line 149
    .line 150
    :goto_5
    move-object/from16 v24, v9

    .line 151
    .line 152
    goto/16 :goto_31

    .line 153
    .line 154
    :catch_1
    move/from16 v36, v4

    .line 155
    .line 156
    :catch_2
    move-object/from16 v37, v8

    .line 157
    .line 158
    move-object/from16 v26, v15

    .line 159
    .line 160
    move-object/from16 v4, v24

    .line 161
    .line 162
    const/4 v8, 0x0

    .line 163
    const/16 v23, 0x5

    .line 164
    .line 165
    :goto_6
    move-object/from16 v24, v9

    .line 166
    .line 167
    goto/16 :goto_32

    .line 168
    .line 169
    :catch_3
    move-exception v0

    .line 170
    move/from16 v36, v4

    .line 171
    .line 172
    :goto_7
    move-object/from16 v37, v8

    .line 173
    .line 174
    move-object/from16 v26, v15

    .line 175
    .line 176
    move-object/from16 v4, v24

    .line 177
    .line 178
    const/4 v8, 0x0

    .line 179
    const/16 v23, 0x5

    .line 180
    .line 181
    :goto_8
    move-object/from16 v24, v9

    .line 182
    .line 183
    goto/16 :goto_33

    .line 184
    .line 185
    :cond_1
    invoke-virtual/range {v24 .. v24}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 186
    .line 187
    .line 188
    const-string v0, "3"
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_1 .. :try_end_1} :catch_3
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 189
    .line 190
    :try_start_2
    const-string v25, "messages"

    .line 191
    .line 192
    filled-new-array {v8}, [Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object v26

    .line 196
    const-string v27, "type=?"

    .line 197
    .line 198
    filled-new-array {v0}, [Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v28

    .line 202
    const-string v31, "rowid desc"

    .line 203
    .line 204
    const-string v32, "1"

    .line 205
    .line 206
    const/16 v29, 0x0

    .line 207
    .line 208
    const/16 v30, 0x0

    .line 209
    .line 210
    invoke-virtual/range {v24 .. v32}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 211
    .line 212
    .line 213
    move-result-object v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_a

    .line 214
    :try_start_3
    invoke-interface {v3}, Landroid/database/Cursor;->moveToFirst()Z

    .line 215
    .line 216
    .line 217
    move-result v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_9

    .line 218
    const-wide/16 v34, -0x1

    .line 219
    .line 220
    if-eqz v0, :cond_2

    .line 221
    .line 222
    move/from16 v36, v4

    .line 223
    .line 224
    const/4 v4, 0x0

    .line 225
    :try_start_4
    invoke-interface {v3, v4}, Landroid/database/Cursor;->getLong(I)J

    .line 226
    .line 227
    .line 228
    move-result-wide v25
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 229
    :try_start_5
    invoke-interface {v3}, Landroid/database/Cursor;->close()V
    :try_end_5
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_5 .. :try_end_5} :catch_5
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_5 .. :try_end_5} :catch_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_5 .. :try_end_5} :catch_4
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 230
    .line 231
    .line 232
    goto :goto_a

    .line 233
    :catch_4
    move-exception v0

    .line 234
    goto :goto_4

    .line 235
    :catch_5
    move-exception v0

    .line 236
    goto :goto_7

    .line 237
    :catchall_1
    move-exception v0

    .line 238
    :goto_9
    move-object/from16 v37, v8

    .line 239
    .line 240
    move-object/from16 v26, v15

    .line 241
    .line 242
    move-object/from16 v4, v24

    .line 243
    .line 244
    const/4 v8, 0x0

    .line 245
    const/16 v23, 0x5

    .line 246
    .line 247
    move-object/from16 v24, v9

    .line 248
    .line 249
    goto/16 :goto_2e

    .line 250
    .line 251
    :cond_2
    move/from16 v36, v4

    .line 252
    .line 253
    :try_start_6
    invoke-interface {v3}, Landroid/database/Cursor;->close()V
    :try_end_6
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_6 .. :try_end_6} :catch_32
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_6 .. :try_end_6} :catch_31
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_6 .. :try_end_6} :catch_30
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 254
    .line 255
    .line 256
    move-wide/from16 v25, v34

    .line 257
    .line 258
    :goto_a
    cmp-long v0, v25, v34

    .line 259
    .line 260
    if-eqz v0, :cond_3

    .line 261
    .line 262
    :try_start_7
    const-string v0, "rowid<?"

    .line 263
    .line 264
    const/4 v3, 0x1

    .line 265
    new-array v4, v3, [Ljava/lang/String;

    .line 266
    .line 267
    invoke-static/range {v25 .. v26}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 268
    .line 269
    .line 270
    move-result-object v3

    .line 271
    const/16 v16, 0x0

    .line 272
    .line 273
    aput-object v3, v4, v16
    :try_end_7
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_7 .. :try_end_7} :catch_5
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_7 .. :try_end_7} :catch_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_7 .. :try_end_7} :catch_4
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 274
    .line 275
    move-object/from16 v27, v0

    .line 276
    .line 277
    move-object/from16 v28, v4

    .line 278
    .line 279
    goto :goto_b

    .line 280
    :cond_3
    const/16 v27, 0x0

    .line 281
    .line 282
    const/16 v28, 0x0

    .line 283
    .line 284
    :goto_b
    :try_start_8
    filled-new-array {v8, v9, v15}, [Ljava/lang/String;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    iget-object v3, v6, Lvp/g1;->g:Lvp/h;

    .line 289
    .line 290
    sget-object v4, Lvp/z;->b1:Lvp/y;
    :try_end_8
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_8 .. :try_end_8} :catch_32
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_8 .. :try_end_8} :catch_31
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_8 .. :try_end_8} :catch_30
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 291
    .line 292
    move-object/from16 v37, v8

    .line 293
    .line 294
    const/4 v8, 0x0

    .line 295
    :try_start_9
    invoke-virtual {v3, v8, v4}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 296
    .line 297
    .line 298
    move-result v3
    :try_end_9
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_9 .. :try_end_9} :catch_2e
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_9 .. :try_end_9} :catch_2d
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_9 .. :try_end_9} :catch_2c
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 299
    const/16 v38, 0x4

    .line 300
    .line 301
    const/16 v39, 0x3

    .line 302
    .line 303
    const/4 v8, 0x2

    .line 304
    if-eqz v3, :cond_4

    .line 305
    .line 306
    const/4 v3, 0x5

    .line 307
    :try_start_a
    new-array v0, v3, [Ljava/lang/String;

    .line 308
    .line 309
    const/16 v16, 0x0

    .line 310
    .line 311
    aput-object v37, v0, v16

    .line 312
    .line 313
    const/16 v33, 0x1

    .line 314
    .line 315
    aput-object v9, v0, v33

    .line 316
    .line 317
    aput-object v15, v0, v8

    .line 318
    .line 319
    const-string v23, "app_version"

    .line 320
    .line 321
    aput-object v23, v0, v39

    .line 322
    .line 323
    const-string v23, "app_version_int"

    .line 324
    .line 325
    aput-object v23, v0, v38
    :try_end_a
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_a .. :try_end_a} :catch_8
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_a .. :try_end_a} :catch_7
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_a .. :try_end_a} :catch_6
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 326
    .line 327
    :goto_c
    move-object/from16 v26, v0

    .line 328
    .line 329
    goto :goto_d

    .line 330
    :catch_6
    move-exception v0

    .line 331
    move/from16 v23, v3

    .line 332
    .line 333
    move-object/from16 v26, v15

    .line 334
    .line 335
    move-object/from16 v4, v24

    .line 336
    .line 337
    const/4 v8, 0x0

    .line 338
    goto/16 :goto_5

    .line 339
    .line 340
    :catch_7
    move/from16 v23, v3

    .line 341
    .line 342
    move-object/from16 v26, v15

    .line 343
    .line 344
    move-object/from16 v4, v24

    .line 345
    .line 346
    const/4 v8, 0x0

    .line 347
    goto/16 :goto_6

    .line 348
    .line 349
    :catch_8
    move-exception v0

    .line 350
    move/from16 v23, v3

    .line 351
    .line 352
    move-object/from16 v26, v15

    .line 353
    .line 354
    move-object/from16 v4, v24

    .line 355
    .line 356
    const/4 v8, 0x0

    .line 357
    goto/16 :goto_8

    .line 358
    .line 359
    :cond_4
    const/4 v3, 0x5

    .line 360
    goto :goto_c

    .line 361
    :goto_d
    :try_start_b
    const-string v25, "messages"

    .line 362
    .line 363
    const-string v31, "rowid asc"

    .line 364
    .line 365
    invoke-static/range {p0 .. p0}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object v32
    :try_end_b
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_b .. :try_end_b} :catch_2e
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_b .. :try_end_b} :catch_2f
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_b .. :try_end_b} :catch_2c
    .catchall {:try_start_b .. :try_end_b} :catchall_0

    .line 369
    const/16 v29, 0x0

    .line 370
    .line 371
    const/16 v30, 0x0

    .line 372
    .line 373
    :try_start_c
    invoke-virtual/range {v24 .. v32}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 374
    .line 375
    .line 376
    move-result-object v3
    :try_end_c
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_c .. :try_end_c} :catch_2e
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_c .. :try_end_c} :catch_2d
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_c .. :try_end_c} :catch_2c
    .catchall {:try_start_c .. :try_end_c} :catchall_0

    .line 377
    move-object/from16 v40, v24

    .line 378
    .line 379
    :goto_e
    :try_start_d
    invoke-interface {v3}, Landroid/database/Cursor;->moveToNext()Z

    .line 380
    .line 381
    .line 382
    move-result v0
    :try_end_d
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_d .. :try_end_d} :catch_2b
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_d .. :try_end_d} :catch_29
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_d .. :try_end_d} :catch_28
    .catchall {:try_start_d .. :try_end_d} :catchall_2

    .line 383
    if-eqz v0, :cond_d

    .line 384
    .line 385
    const/4 v8, 0x0

    .line 386
    :try_start_e
    invoke-interface {v3, v8}, Landroid/database/Cursor;->getLong(I)J

    .line 387
    .line 388
    .line 389
    move-result-wide v34
    :try_end_e
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_e .. :try_end_e} :catch_25
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_e .. :try_end_e} :catch_24
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_e .. :try_end_e} :catch_23
    .catchall {:try_start_e .. :try_end_e} :catchall_2

    .line 390
    const/4 v8, 0x1

    .line 391
    :try_start_f
    invoke-interface {v3, v8}, Landroid/database/Cursor;->getInt(I)I

    .line 392
    .line 393
    .line 394
    move-result v0
    :try_end_f
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_f .. :try_end_f} :catch_22
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_f .. :try_end_f} :catch_21
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_f .. :try_end_f} :catch_20
    .catchall {:try_start_f .. :try_end_f} :catchall_2

    .line 395
    move-object/from16 v24, v9

    .line 396
    .line 397
    const/4 v8, 0x2

    .line 398
    :try_start_10
    invoke-interface {v3, v8}, Landroid/database/Cursor;->getBlob(I)[B

    .line 399
    .line 400
    .line 401
    move-result-object v9

    .line 402
    iget-object v8, v6, Lvp/g1;->g:Lvp/h;
    :try_end_10
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_10 .. :try_end_10} :catch_1f
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_10 .. :try_end_10} :catch_1e
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_10 .. :try_end_10} :catch_1d
    .catchall {:try_start_10 .. :try_end_10} :catchall_2

    .line 403
    .line 404
    move-object/from16 v26, v15

    .line 405
    .line 406
    const/4 v15, 0x0

    .line 407
    :try_start_11
    invoke-virtual {v8, v15, v4}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 408
    .line 409
    .line 410
    move-result v8
    :try_end_11
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_11 .. :try_end_11} :catch_1c
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_11 .. :try_end_11} :catch_1b
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_11 .. :try_end_11} :catch_1a
    .catchall {:try_start_11 .. :try_end_11} :catchall_2

    .line 411
    if-eqz v8, :cond_5

    .line 412
    .line 413
    move/from16 v8, v39

    .line 414
    .line 415
    :try_start_12
    invoke-interface {v3, v8}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 416
    .line 417
    .line 418
    move-result-object v15

    .line 419
    move/from16 v8, v38

    .line 420
    .line 421
    invoke-interface {v3, v8}, Landroid/database/Cursor;->getLong(I)J

    .line 422
    .line 423
    .line 424
    move-result-wide v27
    :try_end_12
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_12 .. :try_end_12} :catch_c
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_12 .. :try_end_12} :catch_a
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_12 .. :try_end_12} :catch_9
    .catchall {:try_start_12 .. :try_end_12} :catchall_2

    .line 425
    move-object v8, v3

    .line 426
    move-wide/from16 v64, v27

    .line 427
    .line 428
    move-object/from16 v27, v4

    .line 429
    .line 430
    move-wide/from16 v3, v64

    .line 431
    .line 432
    goto :goto_13

    .line 433
    :catchall_2
    move-exception v0

    .line 434
    move-object/from16 v28, v3

    .line 435
    .line 436
    :goto_f
    move-object/from16 v4, v40

    .line 437
    .line 438
    goto/16 :goto_27

    .line 439
    .line 440
    :catch_9
    move-exception v0

    .line 441
    move-object/from16 v28, v3

    .line 442
    .line 443
    :goto_10
    move-object/from16 v4, v40

    .line 444
    .line 445
    const/4 v8, 0x0

    .line 446
    goto/16 :goto_28

    .line 447
    .line 448
    :catch_a
    move-object/from16 v28, v3

    .line 449
    .line 450
    :catch_b
    :goto_11
    move-object/from16 v4, v40

    .line 451
    .line 452
    const/4 v8, 0x0

    .line 453
    goto/16 :goto_29

    .line 454
    .line 455
    :catch_c
    move-exception v0

    .line 456
    move-object/from16 v28, v3

    .line 457
    .line 458
    :goto_12
    move-object/from16 v4, v40

    .line 459
    .line 460
    const/4 v8, 0x0

    .line 461
    goto/16 :goto_2a

    .line 462
    .line 463
    :cond_5
    move-object v8, v3

    .line 464
    move-object/from16 v27, v4

    .line 465
    .line 466
    move-wide/from16 v3, v18

    .line 467
    .line 468
    const/4 v15, 0x0

    .line 469
    :goto_13
    if-nez v0, :cond_7

    .line 470
    .line 471
    move-object/from16 v28, v8

    .line 472
    .line 473
    :try_start_13
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 474
    .line 475
    .line 476
    move-result-object v8
    :try_end_13
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_13 .. :try_end_13} :catch_e
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_13 .. :try_end_13} :catch_b
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_13 .. :try_end_13} :catch_d
    .catchall {:try_start_13 .. :try_end_13} :catchall_3

    .line 477
    :try_start_14
    array-length v0, v9

    .line 478
    const/4 v1, 0x0

    .line 479
    invoke-virtual {v8, v9, v1, v0}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 480
    .line 481
    .line 482
    invoke-virtual {v8, v1}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 483
    .line 484
    .line 485
    sget-object v0, Lvp/t;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 486
    .line 487
    invoke-interface {v0, v8}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 488
    .line 489
    .line 490
    move-result-object v0

    .line 491
    check-cast v0, Lvp/t;
    :try_end_14
    .catch Loo/b; {:try_start_14 .. :try_end_14} :catch_f
    .catchall {:try_start_14 .. :try_end_14} :catchall_4

    .line 492
    .line 493
    :try_start_15
    invoke-virtual {v8}, Landroid/os/Parcel;->recycle()V

    .line 494
    .line 495
    .line 496
    if-eqz v0, :cond_6

    .line 497
    .line 498
    new-instance v1, Lvp/i0;

    .line 499
    .line 500
    invoke-direct {v1, v0, v15, v3, v4}, Lvp/i0;-><init>(Loo/a;Ljava/lang/String;J)V

    .line 501
    .line 502
    .line 503
    invoke-virtual {v11, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_15
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_15 .. :try_end_15} :catch_e
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_15 .. :try_end_15} :catch_b
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_15 .. :try_end_15} :catch_d
    .catchall {:try_start_15 .. :try_end_15} :catchall_3

    .line 504
    .line 505
    .line 506
    :cond_6
    :goto_14
    const/4 v1, 0x3

    .line 507
    const/4 v8, 0x0

    .line 508
    goto/16 :goto_22

    .line 509
    .line 510
    :catchall_3
    move-exception v0

    .line 511
    goto :goto_f

    .line 512
    :catch_d
    move-exception v0

    .line 513
    goto :goto_10

    .line 514
    :catch_e
    move-exception v0

    .line 515
    goto :goto_12

    .line 516
    :catchall_4
    move-exception v0

    .line 517
    goto :goto_15

    .line 518
    :catch_f
    :try_start_16
    iget-object v0, v6, Lvp/g1;->i:Lvp/p0;

    .line 519
    .line 520
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 521
    .line 522
    .line 523
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 524
    .line 525
    const-string v1, "Failed to load event from local database"

    .line 526
    .line 527
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_16
    .catchall {:try_start_16 .. :try_end_16} :catchall_4

    .line 528
    .line 529
    .line 530
    :try_start_17
    invoke-virtual {v8}, Landroid/os/Parcel;->recycle()V

    .line 531
    .line 532
    .line 533
    goto :goto_14

    .line 534
    :goto_15
    invoke-virtual {v8}, Landroid/os/Parcel;->recycle()V

    .line 535
    .line 536
    .line 537
    throw v0

    .line 538
    :cond_7
    move-object/from16 v28, v8

    .line 539
    .line 540
    const/4 v8, 0x1

    .line 541
    if-ne v0, v8, :cond_8

    .line 542
    .line 543
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 544
    .line 545
    .line 546
    move-result-object v1
    :try_end_17
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_17 .. :try_end_17} :catch_e
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_17 .. :try_end_17} :catch_b
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_17 .. :try_end_17} :catch_d
    .catchall {:try_start_17 .. :try_end_17} :catchall_3

    .line 547
    :try_start_18
    array-length v0, v9

    .line 548
    const/4 v8, 0x0

    .line 549
    invoke-virtual {v1, v9, v8, v0}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 550
    .line 551
    .line 552
    invoke-virtual {v1, v8}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 553
    .line 554
    .line 555
    sget-object v0, Lvp/b4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 556
    .line 557
    invoke-interface {v0, v1}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 558
    .line 559
    .line 560
    move-result-object v0

    .line 561
    check-cast v0, Lvp/b4;
    :try_end_18
    .catch Loo/b; {:try_start_18 .. :try_end_18} :catch_10
    .catchall {:try_start_18 .. :try_end_18} :catchall_5

    .line 562
    .line 563
    :try_start_19
    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V
    :try_end_19
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_19 .. :try_end_19} :catch_e
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_19 .. :try_end_19} :catch_b
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_19 .. :try_end_19} :catch_d
    .catchall {:try_start_19 .. :try_end_19} :catchall_3

    .line 564
    .line 565
    .line 566
    goto :goto_16

    .line 567
    :catchall_5
    move-exception v0

    .line 568
    goto :goto_17

    .line 569
    :catch_10
    :try_start_1a
    iget-object v0, v6, Lvp/g1;->i:Lvp/p0;

    .line 570
    .line 571
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 572
    .line 573
    .line 574
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 575
    .line 576
    const-string v8, "Failed to load user property from local database"

    .line 577
    .line 578
    invoke-virtual {v0, v8}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_1a
    .catchall {:try_start_1a .. :try_end_1a} :catchall_5

    .line 579
    .line 580
    .line 581
    :try_start_1b
    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    .line 582
    .line 583
    .line 584
    const/4 v0, 0x0

    .line 585
    :goto_16
    if-eqz v0, :cond_6

    .line 586
    .line 587
    new-instance v1, Lvp/i0;

    .line 588
    .line 589
    invoke-direct {v1, v0, v15, v3, v4}, Lvp/i0;-><init>(Loo/a;Ljava/lang/String;J)V

    .line 590
    .line 591
    .line 592
    invoke-virtual {v11, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 593
    .line 594
    .line 595
    goto :goto_14

    .line 596
    :goto_17
    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    .line 597
    .line 598
    .line 599
    throw v0

    .line 600
    :cond_8
    const/4 v8, 0x2

    .line 601
    if-ne v0, v8, :cond_9

    .line 602
    .line 603
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 604
    .line 605
    .line 606
    move-result-object v1
    :try_end_1b
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_1b .. :try_end_1b} :catch_e
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_1b .. :try_end_1b} :catch_b
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1b .. :try_end_1b} :catch_d
    .catchall {:try_start_1b .. :try_end_1b} :catchall_3

    .line 607
    :try_start_1c
    array-length v0, v9

    .line 608
    const/4 v8, 0x0

    .line 609
    invoke-virtual {v1, v9, v8, v0}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 610
    .line 611
    .line 612
    invoke-virtual {v1, v8}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 613
    .line 614
    .line 615
    sget-object v0, Lvp/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 616
    .line 617
    invoke-interface {v0, v1}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 618
    .line 619
    .line 620
    move-result-object v0

    .line 621
    check-cast v0, Lvp/f;
    :try_end_1c
    .catch Loo/b; {:try_start_1c .. :try_end_1c} :catch_11
    .catchall {:try_start_1c .. :try_end_1c} :catchall_6

    .line 622
    .line 623
    :try_start_1d
    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V
    :try_end_1d
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_1d .. :try_end_1d} :catch_e
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_1d .. :try_end_1d} :catch_b
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1d .. :try_end_1d} :catch_d
    .catchall {:try_start_1d .. :try_end_1d} :catchall_3

    .line 624
    .line 625
    .line 626
    goto :goto_18

    .line 627
    :catchall_6
    move-exception v0

    .line 628
    goto :goto_19

    .line 629
    :catch_11
    :try_start_1e
    iget-object v0, v6, Lvp/g1;->i:Lvp/p0;

    .line 630
    .line 631
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 632
    .line 633
    .line 634
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 635
    .line 636
    const-string v8, "Failed to load conditional user property from local database"

    .line 637
    .line 638
    invoke-virtual {v0, v8}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_1e
    .catchall {:try_start_1e .. :try_end_1e} :catchall_6

    .line 639
    .line 640
    .line 641
    :try_start_1f
    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    .line 642
    .line 643
    .line 644
    const/4 v0, 0x0

    .line 645
    :goto_18
    if-eqz v0, :cond_6

    .line 646
    .line 647
    new-instance v1, Lvp/i0;

    .line 648
    .line 649
    invoke-direct {v1, v0, v15, v3, v4}, Lvp/i0;-><init>(Loo/a;Ljava/lang/String;J)V

    .line 650
    .line 651
    .line 652
    invoke-virtual {v11, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 653
    .line 654
    .line 655
    goto/16 :goto_14

    .line 656
    .line 657
    :goto_19
    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    .line 658
    .line 659
    .line 660
    throw v0
    :try_end_1f
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_1f .. :try_end_1f} :catch_e
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_1f .. :try_end_1f} :catch_b
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1f .. :try_end_1f} :catch_d
    .catchall {:try_start_1f .. :try_end_1f} :catchall_3

    .line 661
    :cond_9
    const/4 v8, 0x4

    .line 662
    if-ne v0, v8, :cond_b

    .line 663
    .line 664
    :try_start_20
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 665
    .line 666
    .line 667
    move-result-object v1
    :try_end_20
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_20 .. :try_end_20} :catch_19
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_20 .. :try_end_20} :catch_18
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_20 .. :try_end_20} :catch_17
    .catchall {:try_start_20 .. :try_end_20} :catchall_3

    .line 668
    :try_start_21
    array-length v0, v9
    :try_end_21
    .catch Loo/b; {:try_start_21 .. :try_end_21} :catch_15
    .catchall {:try_start_21 .. :try_end_21} :catchall_8

    .line 669
    const/4 v8, 0x0

    .line 670
    :try_start_22
    invoke-virtual {v1, v9, v8, v0}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 671
    .line 672
    .line 673
    invoke-virtual {v1, v8}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 674
    .line 675
    .line 676
    sget-object v0, Lvp/s;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 677
    .line 678
    invoke-interface {v0, v1}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 679
    .line 680
    .line 681
    move-result-object v0

    .line 682
    check-cast v0, Lvp/s;
    :try_end_22
    .catch Loo/b; {:try_start_22 .. :try_end_22} :catch_16
    .catchall {:try_start_22 .. :try_end_22} :catchall_7

    .line 683
    .line 684
    :try_start_23
    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V
    :try_end_23
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_23 .. :try_end_23} :catch_14
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_23 .. :try_end_23} :catch_13
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_23 .. :try_end_23} :catch_12
    .catchall {:try_start_23 .. :try_end_23} :catchall_3

    .line 685
    .line 686
    .line 687
    goto :goto_1d

    .line 688
    :catch_12
    move-exception v0

    .line 689
    :goto_1a
    move-object/from16 v4, v40

    .line 690
    .line 691
    goto/16 :goto_28

    .line 692
    .line 693
    :catch_13
    :goto_1b
    move-object/from16 v4, v40

    .line 694
    .line 695
    goto/16 :goto_29

    .line 696
    .line 697
    :catch_14
    move-exception v0

    .line 698
    :goto_1c
    move-object/from16 v4, v40

    .line 699
    .line 700
    goto/16 :goto_2a

    .line 701
    .line 702
    :catchall_7
    move-exception v0

    .line 703
    goto :goto_1e

    .line 704
    :catchall_8
    move-exception v0

    .line 705
    const/4 v8, 0x0

    .line 706
    goto :goto_1e

    .line 707
    :catch_15
    const/4 v8, 0x0

    .line 708
    :catch_16
    :try_start_24
    iget-object v0, v6, Lvp/g1;->i:Lvp/p0;

    .line 709
    .line 710
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 711
    .line 712
    .line 713
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 714
    .line 715
    const-string v9, "Failed to load default event parameters from local database"

    .line 716
    .line 717
    invoke-virtual {v0, v9}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_24
    .catchall {:try_start_24 .. :try_end_24} :catchall_7

    .line 718
    .line 719
    .line 720
    :try_start_25
    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    .line 721
    .line 722
    .line 723
    const/4 v0, 0x0

    .line 724
    :goto_1d
    if-eqz v0, :cond_a

    .line 725
    .line 726
    new-instance v1, Lvp/i0;

    .line 727
    .line 728
    invoke-direct {v1, v0, v15, v3, v4}, Lvp/i0;-><init>(Loo/a;Ljava/lang/String;J)V

    .line 729
    .line 730
    .line 731
    invoke-virtual {v11, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 732
    .line 733
    .line 734
    :cond_a
    const/4 v1, 0x3

    .line 735
    goto :goto_22

    .line 736
    :goto_1e
    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    .line 737
    .line 738
    .line 739
    throw v0

    .line 740
    :catch_17
    move-exception v0

    .line 741
    :goto_1f
    const/4 v8, 0x0

    .line 742
    goto :goto_1a

    .line 743
    :catch_18
    :goto_20
    const/4 v8, 0x0

    .line 744
    goto :goto_1b

    .line 745
    :catch_19
    move-exception v0

    .line 746
    :goto_21
    const/4 v8, 0x0

    .line 747
    goto :goto_1c

    .line 748
    :cond_b
    const/4 v1, 0x3

    .line 749
    const/4 v8, 0x0

    .line 750
    if-ne v0, v1, :cond_c

    .line 751
    .line 752
    iget-object v0, v6, Lvp/g1;->i:Lvp/p0;

    .line 753
    .line 754
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 755
    .line 756
    .line 757
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 758
    .line 759
    const-string v3, "Skipping app launch break"

    .line 760
    .line 761
    invoke-virtual {v0, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 762
    .line 763
    .line 764
    goto :goto_22

    .line 765
    :cond_c
    iget-object v0, v6, Lvp/g1;->i:Lvp/p0;

    .line 766
    .line 767
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 768
    .line 769
    .line 770
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 771
    .line 772
    const-string v3, "Unknown record type in local database"

    .line 773
    .line 774
    invoke-virtual {v0, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 775
    .line 776
    .line 777
    :goto_22
    move/from16 v39, v1

    .line 778
    .line 779
    move-object/from16 v9, v24

    .line 780
    .line 781
    move-object/from16 v15, v26

    .line 782
    .line 783
    move-object/from16 v4, v27

    .line 784
    .line 785
    move-object/from16 v3, v28

    .line 786
    .line 787
    const/4 v8, 0x2

    .line 788
    const/16 v38, 0x4

    .line 789
    .line 790
    goto/16 :goto_e

    .line 791
    .line 792
    :catch_1a
    move-exception v0

    .line 793
    move-object/from16 v28, v3

    .line 794
    .line 795
    goto :goto_1f

    .line 796
    :catch_1b
    move-object/from16 v28, v3

    .line 797
    .line 798
    goto :goto_20

    .line 799
    :catch_1c
    move-exception v0

    .line 800
    move-object/from16 v28, v3

    .line 801
    .line 802
    goto :goto_21

    .line 803
    :catch_1d
    move-exception v0

    .line 804
    move-object/from16 v28, v3

    .line 805
    .line 806
    :goto_23
    move-object/from16 v26, v15

    .line 807
    .line 808
    goto :goto_1f

    .line 809
    :catch_1e
    move-object/from16 v28, v3

    .line 810
    .line 811
    :goto_24
    move-object/from16 v26, v15

    .line 812
    .line 813
    goto :goto_20

    .line 814
    :catch_1f
    move-exception v0

    .line 815
    move-object/from16 v28, v3

    .line 816
    .line 817
    :goto_25
    move-object/from16 v26, v15

    .line 818
    .line 819
    goto :goto_21

    .line 820
    :catch_20
    move-exception v0

    .line 821
    move-object/from16 v28, v3

    .line 822
    .line 823
    move-object/from16 v24, v9

    .line 824
    .line 825
    goto :goto_23

    .line 826
    :catch_21
    move-object/from16 v28, v3

    .line 827
    .line 828
    move-object/from16 v24, v9

    .line 829
    .line 830
    goto :goto_24

    .line 831
    :catch_22
    move-exception v0

    .line 832
    move-object/from16 v28, v3

    .line 833
    .line 834
    move-object/from16 v24, v9

    .line 835
    .line 836
    goto :goto_25

    .line 837
    :catch_23
    move-exception v0

    .line 838
    move-object/from16 v28, v3

    .line 839
    .line 840
    move-object/from16 v24, v9

    .line 841
    .line 842
    move-object/from16 v26, v15

    .line 843
    .line 844
    goto/16 :goto_1a

    .line 845
    .line 846
    :catch_24
    move-object/from16 v28, v3

    .line 847
    .line 848
    move-object/from16 v24, v9

    .line 849
    .line 850
    move-object/from16 v26, v15

    .line 851
    .line 852
    goto/16 :goto_1b

    .line 853
    .line 854
    :catch_25
    move-exception v0

    .line 855
    move-object/from16 v28, v3

    .line 856
    .line 857
    move-object/from16 v24, v9

    .line 858
    .line 859
    move-object/from16 v26, v15

    .line 860
    .line 861
    goto/16 :goto_1c

    .line 862
    .line 863
    :cond_d
    move-object/from16 v28, v3

    .line 864
    .line 865
    move-object/from16 v24, v9

    .line 866
    .line 867
    move-object/from16 v26, v15

    .line 868
    .line 869
    const/4 v8, 0x0

    .line 870
    const-string v0, "messages"

    .line 871
    .line 872
    const-string v1, "rowid <= ?"

    .line 873
    .line 874
    invoke-static/range {v34 .. v35}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 875
    .line 876
    .line 877
    move-result-object v3

    .line 878
    filled-new-array {v3}, [Ljava/lang/String;

    .line 879
    .line 880
    .line 881
    move-result-object v3
    :try_end_25
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_25 .. :try_end_25} :catch_14
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_25 .. :try_end_25} :catch_13
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_25 .. :try_end_25} :catch_12
    .catchall {:try_start_25 .. :try_end_25} :catchall_3

    .line 882
    move-object/from16 v4, v40

    .line 883
    .line 884
    :try_start_26
    invoke-virtual {v4, v0, v1, v3}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I

    .line 885
    .line 886
    .line 887
    move-result v0

    .line 888
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 889
    .line 890
    .line 891
    move-result v1

    .line 892
    if-ge v0, v1, :cond_e

    .line 893
    .line 894
    iget-object v0, v6, Lvp/g1;->i:Lvp/p0;

    .line 895
    .line 896
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 897
    .line 898
    .line 899
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 900
    .line 901
    const-string v1, "Fewer entries removed from local database than expected"

    .line 902
    .line 903
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 904
    .line 905
    .line 906
    goto :goto_26

    .line 907
    :catch_26
    move-exception v0

    .line 908
    goto :goto_28

    .line 909
    :catch_27
    move-exception v0

    .line 910
    goto :goto_2a

    .line 911
    :cond_e
    :goto_26
    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V

    .line 912
    .line 913
    .line 914
    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V
    :try_end_26
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_26 .. :try_end_26} :catch_27
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_26 .. :try_end_26} :catch_2a
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_26 .. :try_end_26} :catch_26
    .catchall {:try_start_26 .. :try_end_26} :catchall_d

    .line 915
    .line 916
    .line 917
    invoke-interface/range {v28 .. v28}, Landroid/database/Cursor;->close()V

    .line 918
    .line 919
    .line 920
    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteClosable;->close()V

    .line 921
    .line 922
    .line 923
    goto/16 :goto_3a

    .line 924
    .line 925
    :goto_27
    move-object/from16 v11, v28

    .line 926
    .line 927
    goto/16 :goto_39

    .line 928
    .line 929
    :catch_28
    move-exception v0

    .line 930
    move-object/from16 v28, v3

    .line 931
    .line 932
    move-object/from16 v24, v9

    .line 933
    .line 934
    move-object/from16 v26, v15

    .line 935
    .line 936
    goto/16 :goto_10

    .line 937
    .line 938
    :goto_28
    const/16 v23, 0x5

    .line 939
    .line 940
    goto/16 :goto_34

    .line 941
    .line 942
    :catch_29
    move-object/from16 v28, v3

    .line 943
    .line 944
    move-object/from16 v24, v9

    .line 945
    .line 946
    move-object/from16 v26, v15

    .line 947
    .line 948
    goto/16 :goto_11

    .line 949
    .line 950
    :catch_2a
    :goto_29
    const/16 v23, 0x5

    .line 951
    .line 952
    goto/16 :goto_35

    .line 953
    .line 954
    :catch_2b
    move-exception v0

    .line 955
    move-object/from16 v28, v3

    .line 956
    .line 957
    move-object/from16 v24, v9

    .line 958
    .line 959
    move-object/from16 v26, v15

    .line 960
    .line 961
    goto/16 :goto_12

    .line 962
    .line 963
    :goto_2a
    const/16 v23, 0x5

    .line 964
    .line 965
    goto/16 :goto_37

    .line 966
    .line 967
    :catch_2c
    move-exception v0

    .line 968
    :goto_2b
    move-object/from16 v26, v15

    .line 969
    .line 970
    move-object/from16 v4, v24

    .line 971
    .line 972
    const/4 v8, 0x0

    .line 973
    move-object/from16 v24, v9

    .line 974
    .line 975
    const/16 v23, 0x5

    .line 976
    .line 977
    goto :goto_31

    .line 978
    :catch_2d
    :goto_2c
    move-object/from16 v26, v15

    .line 979
    .line 980
    move-object/from16 v4, v24

    .line 981
    .line 982
    const/4 v8, 0x0

    .line 983
    move-object/from16 v24, v9

    .line 984
    .line 985
    const/16 v23, 0x5

    .line 986
    .line 987
    goto :goto_32

    .line 988
    :catch_2e
    move-exception v0

    .line 989
    :goto_2d
    move-object/from16 v26, v15

    .line 990
    .line 991
    move-object/from16 v4, v24

    .line 992
    .line 993
    const/4 v8, 0x0

    .line 994
    move-object/from16 v24, v9

    .line 995
    .line 996
    const/16 v23, 0x5

    .line 997
    .line 998
    goto :goto_33

    .line 999
    :catch_2f
    move-object/from16 v26, v15

    .line 1000
    .line 1001
    move-object/from16 v4, v24

    .line 1002
    .line 1003
    const/4 v8, 0x0

    .line 1004
    move-object/from16 v24, v9

    .line 1005
    .line 1006
    move/from16 v23, v3

    .line 1007
    .line 1008
    goto :goto_32

    .line 1009
    :catch_30
    move-exception v0

    .line 1010
    move-object/from16 v37, v8

    .line 1011
    .line 1012
    goto :goto_2b

    .line 1013
    :catch_31
    move-object/from16 v37, v8

    .line 1014
    .line 1015
    goto :goto_2c

    .line 1016
    :catch_32
    move-exception v0

    .line 1017
    move-object/from16 v37, v8

    .line 1018
    .line 1019
    goto :goto_2d

    .line 1020
    :catchall_9
    move-exception v0

    .line 1021
    move/from16 v36, v4

    .line 1022
    .line 1023
    goto/16 :goto_9

    .line 1024
    .line 1025
    :catchall_a
    move-exception v0

    .line 1026
    move/from16 v36, v4

    .line 1027
    .line 1028
    move-object/from16 v37, v8

    .line 1029
    .line 1030
    move-object/from16 v26, v15

    .line 1031
    .line 1032
    move-object/from16 v4, v24

    .line 1033
    .line 1034
    const/4 v8, 0x0

    .line 1035
    const/16 v23, 0x5

    .line 1036
    .line 1037
    move-object/from16 v24, v9

    .line 1038
    .line 1039
    const/4 v3, 0x0

    .line 1040
    :goto_2e
    if-eqz v3, :cond_f

    .line 1041
    .line 1042
    :try_start_27
    invoke-interface {v3}, Landroid/database/Cursor;->close()V

    .line 1043
    .line 1044
    .line 1045
    goto :goto_2f

    .line 1046
    :catchall_b
    move-exception v0

    .line 1047
    goto :goto_30

    .line 1048
    :catch_33
    move-exception v0

    .line 1049
    goto :goto_31

    .line 1050
    :catch_34
    move-exception v0

    .line 1051
    goto :goto_33

    .line 1052
    :cond_f
    :goto_2f
    throw v0
    :try_end_27
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_27 .. :try_end_27} :catch_34
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_27 .. :try_end_27} :catch_35
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_27 .. :try_end_27} :catch_33
    .catchall {:try_start_27 .. :try_end_27} :catchall_b

    .line 1053
    :goto_30
    const/4 v11, 0x0

    .line 1054
    goto/16 :goto_39

    .line 1055
    .line 1056
    :goto_31
    const/16 v28, 0x0

    .line 1057
    .line 1058
    goto :goto_34

    .line 1059
    :catch_35
    :goto_32
    const/16 v28, 0x0

    .line 1060
    .line 1061
    goto :goto_35

    .line 1062
    :goto_33
    const/16 v28, 0x0

    .line 1063
    .line 1064
    goto/16 :goto_37

    .line 1065
    .line 1066
    :catchall_c
    move-exception v0

    .line 1067
    const/4 v4, 0x0

    .line 1068
    goto :goto_30

    .line 1069
    :catch_36
    move-exception v0

    .line 1070
    move/from16 v36, v4

    .line 1071
    .line 1072
    move-object/from16 v37, v8

    .line 1073
    .line 1074
    move-object/from16 v24, v9

    .line 1075
    .line 1076
    move-object/from16 v26, v15

    .line 1077
    .line 1078
    const/4 v8, 0x0

    .line 1079
    const/16 v23, 0x5

    .line 1080
    .line 1081
    const/4 v4, 0x0

    .line 1082
    goto :goto_31

    .line 1083
    :goto_34
    if-eqz v4, :cond_10

    .line 1084
    .line 1085
    :try_start_28
    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteDatabase;->inTransaction()Z

    .line 1086
    .line 1087
    .line 1088
    move-result v1

    .line 1089
    if-eqz v1, :cond_10

    .line 1090
    .line 1091
    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 1092
    .line 1093
    .line 1094
    :cond_10
    iget-object v1, v6, Lvp/g1;->i:Lvp/p0;

    .line 1095
    .line 1096
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 1097
    .line 1098
    .line 1099
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 1100
    .line 1101
    invoke-virtual {v1, v0, v14}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1102
    .line 1103
    .line 1104
    const/4 v3, 0x1

    .line 1105
    iput-boolean v3, v13, Lvp/j0;->h:Z
    :try_end_28
    .catchall {:try_start_28 .. :try_end_28} :catchall_d

    .line 1106
    .line 1107
    if-eqz v28, :cond_11

    .line 1108
    .line 1109
    invoke-interface/range {v28 .. v28}, Landroid/database/Cursor;->close()V

    .line 1110
    .line 1111
    .line 1112
    :cond_11
    if-eqz v4, :cond_14

    .line 1113
    .line 1114
    goto :goto_36

    .line 1115
    :catch_37
    move/from16 v36, v4

    .line 1116
    .line 1117
    move-object/from16 v37, v8

    .line 1118
    .line 1119
    move-object/from16 v24, v9

    .line 1120
    .line 1121
    move-object/from16 v26, v15

    .line 1122
    .line 1123
    const/4 v8, 0x0

    .line 1124
    const/16 v23, 0x5

    .line 1125
    .line 1126
    const/4 v4, 0x0

    .line 1127
    goto :goto_32

    .line 1128
    :goto_35
    int-to-long v0, v5

    .line 1129
    :try_start_29
    invoke-static {v0, v1}, Landroid/os/SystemClock;->sleep(J)V
    :try_end_29
    .catchall {:try_start_29 .. :try_end_29} :catchall_d

    .line 1130
    .line 1131
    .line 1132
    add-int/lit8 v5, v5, 0x14

    .line 1133
    .line 1134
    if-eqz v28, :cond_12

    .line 1135
    .line 1136
    invoke-interface/range {v28 .. v28}, Landroid/database/Cursor;->close()V

    .line 1137
    .line 1138
    .line 1139
    :cond_12
    if-eqz v4, :cond_14

    .line 1140
    .line 1141
    :goto_36
    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteClosable;->close()V

    .line 1142
    .line 1143
    .line 1144
    goto :goto_38

    .line 1145
    :catchall_d
    move-exception v0

    .line 1146
    goto/16 :goto_27

    .line 1147
    .line 1148
    :catch_38
    move-exception v0

    .line 1149
    move/from16 v36, v4

    .line 1150
    .line 1151
    move-object/from16 v37, v8

    .line 1152
    .line 1153
    move-object/from16 v24, v9

    .line 1154
    .line 1155
    move-object/from16 v26, v15

    .line 1156
    .line 1157
    const/4 v8, 0x0

    .line 1158
    const/16 v23, 0x5

    .line 1159
    .line 1160
    const/4 v4, 0x0

    .line 1161
    goto :goto_33

    .line 1162
    :goto_37
    :try_start_2a
    iget-object v1, v6, Lvp/g1;->i:Lvp/p0;

    .line 1163
    .line 1164
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 1165
    .line 1166
    .line 1167
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 1168
    .line 1169
    invoke-virtual {v1, v0, v14}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1170
    .line 1171
    .line 1172
    const/4 v3, 0x1

    .line 1173
    iput-boolean v3, v13, Lvp/j0;->h:Z
    :try_end_2a
    .catchall {:try_start_2a .. :try_end_2a} :catchall_d

    .line 1174
    .line 1175
    if-eqz v28, :cond_13

    .line 1176
    .line 1177
    invoke-interface/range {v28 .. v28}, Landroid/database/Cursor;->close()V

    .line 1178
    .line 1179
    .line 1180
    :cond_13
    if-eqz v4, :cond_14

    .line 1181
    .line 1182
    goto :goto_36

    .line 1183
    :cond_14
    :goto_38
    add-int/lit8 v4, v36, 0x1

    .line 1184
    .line 1185
    move/from16 v3, v23

    .line 1186
    .line 1187
    move-object/from16 v9, v24

    .line 1188
    .line 1189
    move-object/from16 v15, v26

    .line 1190
    .line 1191
    move-object/from16 v8, v37

    .line 1192
    .line 1193
    goto/16 :goto_3

    .line 1194
    .line 1195
    :goto_39
    if-eqz v11, :cond_15

    .line 1196
    .line 1197
    invoke-interface {v11}, Landroid/database/Cursor;->close()V

    .line 1198
    .line 1199
    .line 1200
    :cond_15
    if-eqz v4, :cond_16

    .line 1201
    .line 1202
    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteClosable;->close()V

    .line 1203
    .line 1204
    .line 1205
    :cond_16
    throw v0

    .line 1206
    :cond_17
    const/4 v8, 0x0

    .line 1207
    iget-object v0, v6, Lvp/g1;->i:Lvp/p0;

    .line 1208
    .line 1209
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 1210
    .line 1211
    .line 1212
    iget-object v0, v0, Lvp/p0;->m:Lvp/n0;

    .line 1213
    .line 1214
    const-string v1, "Failed to read events from database in reasonable time"

    .line 1215
    .line 1216
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1217
    .line 1218
    .line 1219
    goto/16 :goto_2

    .line 1220
    .line 1221
    :cond_18
    move-object/from16 v21, v4

    .line 1222
    .line 1223
    move-object/from16 v22, v5

    .line 1224
    .line 1225
    const/4 v8, 0x0

    .line 1226
    :goto_3a
    if-eqz v11, :cond_19

    .line 1227
    .line 1228
    invoke-virtual {v12, v11}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 1229
    .line 1230
    .line 1231
    invoke-interface {v11}, Ljava/util/List;->size()I

    .line 1232
    .line 1233
    .line 1234
    move-result v0

    .line 1235
    move v1, v0

    .line 1236
    goto :goto_3b

    .line 1237
    :cond_19
    move v1, v8

    .line 1238
    :goto_3b
    move/from16 v3, p0

    .line 1239
    .line 1240
    if-eqz v2, :cond_1a

    .line 1241
    .line 1242
    if-ge v1, v3, :cond_1a

    .line 1243
    .line 1244
    iget-object v0, v10, Lvp/f4;->f:Ljava/lang/String;

    .line 1245
    .line 1246
    iget-wide v4, v10, Lvp/f4;->m:J

    .line 1247
    .line 1248
    new-instance v6, Lvp/i0;

    .line 1249
    .line 1250
    invoke-direct {v6, v2, v0, v4, v5}, Lvp/i0;-><init>(Loo/a;Ljava/lang/String;J)V

    .line 1251
    .line 1252
    .line 1253
    invoke-virtual {v12, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1254
    .line 1255
    .line 1256
    :cond_1a
    sget-object v0, Lvp/z;->O0:Lvp/y;

    .line 1257
    .line 1258
    const/4 v15, 0x0

    .line 1259
    invoke-virtual {v7, v15, v0}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 1260
    .line 1261
    .line 1262
    move-result v4

    .line 1263
    invoke-virtual {v12}, Ljava/util/ArrayList;->size()I

    .line 1264
    .line 1265
    .line 1266
    move-result v5

    .line 1267
    move v6, v8

    .line 1268
    :goto_3c
    if-ge v6, v5, :cond_25

    .line 1269
    .line 1270
    invoke-virtual {v12, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1271
    .line 1272
    .line 1273
    move-result-object v0

    .line 1274
    check-cast v0, Lvp/i0;

    .line 1275
    .line 1276
    iget-object v9, v0, Lvp/i0;->a:Loo/a;

    .line 1277
    .line 1278
    sget-object v11, Lvp/z;->b1:Lvp/y;

    .line 1279
    .line 1280
    invoke-virtual {v7, v15, v11}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 1281
    .line 1282
    .line 1283
    move-result v13

    .line 1284
    if-eqz v13, :cond_1b

    .line 1285
    .line 1286
    iget-object v13, v0, Lvp/i0;->b:Ljava/lang/String;

    .line 1287
    .line 1288
    invoke-static {v13}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1289
    .line 1290
    .line 1291
    move-result v14

    .line 1292
    if-nez v14, :cond_1b

    .line 1293
    .line 1294
    iget-wide v14, v0, Lvp/i0;->c:J

    .line 1295
    .line 1296
    iget-object v0, v10, Lvp/f4;->d:Ljava/lang/String;

    .line 1297
    .line 1298
    iget-object v3, v10, Lvp/f4;->e:Ljava/lang/String;

    .line 1299
    .line 1300
    iget-object v8, v10, Lvp/f4;->g:Ljava/lang/String;

    .line 1301
    .line 1302
    move-object/from16 v24, v0

    .line 1303
    .line 1304
    move/from16 v63, v1

    .line 1305
    .line 1306
    iget-wide v0, v10, Lvp/f4;->h:J

    .line 1307
    .line 1308
    move-wide/from16 v30, v0

    .line 1309
    .line 1310
    iget-wide v0, v10, Lvp/f4;->i:J

    .line 1311
    .line 1312
    move-wide/from16 v32, v0

    .line 1313
    .line 1314
    iget-object v0, v10, Lvp/f4;->j:Ljava/lang/String;

    .line 1315
    .line 1316
    iget-boolean v1, v10, Lvp/f4;->k:Z

    .line 1317
    .line 1318
    move-object/from16 v34, v0

    .line 1319
    .line 1320
    iget-boolean v0, v10, Lvp/f4;->l:Z

    .line 1321
    .line 1322
    move/from16 v36, v0

    .line 1323
    .line 1324
    iget-object v0, v10, Lvp/f4;->n:Ljava/lang/String;

    .line 1325
    .line 1326
    move-object/from16 v37, v0

    .line 1327
    .line 1328
    move/from16 v35, v1

    .line 1329
    .line 1330
    iget-wide v0, v10, Lvp/f4;->o:J

    .line 1331
    .line 1332
    move-wide/from16 v38, v0

    .line 1333
    .line 1334
    iget v0, v10, Lvp/f4;->p:I

    .line 1335
    .line 1336
    iget-boolean v1, v10, Lvp/f4;->q:Z

    .line 1337
    .line 1338
    move/from16 v40, v0

    .line 1339
    .line 1340
    iget-boolean v0, v10, Lvp/f4;->r:Z

    .line 1341
    .line 1342
    move/from16 v42, v0

    .line 1343
    .line 1344
    iget-object v0, v10, Lvp/f4;->s:Ljava/lang/Boolean;

    .line 1345
    .line 1346
    move-object/from16 v43, v0

    .line 1347
    .line 1348
    move/from16 v41, v1

    .line 1349
    .line 1350
    iget-wide v0, v10, Lvp/f4;->t:J

    .line 1351
    .line 1352
    move-wide/from16 v44, v0

    .line 1353
    .line 1354
    iget-object v0, v10, Lvp/f4;->u:Ljava/util/List;

    .line 1355
    .line 1356
    iget-object v1, v10, Lvp/f4;->v:Ljava/lang/String;

    .line 1357
    .line 1358
    move-object/from16 v46, v0

    .line 1359
    .line 1360
    iget-object v0, v10, Lvp/f4;->w:Ljava/lang/String;

    .line 1361
    .line 1362
    move-object/from16 v48, v0

    .line 1363
    .line 1364
    iget-object v0, v10, Lvp/f4;->x:Ljava/lang/String;

    .line 1365
    .line 1366
    move-object/from16 v49, v0

    .line 1367
    .line 1368
    iget-boolean v0, v10, Lvp/f4;->y:Z

    .line 1369
    .line 1370
    move/from16 v50, v0

    .line 1371
    .line 1372
    move-object/from16 v47, v1

    .line 1373
    .line 1374
    iget-wide v0, v10, Lvp/f4;->z:J

    .line 1375
    .line 1376
    move-wide/from16 v51, v0

    .line 1377
    .line 1378
    iget v0, v10, Lvp/f4;->A:I

    .line 1379
    .line 1380
    iget-object v1, v10, Lvp/f4;->B:Ljava/lang/String;

    .line 1381
    .line 1382
    move/from16 v53, v0

    .line 1383
    .line 1384
    iget v0, v10, Lvp/f4;->C:I

    .line 1385
    .line 1386
    move/from16 v55, v0

    .line 1387
    .line 1388
    move-object/from16 v54, v1

    .line 1389
    .line 1390
    iget-wide v0, v10, Lvp/f4;->D:J

    .line 1391
    .line 1392
    move-wide/from16 v56, v0

    .line 1393
    .line 1394
    iget-object v0, v10, Lvp/f4;->E:Ljava/lang/String;

    .line 1395
    .line 1396
    iget-object v1, v10, Lvp/f4;->F:Ljava/lang/String;

    .line 1397
    .line 1398
    move-object/from16 v58, v0

    .line 1399
    .line 1400
    move-object/from16 v59, v1

    .line 1401
    .line 1402
    iget-wide v0, v10, Lvp/f4;->G:J

    .line 1403
    .line 1404
    iget v10, v10, Lvp/f4;->H:I

    .line 1405
    .line 1406
    new-instance v23, Lvp/f4;

    .line 1407
    .line 1408
    move-wide/from16 v60, v0

    .line 1409
    .line 1410
    move-object/from16 v25, v3

    .line 1411
    .line 1412
    move-object/from16 v29, v8

    .line 1413
    .line 1414
    move/from16 v62, v10

    .line 1415
    .line 1416
    move-object/from16 v26, v13

    .line 1417
    .line 1418
    move-wide/from16 v27, v14

    .line 1419
    .line 1420
    invoke-direct/range {v23 .. v62}, Lvp/f4;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;JJLjava/lang/String;ZZLjava/lang/String;JIZZLjava/lang/Boolean;JLjava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJILjava/lang/String;IJLjava/lang/String;Ljava/lang/String;JI)V

    .line 1421
    .line 1422
    .line 1423
    move-object/from16 v10, v23

    .line 1424
    .line 1425
    goto :goto_3d

    .line 1426
    :cond_1b
    move/from16 v63, v1

    .line 1427
    .line 1428
    :goto_3d
    instance-of v0, v9, Lvp/t;

    .line 1429
    .line 1430
    if-eqz v0, :cond_21

    .line 1431
    .line 1432
    if-eqz v4, :cond_1c

    .line 1433
    .line 1434
    :try_start_2b
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1435
    .line 1436
    .line 1437
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 1438
    .line 1439
    .line 1440
    move-result-wide v13
    :try_end_2b
    .catch Landroid/os/RemoteException; {:try_start_2b .. :try_end_2b} :catch_3a

    .line 1441
    :try_start_2c
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1442
    .line 1443
    .line 1444
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 1445
    .line 1446
    .line 1447
    move-result-wide v0
    :try_end_2c
    .catch Landroid/os/RemoteException; {:try_start_2c .. :try_end_2c} :catch_39

    .line 1448
    move-wide/from16 v24, v13

    .line 1449
    .line 1450
    move-wide v13, v0

    .line 1451
    goto :goto_3f

    .line 1452
    :catch_39
    move-exception v0

    .line 1453
    move-object/from16 v1, p1

    .line 1454
    .line 1455
    move/from16 v30, v5

    .line 1456
    .line 1457
    move-wide/from16 v24, v13

    .line 1458
    .line 1459
    move-wide/from16 v13, v18

    .line 1460
    .line 1461
    :goto_3e
    move-object/from16 v8, v20

    .line 1462
    .line 1463
    move-object/from16 v15, v21

    .line 1464
    .line 1465
    move-object/from16 v3, v22

    .line 1466
    .line 1467
    move/from16 v22, v4

    .line 1468
    .line 1469
    goto/16 :goto_44

    .line 1470
    .line 1471
    :catch_3a
    move-exception v0

    .line 1472
    move-object/from16 v1, p1

    .line 1473
    .line 1474
    move/from16 v30, v5

    .line 1475
    .line 1476
    move-wide/from16 v13, v18

    .line 1477
    .line 1478
    move-wide/from16 v24, v13

    .line 1479
    .line 1480
    goto :goto_3e

    .line 1481
    :cond_1c
    move-wide/from16 v13, v18

    .line 1482
    .line 1483
    move-wide/from16 v24, v13

    .line 1484
    .line 1485
    :goto_3f
    :try_start_2d
    check-cast v9, Lvp/t;
    :try_end_2d
    .catch Landroid/os/RemoteException; {:try_start_2d .. :try_end_2d} :catch_40

    .line 1486
    .line 1487
    move-object/from16 v1, p1

    .line 1488
    .line 1489
    :try_start_2e
    invoke-interface {v1, v9, v10}, Lvp/c0;->o(Lvp/t;Lvp/f4;)V

    .line 1490
    .line 1491
    .line 1492
    if-eqz v4, :cond_1f

    .line 1493
    .line 1494
    invoke-static/range {v22 .. v22}, Lvp/g1;->k(Lvp/n1;)V
    :try_end_2e
    .catch Landroid/os/RemoteException; {:try_start_2e .. :try_end_2e} :catch_3f

    .line 1495
    .line 1496
    .line 1497
    move-object/from16 v3, v22

    .line 1498
    .line 1499
    :try_start_2f
    iget-object v0, v3, Lvp/p0;->r:Lvp/n0;

    .line 1500
    .line 1501
    const-string v8, "Logging telemetry for logEvent from database"

    .line 1502
    .line 1503
    invoke-virtual {v0, v8}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1504
    .line 1505
    .line 1506
    sget-object v0, Lrn/i;->h:Lrn/i;
    :try_end_2f
    .catch Landroid/os/RemoteException; {:try_start_2f .. :try_end_2f} :catch_3e

    .line 1507
    .line 1508
    if-nez v0, :cond_1d

    .line 1509
    .line 1510
    :try_start_30
    new-instance v0, Lrn/i;
    :try_end_30
    .catch Landroid/os/RemoteException; {:try_start_30 .. :try_end_30} :catch_3b

    .line 1511
    .line 1512
    move-object/from16 v8, v20

    .line 1513
    .line 1514
    move-object/from16 v15, v21

    .line 1515
    .line 1516
    :try_start_31
    invoke-direct {v0, v15, v8}, Lrn/i;-><init>(Landroid/content/Context;Lvp/g1;)V

    .line 1517
    .line 1518
    .line 1519
    sput-object v0, Lrn/i;->h:Lrn/i;

    .line 1520
    .line 1521
    goto :goto_40

    .line 1522
    :catch_3b
    move-exception v0

    .line 1523
    move-object/from16 v8, v20

    .line 1524
    .line 1525
    move-object/from16 v15, v21

    .line 1526
    .line 1527
    goto :goto_42

    .line 1528
    :cond_1d
    move-object/from16 v8, v20

    .line 1529
    .line 1530
    move-object/from16 v15, v21

    .line 1531
    .line 1532
    :goto_40
    sget-object v23, Lrn/i;->h:Lrn/i;

    .line 1533
    .line 1534
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1535
    .line 1536
    .line 1537
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 1538
    .line 1539
    .line 1540
    move-result-wide v28

    .line 1541
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1542
    .line 1543
    .line 1544
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 1545
    .line 1546
    .line 1547
    move-result-wide v20
    :try_end_31
    .catch Landroid/os/RemoteException; {:try_start_31 .. :try_end_31} :catch_3d

    .line 1548
    move/from16 v22, v4

    .line 1549
    .line 1550
    move/from16 v30, v5

    .line 1551
    .line 1552
    sub-long v4, v20, v13

    .line 1553
    .line 1554
    long-to-int v0, v4

    .line 1555
    const/16 v26, 0x0

    .line 1556
    .line 1557
    move/from16 v27, v0

    .line 1558
    .line 1559
    :try_start_32
    invoke-virtual/range {v23 .. v29}, Lrn/i;->D(JIIJ)V
    :try_end_32
    .catch Landroid/os/RemoteException; {:try_start_32 .. :try_end_32} :catch_3c

    .line 1560
    .line 1561
    .line 1562
    :cond_1e
    :goto_41
    const/4 v4, 0x0

    .line 1563
    goto/16 :goto_45

    .line 1564
    .line 1565
    :catch_3c
    move-exception v0

    .line 1566
    goto :goto_44

    .line 1567
    :catch_3d
    move-exception v0

    .line 1568
    :goto_42
    move/from16 v22, v4

    .line 1569
    .line 1570
    move/from16 v30, v5

    .line 1571
    .line 1572
    goto :goto_44

    .line 1573
    :catch_3e
    move-exception v0

    .line 1574
    move/from16 v22, v4

    .line 1575
    .line 1576
    move/from16 v30, v5

    .line 1577
    .line 1578
    move-object/from16 v8, v20

    .line 1579
    .line 1580
    move-object/from16 v15, v21

    .line 1581
    .line 1582
    goto :goto_44

    .line 1583
    :catch_3f
    move-exception v0

    .line 1584
    :goto_43
    move/from16 v30, v5

    .line 1585
    .line 1586
    goto :goto_3e

    .line 1587
    :cond_1f
    move/from16 v30, v5

    .line 1588
    .line 1589
    move-object/from16 v8, v20

    .line 1590
    .line 1591
    move-object/from16 v15, v21

    .line 1592
    .line 1593
    move-object/from16 v3, v22

    .line 1594
    .line 1595
    move/from16 v22, v4

    .line 1596
    .line 1597
    goto :goto_41

    .line 1598
    :catch_40
    move-exception v0

    .line 1599
    move-object/from16 v1, p1

    .line 1600
    .line 1601
    goto :goto_43

    .line 1602
    :goto_44
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 1603
    .line 1604
    .line 1605
    iget-object v4, v3, Lvp/p0;->j:Lvp/n0;

    .line 1606
    .line 1607
    const-string v5, "Failed to send event to the service"

    .line 1608
    .line 1609
    invoke-virtual {v4, v0, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1610
    .line 1611
    .line 1612
    if-eqz v22, :cond_1e

    .line 1613
    .line 1614
    cmp-long v0, v24, v18

    .line 1615
    .line 1616
    if-eqz v0, :cond_1e

    .line 1617
    .line 1618
    sget-object v0, Lrn/i;->h:Lrn/i;

    .line 1619
    .line 1620
    if-nez v0, :cond_20

    .line 1621
    .line 1622
    new-instance v0, Lrn/i;

    .line 1623
    .line 1624
    invoke-direct {v0, v15, v8}, Lrn/i;-><init>(Landroid/content/Context;Lvp/g1;)V

    .line 1625
    .line 1626
    .line 1627
    sput-object v0, Lrn/i;->h:Lrn/i;

    .line 1628
    .line 1629
    :cond_20
    sget-object v23, Lrn/i;->h:Lrn/i;

    .line 1630
    .line 1631
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1632
    .line 1633
    .line 1634
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 1635
    .line 1636
    .line 1637
    move-result-wide v28

    .line 1638
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1639
    .line 1640
    .line 1641
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 1642
    .line 1643
    .line 1644
    move-result-wide v4

    .line 1645
    sub-long/2addr v4, v13

    .line 1646
    long-to-int v0, v4

    .line 1647
    const/16 v26, 0xd

    .line 1648
    .line 1649
    move/from16 v27, v0

    .line 1650
    .line 1651
    invoke-virtual/range {v23 .. v29}, Lrn/i;->D(JIIJ)V

    .line 1652
    .line 1653
    .line 1654
    goto :goto_41

    .line 1655
    :cond_21
    move-object/from16 v1, p1

    .line 1656
    .line 1657
    move/from16 v30, v5

    .line 1658
    .line 1659
    move-object/from16 v8, v20

    .line 1660
    .line 1661
    move-object/from16 v15, v21

    .line 1662
    .line 1663
    move-object/from16 v3, v22

    .line 1664
    .line 1665
    move/from16 v22, v4

    .line 1666
    .line 1667
    instance-of v0, v9, Lvp/b4;

    .line 1668
    .line 1669
    if-eqz v0, :cond_22

    .line 1670
    .line 1671
    :try_start_33
    check-cast v9, Lvp/b4;

    .line 1672
    .line 1673
    invoke-interface {v1, v9, v10}, Lvp/c0;->P(Lvp/b4;Lvp/f4;)V
    :try_end_33
    .catch Landroid/os/RemoteException; {:try_start_33 .. :try_end_33} :catch_41

    .line 1674
    .line 1675
    .line 1676
    goto :goto_41

    .line 1677
    :catch_41
    move-exception v0

    .line 1678
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 1679
    .line 1680
    .line 1681
    iget-object v4, v3, Lvp/p0;->j:Lvp/n0;

    .line 1682
    .line 1683
    const-string v5, "Failed to send user property to the service"

    .line 1684
    .line 1685
    invoke-virtual {v4, v0, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1686
    .line 1687
    .line 1688
    goto :goto_41

    .line 1689
    :cond_22
    instance-of v0, v9, Lvp/f;

    .line 1690
    .line 1691
    if-eqz v0, :cond_23

    .line 1692
    .line 1693
    :try_start_34
    check-cast v9, Lvp/f;

    .line 1694
    .line 1695
    invoke-interface {v1, v9, v10}, Lvp/c0;->i(Lvp/f;Lvp/f4;)V
    :try_end_34
    .catch Landroid/os/RemoteException; {:try_start_34 .. :try_end_34} :catch_42

    .line 1696
    .line 1697
    .line 1698
    goto/16 :goto_41

    .line 1699
    .line 1700
    :catch_42
    move-exception v0

    .line 1701
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 1702
    .line 1703
    .line 1704
    iget-object v4, v3, Lvp/p0;->j:Lvp/n0;

    .line 1705
    .line 1706
    const-string v5, "Failed to send conditional user property to the service"

    .line 1707
    .line 1708
    invoke-virtual {v4, v0, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1709
    .line 1710
    .line 1711
    goto/16 :goto_41

    .line 1712
    .line 1713
    :cond_23
    const/4 v4, 0x0

    .line 1714
    invoke-virtual {v7, v4, v11}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 1715
    .line 1716
    .line 1717
    move-result v0

    .line 1718
    if-eqz v0, :cond_24

    .line 1719
    .line 1720
    instance-of v0, v9, Lvp/s;

    .line 1721
    .line 1722
    if-eqz v0, :cond_24

    .line 1723
    .line 1724
    :try_start_35
    check-cast v9, Lvp/s;

    .line 1725
    .line 1726
    invoke-virtual {v9}, Lvp/s;->A0()Landroid/os/Bundle;

    .line 1727
    .line 1728
    .line 1729
    move-result-object v0

    .line 1730
    invoke-interface {v1, v0, v10}, Lvp/c0;->N(Landroid/os/Bundle;Lvp/f4;)V
    :try_end_35
    .catch Landroid/os/RemoteException; {:try_start_35 .. :try_end_35} :catch_43

    .line 1731
    .line 1732
    .line 1733
    goto :goto_45

    .line 1734
    :catch_43
    move-exception v0

    .line 1735
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 1736
    .line 1737
    .line 1738
    iget-object v5, v3, Lvp/p0;->j:Lvp/n0;

    .line 1739
    .line 1740
    const-string v9, "Failed to send default event parameters to the service"

    .line 1741
    .line 1742
    invoke-virtual {v5, v0, v9}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1743
    .line 1744
    .line 1745
    goto :goto_45

    .line 1746
    :cond_24
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 1747
    .line 1748
    .line 1749
    iget-object v0, v3, Lvp/p0;->j:Lvp/n0;

    .line 1750
    .line 1751
    const-string v5, "Discarding data. Unrecognized parcel type."

    .line 1752
    .line 1753
    invoke-virtual {v0, v5}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1754
    .line 1755
    .line 1756
    :goto_45
    add-int/lit8 v6, v6, 0x1

    .line 1757
    .line 1758
    move-object/from16 v20, v8

    .line 1759
    .line 1760
    move-object/from16 v21, v15

    .line 1761
    .line 1762
    move/from16 v5, v30

    .line 1763
    .line 1764
    move/from16 v1, v63

    .line 1765
    .line 1766
    const/4 v8, 0x0

    .line 1767
    move-object v15, v4

    .line 1768
    move/from16 v4, v22

    .line 1769
    .line 1770
    move-object/from16 v22, v3

    .line 1771
    .line 1772
    const/16 v3, 0x64

    .line 1773
    .line 1774
    goto/16 :goto_3c

    .line 1775
    .line 1776
    :cond_25
    move/from16 v63, v1

    .line 1777
    .line 1778
    move-object/from16 v8, v20

    .line 1779
    .line 1780
    move-object/from16 v15, v21

    .line 1781
    .line 1782
    move-object/from16 v3, v22

    .line 1783
    .line 1784
    move-object/from16 v1, p1

    .line 1785
    .line 1786
    add-int/lit8 v11, p3, 0x1

    .line 1787
    .line 1788
    move-object v5, v3

    .line 1789
    move-object v3, v8

    .line 1790
    move-object v4, v15

    .line 1791
    move-object/from16 v6, v17

    .line 1792
    .line 1793
    move/from16 v0, v63

    .line 1794
    .line 1795
    const/16 v9, 0x64

    .line 1796
    .line 1797
    goto/16 :goto_0

    .line 1798
    .line 1799
    :cond_26
    return-void
.end method

.method public final t0(Lvp/f;)V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lvp/g1;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Lvp/g1;->n()Lvp/j0;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Lvp/g1;

    .line 21
    .line 22
    iget-object v2, v1, Lvp/g1;->l:Lvp/d4;

    .line 23
    .line 24
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 25
    .line 26
    .line 27
    invoke-static {p1}, Lvp/d4;->E0(Landroid/os/Parcelable;)[B

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    array-length v3, v2

    .line 32
    const/high16 v4, 0x20000

    .line 33
    .line 34
    if-le v3, v4, :cond_0

    .line 35
    .line 36
    iget-object v0, v1, Lvp/g1;->i:Lvp/p0;

    .line 37
    .line 38
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 39
    .line 40
    .line 41
    iget-object v0, v0, Lvp/p0;->k:Lvp/n0;

    .line 42
    .line 43
    const-string v1, "Conditional user property too long for local database. Sending directly to service"

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const/4 v0, 0x0

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    const/4 v1, 0x2

    .line 51
    invoke-virtual {v0, v1, v2}, Lvp/j0;->h0(I[B)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    :goto_0
    new-instance v1, Lvp/f;

    .line 56
    .line 57
    invoke-direct {v1, p1}, Lvp/f;-><init>(Lvp/f;)V

    .line 58
    .line 59
    .line 60
    const/4 p1, 0x1

    .line 61
    invoke-virtual {p0, p1}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    new-instance v2, Lio/j;

    .line 66
    .line 67
    invoke-direct {v2, p0, p1, v0, v1}, Lio/j;-><init>(Lvp/d3;Lvp/f4;ZLvp/f;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p0, v2}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 71
    .line 72
    .line 73
    return-void
.end method
