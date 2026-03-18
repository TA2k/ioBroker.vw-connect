.class public final Lcom/google/firebase/messaging/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final e:J

.field public final f:Ljava/lang/Object;

.field public final g:Ljava/lang/Object;

.field public final h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lcom/google/firebase/messaging/FirebaseMessaging;J)V
    .locals 9

    const/4 v0, 0x0

    iput v0, p0, Lcom/google/firebase/messaging/z;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    new-instance v1, Ljava/util/concurrent/ThreadPoolExecutor;

    sget-object v6, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    new-instance v7, Ljava/util/concurrent/LinkedBlockingQueue;

    invoke-direct {v7}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>()V

    new-instance v8, Luo/a;

    const-string v0, "firebase-iid-executor"

    invoke-direct {v8, v0}, Luo/a;-><init>(Ljava/lang/String;)V

    const/4 v2, 0x0

    const/4 v3, 0x1

    const-wide/16 v4, 0x1e

    invoke-direct/range {v1 .. v8}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;Ljava/util/concurrent/ThreadFactory;)V

    iput-object v1, p0, Lcom/google/firebase/messaging/z;->h:Ljava/lang/Object;

    .line 5
    iput-object p1, p0, Lcom/google/firebase/messaging/z;->g:Ljava/lang/Object;

    .line 6
    iput-wide p2, p0, Lcom/google/firebase/messaging/z;->e:J

    .line 7
    iget-object p1, p1, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 8
    const-string p2, "power"

    invoke-virtual {p1, p2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/os/PowerManager;

    const/4 p2, 0x1

    .line 9
    const-string p3, "fiid-sync"

    invoke-virtual {p1, p2, p3}, Landroid/os/PowerManager;->newWakeLock(ILjava/lang/String;)Landroid/os/PowerManager$WakeLock;

    move-result-object p1

    iput-object p1, p0, Lcom/google/firebase/messaging/z;->f:Ljava/lang/Object;

    const/4 p0, 0x0

    .line 10
    invoke-virtual {p1, p0}, Landroid/os/PowerManager$WakeLock;->setReferenceCounted(Z)V

    return-void
.end method

.method public synthetic constructor <init>(Ljp/vg;Ljp/u0;JLj1/a;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lcom/google/firebase/messaging/z;->d:I

    sget-object v0, Ljp/bc;->e:Ljp/bc;

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/z;->f:Ljava/lang/Object;

    iput-object p2, p0, Lcom/google/firebase/messaging/z;->g:Ljava/lang/Object;

    iput-wide p3, p0, Lcom/google/firebase/messaging/z;->e:J

    iput-object p5, p0, Lcom/google/firebase/messaging/z;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Llp/lg;Llp/r1;JLpv/g;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lcom/google/firebase/messaging/z;->d:I

    sget-object v0, Llp/ub;->e:Llp/ub;

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/z;->f:Ljava/lang/Object;

    iput-object p2, p0, Lcom/google/firebase/messaging/z;->g:Ljava/lang/Object;

    iput-wide p3, p0, Lcom/google/firebase/messaging/z;->e:J

    iput-object p5, p0, Lcom/google/firebase/messaging/z;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/firebase/messaging/z;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 6
    .line 7
    const-string v0, "connectivity"

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Landroid/net/ConnectivityManager;

    .line 14
    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    :goto_0
    if-eqz p0, :cond_1

    .line 24
    .line 25
    invoke-virtual {p0}, Landroid/net/NetworkInfo;->isConnected()Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    if-eqz p0, :cond_1

    .line 30
    .line 31
    const/4 p0, 0x1

    .line 32
    return p0

    .line 33
    :cond_1
    const/4 p0, 0x0

    .line 34
    return p0
.end method

.method public b()Z
    .locals 4

    .line 1
    const-string v0, "FirebaseMessaging"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/google/firebase/messaging/z;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->a()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    const-string p0, "Token retrieval failed: null"

    .line 15
    .line 16
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 17
    .line 18
    .line 19
    return v1

    .line 20
    :catch_0
    move-exception p0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p0, 0x3

    .line 23
    invoke-static {v0, p0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-eqz p0, :cond_1

    .line 28
    .line 29
    const-string p0, "Token successfully retrieved"

    .line 30
    .line 31
    invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_1

    .line 32
    .line 33
    .line 34
    :cond_1
    const/4 p0, 0x1

    .line 35
    return p0

    .line 36
    :catch_1
    const-string p0, "Token retrieval failed with SecurityException. Will retry token retrieval"

    .line 37
    .line 38
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 39
    .line 40
    .line 41
    return v1

    .line 42
    :goto_0
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    const-string v3, "SERVICE_NOT_AVAILABLE"

    .line 47
    .line 48
    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v3

    .line 52
    if-nez v3, :cond_4

    .line 53
    .line 54
    const-string v3, "INTERNAL_SERVER_ERROR"

    .line 55
    .line 56
    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    if-nez v3, :cond_4

    .line 61
    .line 62
    const-string v3, "InternalServerError"

    .line 63
    .line 64
    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-eqz v2, :cond_2

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    if-nez v2, :cond_3

    .line 76
    .line 77
    const-string p0, "Token retrieval failed without exception message. Will retry token retrieval"

    .line 78
    .line 79
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 80
    .line 81
    .line 82
    return v1

    .line 83
    :cond_3
    throw p0

    .line 84
    :cond_4
    :goto_1
    new-instance v2, Ljava/lang/StringBuilder;

    .line 85
    .line 86
    const-string v3, "Token retrieval failed: "

    .line 87
    .line 88
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    const-string p0, ". Will retry token retrieval"

    .line 99
    .line 100
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 108
    .line 109
    .line 110
    return v1
.end method

.method public final run()V
    .locals 9

    .line 1
    iget v0, p0, Lcom/google/firebase/messaging/z;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/firebase/messaging/z;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Llp/lg;

    .line 9
    .line 10
    sget-object v1, Llp/ub;->v2:Llp/ub;

    .line 11
    .line 12
    iget-object v2, p0, Lcom/google/firebase/messaging/z;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Llp/r1;

    .line 15
    .line 16
    iget-wide v3, p0, Lcom/google/firebase/messaging/z;->e:J

    .line 17
    .line 18
    iget-object p0, p0, Lcom/google/firebase/messaging/z;->h:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lpv/g;

    .line 21
    .line 22
    iget-object v5, v0, Llp/lg;->j:Ljava/util/HashMap;

    .line 23
    .line 24
    invoke-virtual {v5, v1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v6

    .line 28
    if-nez v6, :cond_1

    .line 29
    .line 30
    new-instance v6, Llp/f;

    .line 31
    .line 32
    new-instance v7, Llp/j;

    .line 33
    .line 34
    invoke-direct {v7}, Llp/j;-><init>()V

    .line 35
    .line 36
    .line 37
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v7}, Llp/j;->isEmpty()Z

    .line 41
    .line 42
    .line 43
    move-result v8

    .line 44
    if-eqz v8, :cond_0

    .line 45
    .line 46
    iput-object v7, v6, Llp/f;->f:Llp/j;

    .line 47
    .line 48
    invoke-virtual {v5, v1, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 53
    .line 54
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_1
    :goto_0
    invoke-virtual {v5, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    check-cast v5, Llp/f;

    .line 63
    .line 64
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    iget-object v4, v5, Llp/f;->f:Llp/j;

    .line 69
    .line 70
    invoke-virtual {v4, v2}, Llp/j;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    check-cast v5, Ljava/util/Collection;

    .line 75
    .line 76
    if-nez v5, :cond_3

    .line 77
    .line 78
    new-instance v5, Ljava/util/ArrayList;

    .line 79
    .line 80
    const/4 v6, 0x3

    .line 81
    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    if-eqz v3, :cond_2

    .line 89
    .line 90
    invoke-virtual {v4, v2, v5}, Llp/j;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_2
    new-instance p0, Ljava/lang/AssertionError;

    .line 95
    .line 96
    const-string v0, "New Collection violated the Collection spec"

    .line 97
    .line 98
    invoke-direct {p0, v0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    throw p0

    .line 102
    :cond_3
    invoke-interface {v5, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    :goto_1
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 106
    .line 107
    .line 108
    move-result-wide v2

    .line 109
    invoke-virtual {v0, v1, v2, v3}, Llp/lg;->d(Llp/ub;J)Z

    .line 110
    .line 111
    .line 112
    move-result v4

    .line 113
    if-nez v4, :cond_4

    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_4
    iget-object v4, v0, Llp/lg;->i:Ljava/util/HashMap;

    .line 117
    .line 118
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    invoke-virtual {v4, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    sget-object v1, Lfv/l;->d:Lfv/l;

    .line 126
    .line 127
    new-instance v2, Llr/b;

    .line 128
    .line 129
    invoke-direct {v2, v0, p0}, Llr/b;-><init>(Llp/lg;Lpv/g;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v1, v2}, Lfv/l;->execute(Ljava/lang/Runnable;)V

    .line 133
    .line 134
    .line 135
    :goto_2
    return-void

    .line 136
    :pswitch_0
    iget-object v0, p0, Lcom/google/firebase/messaging/z;->f:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v0, Ljp/vg;

    .line 139
    .line 140
    sget-object v1, Ljp/bc;->r2:Ljp/bc;

    .line 141
    .line 142
    iget-object v2, p0, Lcom/google/firebase/messaging/z;->g:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v2, Ljp/u0;

    .line 145
    .line 146
    iget-wide v3, p0, Lcom/google/firebase/messaging/z;->e:J

    .line 147
    .line 148
    iget-object p0, p0, Lcom/google/firebase/messaging/z;->h:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast p0, Lj1/a;

    .line 151
    .line 152
    iget-object v5, v0, Ljp/vg;->j:Ljava/util/HashMap;

    .line 153
    .line 154
    invoke-virtual {v5, v1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result v6

    .line 158
    if-nez v6, :cond_5

    .line 159
    .line 160
    new-instance v6, Ljp/o;

    .line 161
    .line 162
    invoke-direct {v6}, Ljp/o;-><init>()V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v5, v1, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    :cond_5
    invoke-virtual {v5, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v5

    .line 172
    check-cast v5, Ljp/o;

    .line 173
    .line 174
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 175
    .line 176
    .line 177
    move-result-object v3

    .line 178
    iget-object v4, v5, Ljp/o;->f:Ljp/t;

    .line 179
    .line 180
    invoke-virtual {v4, v2}, Ljp/t;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v5

    .line 184
    check-cast v5, Ljava/util/Collection;

    .line 185
    .line 186
    if-nez v5, :cond_7

    .line 187
    .line 188
    new-instance v5, Ljava/util/ArrayList;

    .line 189
    .line 190
    const/4 v6, 0x3

    .line 191
    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result v3

    .line 198
    if-eqz v3, :cond_6

    .line 199
    .line 200
    invoke-virtual {v4, v2, v5}, Ljp/t;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    goto :goto_3

    .line 204
    :cond_6
    new-instance p0, Ljava/lang/AssertionError;

    .line 205
    .line 206
    const-string v0, "New Collection violated the Collection spec"

    .line 207
    .line 208
    invoke-direct {p0, v0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    throw p0

    .line 212
    :cond_7
    invoke-interface {v5, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 213
    .line 214
    .line 215
    :goto_3
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 216
    .line 217
    .line 218
    move-result-wide v2

    .line 219
    invoke-virtual {v0, v1, v2, v3}, Ljp/vg;->d(Ljp/bc;J)Z

    .line 220
    .line 221
    .line 222
    move-result v4

    .line 223
    if-nez v4, :cond_8

    .line 224
    .line 225
    goto :goto_4

    .line 226
    :cond_8
    iget-object v4, v0, Ljp/vg;->i:Ljava/util/HashMap;

    .line 227
    .line 228
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 229
    .line 230
    .line 231
    move-result-object v2

    .line 232
    invoke-virtual {v4, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    sget-object v1, Lfv/l;->d:Lfv/l;

    .line 236
    .line 237
    new-instance v2, Lk0/g;

    .line 238
    .line 239
    invoke-direct {v2, v0, p0}, Lk0/g;-><init>(Ljp/vg;Lj1/a;)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {v1, v2}, Lfv/l;->execute(Ljava/lang/Runnable;)V

    .line 243
    .line 244
    .line 245
    :goto_4
    return-void

    .line 246
    :pswitch_1
    iget-object v0, p0, Lcom/google/firebase/messaging/z;->f:Ljava/lang/Object;

    .line 247
    .line 248
    check-cast v0, Landroid/os/PowerManager$WakeLock;

    .line 249
    .line 250
    const-string v1, "Topic sync or token retrieval failed on hard failure exceptions: "

    .line 251
    .line 252
    invoke-static {}, Lcom/google/firebase/messaging/w;->k()Lcom/google/firebase/messaging/w;

    .line 253
    .line 254
    .line 255
    move-result-object v2

    .line 256
    iget-object v3, p0, Lcom/google/firebase/messaging/z;->g:Ljava/lang/Object;

    .line 257
    .line 258
    check-cast v3, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 259
    .line 260
    iget-object v4, v3, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 261
    .line 262
    invoke-virtual {v2, v4}, Lcom/google/firebase/messaging/w;->n(Landroid/content/Context;)Z

    .line 263
    .line 264
    .line 265
    move-result v2

    .line 266
    if-eqz v2, :cond_9

    .line 267
    .line 268
    invoke-virtual {v0}, Landroid/os/PowerManager$WakeLock;->acquire()V

    .line 269
    .line 270
    .line 271
    :cond_9
    const/4 v2, 0x0

    .line 272
    :try_start_0
    monitor-enter v3
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 273
    const/4 v4, 0x1

    .line 274
    :try_start_1
    iput-boolean v4, v3, Lcom/google/firebase/messaging/FirebaseMessaging;->i:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_3

    .line 275
    .line 276
    :try_start_2
    monitor-exit v3

    .line 277
    iget-object v4, v3, Lcom/google/firebase/messaging/FirebaseMessaging;->h:Lcom/google/firebase/messaging/r;

    .line 278
    .line 279
    invoke-virtual {v4}, Lcom/google/firebase/messaging/r;->e()Z

    .line 280
    .line 281
    .line 282
    move-result v4

    .line 283
    if-nez v4, :cond_a

    .line 284
    .line 285
    monitor-enter v3
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 286
    :try_start_3
    iput-boolean v2, v3, Lcom/google/firebase/messaging/FirebaseMessaging;->i:Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 287
    .line 288
    :try_start_4
    monitor-exit v3
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 289
    invoke-static {}, Lcom/google/firebase/messaging/w;->k()Lcom/google/firebase/messaging/w;

    .line 290
    .line 291
    .line 292
    move-result-object p0

    .line 293
    iget-object v1, v3, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 294
    .line 295
    invoke-virtual {p0, v1}, Lcom/google/firebase/messaging/w;->n(Landroid/content/Context;)Z

    .line 296
    .line 297
    .line 298
    move-result p0

    .line 299
    if-eqz p0, :cond_d

    .line 300
    .line 301
    :goto_5
    invoke-virtual {v0}, Landroid/os/PowerManager$WakeLock;->release()V

    .line 302
    .line 303
    .line 304
    goto/16 :goto_8

    .line 305
    .line 306
    :catchall_0
    move-exception p0

    .line 307
    :try_start_5
    monitor-exit v3
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 308
    :try_start_6
    throw p0

    .line 309
    :cond_a
    invoke-static {}, Lcom/google/firebase/messaging/w;->k()Lcom/google/firebase/messaging/w;

    .line 310
    .line 311
    .line 312
    move-result-object v4

    .line 313
    iget-object v5, v3, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 314
    .line 315
    invoke-virtual {v4, v5}, Lcom/google/firebase/messaging/w;->m(Landroid/content/Context;)Z

    .line 316
    .line 317
    .line 318
    move-result v4

    .line 319
    if-eqz v4, :cond_b

    .line 320
    .line 321
    invoke-virtual {p0}, Lcom/google/firebase/messaging/z;->a()Z

    .line 322
    .line 323
    .line 324
    move-result v4

    .line 325
    if-nez v4, :cond_b

    .line 326
    .line 327
    new-instance v4, Lcom/google/firebase/messaging/y;

    .line 328
    .line 329
    invoke-direct {v4}, Lcom/google/firebase/messaging/y;-><init>()V

    .line 330
    .line 331
    .line 332
    iput-object p0, v4, Lcom/google/firebase/messaging/y;->c:Ljava/lang/Object;

    .line 333
    .line 334
    invoke-virtual {v4}, Lcom/google/firebase/messaging/y;->a()V
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 335
    .line 336
    .line 337
    invoke-static {}, Lcom/google/firebase/messaging/w;->k()Lcom/google/firebase/messaging/w;

    .line 338
    .line 339
    .line 340
    move-result-object p0

    .line 341
    iget-object v1, v3, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 342
    .line 343
    invoke-virtual {p0, v1}, Lcom/google/firebase/messaging/w;->n(Landroid/content/Context;)Z

    .line 344
    .line 345
    .line 346
    move-result p0

    .line 347
    if-eqz p0, :cond_d

    .line 348
    .line 349
    goto :goto_5

    .line 350
    :catchall_1
    move-exception p0

    .line 351
    goto :goto_9

    .line 352
    :catch_0
    move-exception p0

    .line 353
    goto :goto_7

    .line 354
    :cond_b
    :try_start_7
    invoke-virtual {p0}, Lcom/google/firebase/messaging/z;->b()Z

    .line 355
    .line 356
    .line 357
    move-result v4

    .line 358
    if-eqz v4, :cond_c

    .line 359
    .line 360
    monitor-enter v3
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_0
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 361
    :try_start_8
    iput-boolean v2, v3, Lcom/google/firebase/messaging/FirebaseMessaging;->i:Z
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 362
    .line 363
    :try_start_9
    monitor-exit v3
    :try_end_9
    .catch Ljava/io/IOException; {:try_start_9 .. :try_end_9} :catch_0
    .catchall {:try_start_9 .. :try_end_9} :catchall_1

    .line 364
    goto :goto_6

    .line 365
    :catchall_2
    move-exception p0

    .line 366
    :try_start_a
    monitor-exit v3
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_2

    .line 367
    :try_start_b
    throw p0

    .line 368
    :cond_c
    iget-wide v4, p0, Lcom/google/firebase/messaging/z;->e:J

    .line 369
    .line 370
    invoke-virtual {v3, v4, v5}, Lcom/google/firebase/messaging/FirebaseMessaging;->j(J)V
    :try_end_b
    .catch Ljava/io/IOException; {:try_start_b .. :try_end_b} :catch_0
    .catchall {:try_start_b .. :try_end_b} :catchall_1

    .line 371
    .line 372
    .line 373
    :goto_6
    invoke-static {}, Lcom/google/firebase/messaging/w;->k()Lcom/google/firebase/messaging/w;

    .line 374
    .line 375
    .line 376
    move-result-object p0

    .line 377
    iget-object v1, v3, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 378
    .line 379
    invoke-virtual {p0, v1}, Lcom/google/firebase/messaging/w;->n(Landroid/content/Context;)Z

    .line 380
    .line 381
    .line 382
    move-result p0

    .line 383
    if-eqz p0, :cond_d

    .line 384
    .line 385
    goto :goto_5

    .line 386
    :catchall_3
    move-exception p0

    .line 387
    :try_start_c
    monitor-exit v3
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_3

    .line 388
    :try_start_d
    throw p0
    :try_end_d
    .catch Ljava/io/IOException; {:try_start_d .. :try_end_d} :catch_0
    .catchall {:try_start_d .. :try_end_d} :catchall_1

    .line 389
    :goto_7
    :try_start_e
    const-string v4, "FirebaseMessaging"

    .line 390
    .line 391
    new-instance v5, Ljava/lang/StringBuilder;

    .line 392
    .line 393
    invoke-direct {v5, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 394
    .line 395
    .line 396
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 397
    .line 398
    .line 399
    move-result-object p0

    .line 400
    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 401
    .line 402
    .line 403
    const-string p0, ". Won\'t retry the operation."

    .line 404
    .line 405
    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 406
    .line 407
    .line 408
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 409
    .line 410
    .line 411
    move-result-object p0

    .line 412
    invoke-static {v4, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 413
    .line 414
    .line 415
    monitor-enter v3
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_1

    .line 416
    :try_start_f
    iput-boolean v2, v3, Lcom/google/firebase/messaging/FirebaseMessaging;->i:Z
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_4

    .line 417
    .line 418
    :try_start_10
    monitor-exit v3
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_1

    .line 419
    invoke-static {}, Lcom/google/firebase/messaging/w;->k()Lcom/google/firebase/messaging/w;

    .line 420
    .line 421
    .line 422
    move-result-object p0

    .line 423
    iget-object v1, v3, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 424
    .line 425
    invoke-virtual {p0, v1}, Lcom/google/firebase/messaging/w;->n(Landroid/content/Context;)Z

    .line 426
    .line 427
    .line 428
    move-result p0

    .line 429
    if-eqz p0, :cond_d

    .line 430
    .line 431
    goto/16 :goto_5

    .line 432
    .line 433
    :cond_d
    :goto_8
    return-void

    .line 434
    :catchall_4
    move-exception p0

    .line 435
    :try_start_11
    monitor-exit v3
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_4

    .line 436
    :try_start_12
    throw p0
    :try_end_12
    .catchall {:try_start_12 .. :try_end_12} :catchall_1

    .line 437
    :goto_9
    invoke-static {}, Lcom/google/firebase/messaging/w;->k()Lcom/google/firebase/messaging/w;

    .line 438
    .line 439
    .line 440
    move-result-object v1

    .line 441
    iget-object v2, v3, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 442
    .line 443
    invoke-virtual {v1, v2}, Lcom/google/firebase/messaging/w;->n(Landroid/content/Context;)Z

    .line 444
    .line 445
    .line 446
    move-result v1

    .line 447
    if-eqz v1, :cond_e

    .line 448
    .line 449
    invoke-virtual {v0}, Landroid/os/PowerManager$WakeLock;->release()V

    .line 450
    .line 451
    .line 452
    :cond_e
    throw p0

    .line 453
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
