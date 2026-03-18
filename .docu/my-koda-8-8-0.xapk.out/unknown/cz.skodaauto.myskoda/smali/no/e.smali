.class public abstract Lno/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final x:[Ljo/d;


# instance fields
.field public volatile a:Ljava/lang/String;

.field public b:Lcom/google/android/gms/internal/measurement/i4;

.field public final c:Landroid/content/Context;

.field public final d:Lno/n0;

.field public final e:Ljo/f;

.field public final f:Lno/e0;

.field public final g:Ljava/lang/Object;

.field public final h:Ljava/lang/Object;

.field public i:Lno/y;

.field public j:Lno/d;

.field public k:Landroid/os/IInterface;

.field public final l:Ljava/util/ArrayList;

.field public m:Lno/g0;

.field public n:I

.field public final o:Lno/b;

.field public final p:Lno/c;

.field public final q:I

.field public final r:Ljava/lang/String;

.field public volatile s:Ljava/lang/String;

.field public t:Ljo/b;

.field public u:Z

.field public volatile v:Lno/j0;

.field public final w:Ljava/util/concurrent/atomic/AtomicInteger;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljo/d;

    .line 3
    .line 4
    sput-object v0, Lno/e;->x:[Ljo/d;

    .line 5
    .line 6
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/os/Looper;Lno/n0;Ljo/f;ILno/b;Lno/c;Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lno/e;->a:Ljava/lang/String;

    .line 6
    .line 7
    new-instance v1, Ljava/lang/Object;

    .line 8
    .line 9
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v1, p0, Lno/e;->g:Ljava/lang/Object;

    .line 13
    .line 14
    new-instance v1, Ljava/lang/Object;

    .line 15
    .line 16
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object v1, p0, Lno/e;->h:Ljava/lang/Object;

    .line 20
    .line 21
    new-instance v1, Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object v1, p0, Lno/e;->l:Ljava/util/ArrayList;

    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    iput v1, p0, Lno/e;->n:I

    .line 30
    .line 31
    iput-object v0, p0, Lno/e;->t:Ljo/b;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    iput-boolean v1, p0, Lno/e;->u:Z

    .line 35
    .line 36
    iput-object v0, p0, Lno/e;->v:Lno/j0;

    .line 37
    .line 38
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 39
    .line 40
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 41
    .line 42
    .line 43
    iput-object v0, p0, Lno/e;->w:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 44
    .line 45
    const-string v0, "Context must not be null"

    .line 46
    .line 47
    invoke-static {p1, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    iput-object p1, p0, Lno/e;->c:Landroid/content/Context;

    .line 51
    .line 52
    const-string p1, "Looper must not be null"

    .line 53
    .line 54
    invoke-static {p2, p1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    const-string p1, "Supervisor must not be null"

    .line 58
    .line 59
    invoke-static {p3, p1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    iput-object p3, p0, Lno/e;->d:Lno/n0;

    .line 63
    .line 64
    const-string p1, "API availability must not be null"

    .line 65
    .line 66
    invoke-static {p4, p1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    iput-object p4, p0, Lno/e;->e:Ljo/f;

    .line 70
    .line 71
    new-instance p1, Lno/e0;

    .line 72
    .line 73
    invoke-direct {p1, p0, p2}, Lno/e0;-><init>(Lno/e;Landroid/os/Looper;)V

    .line 74
    .line 75
    .line 76
    iput-object p1, p0, Lno/e;->f:Lno/e0;

    .line 77
    .line 78
    iput p5, p0, Lno/e;->q:I

    .line 79
    .line 80
    iput-object p6, p0, Lno/e;->o:Lno/b;

    .line 81
    .line 82
    iput-object p7, p0, Lno/e;->p:Lno/c;

    .line 83
    .line 84
    iput-object p8, p0, Lno/e;->r:Ljava/lang/String;

    .line 85
    .line 86
    return-void
.end method

.method public static bridge synthetic A(Lno/e;IILandroid/os/IInterface;)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lno/e;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget v1, p0, Lno/e;->n:I

    .line 5
    .line 6
    if-eq v1, p1, :cond_0

    .line 7
    .line 8
    monitor-exit v0

    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-virtual {p0, p2, p3}, Lno/e;->B(ILandroid/os/IInterface;)V

    .line 14
    .line 15
    .line 16
    monitor-exit v0

    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    throw p0
.end method


# virtual methods
.method public final B(ILandroid/os/IInterface;)V
    .locals 10

    .line 1
    const-string v0, "unable to connect to service: "

    .line 2
    .line 3
    const-string v1, "Calling connect() while still connected, missing disconnect() for "

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    const/4 v4, 0x4

    .line 8
    if-eq p1, v4, :cond_0

    .line 9
    .line 10
    move v5, v2

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move v5, v3

    .line 13
    :goto_0
    if-nez p2, :cond_1

    .line 14
    .line 15
    move v6, v2

    .line 16
    goto :goto_1

    .line 17
    :cond_1
    move v6, v3

    .line 18
    :goto_1
    if-ne v5, v6, :cond_2

    .line 19
    .line 20
    move v5, v3

    .line 21
    goto :goto_2

    .line 22
    :cond_2
    move v5, v2

    .line 23
    :goto_2
    invoke-static {v5}, Lno/c0;->a(Z)V

    .line 24
    .line 25
    .line 26
    iget-object v5, p0, Lno/e;->g:Ljava/lang/Object;

    .line 27
    .line 28
    monitor-enter v5

    .line 29
    :try_start_0
    iput p1, p0, Lno/e;->n:I

    .line 30
    .line 31
    iput-object p2, p0, Lno/e;->k:Landroid/os/IInterface;

    .line 32
    .line 33
    const/4 v6, 0x0

    .line 34
    if-eq p1, v3, :cond_d

    .line 35
    .line 36
    const/4 v7, 0x2

    .line 37
    if-eq p1, v7, :cond_4

    .line 38
    .line 39
    const/4 v7, 0x3

    .line 40
    if-eq p1, v7, :cond_4

    .line 41
    .line 42
    if-eq p1, v4, :cond_3

    .line 43
    .line 44
    goto/16 :goto_4

    .line 45
    .line 46
    :cond_3
    invoke-static {p2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 50
    .line 51
    .line 52
    goto/16 :goto_4

    .line 53
    .line 54
    :catchall_0
    move-exception p0

    .line 55
    goto/16 :goto_5

    .line 56
    .line 57
    :cond_4
    iget-object p1, p0, Lno/e;->m:Lno/g0;

    .line 58
    .line 59
    if-eqz p1, :cond_6

    .line 60
    .line 61
    iget-object p2, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 62
    .line 63
    if-eqz p2, :cond_6

    .line 64
    .line 65
    const-string v4, "GmsClient"

    .line 66
    .line 67
    iget-object v7, p2, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v7, Ljava/lang/String;

    .line 70
    .line 71
    iget-object p2, p2, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p2, Ljava/lang/String;

    .line 74
    .line 75
    new-instance v8, Ljava/lang/StringBuilder;

    .line 76
    .line 77
    invoke-direct {v8, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, " on "

    .line 84
    .line 85
    invoke-virtual {v8, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v8, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p2

    .line 95
    invoke-static {v4, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 96
    .line 97
    .line 98
    iget-object p2, p0, Lno/e;->d:Lno/n0;

    .line 99
    .line 100
    iget-object v1, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 101
    .line 102
    iget-object v1, v1, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v1, Ljava/lang/String;

    .line 105
    .line 106
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    iget-object v4, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 110
    .line 111
    iget-object v4, v4, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v4, Ljava/lang/String;

    .line 114
    .line 115
    iget-object v7, p0, Lno/e;->r:Ljava/lang/String;

    .line 116
    .line 117
    if-nez v7, :cond_5

    .line 118
    .line 119
    iget-object v7, p0, Lno/e;->c:Landroid/content/Context;

    .line 120
    .line 121
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 122
    .line 123
    .line 124
    :cond_5
    iget-object v7, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 125
    .line 126
    iget-boolean v7, v7, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 127
    .line 128
    invoke-virtual {p2, v1, v4, p1, v7}, Lno/n0;->c(Ljava/lang/String;Ljava/lang/String;Landroid/content/ServiceConnection;Z)V

    .line 129
    .line 130
    .line 131
    iget-object p1, p0, Lno/e;->w:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 132
    .line 133
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 134
    .line 135
    .line 136
    :cond_6
    new-instance p1, Lno/g0;

    .line 137
    .line 138
    iget-object p2, p0, Lno/e;->w:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 139
    .line 140
    invoke-virtual {p2}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 141
    .line 142
    .line 143
    move-result p2

    .line 144
    invoke-direct {p1, p0, p2}, Lno/g0;-><init>(Lno/e;I)V

    .line 145
    .line 146
    .line 147
    iput-object p1, p0, Lno/e;->m:Lno/g0;

    .line 148
    .line 149
    new-instance p2, Lcom/google/android/gms/internal/measurement/i4;

    .line 150
    .line 151
    invoke-virtual {p0}, Lno/e;->u()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v1

    .line 155
    invoke-virtual {p0}, Lno/e;->t()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v4

    .line 159
    invoke-virtual {p0}, Lno/e;->v()Z

    .line 160
    .line 161
    .line 162
    move-result v7

    .line 163
    invoke-direct {p2, v1, v4, v7}, Lcom/google/android/gms/internal/measurement/i4;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 164
    .line 165
    .line 166
    iput-object p2, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 167
    .line 168
    if-eqz v7, :cond_8

    .line 169
    .line 170
    invoke-virtual {p0}, Lno/e;->j()I

    .line 171
    .line 172
    .line 173
    move-result p2

    .line 174
    const v1, 0x1110e58

    .line 175
    .line 176
    .line 177
    if-lt p2, v1, :cond_7

    .line 178
    .line 179
    goto :goto_3

    .line 180
    :cond_7
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 181
    .line 182
    iget-object p0, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 183
    .line 184
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 185
    .line 186
    check-cast p0, Ljava/lang/String;

    .line 187
    .line 188
    const-string p2, "Internal Error, the minimum apk version of this BaseGmsClient is too low to support dynamic lookup. Start service action: "

    .line 189
    .line 190
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    invoke-virtual {p2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    throw p1

    .line 202
    :cond_8
    :goto_3
    iget-object p2, p0, Lno/e;->d:Lno/n0;

    .line 203
    .line 204
    iget-object v1, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 205
    .line 206
    iget-object v1, v1, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast v1, Ljava/lang/String;

    .line 209
    .line 210
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 211
    .line 212
    .line 213
    iget-object v4, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 214
    .line 215
    iget-object v4, v4, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 216
    .line 217
    check-cast v4, Ljava/lang/String;

    .line 218
    .line 219
    iget-object v7, p0, Lno/e;->r:Ljava/lang/String;

    .line 220
    .line 221
    if-nez v7, :cond_9

    .line 222
    .line 223
    iget-object v7, p0, Lno/e;->c:Landroid/content/Context;

    .line 224
    .line 225
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 226
    .line 227
    .line 228
    move-result-object v7

    .line 229
    invoke-virtual {v7}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v7

    .line 233
    :cond_9
    iget-object v8, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 234
    .line 235
    iget-boolean v8, v8, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 236
    .line 237
    new-instance v9, Lno/k0;

    .line 238
    .line 239
    invoke-direct {v9, v1, v4, v8}, Lno/k0;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {p2, v9, p1, v7, v6}, Lno/n0;->b(Lno/k0;Lno/g0;Ljava/lang/String;Ljava/util/concurrent/Executor;)Ljo/b;

    .line 243
    .line 244
    .line 245
    move-result-object p1

    .line 246
    iget p2, p1, Ljo/b;->e:I

    .line 247
    .line 248
    if-nez p2, :cond_a

    .line 249
    .line 250
    move v2, v3

    .line 251
    :cond_a
    if-nez v2, :cond_f

    .line 252
    .line 253
    const-string p2, "GmsClient"

    .line 254
    .line 255
    iget-object v1, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 256
    .line 257
    iget-object v2, v1, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 258
    .line 259
    check-cast v2, Ljava/lang/String;

    .line 260
    .line 261
    iget-object v1, v1, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 262
    .line 263
    check-cast v1, Ljava/lang/String;

    .line 264
    .line 265
    new-instance v3, Ljava/lang/StringBuilder;

    .line 266
    .line 267
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 271
    .line 272
    .line 273
    const-string v0, " on "

    .line 274
    .line 275
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 276
    .line 277
    .line 278
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 279
    .line 280
    .line 281
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object v0

    .line 285
    invoke-static {p2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 286
    .line 287
    .line 288
    iget p2, p1, Ljo/b;->e:I

    .line 289
    .line 290
    const/4 v0, -0x1

    .line 291
    if-ne p2, v0, :cond_b

    .line 292
    .line 293
    const/16 p2, 0x10

    .line 294
    .line 295
    :cond_b
    iget-object v1, p1, Ljo/b;->f:Landroid/app/PendingIntent;

    .line 296
    .line 297
    if-eqz v1, :cond_c

    .line 298
    .line 299
    new-instance v6, Landroid/os/Bundle;

    .line 300
    .line 301
    invoke-direct {v6}, Landroid/os/Bundle;-><init>()V

    .line 302
    .line 303
    .line 304
    const-string v1, "pendingIntent"

    .line 305
    .line 306
    iget-object p1, p1, Ljo/b;->f:Landroid/app/PendingIntent;

    .line 307
    .line 308
    invoke-virtual {v6, v1, p1}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 309
    .line 310
    .line 311
    :cond_c
    iget-object p1, p0, Lno/e;->w:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 312
    .line 313
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 314
    .line 315
    .line 316
    move-result p1

    .line 317
    new-instance v1, Lno/i0;

    .line 318
    .line 319
    invoke-direct {v1, p0, p2, v6}, Lno/i0;-><init>(Lno/e;ILandroid/os/Bundle;)V

    .line 320
    .line 321
    .line 322
    iget-object p0, p0, Lno/e;->f:Lno/e0;

    .line 323
    .line 324
    const/4 p2, 0x7

    .line 325
    invoke-virtual {p0, p2, p1, v0, v1}, Landroid/os/Handler;->obtainMessage(IIILjava/lang/Object;)Landroid/os/Message;

    .line 326
    .line 327
    .line 328
    move-result-object p1

    .line 329
    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 330
    .line 331
    .line 332
    goto :goto_4

    .line 333
    :cond_d
    iget-object p1, p0, Lno/e;->m:Lno/g0;

    .line 334
    .line 335
    if-eqz p1, :cond_f

    .line 336
    .line 337
    iget-object p2, p0, Lno/e;->d:Lno/n0;

    .line 338
    .line 339
    iget-object v0, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 340
    .line 341
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 342
    .line 343
    check-cast v0, Ljava/lang/String;

    .line 344
    .line 345
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 346
    .line 347
    .line 348
    iget-object v1, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 349
    .line 350
    iget-object v1, v1, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 351
    .line 352
    check-cast v1, Ljava/lang/String;

    .line 353
    .line 354
    iget-object v2, p0, Lno/e;->r:Ljava/lang/String;

    .line 355
    .line 356
    if-nez v2, :cond_e

    .line 357
    .line 358
    iget-object v2, p0, Lno/e;->c:Landroid/content/Context;

    .line 359
    .line 360
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 361
    .line 362
    .line 363
    :cond_e
    iget-object v2, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 364
    .line 365
    iget-boolean v2, v2, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 366
    .line 367
    invoke-virtual {p2, v0, v1, p1, v2}, Lno/n0;->c(Ljava/lang/String;Ljava/lang/String;Landroid/content/ServiceConnection;Z)V

    .line 368
    .line 369
    .line 370
    iput-object v6, p0, Lno/e;->m:Lno/g0;

    .line 371
    .line 372
    :cond_f
    :goto_4
    monitor-exit v5

    .line 373
    return-void

    .line 374
    :goto_5
    monitor-exit v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 375
    throw p0
.end method

.method public final a(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lno/e;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Lno/e;->disconnect()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final b()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lno/e;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget p0, p0, Lno/e;->n:I

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    const/4 v2, 0x1

    .line 8
    if-eq p0, v1, :cond_1

    .line 9
    .line 10
    const/4 v1, 0x3

    .line 11
    if-ne p0, v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 v2, 0x0

    .line 15
    :cond_1
    :goto_0
    monitor-exit v0

    .line 16
    return v2

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    throw p0
.end method

.method public final c()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lno/e;->isConnected()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lno/e;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Ljava/lang/String;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    new-instance p0, Ljava/lang/RuntimeException;

    .line 17
    .line 18
    const-string v0, "Failed to connect when checking package"

    .line 19
    .line 20
    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0
.end method

.method public final d(Lno/j;Ljava/util/Set;)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p2

    .line 4
    .line 5
    invoke-virtual {v1}, Lno/e;->p()Landroid/os/Bundle;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    new-instance v3, Lno/h;

    .line 10
    .line 11
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 12
    .line 13
    const/16 v5, 0x1f

    .line 14
    .line 15
    if-ge v4, v5, :cond_0

    .line 16
    .line 17
    iget-object v4, v1, Lno/e;->s:Ljava/lang/String;

    .line 18
    .line 19
    :goto_0
    move-object/from16 v17, v4

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_0
    iget-object v4, v1, Lno/e;->s:Ljava/lang/String;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :goto_1
    iget v5, v1, Lno/e;->q:I

    .line 26
    .line 27
    sget v6, Ljo/f;->a:I

    .line 28
    .line 29
    sget-object v9, Lno/h;->r:[Lcom/google/android/gms/common/api/Scope;

    .line 30
    .line 31
    new-instance v10, Landroid/os/Bundle;

    .line 32
    .line 33
    invoke-direct {v10}, Landroid/os/Bundle;-><init>()V

    .line 34
    .line 35
    .line 36
    sget-object v12, Lno/h;->s:[Ljo/d;

    .line 37
    .line 38
    const/4 v15, 0x0

    .line 39
    const/16 v16, 0x0

    .line 40
    .line 41
    const/4 v4, 0x6

    .line 42
    const/4 v7, 0x0

    .line 43
    const/4 v8, 0x0

    .line 44
    const/4 v11, 0x0

    .line 45
    const/4 v14, 0x1

    .line 46
    move-object v13, v12

    .line 47
    invoke-direct/range {v3 .. v17}, Lno/h;-><init>(IIILjava/lang/String;Landroid/os/IBinder;[Lcom/google/android/gms/common/api/Scope;Landroid/os/Bundle;Landroid/accounts/Account;[Ljo/d;[Ljo/d;ZIZLjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    iget-object v4, v1, Lno/e;->c:Landroid/content/Context;

    .line 51
    .line 52
    invoke-virtual {v4}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    iput-object v4, v3, Lno/h;->g:Ljava/lang/String;

    .line 57
    .line 58
    iput-object v2, v3, Lno/h;->j:Landroid/os/Bundle;

    .line 59
    .line 60
    if-eqz v0, :cond_1

    .line 61
    .line 62
    const/4 v2, 0x0

    .line 63
    new-array v2, v2, [Lcom/google/android/gms/common/api/Scope;

    .line 64
    .line 65
    invoke-interface {v0, v2}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    check-cast v0, [Lcom/google/android/gms/common/api/Scope;

    .line 70
    .line 71
    iput-object v0, v3, Lno/h;->i:[Lcom/google/android/gms/common/api/Scope;

    .line 72
    .line 73
    :cond_1
    invoke-virtual {v1}, Lno/e;->h()Z

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    if-eqz v0, :cond_3

    .line 78
    .line 79
    invoke-virtual {v1}, Lno/e;->n()Landroid/accounts/Account;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    if-nez v0, :cond_2

    .line 84
    .line 85
    new-instance v0, Landroid/accounts/Account;

    .line 86
    .line 87
    const-string v2, "<<default account>>"

    .line 88
    .line 89
    const-string v4, "com.google"

    .line 90
    .line 91
    invoke-direct {v0, v2, v4}, Landroid/accounts/Account;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    :cond_2
    iput-object v0, v3, Lno/h;->k:Landroid/accounts/Account;

    .line 95
    .line 96
    if-eqz p1, :cond_3

    .line 97
    .line 98
    move-object/from16 v0, p1

    .line 99
    .line 100
    check-cast v0, Lbp/a;

    .line 101
    .line 102
    iget-object v0, v0, Lbp/a;->d:Landroid/os/IBinder;

    .line 103
    .line 104
    iput-object v0, v3, Lno/h;->h:Landroid/os/IBinder;

    .line 105
    .line 106
    :cond_3
    sget-object v0, Lno/e;->x:[Ljo/d;

    .line 107
    .line 108
    iput-object v0, v3, Lno/h;->l:[Ljo/d;

    .line 109
    .line 110
    invoke-virtual {v1}, Lno/e;->o()[Ljo/d;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    iput-object v0, v3, Lno/h;->m:[Ljo/d;

    .line 115
    .line 116
    invoke-virtual {v1}, Lno/e;->z()Z

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    if-eqz v0, :cond_4

    .line 121
    .line 122
    const/4 v0, 0x1

    .line 123
    iput-boolean v0, v3, Lno/h;->p:Z

    .line 124
    .line 125
    :cond_4
    :try_start_0
    iget-object v2, v1, Lno/e;->h:Ljava/lang/Object;

    .line 126
    .line 127
    monitor-enter v2
    :try_end_0
    .catch Landroid/os/DeadObjectException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 128
    :try_start_1
    iget-object v0, v1, Lno/e;->i:Lno/y;

    .line 129
    .line 130
    if-eqz v0, :cond_5

    .line 131
    .line 132
    new-instance v4, Lno/f0;

    .line 133
    .line 134
    iget-object v5, v1, Lno/e;->w:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 135
    .line 136
    invoke-virtual {v5}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 137
    .line 138
    .line 139
    move-result v5

    .line 140
    invoke-direct {v4, v1, v5}, Lno/f0;-><init>(Lno/e;I)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v0, v4, v3}, Lno/y;->a(Lno/f0;Lno/h;)V

    .line 144
    .line 145
    .line 146
    goto :goto_2

    .line 147
    :catchall_0
    move-exception v0

    .line 148
    goto :goto_3

    .line 149
    :cond_5
    const-string v0, "GmsClient"

    .line 150
    .line 151
    const-string v3, "mServiceBroker is null, client disconnected"

    .line 152
    .line 153
    invoke-static {v0, v3}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 154
    .line 155
    .line 156
    :goto_2
    monitor-exit v2

    .line 157
    return-void

    .line 158
    :goto_3
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 159
    :try_start_2
    throw v0
    :try_end_2
    .catch Landroid/os/DeadObjectException; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ljava/lang/SecurityException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Landroid/os/RemoteException; {:try_start_2 .. :try_end_2} :catch_0
    .catch Ljava/lang/RuntimeException; {:try_start_2 .. :try_end_2} :catch_0

    .line 160
    :catch_0
    move-exception v0

    .line 161
    goto :goto_4

    .line 162
    :catch_1
    move-exception v0

    .line 163
    goto :goto_5

    .line 164
    :goto_4
    const-string v2, "GmsClient"

    .line 165
    .line 166
    const-string v3, "IGmsServiceBroker.getService failed"

    .line 167
    .line 168
    invoke-static {v2, v3, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 169
    .line 170
    .line 171
    iget-object v0, v1, Lno/e;->w:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 172
    .line 173
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 174
    .line 175
    .line 176
    move-result v0

    .line 177
    const/16 v2, 0x8

    .line 178
    .line 179
    const/4 v3, 0x0

    .line 180
    invoke-virtual {v1, v2, v3, v3, v0}, Lno/e;->x(ILandroid/os/IBinder;Landroid/os/Bundle;I)V

    .line 181
    .line 182
    .line 183
    return-void

    .line 184
    :catch_2
    move-exception v0

    .line 185
    throw v0

    .line 186
    :goto_5
    const-string v2, "GmsClient"

    .line 187
    .line 188
    const-string v3, "IGmsServiceBroker.getService failed"

    .line 189
    .line 190
    invoke-static {v2, v3, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 191
    .line 192
    .line 193
    iget-object v0, v1, Lno/e;->w:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 194
    .line 195
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 196
    .line 197
    .line 198
    move-result v0

    .line 199
    iget-object v1, v1, Lno/e;->f:Lno/e0;

    .line 200
    .line 201
    const/4 v2, 0x6

    .line 202
    const/4 v3, 0x3

    .line 203
    invoke-virtual {v1, v2, v0, v3}, Landroid/os/Handler;->obtainMessage(III)Landroid/os/Message;

    .line 204
    .line 205
    .line 206
    move-result-object v0

    .line 207
    invoke-virtual {v1, v0}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 208
    .line 209
    .line 210
    return-void
.end method

.method public final disconnect()V
    .locals 5

    .line 1
    iget-object v0, p0, Lno/e;->w:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lno/e;->l:Ljava/util/ArrayList;

    .line 7
    .line 8
    monitor-enter v0

    .line 9
    :try_start_0
    iget-object v1, p0, Lno/e;->l:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const/4 v2, 0x0

    .line 16
    :goto_0
    const/4 v3, 0x0

    .line 17
    if-ge v2, v1, :cond_0

    .line 18
    .line 19
    iget-object v4, p0, Lno/e;->l:Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    check-cast v4, Lno/w;

    .line 26
    .line 27
    monitor-enter v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 28
    :try_start_1
    iput-object v3, v4, Lno/w;->a:Ljava/lang/Boolean;

    .line 29
    .line 30
    monitor-exit v4

    .line 31
    add-int/lit8 v2, v2, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    monitor-exit v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    :try_start_2
    throw p0

    .line 37
    :catchall_1
    move-exception p0

    .line 38
    goto :goto_1

    .line 39
    :cond_0
    iget-object v1, p0, Lno/e;->l:Ljava/util/ArrayList;

    .line 40
    .line 41
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 42
    .line 43
    .line 44
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 45
    iget-object v1, p0, Lno/e;->h:Ljava/lang/Object;

    .line 46
    .line 47
    monitor-enter v1

    .line 48
    :try_start_3
    iput-object v3, p0, Lno/e;->i:Lno/y;

    .line 49
    .line 50
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 51
    const/4 v0, 0x1

    .line 52
    invoke-virtual {p0, v0, v3}, Lno/e;->B(ILandroid/os/IInterface;)V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :catchall_2
    move-exception p0

    .line 57
    :try_start_4
    monitor-exit v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 58
    throw p0

    .line 59
    :goto_1
    :try_start_5
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 60
    throw p0
.end method

.method public e(Lno/d;)V
    .locals 1

    .line 1
    iput-object p1, p0, Lno/e;->j:Lno/d;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-virtual {p0, p1, v0}, Lno/e;->B(ILandroid/os/IInterface;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final f(Lhu/q;)V
    .locals 2

    .line 1
    iget-object p0, p1, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Llo/s;

    .line 4
    .line 5
    iget-object p0, p0, Llo/s;->o:Llo/g;

    .line 6
    .line 7
    iget-object p0, p0, Llo/g;->q:Lbp/c;

    .line 8
    .line 9
    new-instance v0, Laq/p;

    .line 10
    .line 11
    const/16 v1, 0x10

    .line 12
    .line 13
    invoke-direct {v0, p1, v1}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public g()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public h()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final isConnected()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lno/e;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget p0, p0, Lno/e;->n:I

    .line 5
    .line 6
    const/4 v1, 0x4

    .line 7
    if-ne p0, v1, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    :goto_0
    monitor-exit v0

    .line 13
    return p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public abstract j()I
.end method

.method public final k()[Ljo/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lno/e;->v:Lno/j0;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return-object p0

    .line 7
    :cond_0
    iget-object p0, p0, Lno/j0;->e:[Ljo/d;

    .line 8
    .line 9
    return-object p0
.end method

.method public final l()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lno/e;->a:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public abstract m(Landroid/os/IBinder;)Landroid/os/IInterface;
.end method

.method public n()Landroid/accounts/Account;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public o()[Ljo/d;
    .locals 0

    .line 1
    sget-object p0, Lno/e;->x:[Ljo/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public p()Landroid/os/Bundle;
    .locals 0

    .line 1
    new-instance p0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public q()Ljava/util/Set;
    .locals 0

    .line 1
    sget-object p0, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public final r()Landroid/os/IInterface;
    .locals 3

    .line 1
    iget-object v0, p0, Lno/e;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget v1, p0, Lno/e;->n:I

    .line 5
    .line 6
    const/4 v2, 0x5

    .line 7
    if-eq v1, v2, :cond_1

    .line 8
    .line 9
    invoke-virtual {p0}, Lno/e;->isConnected()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lno/e;->k:Landroid/os/IInterface;

    .line 16
    .line 17
    const-string v1, "Client is connected but service is null"

    .line 18
    .line 19
    invoke-static {p0, v1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    monitor-exit v0

    .line 23
    return-object p0

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string v1, "Not connected. Call connect() and wait for onConnected() to be called."

    .line 29
    .line 30
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    new-instance p0, Landroid/os/DeadObjectException;

    .line 35
    .line 36
    invoke-direct {p0}, Landroid/os/DeadObjectException;-><init>()V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 41
    throw p0
.end method

.method public abstract s()Ljava/lang/String;
.end method

.method public abstract t()Ljava/lang/String;
.end method

.method public u()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "com.google.android.gms"

    .line 2
    .line 3
    return-object p0
.end method

.method public v()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lno/e;->j()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const v0, 0xc9e4920

    .line 6
    .line 7
    .line 8
    if-lt p0, v0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0
.end method

.method public w()V
    .locals 0

    .line 1
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public x(ILandroid/os/IBinder;Landroid/os/Bundle;I)V
    .locals 1

    .line 1
    new-instance v0, Lno/h0;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1, p2, p3}, Lno/h0;-><init>(Lno/e;ILandroid/os/IBinder;Landroid/os/Bundle;)V

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x1

    .line 7
    const/4 p2, -0x1

    .line 8
    iget-object p0, p0, Lno/e;->f:Lno/e0;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p4, p2, v0}, Landroid/os/Handler;->obtainMessage(IIILjava/lang/Object;)Landroid/os/Message;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final y(Lno/d;ILandroid/app/PendingIntent;)V
    .locals 1

    .line 1
    iput-object p1, p0, Lno/e;->j:Lno/d;

    .line 2
    .line 3
    iget-object p1, p0, Lno/e;->w:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    const/4 v0, 0x3

    .line 10
    iget-object p0, p0, Lno/e;->f:Lno/e0;

    .line 11
    .line 12
    invoke-virtual {p0, v0, p1, p2, p3}, Landroid/os/Handler;->obtainMessage(IIILjava/lang/Object;)Landroid/os/Message;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public z()Z
    .locals 0

    .line 1
    instance-of p0, p0, Lro/i;

    .line 2
    .line 3
    return p0
.end method
