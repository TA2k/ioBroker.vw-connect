.class public final synthetic La8/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, La8/y0;->d:I

    iput-object p1, p0, La8/y0;->e:Ljava/lang/Object;

    iput-object p2, p0, La8/y0;->f:Ljava/lang/Object;

    iput-object p3, p0, La8/y0;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lp0/c;Lb0/y;Ly4/h;)V
    .locals 1

    .line 2
    const/16 v0, 0xe

    iput v0, p0, La8/y0;->d:I

    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/y0;->e:Ljava/lang/Object;

    iput-object p2, p0, La8/y0;->f:Ljava/lang/Object;

    iput-object p3, p0, La8/y0;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lq0/e;Lb0/y;Ly4/h;)V
    .locals 1

    .line 3
    const/16 v0, 0x10

    iput v0, p0, La8/y0;->d:I

    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/y0;->e:Ljava/lang/Object;

    iput-object p2, p0, La8/y0;->f:Ljava/lang/Object;

    iput-object p3, p0, La8/y0;->g:Ljava/lang/Object;

    return-void
.end method

.method private final a()V
    .locals 4

    .line 1
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ler/i;

    .line 4
    .line 5
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lkp/m7;

    .line 8
    .line 9
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Ljava/util/concurrent/ThreadPoolExecutor;

    .line 12
    .line 13
    :try_start_0
    iget-object v0, v0, Ler/i;->d:Landroid/content/Context;

    .line 14
    .line 15
    invoke-static {v0}, Lkp/j7;->b(Landroid/content/Context;)Ls6/p;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    iget-object v2, v0, Lka/u;->b:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v2, Ls6/g;

    .line 24
    .line 25
    check-cast v2, Ls6/o;

    .line 26
    .line 27
    iget-object v3, v2, Ls6/o;->g:Ljava/lang/Object;

    .line 28
    .line 29
    monitor-enter v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    :try_start_1
    iput-object p0, v2, Ls6/o;->i:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 31
    .line 32
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 33
    :try_start_2
    iget-object v0, v0, Lka/u;->b:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Ls6/g;

    .line 36
    .line 37
    new-instance v2, Ls6/j;

    .line 38
    .line 39
    invoke-direct {v2, v1, p0}, Ls6/j;-><init>(Lkp/m7;Ljava/util/concurrent/ThreadPoolExecutor;)V

    .line 40
    .line 41
    .line 42
    invoke-interface {v0, v2}, Ls6/g;->a(Lkp/m7;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :catchall_0
    move-exception v0

    .line 47
    goto :goto_0

    .line 48
    :catchall_1
    move-exception v0

    .line 49
    :try_start_3
    monitor-exit v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 50
    :try_start_4
    throw v0

    .line 51
    :cond_0
    new-instance v0, Ljava/lang/RuntimeException;

    .line 52
    .line 53
    const-string v2, "EmojiCompat font provider not available on this device."

    .line 54
    .line 55
    invoke-direct {v0, v2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 59
    :goto_0
    invoke-virtual {v1, v0}, Lkp/m7;->b(Ljava/lang/Throwable;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0}, Ljava/util/concurrent/ThreadPoolExecutor;->shutdown()V

    .line 63
    .line 64
    .line 65
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 15

    .line 1
    iget v0, p0, La8/y0;->d:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x1

    .line 5
    const/4 v3, 0x0

    .line 6
    const/4 v4, 0x0

    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Lyt/h;

    .line 13
    .line 14
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lau/o;

    .line 17
    .line 18
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lau/i;

    .line 21
    .line 22
    invoke-static {}, Lau/t;->y()Lau/s;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v2}, Lcom/google/protobuf/n;->j()V

    .line 27
    .line 28
    .line 29
    iget-object v3, v2, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 30
    .line 31
    check-cast v3, Lau/t;

    .line 32
    .line 33
    invoke-static {v3, v1}, Lau/t;->t(Lau/t;Lau/o;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, v2, p0}, Lyt/h;->d(Lau/s;Lau/i;)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :pswitch_0
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v0, Lpv/g;

    .line 43
    .line 44
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v1, Landroid/view/SurfaceView;

    .line 47
    .line 48
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p0, Lm8/o;

    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    invoke-static {v1}, Lh4/b;->i(Landroid/view/SurfaceView;)Landroid/view/AttachedSurfaceControl;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    if-nez v1, :cond_0

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    invoke-static {}, Lt51/b;->i()Landroid/window/SurfaceSyncGroup;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    iput-object v2, v0, Lpv/g;->e:Ljava/lang/Object;

    .line 67
    .line 68
    new-instance v0, Lu/g;

    .line 69
    .line 70
    invoke-direct {v0, v3}, Lu/g;-><init>(I)V

    .line 71
    .line 72
    .line 73
    invoke-static {v2, v1, v0}, Lt51/b;->v(Landroid/window/SurfaceSyncGroup;Landroid/view/AttachedSurfaceControl;Lu/g;)Z

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p0}, Lm8/o;->run()V

    .line 81
    .line 82
    .line 83
    new-instance p0, Landroid/view/SurfaceControl$Transaction;

    .line 84
    .line 85
    invoke-direct {p0}, Landroid/view/SurfaceControl$Transaction;-><init>()V

    .line 86
    .line 87
    .line 88
    invoke-static {v1, p0}, Lh4/b;->u(Landroid/view/AttachedSurfaceControl;Landroid/view/SurfaceControl$Transaction;)V

    .line 89
    .line 90
    .line 91
    :goto_0
    return-void

    .line 92
    :pswitch_1
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v0, Ly1/f;

    .line 95
    .line 96
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v1, Ly1/d;

    .line 99
    .line 100
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p0, Ly1/e;

    .line 103
    .line 104
    iget-object v3, v0, Ly1/f;->a:Landroid/view/View;

    .line 105
    .line 106
    new-instance v4, Ly1/l;

    .line 107
    .line 108
    invoke-direct {v4, v1}, Ly1/l;-><init>(Ly1/d;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v3, v4, v2}, Landroid/view/View;->startActionMode(Landroid/view/ActionMode$Callback;I)Landroid/view/ActionMode;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    iget-object v0, v0, Ly1/f;->h:Landroid/view/ActionMode;

    .line 116
    .line 117
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    if-nez v1, :cond_1

    .line 121
    .line 122
    invoke-virtual {p0}, Ly1/e;->close()V

    .line 123
    .line 124
    .line 125
    :cond_1
    return-void

    .line 126
    :pswitch_2
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v0, Lb6/f;

    .line 129
    .line 130
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast v1, Lu/k;

    .line 133
    .line 134
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast p0, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 137
    .line 138
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 139
    .line 140
    .line 141
    const-string v2, "RequestMonitor"

    .line 142
    .line 143
    new-instance v3, Ljava/lang/StringBuilder;

    .line 144
    .line 145
    const-string v4, "RequestListener "

    .line 146
    .line 147
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    const-string v1, " done "

    .line 154
    .line 155
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    invoke-static {v2, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 166
    .line 167
    .line 168
    iget-object v0, v0, Lb6/f;->e:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v0, Ljava/util/List;

    .line 171
    .line 172
    invoke-interface {v0, p0}, Ljava/util/List;->remove(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    return-void

    .line 176
    :pswitch_3
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v0, Lcom/google/firebase/perf/session/SessionManager;

    .line 179
    .line 180
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 181
    .line 182
    check-cast v1, Landroid/content/Context;

    .line 183
    .line 184
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 185
    .line 186
    check-cast p0, Lwt/a;

    .line 187
    .line 188
    invoke-static {v0, v1, p0}, Lcom/google/firebase/perf/session/SessionManager;->b(Lcom/google/firebase/perf/session/SessionManager;Landroid/content/Context;Lwt/a;)V

    .line 189
    .line 190
    .line 191
    return-void

    .line 192
    :pswitch_4
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast v0, Lw0/p;

    .line 195
    .line 196
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 197
    .line 198
    check-cast v1, Lb0/x1;

    .line 199
    .line 200
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 201
    .line 202
    check-cast p0, Lbb/i;

    .line 203
    .line 204
    iget-object v0, v0, Lw0/p;->f:Lw0/o;

    .line 205
    .line 206
    invoke-virtual {v0}, Lw0/o;->a()V

    .line 207
    .line 208
    .line 209
    iget-boolean v2, v0, Lw0/o;->j:Z

    .line 210
    .line 211
    if-eqz v2, :cond_2

    .line 212
    .line 213
    iput-boolean v3, v0, Lw0/o;->j:Z

    .line 214
    .line 215
    invoke-virtual {v1}, Lb0/x1;->c()Z

    .line 216
    .line 217
    .line 218
    iget-object p0, v1, Lb0/x1;->i:Ly4/h;

    .line 219
    .line 220
    invoke-virtual {p0, v4}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    goto :goto_1

    .line 224
    :cond_2
    iput-object v1, v0, Lw0/o;->e:Lb0/x1;

    .line 225
    .line 226
    iput-object p0, v0, Lw0/o;->g:Lbb/i;

    .line 227
    .line 228
    iget-object p0, v1, Lb0/x1;->b:Landroid/util/Size;

    .line 229
    .line 230
    iput-object p0, v0, Lw0/o;->d:Landroid/util/Size;

    .line 231
    .line 232
    iput-boolean v3, v0, Lw0/o;->i:Z

    .line 233
    .line 234
    invoke-virtual {v0}, Lw0/o;->b()Z

    .line 235
    .line 236
    .line 237
    move-result v1

    .line 238
    if-nez v1, :cond_3

    .line 239
    .line 240
    const-string v1, "SurfaceViewImpl"

    .line 241
    .line 242
    const-string v2, "Wait for new Surface creation."

    .line 243
    .line 244
    invoke-static {v1, v2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    iget-object v0, v0, Lw0/o;->k:Lw0/p;

    .line 248
    .line 249
    iget-object v0, v0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 250
    .line 251
    invoke-virtual {v0}, Landroid/view/SurfaceView;->getHolder()Landroid/view/SurfaceHolder;

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    invoke-virtual {p0}, Landroid/util/Size;->getWidth()I

    .line 256
    .line 257
    .line 258
    move-result v1

    .line 259
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 260
    .line 261
    .line 262
    move-result p0

    .line 263
    invoke-interface {v0, v1, p0}, Landroid/view/SurfaceHolder;->setFixedSize(II)V

    .line 264
    .line 265
    .line 266
    :cond_3
    :goto_1
    return-void

    .line 267
    :pswitch_5
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 268
    .line 269
    move-object v8, v0

    .line 270
    check-cast v8, Lcom/google/android/material/datepicker/d;

    .line 271
    .line 272
    iget-object v0, p0, La8/y0;->f:Ljava/lang/Object;

    .line 273
    .line 274
    move-object v7, v0

    .line 275
    check-cast v7, Luw/b;

    .line 276
    .line 277
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 278
    .line 279
    move-object v9, p0

    .line 280
    check-cast v9, Lhu/q;

    .line 281
    .line 282
    const-string p0, "this$0"

    .line 283
    .line 284
    invoke-static {v8, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    iget-object p0, v8, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 288
    .line 289
    check-cast p0, Lro/f;

    .line 290
    .line 291
    iget-object v0, v8, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 292
    .line 293
    check-cast v0, Lww/e;

    .line 294
    .line 295
    iget-object v5, v0, Lww/e;->c:Lb81/d;

    .line 296
    .line 297
    sget-object v6, Lww/e;->d:[Lhy0/z;

    .line 298
    .line 299
    aget-object v10, v6, v2

    .line 300
    .line 301
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 302
    .line 303
    .line 304
    const-string v11, "property"

    .line 305
    .line 306
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    iget-object v10, v5, Lb81/d;->f:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast v10, Lww/e;

    .line 312
    .line 313
    iget-object v10, v10, Lww/e;->a:Landroid/content/SharedPreferences;

    .line 314
    .line 315
    iget-object v12, v5, Lb81/d;->e:Ljava/lang/Object;

    .line 316
    .line 317
    check-cast v12, Ljava/lang/String;

    .line 318
    .line 319
    invoke-interface {v10, v12, v4}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 320
    .line 321
    .line 322
    move-result-object v10

    .line 323
    if-nez v10, :cond_4

    .line 324
    .line 325
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 326
    .line 327
    .line 328
    move-result-object v10

    .line 329
    invoke-virtual {v10}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v10

    .line 333
    aget-object v12, v6, v2

    .line 334
    .line 335
    invoke-virtual {v5, v12, v10}, Lb81/d;->d(Lhy0/z;Ljava/lang/String;)V

    .line 336
    .line 337
    .line 338
    const-string v5, "randomUUID().toString().also { _uniqueId = it }"

    .line 339
    .line 340
    invoke-static {v10, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 341
    .line 342
    .line 343
    :cond_4
    const-string v5, "3.9.1"

    .line 344
    .line 345
    iget-object v12, v0, Lww/e;->b:Lb81/d;

    .line 346
    .line 347
    aget-object v3, v6, v3

    .line 348
    .line 349
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 350
    .line 351
    .line 352
    invoke-static {v3, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 353
    .line 354
    .line 355
    iget-object v3, v12, Lb81/d;->f:Ljava/lang/Object;

    .line 356
    .line 357
    check-cast v3, Lww/e;

    .line 358
    .line 359
    iget-object v3, v3, Lww/e;->a:Landroid/content/SharedPreferences;

    .line 360
    .line 361
    iget-object v6, v12, Lb81/d;->e:Ljava/lang/Object;

    .line 362
    .line 363
    check-cast v6, Ljava/lang/String;

    .line 364
    .line 365
    invoke-interface {v3, v6, v4}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object v3

    .line 369
    iget-object v6, v8, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 370
    .line 371
    check-cast v6, Luw/b;

    .line 372
    .line 373
    invoke-virtual {v6}, Luw/b;->b()Ljava/lang/String;

    .line 374
    .line 375
    .line 376
    move-result-object v6

    .line 377
    const-string v11, "localeHash"

    .line 378
    .line 379
    invoke-static {v6, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 380
    .line 381
    .line 382
    iget-object v0, v0, Lww/e;->a:Landroid/content/SharedPreferences;

    .line 383
    .line 384
    invoke-interface {v0, v6, v4}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 385
    .line 386
    .line 387
    move-result-object v0

    .line 388
    iget-object v6, v8, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 389
    .line 390
    check-cast v6, Ljava/lang/String;

    .line 391
    .line 392
    if-nez v6, :cond_5

    .line 393
    .line 394
    iget-object v6, v8, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 395
    .line 396
    check-cast v6, Ljava/lang/String;

    .line 397
    .line 398
    :cond_5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 399
    .line 400
    .line 401
    const-string v11, "Fetching Translations: Got status: "

    .line 402
    .line 403
    new-instance v12, Landroid/net/Uri$Builder;

    .line 404
    .line 405
    invoke-direct {v12}, Landroid/net/Uri$Builder;-><init>()V

    .line 406
    .line 407
    .line 408
    const-string v13, "client"

    .line 409
    .line 410
    const-string v14, "android"

    .line 411
    .line 412
    invoke-virtual {v12, v13, v14}, Landroid/net/Uri$Builder;->appendQueryParameter(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 413
    .line 414
    .line 415
    const-string v13, "unique_identifier"

    .line 416
    .line 417
    invoke-virtual {v12, v13, v10}, Landroid/net/Uri$Builder;->appendQueryParameter(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 418
    .line 419
    .line 420
    const-string v10, "sdk_version"

    .line 421
    .line 422
    invoke-virtual {v12, v10, v5}, Landroid/net/Uri$Builder;->appendQueryParameter(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 423
    .line 424
    .line 425
    if-eqz v3, :cond_6

    .line 426
    .line 427
    const-string v5, "last_update"

    .line 428
    .line 429
    invoke-virtual {v12, v5, v3}, Landroid/net/Uri$Builder;->appendQueryParameter(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 430
    .line 431
    .line 432
    :cond_6
    if-eqz v0, :cond_7

    .line 433
    .line 434
    const-string v3, "current_version"

    .line 435
    .line 436
    invoke-virtual {v12, v3, v0}, Landroid/net/Uri$Builder;->appendQueryParameter(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 437
    .line 438
    .line 439
    :cond_7
    if-eqz v6, :cond_8

    .line 440
    .line 441
    const-string v0, "app_version"

    .line 442
    .line 443
    invoke-virtual {v12, v0, v6}, Landroid/net/Uri$Builder;->appendQueryParameter(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 444
    .line 445
    .line 446
    :cond_8
    invoke-virtual {v12}, Landroid/net/Uri$Builder;->build()Landroid/net/Uri;

    .line 447
    .line 448
    .line 449
    move-result-object v0

    .line 450
    invoke-virtual {v0}, Landroid/net/Uri;->getEncodedQuery()Ljava/lang/String;

    .line 451
    .line 452
    .line 453
    move-result-object v0

    .line 454
    new-instance v3, Ljava/lang/StringBuilder;

    .line 455
    .line 456
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 457
    .line 458
    .line 459
    sget-object v5, Luw/c;->c:Ljava/lang/String;

    .line 460
    .line 461
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 462
    .line 463
    .line 464
    const-string v5, "/6ba09622c4ff51e59f80bfd9a2f2649a/KvzCzoTw5T8rIrq-jiRiaYbeN0V3Djof2fzjjQaVnJc/"

    .line 465
    .line 466
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 467
    .line 468
    .line 469
    iget-object v5, v7, Luw/b;->f:Ljava/lang/String;

    .line 470
    .line 471
    const-string v6, "/xml?"

    .line 472
    .line 473
    invoke-static {v3, v5, v6, v0}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 474
    .line 475
    .line 476
    move-result-object v0

    .line 477
    new-instance v3, Ljava/lang/StringBuilder;

    .line 478
    .line 479
    const-string v5, "Fetching Translations: "

    .line 480
    .line 481
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 482
    .line 483
    .line 484
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 485
    .line 486
    .line 487
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 488
    .line 489
    .line 490
    move-result-object v3

    .line 491
    const/4 v5, 0x4

    .line 492
    invoke-static {v5, v3, v4}, Let/d;->g(ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 493
    .line 494
    .line 495
    new-instance v3, Ljava/net/URL;

    .line 496
    .line 497
    invoke-direct {v3, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    invoke-virtual {v3}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    .line 501
    .line 502
    .line 503
    move-result-object v0

    .line 504
    invoke-static {v0}, Lcom/google/firebase/perf/network/FirebasePerfUrlConnection;->instrument(Ljava/lang/Object;)Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    move-result-object v0

    .line 508
    check-cast v0, Ljava/net/URLConnection;

    .line 509
    .line 510
    const-string v3, "null cannot be cast to non-null type java.net.HttpURLConnection"

    .line 511
    .line 512
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 513
    .line 514
    .line 515
    move-object v3, v0

    .line 516
    check-cast v3, Ljava/net/HttpURLConnection;

    .line 517
    .line 518
    const-string v0, "GET"

    .line 519
    .line 520
    invoke-virtual {v3, v0}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 521
    .line 522
    .line 523
    invoke-virtual {v3, v2}, Ljava/net/HttpURLConnection;->setInstanceFollowRedirects(Z)V

    .line 524
    .line 525
    .line 526
    const/16 v0, 0x2710

    .line 527
    .line 528
    invoke-virtual {v3, v0}, Ljava/net/URLConnection;->setConnectTimeout(I)V

    .line 529
    .line 530
    .line 531
    invoke-virtual {v3, v0}, Ljava/net/URLConnection;->setReadTimeout(I)V

    .line 532
    .line 533
    .line 534
    :try_start_0
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 535
    .line 536
    .line 537
    move-result v0

    .line 538
    const/16 v2, 0xc8

    .line 539
    .line 540
    if-eq v0, v2, :cond_a

    .line 541
    .line 542
    const/16 p0, 0x130

    .line 543
    .line 544
    if-ne v0, p0, :cond_9

    .line 545
    .line 546
    const-string p0, "Fetching Translations: Already up to date"

    .line 547
    .line 548
    invoke-static {v5, p0, v4}, Let/d;->g(ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 549
    .line 550
    .line 551
    sget-object p0, Lww/c;->a:Lww/c;
    :try_end_0
    .catch Ljava/net/UnknownHostException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 552
    .line 553
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 554
    .line 555
    .line 556
    :goto_2
    move-object v6, p0

    .line 557
    goto/16 :goto_6

    .line 558
    .line 559
    :cond_9
    :try_start_1
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    .line 560
    .line 561
    .line 562
    move-result-object p0

    .line 563
    const-string v0, "connection.errorStream"

    .line 564
    .line 565
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 566
    .line 567
    .line 568
    sget-object v0, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 569
    .line 570
    new-instance v2, Ljava/io/InputStreamReader;

    .line 571
    .line 572
    invoke-direct {v2, p0, v0}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/nio/charset/Charset;)V

    .line 573
    .line 574
    .line 575
    new-instance p0, Ljava/io/BufferedReader;

    .line 576
    .line 577
    const/16 v0, 0x2000

    .line 578
    .line 579
    invoke-direct {p0, v2, v0}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;I)V
    :try_end_1
    .catch Ljava/net/UnknownHostException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 580
    .line 581
    .line 582
    :try_start_2
    invoke-static {p0}, Llp/xd;->b(Ljava/io/Reader;)Ljava/lang/String;

    .line 583
    .line 584
    .line 585
    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 586
    :try_start_3
    invoke-interface {p0}, Ljava/io/Closeable;->close()V

    .line 587
    .line 588
    .line 589
    new-instance p0, Ljava/lang/StringBuilder;

    .line 590
    .line 591
    invoke-direct {p0, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 592
    .line 593
    .line 594
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 595
    .line 596
    .line 597
    move-result v2

    .line 598
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 599
    .line 600
    .line 601
    const-string v2, ": "

    .line 602
    .line 603
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 604
    .line 605
    .line 606
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 607
    .line 608
    .line 609
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 610
    .line 611
    .line 612
    move-result-object p0

    .line 613
    invoke-static {p0}, Let/d;->d(Ljava/lang/String;)V

    .line 614
    .line 615
    .line 616
    new-instance p0, Lb0/l;

    .line 617
    .line 618
    invoke-direct {p0}, Ljava/lang/Exception;-><init>()V

    .line 619
    .line 620
    .line 621
    throw p0
    :try_end_3
    .catch Ljava/net/UnknownHostException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 622
    :catchall_0
    move-exception v0

    .line 623
    move-object p0, v0

    .line 624
    goto :goto_3

    .line 625
    :catch_0
    move-exception v0

    .line 626
    move-object p0, v0

    .line 627
    goto :goto_5

    .line 628
    :catchall_1
    move-exception v0

    .line 629
    move-object v2, v0

    .line 630
    :try_start_4
    throw v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 631
    :catchall_2
    move-exception v0

    .line 632
    :try_start_5
    invoke-static {p0, v2}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 633
    .line 634
    .line 635
    throw v0

    .line 636
    :cond_a
    invoke-virtual {v3}, Ljava/net/URLConnection;->getURL()Ljava/net/URL;

    .line 637
    .line 638
    .line 639
    move-result-object v0

    .line 640
    invoke-virtual {v0}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 641
    .line 642
    .line 643
    move-result-object v0

    .line 644
    const-string v2, "connection.url.toString()"

    .line 645
    .line 646
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 647
    .line 648
    .line 649
    new-instance v2, Landroid/net/UrlQuerySanitizer;

    .line 650
    .line 651
    invoke-direct {v2, v0}, Landroid/net/UrlQuerySanitizer;-><init>(Ljava/lang/String;)V

    .line 652
    .line 653
    .line 654
    const-string v0, "version"

    .line 655
    .line 656
    invoke-virtual {v2, v0}, Landroid/net/UrlQuerySanitizer;->getValue(Ljava/lang/String;)Ljava/lang/String;

    .line 657
    .line 658
    .line 659
    move-result-object v0

    .line 660
    if-eqz v0, :cond_b

    .line 661
    .line 662
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 663
    .line 664
    check-cast p0, Landroidx/lifecycle/c1;

    .line 665
    .line 666
    invoke-virtual {v3}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    .line 667
    .line 668
    .line 669
    move-result-object v2

    .line 670
    const-string v4, "connection.inputStream"

    .line 671
    .line 672
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 673
    .line 674
    .line 675
    invoke-virtual {p0, v7, v2}, Landroidx/lifecycle/c1;->G(Luw/b;Ljava/io/InputStream;)V

    .line 676
    .line 677
    .line 678
    new-instance p0, Lww/a;

    .line 679
    .line 680
    invoke-direct {p0, v0}, Lww/a;-><init>(Ljava/lang/String;)V
    :try_end_5
    .catch Ljava/net/UnknownHostException; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 681
    .line 682
    .line 683
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 684
    .line 685
    .line 686
    goto/16 :goto_2

    .line 687
    .line 688
    :cond_b
    :try_start_6
    new-instance p0, Lb0/l;

    .line 689
    .line 690
    invoke-direct {p0}, Ljava/lang/Exception;-><init>()V

    .line 691
    .line 692
    .line 693
    throw p0
    :try_end_6
    .catch Ljava/net/UnknownHostException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 694
    :goto_3
    :try_start_7
    const-string v0, "Fetching Translations failed"

    .line 695
    .line 696
    invoke-static {v1, v0, p0}, Let/d;->g(ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 697
    .line 698
    .line 699
    new-instance v0, Lww/b;

    .line 700
    .line 701
    invoke-direct {v0, p0}, Lww/b;-><init>(Ljava/lang/Throwable;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 702
    .line 703
    .line 704
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 705
    .line 706
    .line 707
    :goto_4
    move-object v6, v0

    .line 708
    goto :goto_6

    .line 709
    :catchall_3
    move-exception v0

    .line 710
    move-object p0, v0

    .line 711
    goto :goto_7

    .line 712
    :goto_5
    :try_start_8
    const-string v0, "Fetching Translations: No Internet connection"

    .line 713
    .line 714
    invoke-static {v5, v0, p0}, Let/d;->g(ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 715
    .line 716
    .line 717
    new-instance v0, Lww/b;

    .line 718
    .line 719
    invoke-direct {v0, p0}, Lww/b;-><init>(Ljava/lang/Throwable;)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 720
    .line 721
    .line 722
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 723
    .line 724
    .line 725
    goto :goto_4

    .line 726
    :goto_6
    iget-object p0, v8, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 727
    .line 728
    check-cast p0, Landroid/os/Handler;

    .line 729
    .line 730
    new-instance v5, Lc8/r;

    .line 731
    .line 732
    const/4 v10, 0x5

    .line 733
    invoke-direct/range {v5 .. v10}, Lc8/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 734
    .line 735
    .line 736
    invoke-virtual {p0, v5}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 737
    .line 738
    .line 739
    return-void

    .line 740
    :goto_7
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 741
    .line 742
    .line 743
    throw p0

    .line 744
    :pswitch_6
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 745
    .line 746
    check-cast v0, Lu/m;

    .line 747
    .line 748
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 749
    .line 750
    check-cast v1, Ljava/util/concurrent/Executor;

    .line 751
    .line 752
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 753
    .line 754
    check-cast p0, Lh0/m;

    .line 755
    .line 756
    iget-object v0, v0, Lu/m;->y:Lu/j;

    .line 757
    .line 758
    iget-object v2, v0, Lu/j;->b:Ljava/lang/Object;

    .line 759
    .line 760
    check-cast v2, Ljava/util/HashSet;

    .line 761
    .line 762
    invoke-virtual {v2, p0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 763
    .line 764
    .line 765
    iget-object v0, v0, Lu/j;->c:Ljava/lang/Object;

    .line 766
    .line 767
    check-cast v0, Landroid/util/ArrayMap;

    .line 768
    .line 769
    invoke-virtual {v0, p0, v1}, Landroid/util/ArrayMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 770
    .line 771
    .line 772
    return-void

    .line 773
    :pswitch_7
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 774
    .line 775
    check-cast v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 776
    .line 777
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 778
    .line 779
    check-cast v1, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 780
    .line 781
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 782
    .line 783
    check-cast p0, Ltechnology/cariad/cat/genx/Channel;

    .line 784
    .line 785
    invoke-static {v0, v1, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->R0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Ltechnology/cariad/cat/genx/Channel;)V

    .line 786
    .line 787
    .line 788
    return-void

    .line 789
    :pswitch_8
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 790
    .line 791
    check-cast v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 792
    .line 793
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 794
    .line 795
    check-cast v1, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 796
    .line 797
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 798
    .line 799
    check-cast p0, Ltechnology/cariad/cat/genx/TypedFrame;

    .line 800
    .line 801
    invoke-static {v0, v1, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->M(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Ltechnology/cariad/cat/genx/TypedFrame;)V

    .line 802
    .line 803
    .line 804
    return-void

    .line 805
    :pswitch_9
    invoke-direct {p0}, La8/y0;->a()V

    .line 806
    .line 807
    .line 808
    return-void

    .line 809
    :pswitch_a
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 810
    .line 811
    check-cast v0, Lq0/e;

    .line 812
    .line 813
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 814
    .line 815
    check-cast v1, Ljava/lang/Runnable;

    .line 816
    .line 817
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 818
    .line 819
    check-cast p0, Ljava/lang/Runnable;

    .line 820
    .line 821
    iget-boolean v0, v0, Lq0/e;->i:Z

    .line 822
    .line 823
    if-eqz v0, :cond_c

    .line 824
    .line 825
    invoke-interface {v1}, Ljava/lang/Runnable;->run()V

    .line 826
    .line 827
    .line 828
    goto :goto_8

    .line 829
    :cond_c
    invoke-interface {p0}, Ljava/lang/Runnable;->run()V

    .line 830
    .line 831
    .line 832
    :goto_8
    return-void

    .line 833
    :pswitch_b
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 834
    .line 835
    check-cast v0, Lq0/e;

    .line 836
    .line 837
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 838
    .line 839
    check-cast v1, Lb0/y;

    .line 840
    .line 841
    sget-object v2, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 842
    .line 843
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 844
    .line 845
    check-cast p0, Ly4/h;

    .line 846
    .line 847
    :try_start_9
    iget-object v0, v0, Lq0/e;->d:Lq0/c;

    .line 848
    .line 849
    invoke-virtual {v0, v1}, Lq0/c;->i(Lb0/y;)Lr0/a;

    .line 850
    .line 851
    .line 852
    invoke-virtual {p0, v4}, Ly4/h;->b(Ljava/lang/Object;)Z
    :try_end_9
    .catch Ljava/lang/RuntimeException; {:try_start_9 .. :try_end_9} :catch_1

    .line 853
    .line 854
    .line 855
    goto :goto_9

    .line 856
    :catch_1
    move-exception v0

    .line 857
    invoke-virtual {p0, v0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 858
    .line 859
    .line 860
    :goto_9
    return-void

    .line 861
    :pswitch_c
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 862
    .line 863
    check-cast v0, Lil/g;

    .line 864
    .line 865
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 866
    .line 867
    check-cast v1, Lp0/k;

    .line 868
    .line 869
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 870
    .line 871
    check-cast p0, Ljava/util/Map$Entry;

    .line 872
    .line 873
    invoke-virtual {v0, v1, p0}, Lil/g;->p(Lp0/k;Ljava/util/Map$Entry;)V

    .line 874
    .line 875
    .line 876
    return-void

    .line 877
    :pswitch_d
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 878
    .line 879
    check-cast v0, Lp0/c;

    .line 880
    .line 881
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 882
    .line 883
    check-cast v1, Lb0/y;

    .line 884
    .line 885
    sget-object v2, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 886
    .line 887
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 888
    .line 889
    check-cast p0, Ly4/h;

    .line 890
    .line 891
    :try_start_a
    iget-object v0, v0, Lp0/c;->d:Lc1/k2;

    .line 892
    .line 893
    invoke-virtual {v0, v1}, Lc1/k2;->i(Lb0/y;)Lr0/a;

    .line 894
    .line 895
    .line 896
    invoke-virtual {p0, v4}, Ly4/h;->b(Ljava/lang/Object;)Z
    :try_end_a
    .catch Ljava/lang/RuntimeException; {:try_start_a .. :try_end_a} :catch_2

    .line 897
    .line 898
    .line 899
    goto :goto_a

    .line 900
    :catch_2
    move-exception v0

    .line 901
    invoke-virtual {p0, v0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 902
    .line 903
    .line 904
    :goto_a
    return-void

    .line 905
    :pswitch_e
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 906
    .line 907
    check-cast v0, Lp0/c;

    .line 908
    .line 909
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 910
    .line 911
    check-cast v1, Ljava/lang/Runnable;

    .line 912
    .line 913
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 914
    .line 915
    check-cast p0, Ljava/lang/Runnable;

    .line 916
    .line 917
    iget-boolean v0, v0, Lp0/c;->m:Z

    .line 918
    .line 919
    if-eqz v0, :cond_d

    .line 920
    .line 921
    invoke-interface {v1}, Ljava/lang/Runnable;->run()V

    .line 922
    .line 923
    .line 924
    goto :goto_b

    .line 925
    :cond_d
    invoke-interface {p0}, Ljava/lang/Runnable;->run()V

    .line 926
    .line 927
    .line 928
    :goto_b
    return-void

    .line 929
    :pswitch_f
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 930
    .line 931
    check-cast v0, Landroidx/work/impl/WorkDatabase;

    .line 932
    .line 933
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 934
    .line 935
    check-cast v1, Ljava/lang/String;

    .line 936
    .line 937
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 938
    .line 939
    check-cast p0, Lfb/u;

    .line 940
    .line 941
    invoke-virtual {v0}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 942
    .line 943
    .line 944
    move-result-object v0

    .line 945
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 946
    .line 947
    .line 948
    const-string v4, "name"

    .line 949
    .line 950
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 951
    .line 952
    .line 953
    iget-object v0, v0, Lmb/s;->a:Lla/u;

    .line 954
    .line 955
    new-instance v4, Lif0/d;

    .line 956
    .line 957
    const/16 v5, 0x13

    .line 958
    .line 959
    invoke-direct {v4, v1, v5}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 960
    .line 961
    .line 962
    invoke-static {v0, v2, v3, v4}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 963
    .line 964
    .line 965
    move-result-object v0

    .line 966
    check-cast v0, Ljava/util/List;

    .line 967
    .line 968
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 969
    .line 970
    .line 971
    move-result-object v0

    .line 972
    :goto_c
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 973
    .line 974
    .line 975
    move-result v1

    .line 976
    if-eqz v1, :cond_e

    .line 977
    .line 978
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 979
    .line 980
    .line 981
    move-result-object v1

    .line 982
    check-cast v1, Ljava/lang/String;

    .line 983
    .line 984
    invoke-static {p0, v1}, Lnb/e;->a(Lfb/u;Ljava/lang/String;)V

    .line 985
    .line 986
    .line 987
    goto :goto_c

    .line 988
    :cond_e
    return-void

    .line 989
    :pswitch_10
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 990
    .line 991
    check-cast v0, Lms/p;

    .line 992
    .line 993
    iget-object v2, p0, La8/y0;->f:Ljava/lang/Object;

    .line 994
    .line 995
    check-cast v2, Ljava/lang/String;

    .line 996
    .line 997
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 998
    .line 999
    check-cast p0, Ljava/lang/String;

    .line 1000
    .line 1001
    iget-object v3, v0, Lms/p;->h:Lms/l;

    .line 1002
    .line 1003
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1004
    .line 1005
    .line 1006
    :try_start_b
    iget-object v0, v3, Lms/l;->d:Lss/b;

    .line 1007
    .line 1008
    iget-object v0, v0, Lss/b;->h:Ljava/lang/Object;

    .line 1009
    .line 1010
    check-cast v0, La8/b;

    .line 1011
    .line 1012
    invoke-virtual {v0, v2, p0}, La8/b;->r(Ljava/lang/String;Ljava/lang/String;)Z
    :try_end_b
    .catch Ljava/lang/IllegalArgumentException; {:try_start_b .. :try_end_b} :catch_3

    .line 1013
    .line 1014
    .line 1015
    goto :goto_e

    .line 1016
    :catch_3
    move-exception v0

    .line 1017
    move-object p0, v0

    .line 1018
    iget-object v0, v3, Lms/l;->a:Landroid/content/Context;

    .line 1019
    .line 1020
    if-eqz v0, :cond_10

    .line 1021
    .line 1022
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 1023
    .line 1024
    .line 1025
    move-result-object v0

    .line 1026
    iget v0, v0, Landroid/content/pm/ApplicationInfo;->flags:I

    .line 1027
    .line 1028
    and-int/2addr v0, v1

    .line 1029
    if-nez v0, :cond_f

    .line 1030
    .line 1031
    goto :goto_d

    .line 1032
    :cond_f
    throw p0

    .line 1033
    :cond_10
    :goto_d
    const-string p0, "Attempting to set custom attribute with null key, ignoring."

    .line 1034
    .line 1035
    const-string v0, "FirebaseCrashlytics"

    .line 1036
    .line 1037
    invoke-static {v0, p0, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1038
    .line 1039
    .line 1040
    :goto_e
    return-void

    .line 1041
    :pswitch_11
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 1042
    .line 1043
    check-cast v0, Ljava/util/ArrayList;

    .line 1044
    .line 1045
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 1046
    .line 1047
    check-cast v1, Landroidx/lifecycle/j0;

    .line 1048
    .line 1049
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 1050
    .line 1051
    check-cast p0, Ljava/lang/String;

    .line 1052
    .line 1053
    :try_start_c
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1054
    .line 1055
    .line 1056
    move-result-object v0

    .line 1057
    :cond_11
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1058
    .line 1059
    .line 1060
    move-result v2

    .line 1061
    if-eqz v2, :cond_12

    .line 1062
    .line 1063
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1064
    .line 1065
    .line 1066
    move-result-object v2

    .line 1067
    move-object v3, v2

    .line 1068
    check-cast v3, Lh0/z;

    .line 1069
    .line 1070
    invoke-interface {v3}, Lh0/z;->f()Ljava/lang/String;

    .line 1071
    .line 1072
    .line 1073
    move-result-object v3

    .line 1074
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1075
    .line 1076
    .line 1077
    move-result v3

    .line 1078
    if-eqz v3, :cond_11

    .line 1079
    .line 1080
    move-object v4, v2

    .line 1081
    :cond_12
    check-cast v4, Lh0/z;

    .line 1082
    .line 1083
    if-eqz v4, :cond_13

    .line 1084
    .line 1085
    invoke-interface {v4}, Lh0/z;->c()Landroidx/lifecycle/g0;

    .line 1086
    .line 1087
    .line 1088
    move-result-object p0

    .line 1089
    if-eqz p0, :cond_13

    .line 1090
    .line 1091
    invoke-virtual {p0, v1}, Landroidx/lifecycle/g0;->i(Landroidx/lifecycle/j0;)V
    :try_end_c
    .catch Ljava/lang/IllegalArgumentException; {:try_start_c .. :try_end_c} :catch_4

    .line 1092
    .line 1093
    .line 1094
    :catch_4
    :cond_13
    return-void

    .line 1095
    :pswitch_12
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 1096
    .line 1097
    check-cast v0, Ljava/lang/Throwable;

    .line 1098
    .line 1099
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 1100
    .line 1101
    check-cast v1, Lh0/a;

    .line 1102
    .line 1103
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 1104
    .line 1105
    check-cast p0, Ljava/util/List;

    .line 1106
    .line 1107
    if-eqz v0, :cond_14

    .line 1108
    .line 1109
    iget-object p0, v1, Lh0/a;->b:Lh0/l1;

    .line 1110
    .line 1111
    invoke-interface {p0, v0}, Lh0/l1;->onError(Ljava/lang/Throwable;)V

    .line 1112
    .line 1113
    .line 1114
    goto :goto_f

    .line 1115
    :cond_14
    iget-object v0, v1, Lh0/a;->b:Lh0/l1;

    .line 1116
    .line 1117
    invoke-interface {v0, p0}, Lh0/l1;->a(Ljava/lang/Object;)V

    .line 1118
    .line 1119
    .line 1120
    :goto_f
    return-void

    .line 1121
    :pswitch_13
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 1122
    .line 1123
    check-cast v0, Lb81/b;

    .line 1124
    .line 1125
    iget-object p0, p0, La8/y0;->f:Ljava/lang/Object;

    .line 1126
    .line 1127
    check-cast p0, Lfb/j;

    .line 1128
    .line 1129
    iget-object v0, v0, Lb81/b;->e:Ljava/lang/Object;

    .line 1130
    .line 1131
    move-object v9, v0

    .line 1132
    check-cast v9, Lfb/e;

    .line 1133
    .line 1134
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1135
    .line 1136
    .line 1137
    const-string v0, "Work "

    .line 1138
    .line 1139
    iget-object v1, p0, Lfb/j;->a:Lmb/i;

    .line 1140
    .line 1141
    iget-object v13, v1, Lmb/i;->a:Ljava/lang/String;

    .line 1142
    .line 1143
    new-instance v12, Ljava/util/ArrayList;

    .line 1144
    .line 1145
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 1146
    .line 1147
    .line 1148
    iget-object v5, v9, Lfb/e;->e:Landroidx/work/impl/WorkDatabase;

    .line 1149
    .line 1150
    new-instance v6, Lfb/d;

    .line 1151
    .line 1152
    invoke-direct {v6, v9, v12, v13, v3}, Lfb/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 1153
    .line 1154
    .line 1155
    new-instance v7, Lh50/q0;

    .line 1156
    .line 1157
    const/16 v8, 0x17

    .line 1158
    .line 1159
    invoke-direct {v7, v6, v8}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 1160
    .line 1161
    .line 1162
    invoke-virtual {v5, v7}, Lla/u;->p(Lay0/a;)Ljava/lang/Object;

    .line 1163
    .line 1164
    .line 1165
    move-result-object v5

    .line 1166
    move-object v11, v5

    .line 1167
    check-cast v11, Lmb/o;

    .line 1168
    .line 1169
    if-nez v11, :cond_15

    .line 1170
    .line 1171
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 1172
    .line 1173
    .line 1174
    move-result-object p0

    .line 1175
    sget-object v0, Lfb/e;->l:Ljava/lang/String;

    .line 1176
    .line 1177
    new-instance v2, Ljava/lang/StringBuilder;

    .line 1178
    .line 1179
    const-string v3, "Didn\'t find WorkSpec for id "

    .line 1180
    .line 1181
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1182
    .line 1183
    .line 1184
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1185
    .line 1186
    .line 1187
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1188
    .line 1189
    .line 1190
    move-result-object v2

    .line 1191
    invoke-virtual {p0, v0, v2}, Leb/w;->g(Ljava/lang/String;Ljava/lang/String;)V

    .line 1192
    .line 1193
    .line 1194
    iget-object p0, v9, Lfb/e;->d:Lob/a;

    .line 1195
    .line 1196
    iget-object p0, p0, Lob/a;->d:Lj0/e;

    .line 1197
    .line 1198
    new-instance v0, La8/z;

    .line 1199
    .line 1200
    invoke-direct {v0, v8, v9, v1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1201
    .line 1202
    .line 1203
    invoke-virtual {p0, v0}, Lj0/e;->execute(Ljava/lang/Runnable;)V

    .line 1204
    .line 1205
    .line 1206
    goto/16 :goto_11

    .line 1207
    .line 1208
    :cond_15
    iget-object v14, v9, Lfb/e;->k:Ljava/lang/Object;

    .line 1209
    .line 1210
    monitor-enter v14

    .line 1211
    :try_start_d
    iget-object v5, v9, Lfb/e;->k:Ljava/lang/Object;

    .line 1212
    .line 1213
    monitor-enter v5
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_4

    .line 1214
    :try_start_e
    invoke-virtual {v9, v13}, Lfb/e;->c(Ljava/lang/String;)Lfb/f0;

    .line 1215
    .line 1216
    .line 1217
    move-result-object v6

    .line 1218
    if-eqz v6, :cond_16

    .line 1219
    .line 1220
    move v3, v2

    .line 1221
    :cond_16
    monitor-exit v5
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_5

    .line 1222
    if-eqz v3, :cond_18

    .line 1223
    .line 1224
    :try_start_f
    iget-object v2, v9, Lfb/e;->h:Ljava/util/HashMap;

    .line 1225
    .line 1226
    invoke-virtual {v2, v13}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1227
    .line 1228
    .line 1229
    move-result-object v2

    .line 1230
    check-cast v2, Ljava/util/Set;

    .line 1231
    .line 1232
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1233
    .line 1234
    .line 1235
    move-result-object v3

    .line 1236
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1237
    .line 1238
    .line 1239
    move-result-object v3

    .line 1240
    check-cast v3, Lfb/j;

    .line 1241
    .line 1242
    iget-object v3, v3, Lfb/j;->a:Lmb/i;

    .line 1243
    .line 1244
    iget v3, v3, Lmb/i;->b:I

    .line 1245
    .line 1246
    iget v4, v1, Lmb/i;->b:I

    .line 1247
    .line 1248
    if-ne v3, v4, :cond_17

    .line 1249
    .line 1250
    invoke-interface {v2, p0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 1251
    .line 1252
    .line 1253
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 1254
    .line 1255
    .line 1256
    move-result-object p0

    .line 1257
    sget-object v2, Lfb/e;->l:Ljava/lang/String;

    .line 1258
    .line 1259
    new-instance v3, Ljava/lang/StringBuilder;

    .line 1260
    .line 1261
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1262
    .line 1263
    .line 1264
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1265
    .line 1266
    .line 1267
    const-string v0, " is already enqueued for processing"

    .line 1268
    .line 1269
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1270
    .line 1271
    .line 1272
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1273
    .line 1274
    .line 1275
    move-result-object v0

    .line 1276
    invoke-virtual {p0, v2, v0}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 1277
    .line 1278
    .line 1279
    goto :goto_10

    .line 1280
    :catchall_4
    move-exception v0

    .line 1281
    move-object p0, v0

    .line 1282
    goto/16 :goto_12

    .line 1283
    .line 1284
    :cond_17
    iget-object p0, v9, Lfb/e;->d:Lob/a;

    .line 1285
    .line 1286
    iget-object p0, p0, Lob/a;->d:Lj0/e;

    .line 1287
    .line 1288
    new-instance v0, La8/z;

    .line 1289
    .line 1290
    invoke-direct {v0, v8, v9, v1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1291
    .line 1292
    .line 1293
    invoke-virtual {p0, v0}, Lj0/e;->execute(Ljava/lang/Runnable;)V

    .line 1294
    .line 1295
    .line 1296
    :goto_10
    monitor-exit v14

    .line 1297
    goto/16 :goto_11

    .line 1298
    .line 1299
    :cond_18
    iget v0, v11, Lmb/o;->t:I

    .line 1300
    .line 1301
    iget v3, v1, Lmb/i;->b:I

    .line 1302
    .line 1303
    if-eq v0, v3, :cond_19

    .line 1304
    .line 1305
    iget-object p0, v9, Lfb/e;->d:Lob/a;

    .line 1306
    .line 1307
    iget-object p0, p0, Lob/a;->d:Lj0/e;

    .line 1308
    .line 1309
    new-instance v0, La8/z;

    .line 1310
    .line 1311
    invoke-direct {v0, v8, v9, v1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1312
    .line 1313
    .line 1314
    invoke-virtual {p0, v0}, Lj0/e;->execute(Ljava/lang/Runnable;)V

    .line 1315
    .line 1316
    .line 1317
    monitor-exit v14

    .line 1318
    goto :goto_11

    .line 1319
    :cond_19
    new-instance v5, Lss/b;

    .line 1320
    .line 1321
    iget-object v6, v9, Lfb/e;->b:Landroid/content/Context;

    .line 1322
    .line 1323
    iget-object v7, v9, Lfb/e;->c:Leb/b;

    .line 1324
    .line 1325
    iget-object v8, v9, Lfb/e;->d:Lob/a;

    .line 1326
    .line 1327
    iget-object v10, v9, Lfb/e;->e:Landroidx/work/impl/WorkDatabase;

    .line 1328
    .line 1329
    invoke-direct/range {v5 .. v12}, Lss/b;-><init>(Landroid/content/Context;Leb/b;Lob/a;Llb/a;Landroidx/work/impl/WorkDatabase;Lmb/o;Ljava/util/ArrayList;)V

    .line 1330
    .line 1331
    .line 1332
    new-instance v0, Lfb/f0;

    .line 1333
    .line 1334
    invoke-direct {v0, v5}, Lfb/f0;-><init>(Lss/b;)V

    .line 1335
    .line 1336
    .line 1337
    iget-object v3, v0, Lfb/f0;->d:Lob/a;

    .line 1338
    .line 1339
    iget-object v3, v3, Lob/a;->b:Lvy0/x;

    .line 1340
    .line 1341
    invoke-static {}, Lvy0/e0;->d()Lvy0/k1;

    .line 1342
    .line 1343
    .line 1344
    move-result-object v5

    .line 1345
    invoke-virtual {v3, v5}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 1346
    .line 1347
    .line 1348
    move-result-object v3

    .line 1349
    new-instance v5, Lfb/d0;

    .line 1350
    .line 1351
    invoke-direct {v5, v0, v4, v2}, Lfb/d0;-><init>(Lfb/f0;Lkotlin/coroutines/Continuation;I)V

    .line 1352
    .line 1353
    .line 1354
    invoke-static {v3, v5}, Lkp/c6;->b(Lpx0/g;Lay0/n;)Ly4/k;

    .line 1355
    .line 1356
    .line 1357
    move-result-object v2

    .line 1358
    new-instance v3, La8/y0;

    .line 1359
    .line 1360
    const/4 v4, 0x7

    .line 1361
    invoke-direct {v3, v9, v2, v0, v4}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 1362
    .line 1363
    .line 1364
    iget-object v4, v9, Lfb/e;->d:Lob/a;

    .line 1365
    .line 1366
    iget-object v4, v4, Lob/a;->d:Lj0/e;

    .line 1367
    .line 1368
    iget-object v2, v2, Ly4/k;->e:Ly4/j;

    .line 1369
    .line 1370
    invoke-virtual {v2, v4, v3}, Ly4/g;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 1371
    .line 1372
    .line 1373
    iget-object v2, v9, Lfb/e;->g:Ljava/util/HashMap;

    .line 1374
    .line 1375
    invoke-virtual {v2, v13, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1376
    .line 1377
    .line 1378
    new-instance v0, Ljava/util/HashSet;

    .line 1379
    .line 1380
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 1381
    .line 1382
    .line 1383
    invoke-virtual {v0, p0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 1384
    .line 1385
    .line 1386
    iget-object p0, v9, Lfb/e;->h:Ljava/util/HashMap;

    .line 1387
    .line 1388
    invoke-virtual {p0, v13, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1389
    .line 1390
    .line 1391
    monitor-exit v14
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_4

    .line 1392
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 1393
    .line 1394
    .line 1395
    move-result-object p0

    .line 1396
    sget-object v0, Lfb/e;->l:Ljava/lang/String;

    .line 1397
    .line 1398
    new-instance v2, Ljava/lang/StringBuilder;

    .line 1399
    .line 1400
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 1401
    .line 1402
    .line 1403
    const-class v3, Lfb/e;

    .line 1404
    .line 1405
    invoke-virtual {v3}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 1406
    .line 1407
    .line 1408
    move-result-object v3

    .line 1409
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1410
    .line 1411
    .line 1412
    const-string v3, ": processing "

    .line 1413
    .line 1414
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1415
    .line 1416
    .line 1417
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1418
    .line 1419
    .line 1420
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1421
    .line 1422
    .line 1423
    move-result-object v1

    .line 1424
    invoke-virtual {p0, v0, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 1425
    .line 1426
    .line 1427
    :goto_11
    return-void

    .line 1428
    :catchall_5
    move-exception v0

    .line 1429
    move-object p0, v0

    .line 1430
    :try_start_10
    monitor-exit v5
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_5

    .line 1431
    :try_start_11
    throw p0

    .line 1432
    :goto_12
    monitor-exit v14
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_4

    .line 1433
    throw p0

    .line 1434
    :pswitch_14
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 1435
    .line 1436
    check-cast v0, Lfb/e;

    .line 1437
    .line 1438
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 1439
    .line 1440
    check-cast v1, Ly4/k;

    .line 1441
    .line 1442
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 1443
    .line 1444
    check-cast p0, Lfb/f0;

    .line 1445
    .line 1446
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1447
    .line 1448
    .line 1449
    :try_start_12
    iget-object v1, v1, Ly4/k;->e:Ly4/j;

    .line 1450
    .line 1451
    invoke-virtual {v1}, Ly4/g;->get()Ljava/lang/Object;

    .line 1452
    .line 1453
    .line 1454
    move-result-object v1

    .line 1455
    check-cast v1, Ljava/lang/Boolean;

    .line 1456
    .line 1457
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1458
    .line 1459
    .line 1460
    move-result v2
    :try_end_12
    .catch Ljava/lang/InterruptedException; {:try_start_12 .. :try_end_12} :catch_5
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_12 .. :try_end_12} :catch_5

    .line 1461
    :catch_5
    iget-object v1, v0, Lfb/e;->k:Ljava/lang/Object;

    .line 1462
    .line 1463
    monitor-enter v1

    .line 1464
    :try_start_13
    iget-object v3, p0, Lfb/f0;->a:Lmb/o;

    .line 1465
    .line 1466
    invoke-static {v3}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 1467
    .line 1468
    .line 1469
    move-result-object v3

    .line 1470
    iget-object v4, v3, Lmb/i;->a:Ljava/lang/String;

    .line 1471
    .line 1472
    invoke-virtual {v0, v4}, Lfb/e;->c(Ljava/lang/String;)Lfb/f0;

    .line 1473
    .line 1474
    .line 1475
    move-result-object v5

    .line 1476
    if-ne v5, p0, :cond_1a

    .line 1477
    .line 1478
    invoke-virtual {v0, v4}, Lfb/e;->b(Ljava/lang/String;)Lfb/f0;

    .line 1479
    .line 1480
    .line 1481
    goto :goto_13

    .line 1482
    :catchall_6
    move-exception v0

    .line 1483
    move-object p0, v0

    .line 1484
    goto :goto_15

    .line 1485
    :cond_1a
    :goto_13
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 1486
    .line 1487
    .line 1488
    move-result-object p0

    .line 1489
    sget-object v5, Lfb/e;->l:Ljava/lang/String;

    .line 1490
    .line 1491
    new-instance v6, Ljava/lang/StringBuilder;

    .line 1492
    .line 1493
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 1494
    .line 1495
    .line 1496
    const-class v7, Lfb/e;

    .line 1497
    .line 1498
    invoke-virtual {v7}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 1499
    .line 1500
    .line 1501
    move-result-object v7

    .line 1502
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1503
    .line 1504
    .line 1505
    const-string v7, " "

    .line 1506
    .line 1507
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1508
    .line 1509
    .line 1510
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1511
    .line 1512
    .line 1513
    const-string v4, " executed; reschedule = "

    .line 1514
    .line 1515
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1516
    .line 1517
    .line 1518
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 1519
    .line 1520
    .line 1521
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1522
    .line 1523
    .line 1524
    move-result-object v4

    .line 1525
    invoke-virtual {p0, v5, v4}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 1526
    .line 1527
    .line 1528
    iget-object p0, v0, Lfb/e;->j:Ljava/util/ArrayList;

    .line 1529
    .line 1530
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1531
    .line 1532
    .line 1533
    move-result-object p0

    .line 1534
    :goto_14
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 1535
    .line 1536
    .line 1537
    move-result v0

    .line 1538
    if-eqz v0, :cond_1b

    .line 1539
    .line 1540
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1541
    .line 1542
    .line 1543
    move-result-object v0

    .line 1544
    check-cast v0, Lfb/b;

    .line 1545
    .line 1546
    invoke-interface {v0, v3, v2}, Lfb/b;->b(Lmb/i;Z)V

    .line 1547
    .line 1548
    .line 1549
    goto :goto_14

    .line 1550
    :cond_1b
    monitor-exit v1

    .line 1551
    return-void

    .line 1552
    :goto_15
    monitor-exit v1
    :try_end_13
    .catchall {:try_start_13 .. :try_end_13} :catchall_6

    .line 1553
    throw p0

    .line 1554
    :pswitch_15
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 1555
    .line 1556
    check-cast v0, Lcu/h;

    .line 1557
    .line 1558
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 1559
    .line 1560
    check-cast v1, Ljava/lang/String;

    .line 1561
    .line 1562
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 1563
    .line 1564
    check-cast p0, Ldu/e;

    .line 1565
    .line 1566
    iget-object v0, v0, Lcu/h;->a:Lb81/a;

    .line 1567
    .line 1568
    iget-object v3, v0, Lb81/a;->e:Ljava/lang/Object;

    .line 1569
    .line 1570
    check-cast v3, Lgt/b;

    .line 1571
    .line 1572
    invoke-interface {v3}, Lgt/b;->get()Ljava/lang/Object;

    .line 1573
    .line 1574
    .line 1575
    move-result-object v3

    .line 1576
    check-cast v3, Lwr/b;

    .line 1577
    .line 1578
    if-nez v3, :cond_1c

    .line 1579
    .line 1580
    goto/16 :goto_16

    .line 1581
    .line 1582
    :cond_1c
    iget-object v4, p0, Ldu/e;->e:Lorg/json/JSONObject;

    .line 1583
    .line 1584
    invoke-virtual {v4}, Lorg/json/JSONObject;->length()I

    .line 1585
    .line 1586
    .line 1587
    move-result v5

    .line 1588
    if-ge v5, v2, :cond_1d

    .line 1589
    .line 1590
    goto/16 :goto_16

    .line 1591
    .line 1592
    :cond_1d
    iget-object p0, p0, Ldu/e;->b:Lorg/json/JSONObject;

    .line 1593
    .line 1594
    invoke-virtual {p0}, Lorg/json/JSONObject;->length()I

    .line 1595
    .line 1596
    .line 1597
    move-result v5

    .line 1598
    if-ge v5, v2, :cond_1e

    .line 1599
    .line 1600
    goto/16 :goto_16

    .line 1601
    .line 1602
    :cond_1e
    invoke-virtual {v4, v1}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 1603
    .line 1604
    .line 1605
    move-result-object v2

    .line 1606
    if-nez v2, :cond_1f

    .line 1607
    .line 1608
    goto/16 :goto_16

    .line 1609
    .line 1610
    :cond_1f
    const-string v4, "choiceId"

    .line 1611
    .line 1612
    invoke-virtual {v2, v4}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1613
    .line 1614
    .line 1615
    move-result-object v4

    .line 1616
    invoke-virtual {v4}, Ljava/lang/String;->isEmpty()Z

    .line 1617
    .line 1618
    .line 1619
    move-result v5

    .line 1620
    if-eqz v5, :cond_20

    .line 1621
    .line 1622
    goto :goto_16

    .line 1623
    :cond_20
    iget-object v5, v0, Lb81/a;->f:Ljava/lang/Object;

    .line 1624
    .line 1625
    check-cast v5, Ljava/util/Map;

    .line 1626
    .line 1627
    monitor-enter v5

    .line 1628
    :try_start_14
    iget-object v6, v0, Lb81/a;->f:Ljava/lang/Object;

    .line 1629
    .line 1630
    check-cast v6, Ljava/util/Map;

    .line 1631
    .line 1632
    invoke-interface {v6, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1633
    .line 1634
    .line 1635
    move-result-object v6

    .line 1636
    invoke-virtual {v4, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1637
    .line 1638
    .line 1639
    move-result v6

    .line 1640
    if-eqz v6, :cond_21

    .line 1641
    .line 1642
    monitor-exit v5

    .line 1643
    goto :goto_16

    .line 1644
    :catchall_7
    move-exception v0

    .line 1645
    move-object p0, v0

    .line 1646
    goto :goto_17

    .line 1647
    :cond_21
    iget-object v0, v0, Lb81/a;->f:Ljava/lang/Object;

    .line 1648
    .line 1649
    check-cast v0, Ljava/util/Map;

    .line 1650
    .line 1651
    invoke-interface {v0, v1, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1652
    .line 1653
    .line 1654
    monitor-exit v5
    :try_end_14
    .catchall {:try_start_14 .. :try_end_14} :catchall_7

    .line 1655
    new-instance v0, Landroid/os/Bundle;

    .line 1656
    .line 1657
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 1658
    .line 1659
    .line 1660
    const-string v5, "arm_key"

    .line 1661
    .line 1662
    invoke-virtual {v0, v5, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 1663
    .line 1664
    .line 1665
    const-string v5, "arm_value"

    .line 1666
    .line 1667
    invoke-virtual {p0, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1668
    .line 1669
    .line 1670
    move-result-object p0

    .line 1671
    invoke-virtual {v0, v5, p0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 1672
    .line 1673
    .line 1674
    const-string p0, "personalization_id"

    .line 1675
    .line 1676
    const-string v1, "personalizationId"

    .line 1677
    .line 1678
    invoke-virtual {v2, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1679
    .line 1680
    .line 1681
    move-result-object v1

    .line 1682
    invoke-virtual {v0, p0, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 1683
    .line 1684
    .line 1685
    const-string p0, "arm_index"

    .line 1686
    .line 1687
    const-string v1, "armIndex"

    .line 1688
    .line 1689
    const/4 v5, -0x1

    .line 1690
    invoke-virtual {v2, v1, v5}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    .line 1691
    .line 1692
    .line 1693
    move-result v1

    .line 1694
    invoke-virtual {v0, p0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 1695
    .line 1696
    .line 1697
    const-string p0, "group"

    .line 1698
    .line 1699
    const-string v1, "group"

    .line 1700
    .line 1701
    invoke-virtual {v2, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1702
    .line 1703
    .line 1704
    move-result-object v1

    .line 1705
    invoke-virtual {v0, p0, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 1706
    .line 1707
    .line 1708
    const-string p0, "fp"

    .line 1709
    .line 1710
    const-string v1, "personalization_assignment"

    .line 1711
    .line 1712
    check-cast v3, Lwr/c;

    .line 1713
    .line 1714
    invoke-virtual {v3, p0, v1, v0}, Lwr/c;->a(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 1715
    .line 1716
    .line 1717
    new-instance p0, Landroid/os/Bundle;

    .line 1718
    .line 1719
    invoke-direct {p0}, Landroid/os/Bundle;-><init>()V

    .line 1720
    .line 1721
    .line 1722
    const-string v0, "_fpid"

    .line 1723
    .line 1724
    invoke-virtual {p0, v0, v4}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 1725
    .line 1726
    .line 1727
    const-string v0, "fp"

    .line 1728
    .line 1729
    const-string v1, "_fpc"

    .line 1730
    .line 1731
    invoke-virtual {v3, v0, v1, p0}, Lwr/c;->a(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 1732
    .line 1733
    .line 1734
    :goto_16
    return-void

    .line 1735
    :goto_17
    :try_start_15
    monitor-exit v5
    :try_end_15
    .catchall {:try_start_15 .. :try_end_15} :catchall_7

    .line 1736
    throw p0

    .line 1737
    :pswitch_16
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 1738
    .line 1739
    check-cast v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;

    .line 1740
    .line 1741
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 1742
    .line 1743
    check-cast v1, Lay0/k;

    .line 1744
    .line 1745
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 1746
    .line 1747
    check-cast p0, Landroid/content/Context;

    .line 1748
    .line 1749
    invoke-static {v0, v1, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->a(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;Lay0/k;Landroid/content/Context;)V

    .line 1750
    .line 1751
    .line 1752
    return-void

    .line 1753
    :pswitch_17
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 1754
    .line 1755
    check-cast v0, Lcom/google/firebase/messaging/g;

    .line 1756
    .line 1757
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 1758
    .line 1759
    check-cast v1, Landroid/content/Intent;

    .line 1760
    .line 1761
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 1762
    .line 1763
    check-cast p0, Laq/k;

    .line 1764
    .line 1765
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1766
    .line 1767
    .line 1768
    :try_start_16
    invoke-virtual {v0, v1}, Lcom/google/firebase/messaging/g;->handleIntent(Landroid/content/Intent;)V
    :try_end_16
    .catchall {:try_start_16 .. :try_end_16} :catchall_8

    .line 1769
    .line 1770
    .line 1771
    invoke-virtual {p0, v4}, Laq/k;->b(Ljava/lang/Object;)V

    .line 1772
    .line 1773
    .line 1774
    return-void

    .line 1775
    :catchall_8
    move-exception v0

    .line 1776
    invoke-virtual {p0, v4}, Laq/k;->b(Ljava/lang/Object;)V

    .line 1777
    .line 1778
    .line 1779
    throw v0

    .line 1780
    :pswitch_18
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 1781
    .line 1782
    check-cast v0, Landroidx/fragment/app/g2;

    .line 1783
    .line 1784
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 1785
    .line 1786
    check-cast v1, Landroidx/fragment/app/g2;

    .line 1787
    .line 1788
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 1789
    .line 1790
    check-cast p0, Landroidx/fragment/app/p;

    .line 1791
    .line 1792
    iget-object v0, v0, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 1793
    .line 1794
    iget-object v1, v1, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 1795
    .line 1796
    iget-boolean p0, p0, Landroidx/fragment/app/p;->o:Z

    .line 1797
    .line 1798
    sget-object v2, Landroidx/fragment/app/u1;->a:Landroidx/fragment/app/z1;

    .line 1799
    .line 1800
    const-string v2, "inFragment"

    .line 1801
    .line 1802
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1803
    .line 1804
    .line 1805
    const-string v2, "outFragment"

    .line 1806
    .line 1807
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1808
    .line 1809
    .line 1810
    if-eqz p0, :cond_22

    .line 1811
    .line 1812
    invoke-virtual {v1}, Landroidx/fragment/app/j0;->getEnterTransitionCallback()Landroidx/core/app/l0;

    .line 1813
    .line 1814
    .line 1815
    goto :goto_18

    .line 1816
    :cond_22
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getEnterTransitionCallback()Landroidx/core/app/l0;

    .line 1817
    .line 1818
    .line 1819
    :goto_18
    return-void

    .line 1820
    :pswitch_19
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 1821
    .line 1822
    check-cast v0, Landroid/view/ViewGroup;

    .line 1823
    .line 1824
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 1825
    .line 1826
    check-cast v1, Landroid/view/View;

    .line 1827
    .line 1828
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 1829
    .line 1830
    check-cast p0, Landroidx/fragment/app/e;

    .line 1831
    .line 1832
    const-string v2, "$container"

    .line 1833
    .line 1834
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1835
    .line 1836
    .line 1837
    const-string v2, "this$0"

    .line 1838
    .line 1839
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1840
    .line 1841
    .line 1842
    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->endViewTransition(Landroid/view/View;)V

    .line 1843
    .line 1844
    .line 1845
    iget-object v0, p0, Landroidx/fragment/app/e;->c:Landroidx/fragment/app/f;

    .line 1846
    .line 1847
    iget-object v0, v0, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 1848
    .line 1849
    invoke-virtual {v0, p0}, Landroidx/fragment/app/g2;->c(Landroidx/fragment/app/f2;)V

    .line 1850
    .line 1851
    .line 1852
    return-void

    .line 1853
    :pswitch_1a
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 1854
    .line 1855
    check-cast v0, La8/f1;

    .line 1856
    .line 1857
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 1858
    .line 1859
    check-cast v1, Landroid/util/Pair;

    .line 1860
    .line 1861
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 1862
    .line 1863
    check-cast p0, Lh8/x;

    .line 1864
    .line 1865
    iget-object v0, v0, La8/f1;->e:Lac/i;

    .line 1866
    .line 1867
    iget-object v0, v0, Lac/i;->i:Ljava/lang/Object;

    .line 1868
    .line 1869
    check-cast v0, Lb8/e;

    .line 1870
    .line 1871
    iget-object v2, v1, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 1872
    .line 1873
    check-cast v2, Ljava/lang/Integer;

    .line 1874
    .line 1875
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1876
    .line 1877
    .line 1878
    move-result v2

    .line 1879
    iget-object v1, v1, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 1880
    .line 1881
    check-cast v1, Lh8/b0;

    .line 1882
    .line 1883
    invoke-virtual {v0, v2, v1, p0}, Lb8/e;->d(ILh8/b0;Lh8/x;)V

    .line 1884
    .line 1885
    .line 1886
    return-void

    .line 1887
    :pswitch_1b
    iget-object v0, p0, La8/y0;->e:Ljava/lang/Object;

    .line 1888
    .line 1889
    check-cast v0, La8/z0;

    .line 1890
    .line 1891
    iget-object v1, p0, La8/y0;->f:Ljava/lang/Object;

    .line 1892
    .line 1893
    check-cast v1, Lhr/e0;

    .line 1894
    .line 1895
    iget-object p0, p0, La8/y0;->g:Ljava/lang/Object;

    .line 1896
    .line 1897
    check-cast p0, Lh8/b0;

    .line 1898
    .line 1899
    iget-object v0, v0, La8/z0;->c:Lb8/e;

    .line 1900
    .line 1901
    invoke-virtual {v1}, Lhr/e0;->i()Lhr/x0;

    .line 1902
    .line 1903
    .line 1904
    move-result-object v1

    .line 1905
    iget-object v2, v0, Lb8/e;->g:Lin/z1;

    .line 1906
    .line 1907
    iget-object v0, v0, Lb8/e;->j:Lt7/l0;

    .line 1908
    .line 1909
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1910
    .line 1911
    .line 1912
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1913
    .line 1914
    .line 1915
    invoke-static {v1}, Lhr/h0;->p(Ljava/util/Collection;)Lhr/h0;

    .line 1916
    .line 1917
    .line 1918
    move-result-object v4

    .line 1919
    iput-object v4, v2, Lin/z1;->b:Ljava/lang/Object;

    .line 1920
    .line 1921
    invoke-virtual {v1}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 1922
    .line 1923
    .line 1924
    move-result v4

    .line 1925
    if-nez v4, :cond_23

    .line 1926
    .line 1927
    invoke-virtual {v1, v3}, Lhr/x0;->get(I)Ljava/lang/Object;

    .line 1928
    .line 1929
    .line 1930
    move-result-object v1

    .line 1931
    check-cast v1, Lh8/b0;

    .line 1932
    .line 1933
    iput-object v1, v2, Lin/z1;->e:Ljava/lang/Object;

    .line 1934
    .line 1935
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1936
    .line 1937
    .line 1938
    iput-object p0, v2, Lin/z1;->f:Ljava/lang/Object;

    .line 1939
    .line 1940
    :cond_23
    iget-object p0, v2, Lin/z1;->d:Ljava/lang/Object;

    .line 1941
    .line 1942
    check-cast p0, Lh8/b0;

    .line 1943
    .line 1944
    if-nez p0, :cond_24

    .line 1945
    .line 1946
    iget-object p0, v2, Lin/z1;->b:Ljava/lang/Object;

    .line 1947
    .line 1948
    check-cast p0, Lhr/h0;

    .line 1949
    .line 1950
    iget-object v1, v2, Lin/z1;->e:Ljava/lang/Object;

    .line 1951
    .line 1952
    check-cast v1, Lh8/b0;

    .line 1953
    .line 1954
    iget-object v3, v2, Lin/z1;->a:Ljava/lang/Object;

    .line 1955
    .line 1956
    check-cast v3, Lt7/n0;

    .line 1957
    .line 1958
    invoke-static {v0, p0, v1, v3}, Lin/z1;->C(Lt7/l0;Lhr/h0;Lh8/b0;Lt7/n0;)Lh8/b0;

    .line 1959
    .line 1960
    .line 1961
    move-result-object p0

    .line 1962
    iput-object p0, v2, Lin/z1;->d:Ljava/lang/Object;

    .line 1963
    .line 1964
    :cond_24
    check-cast v0, La8/i0;

    .line 1965
    .line 1966
    invoke-virtual {v0}, La8/i0;->k0()Lt7/p0;

    .line 1967
    .line 1968
    .line 1969
    move-result-object p0

    .line 1970
    invoke-virtual {v2, p0}, Lin/z1;->h0(Lt7/p0;)V

    .line 1971
    .line 1972
    .line 1973
    return-void

    .line 1974
    nop

    .line 1975
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
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
