.class public final Lu/t;
.super Landroid/hardware/camera2/CameraDevice$StateCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Ly4/h;

.field public final synthetic b:Lu/y;


# direct methods
.method public constructor <init>(Lu/y;Ly4/h;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lu/t;->b:Lu/y;

    .line 2
    .line 3
    iput-object p2, p0, Lu/t;->a:Ly4/h;

    .line 4
    .line 5
    invoke-direct {p0}, Landroid/hardware/camera2/CameraDevice$StateCallback;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onClosed(Landroid/hardware/camera2/CameraDevice;)V
    .locals 2

    .line 1
    iget-object p1, p0, Lu/t;->b:Lu/y;

    .line 2
    .line 3
    const-string v0, "openCameraConfigAndClose camera closed"

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {p1, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lu/t;->a:Ly4/h;

    .line 10
    .line 11
    invoke-virtual {p0, v1}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final onDisconnected(Landroid/hardware/camera2/CameraDevice;)V
    .locals 2

    .line 1
    iget-object p1, p0, Lu/t;->b:Lu/y;

    .line 2
    .line 3
    const-string v0, "openCameraConfigAndClose camera disconnected"

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {p1, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lu/t;->a:Ly4/h;

    .line 10
    .line 11
    invoke-virtual {p0, v1}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final onError(Landroid/hardware/camera2/CameraDevice;I)V
    .locals 1

    .line 1
    new-instance p1, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v0, "openCameraConfigAndClose camera error "

    .line 4
    .line 5
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iget-object p2, p0, Lu/t;->b:Lu/y;

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    invoke-virtual {p2, p1, v0}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lu/t;->a:Ly4/h;

    .line 22
    .line 23
    invoke-virtual {p0, v0}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final onOpened(Landroid/hardware/camera2/CameraDevice;)V
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v0, v0, Lu/t;->b:Lu/y;

    .line 6
    .line 7
    iget-object v2, v0, Lu/y;->f:Lj0/h;

    .line 8
    .line 9
    const-string v3, "openCameraConfigAndClose camera opened"

    .line 10
    .line 11
    const/4 v4, 0x0

    .line 12
    invoke-virtual {v0, v3, v4}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 13
    .line 14
    .line 15
    new-instance v3, Lu/p0;

    .line 16
    .line 17
    iget-object v5, v0, Lu/y;->L:Lpv/g;

    .line 18
    .line 19
    new-instance v6, Ld01/x;

    .line 20
    .line 21
    sget-object v7, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 22
    .line 23
    invoke-direct {v6, v7}, Ld01/x;-><init>(Ljava/util/List;)V

    .line 24
    .line 25
    .line 26
    const/4 v7, 0x0

    .line 27
    invoke-direct {v3, v5, v6, v7}, Lu/p0;-><init>(Lpv/g;Ld01/x;Z)V

    .line 28
    .line 29
    .line 30
    new-instance v5, Landroid/graphics/SurfaceTexture;

    .line 31
    .line 32
    invoke-direct {v5, v7}, Landroid/graphics/SurfaceTexture;-><init>(I)V

    .line 33
    .line 34
    .line 35
    const/16 v6, 0x280

    .line 36
    .line 37
    const/16 v7, 0x1e0

    .line 38
    .line 39
    invoke-virtual {v5, v6, v7}, Landroid/graphics/SurfaceTexture;->setDefaultBufferSize(II)V

    .line 40
    .line 41
    .line 42
    new-instance v6, Landroid/view/Surface;

    .line 43
    .line 44
    invoke-direct {v6, v5}, Landroid/view/Surface;-><init>(Landroid/graphics/SurfaceTexture;)V

    .line 45
    .line 46
    .line 47
    new-instance v7, Lb0/u1;

    .line 48
    .line 49
    invoke-direct {v7, v6}, Lb0/u1;-><init>(Landroid/view/Surface;)V

    .line 50
    .line 51
    .line 52
    iget-object v8, v7, Lh0/t0;->e:Ly4/k;

    .line 53
    .line 54
    invoke-static {v8}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 55
    .line 56
    .line 57
    move-result-object v8

    .line 58
    new-instance v9, Lno/nordicsemi/android/ble/o0;

    .line 59
    .line 60
    const/16 v10, 0xf

    .line 61
    .line 62
    invoke-direct {v9, v10, v6, v5}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    invoke-interface {v8, v5, v9}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 70
    .line 71
    .line 72
    new-instance v5, Ljava/util/LinkedHashSet;

    .line 73
    .line 74
    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 75
    .line 76
    .line 77
    new-instance v6, Ljava/util/HashSet;

    .line 78
    .line 79
    invoke-direct {v6}, Ljava/util/HashSet;-><init>()V

    .line 80
    .line 81
    .line 82
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 83
    .line 84
    .line 85
    move-result-object v8

    .line 86
    new-instance v9, Ljava/util/ArrayList;

    .line 87
    .line 88
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 89
    .line 90
    .line 91
    invoke-static {}, Lh0/k1;->a()Lh0/k1;

    .line 92
    .line 93
    .line 94
    move-result-object v10

    .line 95
    new-instance v11, Ljava/util/ArrayList;

    .line 96
    .line 97
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 98
    .line 99
    .line 100
    new-instance v12, Ljava/util/ArrayList;

    .line 101
    .line 102
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 103
    .line 104
    .line 105
    new-instance v13, Ljava/util/ArrayList;

    .line 106
    .line 107
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 108
    .line 109
    .line 110
    invoke-static {v7}, Lh0/i;->a(Lh0/t0;)Landroidx/lifecycle/c1;

    .line 111
    .line 112
    .line 113
    move-result-object v14

    .line 114
    sget-object v15, Lb0/y;->d:Lb0/y;

    .line 115
    .line 116
    iput-object v15, v14, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 117
    .line 118
    invoke-virtual {v14}, Landroidx/lifecycle/c1;->h()Lh0/i;

    .line 119
    .line 120
    .line 121
    move-result-object v14

    .line 122
    invoke-interface {v5, v14}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    const-string v14, "Start configAndClose."

    .line 126
    .line 127
    invoke-virtual {v0, v14, v4}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 128
    .line 129
    .line 130
    new-instance v15, Lh0/z1;

    .line 131
    .line 132
    new-instance v4, Ljava/util/ArrayList;

    .line 133
    .line 134
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 135
    .line 136
    .line 137
    new-instance v5, Ljava/util/ArrayList;

    .line 138
    .line 139
    invoke-direct {v5, v11}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 140
    .line 141
    .line 142
    new-instance v11, Ljava/util/ArrayList;

    .line 143
    .line 144
    invoke-direct {v11, v12}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 145
    .line 146
    .line 147
    new-instance v12, Ljava/util/ArrayList;

    .line 148
    .line 149
    invoke-direct {v12, v13}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 150
    .line 151
    .line 152
    new-instance v16, Lh0/o0;

    .line 153
    .line 154
    new-instance v13, Ljava/util/ArrayList;

    .line 155
    .line 156
    invoke-direct {v13, v6}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 157
    .line 158
    .line 159
    invoke-static {v8}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 160
    .line 161
    .line 162
    move-result-object v18

    .line 163
    new-instance v6, Ljava/util/ArrayList;

    .line 164
    .line 165
    invoke-direct {v6, v9}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 166
    .line 167
    .line 168
    sget-object v8, Lh0/j2;->b:Lh0/j2;

    .line 169
    .line 170
    new-instance v8, Landroid/util/ArrayMap;

    .line 171
    .line 172
    invoke-direct {v8}, Landroid/util/ArrayMap;-><init>()V

    .line 173
    .line 174
    .line 175
    iget-object v9, v10, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 176
    .line 177
    invoke-virtual {v9}, Landroid/util/ArrayMap;->keySet()Ljava/util/Set;

    .line 178
    .line 179
    .line 180
    move-result-object v10

    .line 181
    invoke-interface {v10}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 182
    .line 183
    .line 184
    move-result-object v10

    .line 185
    :goto_0
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 186
    .line 187
    .line 188
    move-result v14

    .line 189
    if-eqz v14, :cond_0

    .line 190
    .line 191
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v14

    .line 195
    check-cast v14, Ljava/lang/String;

    .line 196
    .line 197
    move-object/from16 p0, v4

    .line 198
    .line 199
    invoke-virtual {v9, v14}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v4

    .line 203
    invoke-virtual {v8, v14, v4}, Landroid/util/ArrayMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-object/from16 v4, p0

    .line 207
    .line 208
    goto :goto_0

    .line 209
    :cond_0
    move-object/from16 p0, v4

    .line 210
    .line 211
    new-instance v4, Lh0/j2;

    .line 212
    .line 213
    invoke-direct {v4, v8}, Lh0/j2;-><init>(Landroid/util/ArrayMap;)V

    .line 214
    .line 215
    .line 216
    const/16 v19, 0x1

    .line 217
    .line 218
    const/16 v21, 0x0

    .line 219
    .line 220
    const/16 v23, 0x0

    .line 221
    .line 222
    move-object/from16 v22, v4

    .line 223
    .line 224
    move-object/from16 v20, v6

    .line 225
    .line 226
    move-object/from16 v17, v13

    .line 227
    .line 228
    invoke-direct/range {v16 .. v23}, Lh0/o0;-><init>(Ljava/util/ArrayList;Lh0/n1;ILjava/util/ArrayList;ZLh0/j2;Lh0/s;)V

    .line 229
    .line 230
    .line 231
    const/16 v21, 0x0

    .line 232
    .line 233
    const/16 v22, 0x0

    .line 234
    .line 235
    const/16 v23, 0x0

    .line 236
    .line 237
    const/16 v24, 0x0

    .line 238
    .line 239
    move-object/from16 v17, v5

    .line 240
    .line 241
    move-object/from16 v18, v11

    .line 242
    .line 243
    move-object/from16 v19, v12

    .line 244
    .line 245
    move-object/from16 v20, v16

    .line 246
    .line 247
    move-object/from16 v16, p0

    .line 248
    .line 249
    invoke-direct/range {v15 .. v24}, Lh0/z1;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Lh0/o0;Lh0/x1;Landroid/hardware/camera2/params/InputConfiguration;ILh0/i;)V

    .line 250
    .line 251
    .line 252
    iget-object v0, v0, Lu/y;->F:Lin/z1;

    .line 253
    .line 254
    new-instance v8, Lu/g1;

    .line 255
    .line 256
    iget-object v4, v0, Lin/z1;->e:Ljava/lang/Object;

    .line 257
    .line 258
    move-object v9, v4

    .line 259
    check-cast v9, Ld01/x;

    .line 260
    .line 261
    iget-object v4, v0, Lin/z1;->f:Ljava/lang/Object;

    .line 262
    .line 263
    move-object v10, v4

    .line 264
    check-cast v10, Ld01/x;

    .line 265
    .line 266
    iget-object v4, v0, Lin/z1;->d:Ljava/lang/Object;

    .line 267
    .line 268
    move-object v11, v4

    .line 269
    check-cast v11, Lu/x0;

    .line 270
    .line 271
    iget-object v4, v0, Lin/z1;->a:Ljava/lang/Object;

    .line 272
    .line 273
    move-object v12, v4

    .line 274
    check-cast v12, Lj0/h;

    .line 275
    .line 276
    iget-object v4, v0, Lin/z1;->b:Ljava/lang/Object;

    .line 277
    .line 278
    move-object v13, v4

    .line 279
    check-cast v13, Lj0/c;

    .line 280
    .line 281
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 282
    .line 283
    move-object v14, v0

    .line 284
    check-cast v14, Landroid/os/Handler;

    .line 285
    .line 286
    invoke-direct/range {v8 .. v14}, Lu/g1;-><init>(Ld01/x;Ld01/x;Lu/x0;Lj0/h;Lj0/c;Landroid/os/Handler;)V

    .line 287
    .line 288
    .line 289
    invoke-virtual {v3, v15, v1, v8}, Lu/p0;->m(Lh0/z1;Landroid/hardware/camera2/CameraDevice;Lu/g1;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 290
    .line 291
    .line 292
    move-result-object v0

    .line 293
    new-instance v4, Lk0/e;

    .line 294
    .line 295
    const/4 v5, 0x1

    .line 296
    invoke-direct {v4, v0, v5}, Lk0/e;-><init>(Lcom/google/common/util/concurrent/ListenableFuture;I)V

    .line 297
    .line 298
    .line 299
    invoke-static {v4}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 300
    .line 301
    .line 302
    move-result-object v0

    .line 303
    invoke-static {v0}, Lk0/d;->b(Lcom/google/common/util/concurrent/ListenableFuture;)Lk0/d;

    .line 304
    .line 305
    .line 306
    move-result-object v0

    .line 307
    new-instance v4, La0/h;

    .line 308
    .line 309
    const/16 v5, 0x19

    .line 310
    .line 311
    invoke-direct {v4, v5, v3, v7}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 312
    .line 313
    .line 314
    invoke-static {v0, v4, v2}, Lk0/h;->g(Lcom/google/common/util/concurrent/ListenableFuture;Lk0/a;Ljava/util/concurrent/Executor;)Lk0/b;

    .line 315
    .line 316
    .line 317
    move-result-object v0

    .line 318
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    new-instance v3, Lm8/o;

    .line 322
    .line 323
    const/16 v4, 0xd

    .line 324
    .line 325
    invoke-direct {v3, v1, v4}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 326
    .line 327
    .line 328
    invoke-virtual {v0, v2, v3}, Lk0/d;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 329
    .line 330
    .line 331
    return-void
.end method
