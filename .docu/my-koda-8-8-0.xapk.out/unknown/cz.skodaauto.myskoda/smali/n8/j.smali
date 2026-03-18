.class public final Ln8/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/opengl/GLSurfaceView$Renderer;
.implements Ln8/c;


# instance fields
.field public final d:Ln8/i;

.field public final e:[F

.field public final f:[F

.field public final g:[F

.field public final h:[F

.field public final i:[F

.field public j:F

.field public k:F

.field public final l:[F

.field public final m:[F

.field public final synthetic n:Ln8/k;


# direct methods
.method public constructor <init>(Ln8/k;Ln8/i;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln8/j;->n:Ln8/k;

    .line 5
    .line 6
    const/16 p1, 0x10

    .line 7
    .line 8
    new-array v0, p1, [F

    .line 9
    .line 10
    iput-object v0, p0, Ln8/j;->e:[F

    .line 11
    .line 12
    new-array v0, p1, [F

    .line 13
    .line 14
    iput-object v0, p0, Ln8/j;->f:[F

    .line 15
    .line 16
    new-array v0, p1, [F

    .line 17
    .line 18
    iput-object v0, p0, Ln8/j;->g:[F

    .line 19
    .line 20
    new-array v1, p1, [F

    .line 21
    .line 22
    iput-object v1, p0, Ln8/j;->h:[F

    .line 23
    .line 24
    new-array v2, p1, [F

    .line 25
    .line 26
    iput-object v2, p0, Ln8/j;->i:[F

    .line 27
    .line 28
    new-array v3, p1, [F

    .line 29
    .line 30
    iput-object v3, p0, Ln8/j;->l:[F

    .line 31
    .line 32
    new-array p1, p1, [F

    .line 33
    .line 34
    iput-object p1, p0, Ln8/j;->m:[F

    .line 35
    .line 36
    iput-object p2, p0, Ln8/j;->d:Ln8/i;

    .line 37
    .line 38
    const/4 p1, 0x0

    .line 39
    invoke-static {v0, p1}, Landroid/opengl/Matrix;->setIdentityM([FI)V

    .line 40
    .line 41
    .line 42
    invoke-static {v1, p1}, Landroid/opengl/Matrix;->setIdentityM([FI)V

    .line 43
    .line 44
    .line 45
    invoke-static {v2, p1}, Landroid/opengl/Matrix;->setIdentityM([FI)V

    .line 46
    .line 47
    .line 48
    const p1, 0x40490fdb    # (float)Math.PI

    .line 49
    .line 50
    .line 51
    iput p1, p0, Ln8/j;->k:F

    .line 52
    .line 53
    return-void
.end method


# virtual methods
.method public final declared-synchronized a(F[F)V
    .locals 6

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Ln8/j;->g:[F

    .line 3
    .line 4
    array-length v1, v0

    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-static {p2, v2, v0, v2, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 7
    .line 8
    .line 9
    neg-float p1, p1

    .line 10
    iput p1, p0, Ln8/j;->k:F

    .line 11
    .line 12
    iget-object v0, p0, Ln8/j;->h:[F

    .line 13
    .line 14
    iget p2, p0, Ln8/j;->j:F

    .line 15
    .line 16
    neg-float v2, p2

    .line 17
    float-to-double p1, p1

    .line 18
    invoke-static {p1, p2}, Ljava/lang/Math;->cos(D)D

    .line 19
    .line 20
    .line 21
    move-result-wide p1

    .line 22
    double-to-float v3, p1

    .line 23
    iget p1, p0, Ln8/j;->k:F

    .line 24
    .line 25
    float-to-double p1, p1

    .line 26
    invoke-static {p1, p2}, Ljava/lang/Math;->sin(D)D

    .line 27
    .line 28
    .line 29
    move-result-wide p1

    .line 30
    double-to-float v4, p1

    .line 31
    const/4 v5, 0x0

    .line 32
    const/4 v1, 0x0

    .line 33
    invoke-static/range {v0 .. v5}, Landroid/opengl/Matrix;->setRotateM([FIFFFF)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    .line 35
    .line 36
    monitor-exit p0

    .line 37
    return-void

    .line 38
    :catchall_0
    move-exception v0

    .line 39
    move-object p1, v0

    .line 40
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 41
    throw p1
.end method

.method public final onDrawFrame(Ljavax/microedition/khronos/opengles/GL10;)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    iget-object v2, v1, Ln8/j;->m:[F

    .line 5
    .line 6
    iget-object v4, v1, Ln8/j;->g:[F

    .line 7
    .line 8
    iget-object v6, v1, Ln8/j;->i:[F

    .line 9
    .line 10
    const/4 v7, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    const/4 v5, 0x0

    .line 13
    invoke-static/range {v2 .. v7}, Landroid/opengl/Matrix;->multiplyMM([FI[FI[FI)V

    .line 14
    .line 15
    .line 16
    iget-object v8, v1, Ln8/j;->l:[F

    .line 17
    .line 18
    iget-object v10, v1, Ln8/j;->h:[F

    .line 19
    .line 20
    iget-object v12, v1, Ln8/j;->m:[F

    .line 21
    .line 22
    const/4 v13, 0x0

    .line 23
    const/4 v9, 0x0

    .line 24
    const/4 v11, 0x0

    .line 25
    invoke-static/range {v8 .. v13}, Landroid/opengl/Matrix;->multiplyMM([FI[FI[FI)V

    .line 26
    .line 27
    .line 28
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 29
    iget-object v2, v1, Ln8/j;->f:[F

    .line 30
    .line 31
    iget-object v4, v1, Ln8/j;->e:[F

    .line 32
    .line 33
    iget-object v6, v1, Ln8/j;->l:[F

    .line 34
    .line 35
    const/4 v7, 0x0

    .line 36
    const/4 v3, 0x0

    .line 37
    const/4 v5, 0x0

    .line 38
    invoke-static/range {v2 .. v7}, Landroid/opengl/Matrix;->multiplyMM([FI[FI[FI)V

    .line 39
    .line 40
    .line 41
    iget-object v2, v1, Ln8/j;->d:Ln8/i;

    .line 42
    .line 43
    iget-object v5, v1, Ln8/j;->f:[F

    .line 44
    .line 45
    const/16 v0, 0x4000

    .line 46
    .line 47
    invoke-static {v0}, Landroid/opengl/GLES20;->glClear(I)V

    .line 48
    .line 49
    .line 50
    :try_start_1
    invoke-static {}, Lw7/a;->e()V
    :try_end_1
    .catch Lw7/h; {:try_start_1 .. :try_end_1} :catch_0

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :catch_0
    move-exception v0

    .line 55
    const-string v1, "SceneRenderer"

    .line 56
    .line 57
    const-string v3, "Failed to draw a frame"

    .line 58
    .line 59
    invoke-static {v1, v3, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 60
    .line 61
    .line 62
    :goto_0
    iget-object v0, v2, Ln8/i;->d:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 63
    .line 64
    const/4 v1, 0x1

    .line 65
    const/4 v9, 0x0

    .line 66
    invoke-virtual {v0, v1, v9}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    const/4 v10, 0x2

    .line 71
    if-eqz v0, :cond_7

    .line 72
    .line 73
    iget-object v0, v2, Ln8/i;->m:Landroid/graphics/SurfaceTexture;

    .line 74
    .line 75
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0}, Landroid/graphics/SurfaceTexture;->updateTexImage()V

    .line 79
    .line 80
    .line 81
    :try_start_2
    invoke-static {}, Lw7/a;->e()V
    :try_end_2
    .catch Lw7/h; {:try_start_2 .. :try_end_2} :catch_1

    .line 82
    .line 83
    .line 84
    goto :goto_1

    .line 85
    :catch_1
    move-exception v0

    .line 86
    const-string v3, "SceneRenderer"

    .line 87
    .line 88
    const-string v4, "Failed to draw a frame"

    .line 89
    .line 90
    invoke-static {v3, v4, v0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 91
    .line 92
    .line 93
    :goto_1
    iget-object v0, v2, Ln8/i;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 94
    .line 95
    invoke-virtual {v0, v1, v9}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    if-eqz v0, :cond_0

    .line 100
    .line 101
    iget-object v0, v2, Ln8/i;->j:[F

    .line 102
    .line 103
    invoke-static {v0, v9}, Landroid/opengl/Matrix;->setIdentityM([FI)V

    .line 104
    .line 105
    .line 106
    :cond_0
    iget-object v0, v2, Ln8/i;->m:Landroid/graphics/SurfaceTexture;

    .line 107
    .line 108
    invoke-virtual {v0}, Landroid/graphics/SurfaceTexture;->getTimestamp()J

    .line 109
    .line 110
    .line 111
    move-result-wide v3

    .line 112
    iget-object v6, v2, Ln8/i;->h:Li4/c;

    .line 113
    .line 114
    monitor-enter v6

    .line 115
    :try_start_3
    invoke-virtual {v6, v3, v4, v9}, Li4/c;->I(JZ)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 119
    monitor-exit v6

    .line 120
    check-cast v0, Ljava/lang/Long;

    .line 121
    .line 122
    if-eqz v0, :cond_4

    .line 123
    .line 124
    iget-object v6, v2, Ln8/i;->g:La8/b;

    .line 125
    .line 126
    iget-object v11, v2, Ln8/i;->j:[F

    .line 127
    .line 128
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 129
    .line 130
    .line 131
    move-result-wide v7

    .line 132
    iget-object v0, v6, La8/b;->h:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast v0, Li4/c;

    .line 135
    .line 136
    invoke-virtual {v0, v7, v8}, Li4/c;->K(J)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    check-cast v0, [F

    .line 141
    .line 142
    if-nez v0, :cond_1

    .line 143
    .line 144
    goto :goto_3

    .line 145
    :cond_1
    iget-object v7, v6, La8/b;->g:Ljava/lang/Object;

    .line 146
    .line 147
    move-object v12, v7

    .line 148
    check-cast v12, [F

    .line 149
    .line 150
    aget v7, v0, v9

    .line 151
    .line 152
    aget v8, v0, v1

    .line 153
    .line 154
    neg-float v8, v8

    .line 155
    aget v0, v0, v10

    .line 156
    .line 157
    neg-float v0, v0

    .line 158
    invoke-static {v7, v8, v0}, Landroid/opengl/Matrix;->length(FFF)F

    .line 159
    .line 160
    .line 161
    move-result v13

    .line 162
    const/4 v14, 0x0

    .line 163
    cmpl-float v14, v13, v14

    .line 164
    .line 165
    if-eqz v14, :cond_2

    .line 166
    .line 167
    float-to-double v14, v13

    .line 168
    invoke-static {v14, v15}, Ljava/lang/Math;->toDegrees(D)D

    .line 169
    .line 170
    .line 171
    move-result-wide v14

    .line 172
    double-to-float v14, v14

    .line 173
    div-float v15, v7, v13

    .line 174
    .line 175
    div-float v16, v8, v13

    .line 176
    .line 177
    div-float v17, v0, v13

    .line 178
    .line 179
    const/4 v13, 0x0

    .line 180
    invoke-static/range {v12 .. v17}, Landroid/opengl/Matrix;->setRotateM([FIFFFF)V

    .line 181
    .line 182
    .line 183
    goto :goto_2

    .line 184
    :cond_2
    invoke-static {v12, v9}, Landroid/opengl/Matrix;->setIdentityM([FI)V

    .line 185
    .line 186
    .line 187
    :goto_2
    iget-boolean v0, v6, La8/b;->e:Z

    .line 188
    .line 189
    if-nez v0, :cond_3

    .line 190
    .line 191
    iget-object v0, v6, La8/b;->f:Ljava/lang/Object;

    .line 192
    .line 193
    check-cast v0, [F

    .line 194
    .line 195
    iget-object v7, v6, La8/b;->g:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast v7, [F

    .line 198
    .line 199
    invoke-static {v0, v7}, La8/b;->f([F[F)V

    .line 200
    .line 201
    .line 202
    iput-boolean v1, v6, La8/b;->e:Z

    .line 203
    .line 204
    :cond_3
    iget-object v0, v6, La8/b;->f:Ljava/lang/Object;

    .line 205
    .line 206
    move-object v13, v0

    .line 207
    check-cast v13, [F

    .line 208
    .line 209
    iget-object v0, v6, La8/b;->g:Ljava/lang/Object;

    .line 210
    .line 211
    move-object v15, v0

    .line 212
    check-cast v15, [F

    .line 213
    .line 214
    const/16 v16, 0x0

    .line 215
    .line 216
    const/4 v12, 0x0

    .line 217
    const/4 v14, 0x0

    .line 218
    invoke-static/range {v11 .. v16}, Landroid/opengl/Matrix;->multiplyMM([FI[FI[FI)V

    .line 219
    .line 220
    .line 221
    :cond_4
    :goto_3
    iget-object v0, v2, Ln8/i;->i:Li4/c;

    .line 222
    .line 223
    invoke-virtual {v0, v3, v4}, Li4/c;->K(J)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v0

    .line 227
    check-cast v0, Ln8/f;

    .line 228
    .line 229
    if-eqz v0, :cond_7

    .line 230
    .line 231
    iget-object v3, v2, Ln8/i;->f:Ln8/g;

    .line 232
    .line 233
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 234
    .line 235
    .line 236
    invoke-static {v0}, Ln8/g;->b(Ln8/f;)Z

    .line 237
    .line 238
    .line 239
    move-result v4

    .line 240
    if-nez v4, :cond_5

    .line 241
    .line 242
    goto :goto_4

    .line 243
    :cond_5
    iget v4, v0, Ln8/f;->c:I

    .line 244
    .line 245
    iput v4, v3, Ln8/g;->a:I

    .line 246
    .line 247
    new-instance v4, Li4/c;

    .line 248
    .line 249
    iget-object v6, v0, Ln8/f;->a:Ln8/e;

    .line 250
    .line 251
    iget-object v6, v6, Ln8/e;->a:[Li4/c;

    .line 252
    .line 253
    aget-object v6, v6, v9

    .line 254
    .line 255
    invoke-direct {v4, v6}, Li4/c;-><init>(Li4/c;)V

    .line 256
    .line 257
    .line 258
    iput-object v4, v3, Ln8/g;->b:Li4/c;

    .line 259
    .line 260
    iget-boolean v3, v0, Ln8/f;->d:Z

    .line 261
    .line 262
    if-eqz v3, :cond_6

    .line 263
    .line 264
    goto :goto_4

    .line 265
    :cond_6
    iget-object v0, v0, Ln8/f;->b:Ln8/e;

    .line 266
    .line 267
    iget-object v0, v0, Ln8/e;->a:[Li4/c;

    .line 268
    .line 269
    aget-object v0, v0, v9

    .line 270
    .line 271
    iget-object v3, v0, Li4/c;->d:Ljava/lang/Object;

    .line 272
    .line 273
    check-cast v3, [F

    .line 274
    .line 275
    array-length v4, v3

    .line 276
    invoke-static {v3}, Lw7/a;->m([F)Ljava/nio/FloatBuffer;

    .line 277
    .line 278
    .line 279
    iget-object v0, v0, Li4/c;->e:Ljava/lang/Object;

    .line 280
    .line 281
    check-cast v0, [F

    .line 282
    .line 283
    invoke-static {v0}, Lw7/a;->m([F)Ljava/nio/FloatBuffer;

    .line 284
    .line 285
    .line 286
    goto :goto_4

    .line 287
    :catchall_0
    move-exception v0

    .line 288
    :try_start_4
    monitor-exit v6
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 289
    throw v0

    .line 290
    :cond_7
    :goto_4
    iget-object v3, v2, Ln8/i;->k:[F

    .line 291
    .line 292
    iget-object v7, v2, Ln8/i;->j:[F

    .line 293
    .line 294
    const/4 v8, 0x0

    .line 295
    const/4 v4, 0x0

    .line 296
    const/4 v6, 0x0

    .line 297
    invoke-static/range {v3 .. v8}, Landroid/opengl/Matrix;->multiplyMM([FI[FI[FI)V

    .line 298
    .line 299
    .line 300
    iget-object v3, v2, Ln8/i;->f:Ln8/g;

    .line 301
    .line 302
    iget v0, v2, Ln8/i;->l:I

    .line 303
    .line 304
    iget-object v2, v2, Ln8/i;->k:[F

    .line 305
    .line 306
    const-string v4, "ProjectionRenderer"

    .line 307
    .line 308
    iget-object v5, v3, Ln8/g;->b:Li4/c;

    .line 309
    .line 310
    if-nez v5, :cond_8

    .line 311
    .line 312
    goto/16 :goto_9

    .line 313
    .line 314
    :cond_8
    iget v6, v3, Ln8/g;->a:I

    .line 315
    .line 316
    if-ne v6, v1, :cond_9

    .line 317
    .line 318
    sget-object v6, Ln8/g;->j:[F

    .line 319
    .line 320
    goto :goto_5

    .line 321
    :cond_9
    if-ne v6, v10, :cond_a

    .line 322
    .line 323
    sget-object v6, Ln8/g;->k:[F

    .line 324
    .line 325
    goto :goto_5

    .line 326
    :cond_a
    sget-object v6, Ln8/g;->i:[F

    .line 327
    .line 328
    :goto_5
    iget v7, v3, Ln8/g;->e:I

    .line 329
    .line 330
    invoke-static {v7, v1, v9, v6, v9}, Landroid/opengl/GLES20;->glUniformMatrix3fv(IIZ[FI)V

    .line 331
    .line 332
    .line 333
    iget v6, v3, Ln8/g;->d:I

    .line 334
    .line 335
    invoke-static {v6, v1, v9, v2, v9}, Landroid/opengl/GLES20;->glUniformMatrix4fv(IIZ[FI)V

    .line 336
    .line 337
    .line 338
    const v1, 0x84c0

    .line 339
    .line 340
    .line 341
    invoke-static {v1}, Landroid/opengl/GLES20;->glActiveTexture(I)V

    .line 342
    .line 343
    .line 344
    const v1, 0x8d65

    .line 345
    .line 346
    .line 347
    invoke-static {v1, v0}, Landroid/opengl/GLES20;->glBindTexture(II)V

    .line 348
    .line 349
    .line 350
    iget v0, v3, Ln8/g;->h:I

    .line 351
    .line 352
    invoke-static {v0, v9}, Landroid/opengl/GLES20;->glUniform1i(II)V

    .line 353
    .line 354
    .line 355
    :try_start_5
    invoke-static {}, Lw7/a;->e()V
    :try_end_5
    .catch Lw7/h; {:try_start_5 .. :try_end_5} :catch_2

    .line 356
    .line 357
    .line 358
    goto :goto_6

    .line 359
    :catch_2
    move-exception v0

    .line 360
    const-string v1, "Failed to bind uniforms"

    .line 361
    .line 362
    invoke-static {v4, v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 363
    .line 364
    .line 365
    :goto_6
    iget v10, v3, Ln8/g;->f:I

    .line 366
    .line 367
    iget-object v0, v5, Li4/c;->d:Ljava/lang/Object;

    .line 368
    .line 369
    move-object v15, v0

    .line 370
    check-cast v15, Ljava/nio/FloatBuffer;

    .line 371
    .line 372
    const/4 v11, 0x3

    .line 373
    const/16 v12, 0x1406

    .line 374
    .line 375
    const/4 v13, 0x0

    .line 376
    const/16 v14, 0xc

    .line 377
    .line 378
    invoke-static/range {v10 .. v15}, Landroid/opengl/GLES20;->glVertexAttribPointer(IIIZILjava/nio/Buffer;)V

    .line 379
    .line 380
    .line 381
    :try_start_6
    invoke-static {}, Lw7/a;->e()V
    :try_end_6
    .catch Lw7/h; {:try_start_6 .. :try_end_6} :catch_3

    .line 382
    .line 383
    .line 384
    goto :goto_7

    .line 385
    :catch_3
    move-exception v0

    .line 386
    const-string v1, "Failed to load position data"

    .line 387
    .line 388
    invoke-static {v4, v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 389
    .line 390
    .line 391
    :goto_7
    iget v10, v3, Ln8/g;->g:I

    .line 392
    .line 393
    iget-object v0, v5, Li4/c;->e:Ljava/lang/Object;

    .line 394
    .line 395
    move-object v15, v0

    .line 396
    check-cast v15, Ljava/nio/FloatBuffer;

    .line 397
    .line 398
    const/4 v11, 0x2

    .line 399
    const/16 v12, 0x1406

    .line 400
    .line 401
    const/4 v13, 0x0

    .line 402
    const/16 v14, 0x8

    .line 403
    .line 404
    invoke-static/range {v10 .. v15}, Landroid/opengl/GLES20;->glVertexAttribPointer(IIIZILjava/nio/Buffer;)V

    .line 405
    .line 406
    .line 407
    :try_start_7
    invoke-static {}, Lw7/a;->e()V
    :try_end_7
    .catch Lw7/h; {:try_start_7 .. :try_end_7} :catch_4

    .line 408
    .line 409
    .line 410
    goto :goto_8

    .line 411
    :catch_4
    move-exception v0

    .line 412
    const-string v1, "Failed to load texture data"

    .line 413
    .line 414
    invoke-static {v4, v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 415
    .line 416
    .line 417
    :goto_8
    iget v0, v5, Li4/c;->c:I

    .line 418
    .line 419
    iget v1, v5, Li4/c;->b:I

    .line 420
    .line 421
    invoke-static {v0, v9, v1}, Landroid/opengl/GLES20;->glDrawArrays(III)V

    .line 422
    .line 423
    .line 424
    :try_start_8
    invoke-static {}, Lw7/a;->e()V
    :try_end_8
    .catch Lw7/h; {:try_start_8 .. :try_end_8} :catch_5

    .line 425
    .line 426
    .line 427
    goto :goto_9

    .line 428
    :catch_5
    move-exception v0

    .line 429
    const-string v1, "Failed to render"

    .line 430
    .line 431
    invoke-static {v4, v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 432
    .line 433
    .line 434
    :goto_9
    return-void

    .line 435
    :catchall_1
    move-exception v0

    .line 436
    :try_start_9
    monitor-exit p0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_1

    .line 437
    throw v0
.end method

.method public final onSurfaceChanged(Ljavax/microedition/khronos/opengles/GL10;II)V
    .locals 6

    .line 1
    const/4 p1, 0x0

    .line 2
    invoke-static {p1, p1, p2, p3}, Landroid/opengl/GLES20;->glViewport(IIII)V

    .line 3
    .line 4
    .line 5
    int-to-float p1, p2

    .line 6
    int-to-float p2, p3

    .line 7
    div-float v3, p1, p2

    .line 8
    .line 9
    const/high16 p1, 0x3f800000    # 1.0f

    .line 10
    .line 11
    cmpl-float p1, v3, p1

    .line 12
    .line 13
    if-lez p1, :cond_0

    .line 14
    .line 15
    const-wide p1, 0x4046800000000000L    # 45.0

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    invoke-static {p1, p2}, Ljava/lang/Math;->toRadians(D)D

    .line 21
    .line 22
    .line 23
    move-result-wide p1

    .line 24
    invoke-static {p1, p2}, Ljava/lang/Math;->tan(D)D

    .line 25
    .line 26
    .line 27
    move-result-wide p1

    .line 28
    float-to-double v0, v3

    .line 29
    div-double/2addr p1, v0

    .line 30
    invoke-static {p1, p2}, Ljava/lang/Math;->atan(D)D

    .line 31
    .line 32
    .line 33
    move-result-wide p1

    .line 34
    invoke-static {p1, p2}, Ljava/lang/Math;->toDegrees(D)D

    .line 35
    .line 36
    .line 37
    move-result-wide p1

    .line 38
    const-wide/high16 v0, 0x4000000000000000L    # 2.0

    .line 39
    .line 40
    mul-double/2addr p1, v0

    .line 41
    double-to-float p1, p1

    .line 42
    :goto_0
    move v2, p1

    .line 43
    goto :goto_1

    .line 44
    :cond_0
    const/high16 p1, 0x42b40000    # 90.0f

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :goto_1
    const v4, 0x3dcccccd    # 0.1f

    .line 48
    .line 49
    .line 50
    const/high16 v5, 0x42c80000    # 100.0f

    .line 51
    .line 52
    iget-object v0, p0, Ln8/j;->e:[F

    .line 53
    .line 54
    const/4 v1, 0x0

    .line 55
    invoke-static/range {v0 .. v5}, Landroid/opengl/Matrix;->perspectiveM([FIFFFF)V

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method public final declared-synchronized onSurfaceCreated(Ljavax/microedition/khronos/opengles/GL10;Ljavax/microedition/khronos/egl/EGLConfig;)V
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object p1, p0, Ln8/j;->n:Ln8/k;

    .line 3
    .line 4
    iget-object p2, p0, Ln8/j;->d:Ln8/i;

    .line 5
    .line 6
    invoke-virtual {p2}, Ln8/i;->a()Landroid/graphics/SurfaceTexture;

    .line 7
    .line 8
    .line 9
    move-result-object p2

    .line 10
    iget-object v0, p1, Ln8/k;->h:Landroid/os/Handler;

    .line 11
    .line 12
    new-instance v1, Lh0/h0;

    .line 13
    .line 14
    const/16 v2, 0x19

    .line 15
    .line 16
    invoke-direct {v1, v2, p1, p2}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    .line 21
    .line 22
    monitor-exit p0

    .line 23
    return-void

    .line 24
    :catchall_0
    move-exception p1

    .line 25
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 26
    throw p1
.end method
