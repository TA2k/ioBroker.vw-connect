.class public final Lt/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld0/b;


# static fields
.field public static final l:Lt/d;


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Ljava/lang/String;

.field public final f:Lv/d;

.field public final g:Llx0/q;

.field public final h:Llx0/q;

.field public final i:Llx0/q;

.field public final j:Llx0/q;

.field public final k:Llx0/q;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lt/d;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lt/e;->l:Lt/d;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Lv/d;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "cameraId"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "cameraManagerCompat"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lt/e;->d:Landroid/content/Context;

    .line 20
    .line 21
    iput-object p2, p0, Lt/e;->e:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p3, p0, Lt/e;->f:Lv/d;

    .line 24
    .line 25
    new-instance p1, Lt/b;

    .line 26
    .line 27
    const/4 p2, 0x0

    .line 28
    invoke-direct {p1, p0, p2}, Lt/b;-><init>(Lt/e;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iput-object p1, p0, Lt/e;->g:Llx0/q;

    .line 36
    .line 37
    new-instance p1, Lt/b;

    .line 38
    .line 39
    const/4 p2, 0x1

    .line 40
    invoke-direct {p1, p0, p2}, Lt/b;-><init>(Lt/e;I)V

    .line 41
    .line 42
    .line 43
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iput-object p1, p0, Lt/e;->h:Llx0/q;

    .line 48
    .line 49
    new-instance p1, Lt/b;

    .line 50
    .line 51
    const/4 p2, 0x2

    .line 52
    invoke-direct {p1, p0, p2}, Lt/b;-><init>(Lt/e;I)V

    .line 53
    .line 54
    .line 55
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    iput-object p1, p0, Lt/e;->i:Llx0/q;

    .line 60
    .line 61
    new-instance p1, Lt/b;

    .line 62
    .line 63
    const/4 p2, 0x3

    .line 64
    invoke-direct {p1, p0, p2}, Lt/b;-><init>(Lt/e;I)V

    .line 65
    .line 66
    .line 67
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    iput-object p1, p0, Lt/e;->j:Llx0/q;

    .line 72
    .line 73
    new-instance p1, Lt/b;

    .line 74
    .line 75
    const/4 p2, 0x4

    .line 76
    invoke-direct {p1, p0, p2}, Lt/b;-><init>(Lt/e;I)V

    .line 77
    .line 78
    .line 79
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    iput-object p1, p0, Lt/e;->k:Llx0/q;

    .line 84
    .line 85
    return-void
.end method


# virtual methods
.method public final a(Lh0/z1;)Z
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Lh0/z1;->g:Lh0/o0;

    .line 6
    .line 7
    iget-object v1, v1, Lh0/z1;->a:Ljava/util/ArrayList;

    .line 8
    .line 9
    new-instance v3, Ljava/util/ArrayList;

    .line 10
    .line 11
    const/16 v4, 0xa

    .line 12
    .line 13
    invoke-static {v1, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 14
    .line 15
    .line 16
    move-result v5

    .line 17
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v6

    .line 28
    const/4 v7, 0x0

    .line 29
    const-string v8, "FeatureCombinationQueryImpl"

    .line 30
    .line 31
    if-eqz v6, :cond_9

    .line 32
    .line 33
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v6

    .line 37
    check-cast v6, Lh0/i;

    .line 38
    .line 39
    iget-object v9, v0, Lt/e;->k:Llx0/q;

    .line 40
    .line 41
    invoke-virtual {v9}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v9

    .line 45
    check-cast v9, Ljava/lang/Boolean;

    .line 46
    .line 47
    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    .line 48
    .line 49
    .line 50
    move-result v9

    .line 51
    const-string v10, "Required value was null."

    .line 52
    .line 53
    if-eqz v9, :cond_2

    .line 54
    .line 55
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iget-object v9, v6, Lh0/i;->a:Lh0/t0;

    .line 59
    .line 60
    iget-object v11, v9, Lh0/t0;->j:Ljava/lang/Class;

    .line 61
    .line 62
    new-instance v12, Ljava/lang/StringBuilder;

    .line 63
    .line 64
    const-string v13, "toDeferredOutputConfiguration: surface containerClass = "

    .line 65
    .line 66
    invoke-direct {v12, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    iget-object v13, v9, Lh0/t0;->j:Ljava/lang/Class;

    .line 70
    .line 71
    iget-object v14, v9, Lh0/t0;->h:Landroid/util/Size;

    .line 72
    .line 73
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v12

    .line 80
    invoke-static {v8, v12}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    new-instance v8, Lt/c;

    .line 84
    .line 85
    if-eqz v11, :cond_1

    .line 86
    .line 87
    new-instance v9, Landroid/hardware/camera2/params/OutputConfiguration;

    .line 88
    .line 89
    if-eqz v14, :cond_0

    .line 90
    .line 91
    invoke-direct {v9, v14, v11}, Landroid/hardware/camera2/params/OutputConfiguration;-><init>(Landroid/util/Size;Ljava/lang/Class;)V

    .line 92
    .line 93
    .line 94
    goto :goto_1

    .line 95
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 96
    .line 97
    invoke-direct {v0, v10}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw v0

    .line 101
    :cond_1
    new-instance v11, Landroid/hardware/camera2/params/OutputConfiguration;

    .line 102
    .line 103
    iget v9, v9, Lh0/t0;->i:I

    .line 104
    .line 105
    invoke-direct {v11, v9, v14}, Landroid/hardware/camera2/params/OutputConfiguration;-><init>(ILandroid/util/Size;)V

    .line 106
    .line 107
    .line 108
    move-object v9, v11

    .line 109
    :goto_1
    invoke-direct {v8, v9, v7}, Lt/c;-><init>(Landroid/hardware/camera2/params/OutputConfiguration;Landroid/media/ImageReader;)V

    .line 110
    .line 111
    .line 112
    goto :goto_3

    .line 113
    :cond_2
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    iget-object v7, v6, Lh0/i;->a:Lh0/t0;

    .line 117
    .line 118
    iget-object v9, v7, Lh0/t0;->j:Ljava/lang/Class;

    .line 119
    .line 120
    const-class v11, Landroid/media/MediaCodec;

    .line 121
    .line 122
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v11

    .line 126
    if-eqz v11, :cond_3

    .line 127
    .line 128
    const-wide/32 v11, 0x10000

    .line 129
    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_3
    const-class v11, Landroid/view/SurfaceHolder;

    .line 133
    .line 134
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v11

    .line 138
    if-eqz v11, :cond_4

    .line 139
    .line 140
    const-wide/16 v11, 0x800

    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_4
    const-class v11, Landroid/graphics/SurfaceTexture;

    .line 144
    .line 145
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v9

    .line 149
    if-eqz v9, :cond_5

    .line 150
    .line 151
    const-wide/16 v11, 0x100

    .line 152
    .line 153
    goto :goto_2

    .line 154
    :cond_5
    const-wide/16 v11, 0x0

    .line 155
    .line 156
    :goto_2
    new-instance v9, Ljava/lang/StringBuilder;

    .line 157
    .line 158
    const-string v13, "toConcreteOutputConfiguration: surface containerClass = "

    .line 159
    .line 160
    invoke-direct {v9, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    iget-object v13, v7, Lh0/t0;->j:Ljava/lang/Class;

    .line 164
    .line 165
    iget-object v14, v7, Lh0/t0;->h:Landroid/util/Size;

    .line 166
    .line 167
    invoke-virtual {v9, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    const-string v13, ", usageFlag = "

    .line 171
    .line 172
    invoke-virtual {v9, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    invoke-virtual {v9, v11, v12}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v9

    .line 182
    invoke-static {v8, v9}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v14}, Landroid/util/Size;->getWidth()I

    .line 186
    .line 187
    .line 188
    move-result v13

    .line 189
    invoke-virtual {v14}, Landroid/util/Size;->getHeight()I

    .line 190
    .line 191
    .line 192
    move-result v14

    .line 193
    iget v15, v7, Lh0/t0;->i:I

    .line 194
    .line 195
    const/16 v16, 0x1

    .line 196
    .line 197
    move-wide/from16 v17, v11

    .line 198
    .line 199
    invoke-static/range {v13 .. v18}, Landroid/media/ImageReader;->newInstance(IIIIJ)Landroid/media/ImageReader;

    .line 200
    .line 201
    .line 202
    move-result-object v7

    .line 203
    const-string v8, "newInstance(...)"

    .line 204
    .line 205
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    new-instance v8, Lt/c;

    .line 209
    .line 210
    new-instance v9, Landroid/hardware/camera2/params/OutputConfiguration;

    .line 211
    .line 212
    invoke-virtual {v7}, Landroid/media/ImageReader;->getSurface()Landroid/view/Surface;

    .line 213
    .line 214
    .line 215
    move-result-object v11

    .line 216
    invoke-direct {v9, v11}, Landroid/hardware/camera2/params/OutputConfiguration;-><init>(Landroid/view/Surface;)V

    .line 217
    .line 218
    .line 219
    invoke-direct {v8, v9, v7}, Lt/c;-><init>(Landroid/hardware/camera2/params/OutputConfiguration;Landroid/media/ImageReader;)V

    .line 220
    .line 221
    .line 222
    :goto_3
    iget-object v7, v6, Lh0/i;->a:Lh0/t0;

    .line 223
    .line 224
    iget-object v7, v7, Lh0/t0;->j:Ljava/lang/Class;

    .line 225
    .line 226
    if-eqz v7, :cond_8

    .line 227
    .line 228
    iget-object v7, v0, Lt/e;->j:Llx0/q;

    .line 229
    .line 230
    invoke-virtual {v7}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v7

    .line 234
    check-cast v7, Landroid/hardware/camera2/params/DynamicRangeProfiles;

    .line 235
    .line 236
    if-nez v7, :cond_6

    .line 237
    .line 238
    goto :goto_4

    .line 239
    :cond_6
    iget-object v6, v6, Lh0/i;->e:Lb0/y;

    .line 240
    .line 241
    invoke-static {v6, v7}, Lw/a;->a(Lb0/y;Landroid/hardware/camera2/params/DynamicRangeProfiles;)Ljava/lang/Long;

    .line 242
    .line 243
    .line 244
    move-result-object v6

    .line 245
    if-eqz v6, :cond_7

    .line 246
    .line 247
    invoke-virtual {v6}, Ljava/lang/Number;->longValue()J

    .line 248
    .line 249
    .line 250
    move-result-wide v6

    .line 251
    iget-object v9, v8, Lt/c;->d:Landroid/hardware/camera2/params/OutputConfiguration;

    .line 252
    .line 253
    invoke-virtual {v9, v6, v7}, Landroid/hardware/camera2/params/OutputConfiguration;->setDynamicRangeProfile(J)V

    .line 254
    .line 255
    .line 256
    goto :goto_4

    .line 257
    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 258
    .line 259
    invoke-direct {v0, v10}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 260
    .line 261
    .line 262
    throw v0

    .line 263
    :cond_8
    :goto_4
    invoke-virtual {v3, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 264
    .line 265
    .line 266
    goto/16 :goto_0

    .line 267
    .line 268
    :cond_9
    new-instance v5, Ljava/util/ArrayList;

    .line 269
    .line 270
    invoke-static {v3, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 271
    .line 272
    .line 273
    move-result v4

    .line 274
    invoke-direct {v5, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 275
    .line 276
    .line 277
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 278
    .line 279
    .line 280
    move-result-object v4

    .line 281
    :goto_5
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 282
    .line 283
    .line 284
    move-result v6

    .line 285
    if-eqz v6, :cond_a

    .line 286
    .line 287
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v6

    .line 291
    check-cast v6, Lt/c;

    .line 292
    .line 293
    iget-object v6, v6, Lt/c;->d:Landroid/hardware/camera2/params/OutputConfiguration;

    .line 294
    .line 295
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 296
    .line 297
    .line 298
    goto :goto_5

    .line 299
    :cond_a
    new-instance v4, Landroid/hardware/camera2/params/SessionConfiguration;

    .line 300
    .line 301
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 302
    .line 303
    .line 304
    move-result-object v6

    .line 305
    sget-object v9, Lt/e;->l:Lt/d;

    .line 306
    .line 307
    const/4 v10, 0x0

    .line 308
    invoke-direct {v4, v10, v5, v6, v9}, Landroid/hardware/camera2/params/SessionConfiguration;-><init>(ILjava/util/List;Ljava/util/concurrent/Executor;Landroid/hardware/camera2/CameraCaptureSession$StateCallback;)V

    .line 309
    .line 310
    .line 311
    iget-object v5, v0, Lt/e;->h:Llx0/q;

    .line 312
    .line 313
    invoke-virtual {v5}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v5

    .line 317
    check-cast v5, Landroid/hardware/camera2/CameraDevice$CameraDeviceSetup;

    .line 318
    .line 319
    if-nez v5, :cond_b

    .line 320
    .line 321
    move-object v4, v7

    .line 322
    goto :goto_6

    .line 323
    :cond_b
    iget v6, v2, Lh0/o0;->c:I

    .line 324
    .line 325
    invoke-virtual {v5, v6}, Landroid/hardware/camera2/CameraDevice$CameraDeviceSetup;->createCaptureRequest(I)Landroid/hardware/camera2/CaptureRequest$Builder;

    .line 326
    .line 327
    .line 328
    move-result-object v5

    .line 329
    sget-object v6, Landroid/hardware/camera2/CaptureRequest;->CONTROL_AE_TARGET_FPS_RANGE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 330
    .line 331
    invoke-virtual {v2}, Lh0/o0;->a()Landroid/util/Range;

    .line 332
    .line 333
    .line 334
    move-result-object v9

    .line 335
    invoke-virtual {v5, v6, v9}, Landroid/hardware/camera2/CaptureRequest$Builder;->set(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 336
    .line 337
    .line 338
    invoke-virtual {v2}, Lh0/o0;->b()I

    .line 339
    .line 340
    .line 341
    move-result v6

    .line 342
    const/4 v9, 0x2

    .line 343
    if-ne v6, v9, :cond_c

    .line 344
    .line 345
    sget-object v6, Landroid/hardware/camera2/CaptureRequest;->CONTROL_VIDEO_STABILIZATION_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 346
    .line 347
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 348
    .line 349
    .line 350
    move-result-object v9

    .line 351
    invoke-virtual {v5, v6, v9}, Landroid/hardware/camera2/CaptureRequest$Builder;->set(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 352
    .line 353
    .line 354
    :cond_c
    invoke-virtual {v5}, Landroid/hardware/camera2/CaptureRequest$Builder;->build()Landroid/hardware/camera2/CaptureRequest;

    .line 355
    .line 356
    .line 357
    move-result-object v5

    .line 358
    invoke-virtual {v4, v5}, Landroid/hardware/camera2/params/SessionConfiguration;->setSessionParameters(Landroid/hardware/camera2/CaptureRequest;)V

    .line 359
    .line 360
    .line 361
    :goto_6
    if-nez v4, :cond_d

    .line 362
    .line 363
    return v10

    .line 364
    :cond_d
    iget-object v0, v0, Lt/e;->g:Llx0/q;

    .line 365
    .line 366
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 367
    .line 368
    .line 369
    move-result-object v0

    .line 370
    check-cast v0, Lu0/a;

    .line 371
    .line 372
    invoke-virtual {v0, v4}, Lu0/a;->a(Landroid/hardware/camera2/params/SessionConfiguration;)Lc1/l2;

    .line 373
    .line 374
    .line 375
    move-result-object v0

    .line 376
    iget v0, v0, Lc1/l2;->e:I

    .line 377
    .line 378
    const-string v4, "isSupported: supported = "

    .line 379
    .line 380
    const-string v5, " for session config with "

    .line 381
    .line 382
    invoke-static {v4, v0, v5}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 383
    .line 384
    .line 385
    move-result-object v4

    .line 386
    new-instance v5, Ljava/lang/StringBuilder;

    .line 387
    .line 388
    const-string v6, "sessionParameters=["

    .line 389
    .line 390
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 391
    .line 392
    .line 393
    new-instance v6, Ljava/lang/StringBuilder;

    .line 394
    .line 395
    const-string v9, "fpsRange="

    .line 396
    .line 397
    invoke-direct {v6, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 398
    .line 399
    .line 400
    invoke-virtual {v2}, Lh0/o0;->a()Landroid/util/Range;

    .line 401
    .line 402
    .line 403
    move-result-object v9

    .line 404
    invoke-virtual {v6, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 405
    .line 406
    .line 407
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 408
    .line 409
    .line 410
    move-result-object v6

    .line 411
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 412
    .line 413
    .line 414
    new-instance v6, Ljava/lang/StringBuilder;

    .line 415
    .line 416
    const-string v9, ", previewStabilizationMode="

    .line 417
    .line 418
    invoke-direct {v6, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    invoke-virtual {v2}, Lh0/o0;->b()I

    .line 422
    .line 423
    .line 424
    move-result v2

    .line 425
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 426
    .line 427
    .line 428
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 429
    .line 430
    .line 431
    move-result-object v2

    .line 432
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 433
    .line 434
    .line 435
    const-string v2, "], outputConfigurations=["

    .line 436
    .line 437
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 438
    .line 439
    .line 440
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 441
    .line 442
    .line 443
    move-result-object v1

    .line 444
    move v2, v10

    .line 445
    :goto_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 446
    .line 447
    .line 448
    move-result v6

    .line 449
    if-eqz v6, :cond_10

    .line 450
    .line 451
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 452
    .line 453
    .line 454
    move-result-object v6

    .line 455
    add-int/lit8 v9, v2, 0x1

    .line 456
    .line 457
    if-ltz v2, :cond_f

    .line 458
    .line 459
    check-cast v6, Lh0/i;

    .line 460
    .line 461
    if-eqz v2, :cond_e

    .line 462
    .line 463
    const-string v2, ","

    .line 464
    .line 465
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 466
    .line 467
    .line 468
    :cond_e
    new-instance v2, Ljava/lang/StringBuilder;

    .line 469
    .line 470
    const-string v11, "{format="

    .line 471
    .line 472
    invoke-direct {v2, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 473
    .line 474
    .line 475
    iget-object v11, v6, Lh0/i;->a:Lh0/t0;

    .line 476
    .line 477
    iget v12, v11, Lh0/t0;->i:I

    .line 478
    .line 479
    invoke-virtual {v2, v12}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 480
    .line 481
    .line 482
    const-string v12, ", size="

    .line 483
    .line 484
    invoke-virtual {v2, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 485
    .line 486
    .line 487
    iget-object v12, v11, Lh0/t0;->h:Landroid/util/Size;

    .line 488
    .line 489
    invoke-virtual {v2, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 490
    .line 491
    .line 492
    const-string v12, ", dynamicRange="

    .line 493
    .line 494
    invoke-virtual {v2, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 495
    .line 496
    .line 497
    iget-object v6, v6, Lh0/i;->e:Lb0/y;

    .line 498
    .line 499
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 500
    .line 501
    .line 502
    const-string v6, ", class="

    .line 503
    .line 504
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 505
    .line 506
    .line 507
    iget-object v6, v11, Lh0/t0;->j:Ljava/lang/Class;

    .line 508
    .line 509
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 510
    .line 511
    .line 512
    const/16 v6, 0x7d

    .line 513
    .line 514
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 515
    .line 516
    .line 517
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 518
    .line 519
    .line 520
    move-result-object v2

    .line 521
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 522
    .line 523
    .line 524
    move v2, v9

    .line 525
    goto :goto_7

    .line 526
    :cond_f
    invoke-static {}, Ljp/k1;->r()V

    .line 527
    .line 528
    .line 529
    throw v7

    .line 530
    :cond_10
    const-string v1, "]"

    .line 531
    .line 532
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 533
    .line 534
    .line 535
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 536
    .line 537
    .line 538
    move-result-object v1

    .line 539
    const-string v2, "toString(...)"

    .line 540
    .line 541
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 542
    .line 543
    .line 544
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 545
    .line 546
    .line 547
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 548
    .line 549
    .line 550
    move-result-object v1

    .line 551
    invoke-static {v8, v1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 552
    .line 553
    .line 554
    const/4 v1, 0x1

    .line 555
    if-ne v0, v1, :cond_11

    .line 556
    .line 557
    move v0, v1

    .line 558
    goto :goto_8

    .line 559
    :cond_11
    move v0, v10

    .line 560
    :goto_8
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 561
    .line 562
    .line 563
    move-result-object v2

    .line 564
    :cond_12
    :goto_9
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 565
    .line 566
    .line 567
    move-result v3

    .line 568
    if-eqz v3, :cond_19

    .line 569
    .line 570
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 571
    .line 572
    .line 573
    move-result-object v3

    .line 574
    check-cast v3, Ljava/lang/AutoCloseable;

    .line 575
    .line 576
    instance-of v4, v3, Ljava/lang/AutoCloseable;

    .line 577
    .line 578
    if-eqz v4, :cond_13

    .line 579
    .line 580
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 581
    .line 582
    .line 583
    goto :goto_9

    .line 584
    :cond_13
    instance-of v4, v3, Ljava/util/concurrent/ExecutorService;

    .line 585
    .line 586
    if-eqz v4, :cond_17

    .line 587
    .line 588
    check-cast v3, Ljava/util/concurrent/ExecutorService;

    .line 589
    .line 590
    invoke-static {}, Ljava/util/concurrent/ForkJoinPool;->commonPool()Ljava/util/concurrent/ForkJoinPool;

    .line 591
    .line 592
    .line 593
    move-result-object v4

    .line 594
    if-ne v3, v4, :cond_14

    .line 595
    .line 596
    goto :goto_9

    .line 597
    :cond_14
    invoke-interface {v3}, Ljava/util/concurrent/ExecutorService;->isTerminated()Z

    .line 598
    .line 599
    .line 600
    move-result v4

    .line 601
    if-nez v4, :cond_12

    .line 602
    .line 603
    invoke-interface {v3}, Ljava/util/concurrent/ExecutorService;->shutdown()V

    .line 604
    .line 605
    .line 606
    move v5, v10

    .line 607
    :cond_15
    :goto_a
    if-nez v4, :cond_16

    .line 608
    .line 609
    :try_start_0
    sget-object v6, Ljava/util/concurrent/TimeUnit;->DAYS:Ljava/util/concurrent/TimeUnit;

    .line 610
    .line 611
    const-wide/16 v7, 0x1

    .line 612
    .line 613
    invoke-interface {v3, v7, v8, v6}, Ljava/util/concurrent/ExecutorService;->awaitTermination(JLjava/util/concurrent/TimeUnit;)Z

    .line 614
    .line 615
    .line 616
    move-result v4
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 617
    goto :goto_a

    .line 618
    :catch_0
    if-nez v5, :cond_15

    .line 619
    .line 620
    invoke-interface {v3}, Ljava/util/concurrent/ExecutorService;->shutdownNow()Ljava/util/List;

    .line 621
    .line 622
    .line 623
    move v5, v1

    .line 624
    goto :goto_a

    .line 625
    :cond_16
    if-eqz v5, :cond_12

    .line 626
    .line 627
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 628
    .line 629
    .line 630
    move-result-object v3

    .line 631
    invoke-virtual {v3}, Ljava/lang/Thread;->interrupt()V

    .line 632
    .line 633
    .line 634
    goto :goto_9

    .line 635
    :cond_17
    instance-of v4, v3, Landroid/content/res/TypedArray;

    .line 636
    .line 637
    if-eqz v4, :cond_18

    .line 638
    .line 639
    check-cast v3, Landroid/content/res/TypedArray;

    .line 640
    .line 641
    invoke-virtual {v3}, Landroid/content/res/TypedArray;->recycle()V

    .line 642
    .line 643
    .line 644
    goto :goto_9

    .line 645
    :cond_18
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 646
    .line 647
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 648
    .line 649
    .line 650
    throw v0

    .line 651
    :cond_19
    return v0
.end method
