.class public final Lkp/g3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/d;


# static fields
.field public static final A:Lzs/c;

.field public static final A0:Lzs/c;

.field public static final B:Lzs/c;

.field public static final B0:Lzs/c;

.field public static final C:Lzs/c;

.field public static final C0:Lzs/c;

.field public static final D:Lzs/c;

.field public static final D0:Lzs/c;

.field public static final E:Lzs/c;

.field public static final E0:Lzs/c;

.field public static final F:Lzs/c;

.field public static final F0:Lzs/c;

.field public static final G:Lzs/c;

.field public static final G0:Lzs/c;

.field public static final H:Lzs/c;

.field public static final H0:Lzs/c;

.field public static final I:Lzs/c;

.field public static final I0:Lzs/c;

.field public static final J:Lzs/c;

.field public static final J0:Lzs/c;

.field public static final K:Lzs/c;

.field public static final K0:Lzs/c;

.field public static final L:Lzs/c;

.field public static final L0:Lzs/c;

.field public static final M:Lzs/c;

.field public static final M0:Lzs/c;

.field public static final N:Lzs/c;

.field public static final O:Lzs/c;

.field public static final P:Lzs/c;

.field public static final Q:Lzs/c;

.field public static final R:Lzs/c;

.field public static final S:Lzs/c;

.field public static final T:Lzs/c;

.field public static final U:Lzs/c;

.field public static final V:Lzs/c;

.field public static final W:Lzs/c;

.field public static final X:Lzs/c;

.field public static final Y:Lzs/c;

.field public static final Z:Lzs/c;

.field public static final a:Lkp/g3;

.field public static final a0:Lzs/c;

.field public static final b:Lzs/c;

.field public static final b0:Lzs/c;

.field public static final c:Lzs/c;

.field public static final c0:Lzs/c;

.field public static final d:Lzs/c;

.field public static final d0:Lzs/c;

.field public static final e:Lzs/c;

.field public static final e0:Lzs/c;

.field public static final f:Lzs/c;

.field public static final f0:Lzs/c;

.field public static final g:Lzs/c;

.field public static final g0:Lzs/c;

.field public static final h:Lzs/c;

.field public static final h0:Lzs/c;

.field public static final i:Lzs/c;

.field public static final i0:Lzs/c;

.field public static final j:Lzs/c;

.field public static final j0:Lzs/c;

.field public static final k:Lzs/c;

.field public static final k0:Lzs/c;

.field public static final l:Lzs/c;

.field public static final l0:Lzs/c;

.field public static final m:Lzs/c;

.field public static final m0:Lzs/c;

.field public static final n:Lzs/c;

.field public static final n0:Lzs/c;

.field public static final o:Lzs/c;

.field public static final o0:Lzs/c;

.field public static final p:Lzs/c;

.field public static final p0:Lzs/c;

.field public static final q:Lzs/c;

.field public static final q0:Lzs/c;

.field public static final r:Lzs/c;

.field public static final r0:Lzs/c;

.field public static final s:Lzs/c;

.field public static final s0:Lzs/c;

.field public static final t:Lzs/c;

.field public static final t0:Lzs/c;

.field public static final u:Lzs/c;

.field public static final u0:Lzs/c;

.field public static final v:Lzs/c;

.field public static final v0:Lzs/c;

.field public static final w:Lzs/c;

.field public static final w0:Lzs/c;

.field public static final x:Lzs/c;

.field public static final x0:Lzs/c;

.field public static final y:Lzs/c;

.field public static final y0:Lzs/c;

.field public static final z:Lzs/c;

.field public static final z0:Lzs/c;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lkp/g3;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lkp/g3;->a:Lkp/g3;

    .line 7
    .line 8
    new-instance v0, Lkp/a;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, v1}, Lkp/a;-><init>(I)V

    .line 12
    .line 13
    .line 14
    const-class v1, Lkp/d;

    .line 15
    .line 16
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    new-instance v2, Lzs/c;

    .line 21
    .line 22
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    const-string v3, "systemInfo"

    .line 27
    .line 28
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 29
    .line 30
    .line 31
    sput-object v2, Lkp/g3;->b:Lzs/c;

    .line 32
    .line 33
    new-instance v0, Lkp/a;

    .line 34
    .line 35
    const/4 v2, 0x2

    .line 36
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 37
    .line 38
    .line 39
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    new-instance v2, Lzs/c;

    .line 44
    .line 45
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    const-string v3, "eventName"

    .line 50
    .line 51
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 52
    .line 53
    .line 54
    sput-object v2, Lkp/g3;->c:Lzs/c;

    .line 55
    .line 56
    new-instance v0, Lkp/a;

    .line 57
    .line 58
    const/16 v2, 0x25

    .line 59
    .line 60
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 61
    .line 62
    .line 63
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    new-instance v2, Lzs/c;

    .line 68
    .line 69
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    const-string v3, "isThickClient"

    .line 74
    .line 75
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 76
    .line 77
    .line 78
    sput-object v2, Lkp/g3;->d:Lzs/c;

    .line 79
    .line 80
    new-instance v0, Lkp/a;

    .line 81
    .line 82
    const/16 v2, 0x3d

    .line 83
    .line 84
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 85
    .line 86
    .line 87
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    new-instance v2, Lzs/c;

    .line 92
    .line 93
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    const-string v3, "clientType"

    .line 98
    .line 99
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 100
    .line 101
    .line 102
    sput-object v2, Lkp/g3;->e:Lzs/c;

    .line 103
    .line 104
    new-instance v0, Lkp/a;

    .line 105
    .line 106
    const/4 v2, 0x3

    .line 107
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 108
    .line 109
    .line 110
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    new-instance v2, Lzs/c;

    .line 115
    .line 116
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    const-string v3, "modelDownloadLogEvent"

    .line 121
    .line 122
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 123
    .line 124
    .line 125
    sput-object v2, Lkp/g3;->f:Lzs/c;

    .line 126
    .line 127
    new-instance v0, Lkp/a;

    .line 128
    .line 129
    const/16 v2, 0x14

    .line 130
    .line 131
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 132
    .line 133
    .line 134
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    new-instance v2, Lzs/c;

    .line 139
    .line 140
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    const-string v3, "customModelLoadLogEvent"

    .line 145
    .line 146
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 147
    .line 148
    .line 149
    sput-object v2, Lkp/g3;->g:Lzs/c;

    .line 150
    .line 151
    new-instance v0, Lkp/a;

    .line 152
    .line 153
    const/4 v2, 0x4

    .line 154
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 155
    .line 156
    .line 157
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    new-instance v2, Lzs/c;

    .line 162
    .line 163
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    const-string v3, "customModelInferenceLogEvent"

    .line 168
    .line 169
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 170
    .line 171
    .line 172
    sput-object v2, Lkp/g3;->h:Lzs/c;

    .line 173
    .line 174
    new-instance v0, Lkp/a;

    .line 175
    .line 176
    const/16 v2, 0x1d

    .line 177
    .line 178
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 179
    .line 180
    .line 181
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    new-instance v2, Lzs/c;

    .line 186
    .line 187
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    const-string v3, "customModelCreateLogEvent"

    .line 192
    .line 193
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 194
    .line 195
    .line 196
    sput-object v2, Lkp/g3;->i:Lzs/c;

    .line 197
    .line 198
    new-instance v0, Lkp/a;

    .line 199
    .line 200
    const/4 v2, 0x5

    .line 201
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 202
    .line 203
    .line 204
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    new-instance v2, Lzs/c;

    .line 209
    .line 210
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    const-string v3, "onDeviceFaceDetectionLogEvent"

    .line 215
    .line 216
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 217
    .line 218
    .line 219
    sput-object v2, Lkp/g3;->j:Lzs/c;

    .line 220
    .line 221
    new-instance v0, Lkp/a;

    .line 222
    .line 223
    const/16 v2, 0x3b

    .line 224
    .line 225
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 226
    .line 227
    .line 228
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 229
    .line 230
    .line 231
    move-result-object v0

    .line 232
    new-instance v2, Lzs/c;

    .line 233
    .line 234
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 235
    .line 236
    .line 237
    move-result-object v0

    .line 238
    const-string v3, "onDeviceFaceLoadLogEvent"

    .line 239
    .line 240
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 241
    .line 242
    .line 243
    sput-object v2, Lkp/g3;->k:Lzs/c;

    .line 244
    .line 245
    new-instance v0, Lkp/a;

    .line 246
    .line 247
    const/4 v2, 0x6

    .line 248
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 249
    .line 250
    .line 251
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    new-instance v2, Lzs/c;

    .line 256
    .line 257
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 258
    .line 259
    .line 260
    move-result-object v0

    .line 261
    const-string v3, "onDeviceTextDetectionLogEvent"

    .line 262
    .line 263
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 264
    .line 265
    .line 266
    sput-object v2, Lkp/g3;->l:Lzs/c;

    .line 267
    .line 268
    new-instance v0, Lkp/a;

    .line 269
    .line 270
    const/16 v2, 0x4f

    .line 271
    .line 272
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 273
    .line 274
    .line 275
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 276
    .line 277
    .line 278
    move-result-object v0

    .line 279
    new-instance v2, Lzs/c;

    .line 280
    .line 281
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 282
    .line 283
    .line 284
    move-result-object v0

    .line 285
    const-string v3, "onDeviceTextDetectionLoadLogEvent"

    .line 286
    .line 287
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 288
    .line 289
    .line 290
    sput-object v2, Lkp/g3;->m:Lzs/c;

    .line 291
    .line 292
    new-instance v0, Lkp/a;

    .line 293
    .line 294
    const/4 v2, 0x7

    .line 295
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 296
    .line 297
    .line 298
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 299
    .line 300
    .line 301
    move-result-object v0

    .line 302
    new-instance v2, Lzs/c;

    .line 303
    .line 304
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 305
    .line 306
    .line 307
    move-result-object v0

    .line 308
    const-string v3, "onDeviceBarcodeDetectionLogEvent"

    .line 309
    .line 310
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 311
    .line 312
    .line 313
    sput-object v2, Lkp/g3;->n:Lzs/c;

    .line 314
    .line 315
    new-instance v0, Lkp/a;

    .line 316
    .line 317
    const/16 v2, 0x3a

    .line 318
    .line 319
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 320
    .line 321
    .line 322
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 323
    .line 324
    .line 325
    move-result-object v0

    .line 326
    new-instance v2, Lzs/c;

    .line 327
    .line 328
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 329
    .line 330
    .line 331
    move-result-object v0

    .line 332
    const-string v3, "onDeviceBarcodeLoadLogEvent"

    .line 333
    .line 334
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 335
    .line 336
    .line 337
    sput-object v2, Lkp/g3;->o:Lzs/c;

    .line 338
    .line 339
    new-instance v0, Lkp/a;

    .line 340
    .line 341
    const/16 v2, 0x30

    .line 342
    .line 343
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 344
    .line 345
    .line 346
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 347
    .line 348
    .line 349
    move-result-object v0

    .line 350
    new-instance v2, Lzs/c;

    .line 351
    .line 352
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 353
    .line 354
    .line 355
    move-result-object v0

    .line 356
    const-string v3, "onDeviceImageLabelCreateLogEvent"

    .line 357
    .line 358
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 359
    .line 360
    .line 361
    sput-object v2, Lkp/g3;->p:Lzs/c;

    .line 362
    .line 363
    new-instance v0, Lkp/a;

    .line 364
    .line 365
    const/16 v2, 0x31

    .line 366
    .line 367
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 368
    .line 369
    .line 370
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 371
    .line 372
    .line 373
    move-result-object v0

    .line 374
    new-instance v2, Lzs/c;

    .line 375
    .line 376
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 377
    .line 378
    .line 379
    move-result-object v0

    .line 380
    const-string v3, "onDeviceImageLabelLoadLogEvent"

    .line 381
    .line 382
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 383
    .line 384
    .line 385
    sput-object v2, Lkp/g3;->q:Lzs/c;

    .line 386
    .line 387
    new-instance v0, Lkp/a;

    .line 388
    .line 389
    const/16 v2, 0x12

    .line 390
    .line 391
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 392
    .line 393
    .line 394
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 395
    .line 396
    .line 397
    move-result-object v0

    .line 398
    new-instance v2, Lzs/c;

    .line 399
    .line 400
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 401
    .line 402
    .line 403
    move-result-object v0

    .line 404
    const-string v3, "onDeviceImageLabelDetectionLogEvent"

    .line 405
    .line 406
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 407
    .line 408
    .line 409
    sput-object v2, Lkp/g3;->r:Lzs/c;

    .line 410
    .line 411
    new-instance v0, Lkp/a;

    .line 412
    .line 413
    const/16 v2, 0x1a

    .line 414
    .line 415
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 416
    .line 417
    .line 418
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 419
    .line 420
    .line 421
    move-result-object v0

    .line 422
    new-instance v2, Lzs/c;

    .line 423
    .line 424
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 425
    .line 426
    .line 427
    move-result-object v0

    .line 428
    const-string v3, "onDeviceObjectCreateLogEvent"

    .line 429
    .line 430
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 431
    .line 432
    .line 433
    sput-object v2, Lkp/g3;->s:Lzs/c;

    .line 434
    .line 435
    new-instance v0, Lkp/a;

    .line 436
    .line 437
    const/16 v2, 0x1b

    .line 438
    .line 439
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 440
    .line 441
    .line 442
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 443
    .line 444
    .line 445
    move-result-object v0

    .line 446
    new-instance v2, Lzs/c;

    .line 447
    .line 448
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 449
    .line 450
    .line 451
    move-result-object v0

    .line 452
    const-string v3, "onDeviceObjectLoadLogEvent"

    .line 453
    .line 454
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 455
    .line 456
    .line 457
    sput-object v2, Lkp/g3;->t:Lzs/c;

    .line 458
    .line 459
    new-instance v0, Lkp/a;

    .line 460
    .line 461
    const/16 v2, 0x1c

    .line 462
    .line 463
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 464
    .line 465
    .line 466
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 467
    .line 468
    .line 469
    move-result-object v0

    .line 470
    new-instance v2, Lzs/c;

    .line 471
    .line 472
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 473
    .line 474
    .line 475
    move-result-object v0

    .line 476
    const-string v3, "onDeviceObjectInferenceLogEvent"

    .line 477
    .line 478
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 479
    .line 480
    .line 481
    sput-object v2, Lkp/g3;->u:Lzs/c;

    .line 482
    .line 483
    new-instance v0, Lkp/a;

    .line 484
    .line 485
    const/16 v2, 0x2c

    .line 486
    .line 487
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 488
    .line 489
    .line 490
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 491
    .line 492
    .line 493
    move-result-object v0

    .line 494
    new-instance v2, Lzs/c;

    .line 495
    .line 496
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 497
    .line 498
    .line 499
    move-result-object v0

    .line 500
    const-string v3, "onDevicePoseDetectionLogEvent"

    .line 501
    .line 502
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 503
    .line 504
    .line 505
    sput-object v2, Lkp/g3;->v:Lzs/c;

    .line 506
    .line 507
    new-instance v0, Lkp/a;

    .line 508
    .line 509
    const/16 v2, 0x2d

    .line 510
    .line 511
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 512
    .line 513
    .line 514
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 515
    .line 516
    .line 517
    move-result-object v0

    .line 518
    new-instance v2, Lzs/c;

    .line 519
    .line 520
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 521
    .line 522
    .line 523
    move-result-object v0

    .line 524
    const-string v3, "onDeviceSegmentationLogEvent"

    .line 525
    .line 526
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 527
    .line 528
    .line 529
    sput-object v2, Lkp/g3;->w:Lzs/c;

    .line 530
    .line 531
    new-instance v0, Lkp/a;

    .line 532
    .line 533
    const/16 v2, 0x13

    .line 534
    .line 535
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 536
    .line 537
    .line 538
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 539
    .line 540
    .line 541
    move-result-object v0

    .line 542
    new-instance v2, Lzs/c;

    .line 543
    .line 544
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 545
    .line 546
    .line 547
    move-result-object v0

    .line 548
    const-string v3, "onDeviceSmartReplyLogEvent"

    .line 549
    .line 550
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 551
    .line 552
    .line 553
    sput-object v2, Lkp/g3;->x:Lzs/c;

    .line 554
    .line 555
    new-instance v0, Lkp/a;

    .line 556
    .line 557
    const/16 v2, 0x15

    .line 558
    .line 559
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 560
    .line 561
    .line 562
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 563
    .line 564
    .line 565
    move-result-object v0

    .line 566
    new-instance v2, Lzs/c;

    .line 567
    .line 568
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 569
    .line 570
    .line 571
    move-result-object v0

    .line 572
    const-string v3, "onDeviceLanguageIdentificationLogEvent"

    .line 573
    .line 574
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 575
    .line 576
    .line 577
    sput-object v2, Lkp/g3;->y:Lzs/c;

    .line 578
    .line 579
    new-instance v0, Lkp/a;

    .line 580
    .line 581
    const/16 v2, 0x16

    .line 582
    .line 583
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 584
    .line 585
    .line 586
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 587
    .line 588
    .line 589
    move-result-object v0

    .line 590
    new-instance v2, Lzs/c;

    .line 591
    .line 592
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 593
    .line 594
    .line 595
    move-result-object v0

    .line 596
    const-string v3, "onDeviceTranslationLogEvent"

    .line 597
    .line 598
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 599
    .line 600
    .line 601
    sput-object v2, Lkp/g3;->z:Lzs/c;

    .line 602
    .line 603
    new-instance v0, Lkp/a;

    .line 604
    .line 605
    const/16 v2, 0x8

    .line 606
    .line 607
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 608
    .line 609
    .line 610
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 611
    .line 612
    .line 613
    move-result-object v0

    .line 614
    new-instance v2, Lzs/c;

    .line 615
    .line 616
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 617
    .line 618
    .line 619
    move-result-object v0

    .line 620
    const-string v3, "cloudFaceDetectionLogEvent"

    .line 621
    .line 622
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 623
    .line 624
    .line 625
    sput-object v2, Lkp/g3;->A:Lzs/c;

    .line 626
    .line 627
    new-instance v0, Lkp/a;

    .line 628
    .line 629
    const/16 v2, 0x9

    .line 630
    .line 631
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 632
    .line 633
    .line 634
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 635
    .line 636
    .line 637
    move-result-object v0

    .line 638
    new-instance v2, Lzs/c;

    .line 639
    .line 640
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 641
    .line 642
    .line 643
    move-result-object v0

    .line 644
    const-string v3, "cloudCropHintDetectionLogEvent"

    .line 645
    .line 646
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 647
    .line 648
    .line 649
    sput-object v2, Lkp/g3;->B:Lzs/c;

    .line 650
    .line 651
    new-instance v0, Lkp/a;

    .line 652
    .line 653
    const/16 v2, 0xa

    .line 654
    .line 655
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 656
    .line 657
    .line 658
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 659
    .line 660
    .line 661
    move-result-object v0

    .line 662
    new-instance v2, Lzs/c;

    .line 663
    .line 664
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 665
    .line 666
    .line 667
    move-result-object v0

    .line 668
    const-string v3, "cloudDocumentTextDetectionLogEvent"

    .line 669
    .line 670
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 671
    .line 672
    .line 673
    sput-object v2, Lkp/g3;->C:Lzs/c;

    .line 674
    .line 675
    new-instance v0, Lkp/a;

    .line 676
    .line 677
    const/16 v2, 0xb

    .line 678
    .line 679
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 680
    .line 681
    .line 682
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 683
    .line 684
    .line 685
    move-result-object v0

    .line 686
    new-instance v2, Lzs/c;

    .line 687
    .line 688
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 689
    .line 690
    .line 691
    move-result-object v0

    .line 692
    const-string v3, "cloudImagePropertiesDetectionLogEvent"

    .line 693
    .line 694
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 695
    .line 696
    .line 697
    sput-object v2, Lkp/g3;->D:Lzs/c;

    .line 698
    .line 699
    new-instance v0, Lkp/a;

    .line 700
    .line 701
    const/16 v2, 0xc

    .line 702
    .line 703
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 704
    .line 705
    .line 706
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 707
    .line 708
    .line 709
    move-result-object v0

    .line 710
    new-instance v2, Lzs/c;

    .line 711
    .line 712
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 713
    .line 714
    .line 715
    move-result-object v0

    .line 716
    const-string v3, "cloudImageLabelDetectionLogEvent"

    .line 717
    .line 718
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 719
    .line 720
    .line 721
    sput-object v2, Lkp/g3;->E:Lzs/c;

    .line 722
    .line 723
    new-instance v0, Lkp/a;

    .line 724
    .line 725
    const/16 v2, 0xd

    .line 726
    .line 727
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 728
    .line 729
    .line 730
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 731
    .line 732
    .line 733
    move-result-object v0

    .line 734
    new-instance v2, Lzs/c;

    .line 735
    .line 736
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 737
    .line 738
    .line 739
    move-result-object v0

    .line 740
    const-string v3, "cloudLandmarkDetectionLogEvent"

    .line 741
    .line 742
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 743
    .line 744
    .line 745
    sput-object v2, Lkp/g3;->F:Lzs/c;

    .line 746
    .line 747
    new-instance v0, Lkp/a;

    .line 748
    .line 749
    const/16 v2, 0xe

    .line 750
    .line 751
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 752
    .line 753
    .line 754
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 755
    .line 756
    .line 757
    move-result-object v0

    .line 758
    new-instance v2, Lzs/c;

    .line 759
    .line 760
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 761
    .line 762
    .line 763
    move-result-object v0

    .line 764
    const-string v3, "cloudLogoDetectionLogEvent"

    .line 765
    .line 766
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 767
    .line 768
    .line 769
    sput-object v2, Lkp/g3;->G:Lzs/c;

    .line 770
    .line 771
    new-instance v0, Lkp/a;

    .line 772
    .line 773
    const/16 v2, 0xf

    .line 774
    .line 775
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 776
    .line 777
    .line 778
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 779
    .line 780
    .line 781
    move-result-object v0

    .line 782
    new-instance v2, Lzs/c;

    .line 783
    .line 784
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 785
    .line 786
    .line 787
    move-result-object v0

    .line 788
    const-string v3, "cloudSafeSearchDetectionLogEvent"

    .line 789
    .line 790
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 791
    .line 792
    .line 793
    sput-object v2, Lkp/g3;->H:Lzs/c;

    .line 794
    .line 795
    new-instance v0, Lkp/a;

    .line 796
    .line 797
    const/16 v2, 0x10

    .line 798
    .line 799
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 800
    .line 801
    .line 802
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 803
    .line 804
    .line 805
    move-result-object v0

    .line 806
    new-instance v2, Lzs/c;

    .line 807
    .line 808
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 809
    .line 810
    .line 811
    move-result-object v0

    .line 812
    const-string v3, "cloudTextDetectionLogEvent"

    .line 813
    .line 814
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 815
    .line 816
    .line 817
    sput-object v2, Lkp/g3;->I:Lzs/c;

    .line 818
    .line 819
    new-instance v0, Lkp/a;

    .line 820
    .line 821
    const/16 v2, 0x11

    .line 822
    .line 823
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 824
    .line 825
    .line 826
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 827
    .line 828
    .line 829
    move-result-object v0

    .line 830
    new-instance v2, Lzs/c;

    .line 831
    .line 832
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 833
    .line 834
    .line 835
    move-result-object v0

    .line 836
    const-string v3, "cloudWebSearchDetectionLogEvent"

    .line 837
    .line 838
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 839
    .line 840
    .line 841
    sput-object v2, Lkp/g3;->J:Lzs/c;

    .line 842
    .line 843
    new-instance v0, Lkp/a;

    .line 844
    .line 845
    const/16 v2, 0x17

    .line 846
    .line 847
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 848
    .line 849
    .line 850
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 851
    .line 852
    .line 853
    move-result-object v0

    .line 854
    new-instance v2, Lzs/c;

    .line 855
    .line 856
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 857
    .line 858
    .line 859
    move-result-object v0

    .line 860
    const-string v3, "automlImageLabelingCreateLogEvent"

    .line 861
    .line 862
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 863
    .line 864
    .line 865
    sput-object v2, Lkp/g3;->K:Lzs/c;

    .line 866
    .line 867
    new-instance v0, Lkp/a;

    .line 868
    .line 869
    const/16 v2, 0x18

    .line 870
    .line 871
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 872
    .line 873
    .line 874
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 875
    .line 876
    .line 877
    move-result-object v0

    .line 878
    new-instance v2, Lzs/c;

    .line 879
    .line 880
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 881
    .line 882
    .line 883
    move-result-object v0

    .line 884
    const-string v3, "automlImageLabelingLoadLogEvent"

    .line 885
    .line 886
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 887
    .line 888
    .line 889
    sput-object v2, Lkp/g3;->L:Lzs/c;

    .line 890
    .line 891
    new-instance v0, Lkp/a;

    .line 892
    .line 893
    const/16 v2, 0x19

    .line 894
    .line 895
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 896
    .line 897
    .line 898
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 899
    .line 900
    .line 901
    move-result-object v0

    .line 902
    new-instance v2, Lzs/c;

    .line 903
    .line 904
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 905
    .line 906
    .line 907
    move-result-object v0

    .line 908
    const-string v3, "automlImageLabelingInferenceLogEvent"

    .line 909
    .line 910
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 911
    .line 912
    .line 913
    sput-object v2, Lkp/g3;->M:Lzs/c;

    .line 914
    .line 915
    new-instance v0, Lkp/a;

    .line 916
    .line 917
    const/16 v2, 0x27

    .line 918
    .line 919
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 920
    .line 921
    .line 922
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 923
    .line 924
    .line 925
    move-result-object v0

    .line 926
    new-instance v2, Lzs/c;

    .line 927
    .line 928
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 929
    .line 930
    .line 931
    move-result-object v0

    .line 932
    const-string v3, "isModelDownloadedLogEvent"

    .line 933
    .line 934
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 935
    .line 936
    .line 937
    sput-object v2, Lkp/g3;->N:Lzs/c;

    .line 938
    .line 939
    new-instance v0, Lkp/a;

    .line 940
    .line 941
    const/16 v2, 0x28

    .line 942
    .line 943
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 944
    .line 945
    .line 946
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 947
    .line 948
    .line 949
    move-result-object v0

    .line 950
    new-instance v2, Lzs/c;

    .line 951
    .line 952
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 953
    .line 954
    .line 955
    move-result-object v0

    .line 956
    const-string v3, "deleteModelLogEvent"

    .line 957
    .line 958
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 959
    .line 960
    .line 961
    sput-object v2, Lkp/g3;->O:Lzs/c;

    .line 962
    .line 963
    new-instance v0, Lkp/a;

    .line 964
    .line 965
    const/16 v2, 0x1e

    .line 966
    .line 967
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 968
    .line 969
    .line 970
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 971
    .line 972
    .line 973
    move-result-object v0

    .line 974
    new-instance v2, Lzs/c;

    .line 975
    .line 976
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 977
    .line 978
    .line 979
    move-result-object v0

    .line 980
    const-string v3, "aggregatedAutomlImageLabelingInferenceLogEvent"

    .line 981
    .line 982
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 983
    .line 984
    .line 985
    sput-object v2, Lkp/g3;->P:Lzs/c;

    .line 986
    .line 987
    new-instance v0, Lkp/a;

    .line 988
    .line 989
    const/16 v2, 0x1f

    .line 990
    .line 991
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 992
    .line 993
    .line 994
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 995
    .line 996
    .line 997
    move-result-object v0

    .line 998
    new-instance v2, Lzs/c;

    .line 999
    .line 1000
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1001
    .line 1002
    .line 1003
    move-result-object v0

    .line 1004
    const-string v3, "aggregatedCustomModelInferenceLogEvent"

    .line 1005
    .line 1006
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1007
    .line 1008
    .line 1009
    sput-object v2, Lkp/g3;->Q:Lzs/c;

    .line 1010
    .line 1011
    new-instance v0, Lkp/a;

    .line 1012
    .line 1013
    const/16 v2, 0x20

    .line 1014
    .line 1015
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1016
    .line 1017
    .line 1018
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1019
    .line 1020
    .line 1021
    move-result-object v0

    .line 1022
    new-instance v2, Lzs/c;

    .line 1023
    .line 1024
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1025
    .line 1026
    .line 1027
    move-result-object v0

    .line 1028
    const-string v3, "aggregatedOnDeviceFaceDetectionLogEvent"

    .line 1029
    .line 1030
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1031
    .line 1032
    .line 1033
    sput-object v2, Lkp/g3;->R:Lzs/c;

    .line 1034
    .line 1035
    new-instance v0, Lkp/a;

    .line 1036
    .line 1037
    const/16 v2, 0x21

    .line 1038
    .line 1039
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1040
    .line 1041
    .line 1042
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1043
    .line 1044
    .line 1045
    move-result-object v0

    .line 1046
    new-instance v2, Lzs/c;

    .line 1047
    .line 1048
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1049
    .line 1050
    .line 1051
    move-result-object v0

    .line 1052
    const-string v3, "aggregatedOnDeviceBarcodeDetectionLogEvent"

    .line 1053
    .line 1054
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1055
    .line 1056
    .line 1057
    sput-object v2, Lkp/g3;->S:Lzs/c;

    .line 1058
    .line 1059
    new-instance v0, Lkp/a;

    .line 1060
    .line 1061
    const/16 v2, 0x22

    .line 1062
    .line 1063
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1064
    .line 1065
    .line 1066
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v0

    .line 1070
    new-instance v2, Lzs/c;

    .line 1071
    .line 1072
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1073
    .line 1074
    .line 1075
    move-result-object v0

    .line 1076
    const-string v3, "aggregatedOnDeviceImageLabelDetectionLogEvent"

    .line 1077
    .line 1078
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1079
    .line 1080
    .line 1081
    sput-object v2, Lkp/g3;->T:Lzs/c;

    .line 1082
    .line 1083
    new-instance v0, Lkp/a;

    .line 1084
    .line 1085
    const/16 v2, 0x23

    .line 1086
    .line 1087
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1088
    .line 1089
    .line 1090
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1091
    .line 1092
    .line 1093
    move-result-object v0

    .line 1094
    new-instance v2, Lzs/c;

    .line 1095
    .line 1096
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1097
    .line 1098
    .line 1099
    move-result-object v0

    .line 1100
    const-string v3, "aggregatedOnDeviceObjectInferenceLogEvent"

    .line 1101
    .line 1102
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1103
    .line 1104
    .line 1105
    sput-object v2, Lkp/g3;->U:Lzs/c;

    .line 1106
    .line 1107
    new-instance v0, Lkp/a;

    .line 1108
    .line 1109
    const/16 v2, 0x24

    .line 1110
    .line 1111
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1112
    .line 1113
    .line 1114
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1115
    .line 1116
    .line 1117
    move-result-object v0

    .line 1118
    new-instance v2, Lzs/c;

    .line 1119
    .line 1120
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1121
    .line 1122
    .line 1123
    move-result-object v0

    .line 1124
    const-string v3, "aggregatedOnDeviceTextDetectionLogEvent"

    .line 1125
    .line 1126
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1127
    .line 1128
    .line 1129
    sput-object v2, Lkp/g3;->V:Lzs/c;

    .line 1130
    .line 1131
    new-instance v0, Lkp/a;

    .line 1132
    .line 1133
    const/16 v2, 0x2e

    .line 1134
    .line 1135
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1136
    .line 1137
    .line 1138
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1139
    .line 1140
    .line 1141
    move-result-object v0

    .line 1142
    new-instance v2, Lzs/c;

    .line 1143
    .line 1144
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1145
    .line 1146
    .line 1147
    move-result-object v0

    .line 1148
    const-string v3, "aggregatedOnDevicePoseDetectionLogEvent"

    .line 1149
    .line 1150
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1151
    .line 1152
    .line 1153
    sput-object v2, Lkp/g3;->W:Lzs/c;

    .line 1154
    .line 1155
    new-instance v0, Lkp/a;

    .line 1156
    .line 1157
    const/16 v2, 0x2f

    .line 1158
    .line 1159
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1160
    .line 1161
    .line 1162
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1163
    .line 1164
    .line 1165
    move-result-object v0

    .line 1166
    new-instance v2, Lzs/c;

    .line 1167
    .line 1168
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1169
    .line 1170
    .line 1171
    move-result-object v0

    .line 1172
    const-string v3, "aggregatedOnDeviceSegmentationLogEvent"

    .line 1173
    .line 1174
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1175
    .line 1176
    .line 1177
    sput-object v2, Lkp/g3;->X:Lzs/c;

    .line 1178
    .line 1179
    new-instance v0, Lkp/a;

    .line 1180
    .line 1181
    const/16 v2, 0x45

    .line 1182
    .line 1183
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1184
    .line 1185
    .line 1186
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1187
    .line 1188
    .line 1189
    move-result-object v0

    .line 1190
    new-instance v2, Lzs/c;

    .line 1191
    .line 1192
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1193
    .line 1194
    .line 1195
    move-result-object v0

    .line 1196
    const-string v3, "pipelineAccelerationInferenceEvents"

    .line 1197
    .line 1198
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1199
    .line 1200
    .line 1201
    sput-object v2, Lkp/g3;->Y:Lzs/c;

    .line 1202
    .line 1203
    new-instance v0, Lkp/a;

    .line 1204
    .line 1205
    const/16 v2, 0x2a

    .line 1206
    .line 1207
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1208
    .line 1209
    .line 1210
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1211
    .line 1212
    .line 1213
    move-result-object v0

    .line 1214
    new-instance v2, Lzs/c;

    .line 1215
    .line 1216
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1217
    .line 1218
    .line 1219
    move-result-object v0

    .line 1220
    const-string v3, "remoteConfigLogEvent"

    .line 1221
    .line 1222
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1223
    .line 1224
    .line 1225
    sput-object v2, Lkp/g3;->Z:Lzs/c;

    .line 1226
    .line 1227
    new-instance v0, Lkp/a;

    .line 1228
    .line 1229
    const/16 v2, 0x32

    .line 1230
    .line 1231
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1232
    .line 1233
    .line 1234
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1235
    .line 1236
    .line 1237
    move-result-object v0

    .line 1238
    new-instance v2, Lzs/c;

    .line 1239
    .line 1240
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1241
    .line 1242
    .line 1243
    move-result-object v0

    .line 1244
    const-string v3, "inputImageConstructionLogEvent"

    .line 1245
    .line 1246
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1247
    .line 1248
    .line 1249
    sput-object v2, Lkp/g3;->a0:Lzs/c;

    .line 1250
    .line 1251
    new-instance v0, Lkp/a;

    .line 1252
    .line 1253
    const/16 v2, 0x33

    .line 1254
    .line 1255
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1256
    .line 1257
    .line 1258
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1259
    .line 1260
    .line 1261
    move-result-object v0

    .line 1262
    new-instance v2, Lzs/c;

    .line 1263
    .line 1264
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1265
    .line 1266
    .line 1267
    move-result-object v0

    .line 1268
    const-string v3, "leakedHandleEvent"

    .line 1269
    .line 1270
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1271
    .line 1272
    .line 1273
    sput-object v2, Lkp/g3;->b0:Lzs/c;

    .line 1274
    .line 1275
    new-instance v0, Lkp/a;

    .line 1276
    .line 1277
    const/16 v2, 0x34

    .line 1278
    .line 1279
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1280
    .line 1281
    .line 1282
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1283
    .line 1284
    .line 1285
    move-result-object v0

    .line 1286
    new-instance v2, Lzs/c;

    .line 1287
    .line 1288
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1289
    .line 1290
    .line 1291
    move-result-object v0

    .line 1292
    const-string v3, "cameraSourceLogEvent"

    .line 1293
    .line 1294
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1295
    .line 1296
    .line 1297
    sput-object v2, Lkp/g3;->c0:Lzs/c;

    .line 1298
    .line 1299
    new-instance v0, Lkp/a;

    .line 1300
    .line 1301
    const/16 v2, 0x35

    .line 1302
    .line 1303
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1304
    .line 1305
    .line 1306
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1307
    .line 1308
    .line 1309
    move-result-object v0

    .line 1310
    new-instance v2, Lzs/c;

    .line 1311
    .line 1312
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1313
    .line 1314
    .line 1315
    move-result-object v0

    .line 1316
    const-string v3, "imageLabelOptionalModuleLogEvent"

    .line 1317
    .line 1318
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1319
    .line 1320
    .line 1321
    sput-object v2, Lkp/g3;->d0:Lzs/c;

    .line 1322
    .line 1323
    new-instance v0, Lkp/a;

    .line 1324
    .line 1325
    const/16 v2, 0x36

    .line 1326
    .line 1327
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1328
    .line 1329
    .line 1330
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1331
    .line 1332
    .line 1333
    move-result-object v0

    .line 1334
    new-instance v2, Lzs/c;

    .line 1335
    .line 1336
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1337
    .line 1338
    .line 1339
    move-result-object v0

    .line 1340
    const-string v3, "languageIdentificationOptionalModuleLogEvent"

    .line 1341
    .line 1342
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1343
    .line 1344
    .line 1345
    sput-object v2, Lkp/g3;->e0:Lzs/c;

    .line 1346
    .line 1347
    new-instance v0, Lkp/a;

    .line 1348
    .line 1349
    const/16 v2, 0x3c

    .line 1350
    .line 1351
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1352
    .line 1353
    .line 1354
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1355
    .line 1356
    .line 1357
    move-result-object v0

    .line 1358
    new-instance v2, Lzs/c;

    .line 1359
    .line 1360
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1361
    .line 1362
    .line 1363
    move-result-object v0

    .line 1364
    const-string v3, "faceDetectionOptionalModuleLogEvent"

    .line 1365
    .line 1366
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1367
    .line 1368
    .line 1369
    sput-object v2, Lkp/g3;->f0:Lzs/c;

    .line 1370
    .line 1371
    new-instance v0, Lkp/a;

    .line 1372
    .line 1373
    const/16 v2, 0x55

    .line 1374
    .line 1375
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1376
    .line 1377
    .line 1378
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1379
    .line 1380
    .line 1381
    move-result-object v0

    .line 1382
    new-instance v2, Lzs/c;

    .line 1383
    .line 1384
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1385
    .line 1386
    .line 1387
    move-result-object v0

    .line 1388
    const-string v3, "documentDetectionOptionalModuleLogEvent"

    .line 1389
    .line 1390
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1391
    .line 1392
    .line 1393
    sput-object v2, Lkp/g3;->g0:Lzs/c;

    .line 1394
    .line 1395
    new-instance v0, Lkp/a;

    .line 1396
    .line 1397
    const/16 v2, 0x56

    .line 1398
    .line 1399
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1400
    .line 1401
    .line 1402
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1403
    .line 1404
    .line 1405
    move-result-object v0

    .line 1406
    new-instance v2, Lzs/c;

    .line 1407
    .line 1408
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1409
    .line 1410
    .line 1411
    move-result-object v0

    .line 1412
    const-string v3, "documentCroppingOptionalModuleLogEvent"

    .line 1413
    .line 1414
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1415
    .line 1416
    .line 1417
    sput-object v2, Lkp/g3;->h0:Lzs/c;

    .line 1418
    .line 1419
    new-instance v0, Lkp/a;

    .line 1420
    .line 1421
    const/16 v2, 0x57

    .line 1422
    .line 1423
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1424
    .line 1425
    .line 1426
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1427
    .line 1428
    .line 1429
    move-result-object v0

    .line 1430
    new-instance v2, Lzs/c;

    .line 1431
    .line 1432
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1433
    .line 1434
    .line 1435
    move-result-object v0

    .line 1436
    const-string v3, "documentEnhancementOptionalModuleLogEvent"

    .line 1437
    .line 1438
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1439
    .line 1440
    .line 1441
    sput-object v2, Lkp/g3;->i0:Lzs/c;

    .line 1442
    .line 1443
    new-instance v0, Lkp/a;

    .line 1444
    .line 1445
    const/16 v2, 0x37

    .line 1446
    .line 1447
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1448
    .line 1449
    .line 1450
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1451
    .line 1452
    .line 1453
    move-result-object v0

    .line 1454
    new-instance v2, Lzs/c;

    .line 1455
    .line 1456
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1457
    .line 1458
    .line 1459
    move-result-object v0

    .line 1460
    const-string v3, "nlClassifierOptionalModuleLogEvent"

    .line 1461
    .line 1462
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1463
    .line 1464
    .line 1465
    sput-object v2, Lkp/g3;->j0:Lzs/c;

    .line 1466
    .line 1467
    new-instance v0, Lkp/a;

    .line 1468
    .line 1469
    const/16 v2, 0x38

    .line 1470
    .line 1471
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1472
    .line 1473
    .line 1474
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1475
    .line 1476
    .line 1477
    move-result-object v0

    .line 1478
    new-instance v2, Lzs/c;

    .line 1479
    .line 1480
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1481
    .line 1482
    .line 1483
    move-result-object v0

    .line 1484
    const-string v3, "nlClassifierClientLibraryLogEvent"

    .line 1485
    .line 1486
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1487
    .line 1488
    .line 1489
    sput-object v2, Lkp/g3;->k0:Lzs/c;

    .line 1490
    .line 1491
    new-instance v0, Lkp/a;

    .line 1492
    .line 1493
    const/16 v2, 0x39

    .line 1494
    .line 1495
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1496
    .line 1497
    .line 1498
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1499
    .line 1500
    .line 1501
    move-result-object v0

    .line 1502
    new-instance v2, Lzs/c;

    .line 1503
    .line 1504
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1505
    .line 1506
    .line 1507
    move-result-object v0

    .line 1508
    const-string v3, "accelerationAllowlistLogEvent"

    .line 1509
    .line 1510
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1511
    .line 1512
    .line 1513
    sput-object v2, Lkp/g3;->l0:Lzs/c;

    .line 1514
    .line 1515
    new-instance v0, Lkp/a;

    .line 1516
    .line 1517
    const/16 v2, 0x3e

    .line 1518
    .line 1519
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1520
    .line 1521
    .line 1522
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1523
    .line 1524
    .line 1525
    move-result-object v0

    .line 1526
    new-instance v2, Lzs/c;

    .line 1527
    .line 1528
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1529
    .line 1530
    .line 1531
    move-result-object v0

    .line 1532
    const-string v3, "toxicityDetectionCreateEvent"

    .line 1533
    .line 1534
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1535
    .line 1536
    .line 1537
    sput-object v2, Lkp/g3;->m0:Lzs/c;

    .line 1538
    .line 1539
    new-instance v0, Lkp/a;

    .line 1540
    .line 1541
    const/16 v2, 0x3f

    .line 1542
    .line 1543
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1544
    .line 1545
    .line 1546
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1547
    .line 1548
    .line 1549
    move-result-object v0

    .line 1550
    new-instance v2, Lzs/c;

    .line 1551
    .line 1552
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1553
    .line 1554
    .line 1555
    move-result-object v0

    .line 1556
    const-string v3, "toxicityDetectionLoadEvent"

    .line 1557
    .line 1558
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1559
    .line 1560
    .line 1561
    sput-object v2, Lkp/g3;->n0:Lzs/c;

    .line 1562
    .line 1563
    new-instance v0, Lkp/a;

    .line 1564
    .line 1565
    const/16 v2, 0x40

    .line 1566
    .line 1567
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1568
    .line 1569
    .line 1570
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1571
    .line 1572
    .line 1573
    move-result-object v0

    .line 1574
    new-instance v2, Lzs/c;

    .line 1575
    .line 1576
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1577
    .line 1578
    .line 1579
    move-result-object v0

    .line 1580
    const-string v3, "toxicityDetectionInferenceEvent"

    .line 1581
    .line 1582
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1583
    .line 1584
    .line 1585
    sput-object v2, Lkp/g3;->o0:Lzs/c;

    .line 1586
    .line 1587
    new-instance v0, Lkp/a;

    .line 1588
    .line 1589
    const/16 v2, 0x41

    .line 1590
    .line 1591
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1592
    .line 1593
    .line 1594
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1595
    .line 1596
    .line 1597
    move-result-object v0

    .line 1598
    new-instance v2, Lzs/c;

    .line 1599
    .line 1600
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1601
    .line 1602
    .line 1603
    move-result-object v0

    .line 1604
    const-string v3, "barcodeDetectionOptionalModuleLogEvent"

    .line 1605
    .line 1606
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1607
    .line 1608
    .line 1609
    sput-object v2, Lkp/g3;->p0:Lzs/c;

    .line 1610
    .line 1611
    new-instance v0, Lkp/a;

    .line 1612
    .line 1613
    const/16 v2, 0x42

    .line 1614
    .line 1615
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1616
    .line 1617
    .line 1618
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1619
    .line 1620
    .line 1621
    move-result-object v0

    .line 1622
    new-instance v2, Lzs/c;

    .line 1623
    .line 1624
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1625
    .line 1626
    .line 1627
    move-result-object v0

    .line 1628
    const-string v3, "customImageLabelOptionalModuleLogEvent"

    .line 1629
    .line 1630
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1631
    .line 1632
    .line 1633
    sput-object v2, Lkp/g3;->q0:Lzs/c;

    .line 1634
    .line 1635
    new-instance v0, Lkp/a;

    .line 1636
    .line 1637
    const/16 v2, 0x43

    .line 1638
    .line 1639
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1640
    .line 1641
    .line 1642
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1643
    .line 1644
    .line 1645
    move-result-object v0

    .line 1646
    new-instance v2, Lzs/c;

    .line 1647
    .line 1648
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1649
    .line 1650
    .line 1651
    move-result-object v0

    .line 1652
    const-string v3, "codeScannerScanApiEvent"

    .line 1653
    .line 1654
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1655
    .line 1656
    .line 1657
    sput-object v2, Lkp/g3;->r0:Lzs/c;

    .line 1658
    .line 1659
    new-instance v0, Lkp/a;

    .line 1660
    .line 1661
    const/16 v2, 0x44

    .line 1662
    .line 1663
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1664
    .line 1665
    .line 1666
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1667
    .line 1668
    .line 1669
    move-result-object v0

    .line 1670
    new-instance v2, Lzs/c;

    .line 1671
    .line 1672
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1673
    .line 1674
    .line 1675
    move-result-object v0

    .line 1676
    const-string v3, "codeScannerOptionalModuleEvent"

    .line 1677
    .line 1678
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1679
    .line 1680
    .line 1681
    sput-object v2, Lkp/g3;->s0:Lzs/c;

    .line 1682
    .line 1683
    new-instance v0, Lkp/a;

    .line 1684
    .line 1685
    const/16 v2, 0x46

    .line 1686
    .line 1687
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1688
    .line 1689
    .line 1690
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1691
    .line 1692
    .line 1693
    move-result-object v0

    .line 1694
    new-instance v2, Lzs/c;

    .line 1695
    .line 1696
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1697
    .line 1698
    .line 1699
    move-result-object v0

    .line 1700
    const-string v3, "onDeviceExplicitContentCreateLogEvent"

    .line 1701
    .line 1702
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1703
    .line 1704
    .line 1705
    sput-object v2, Lkp/g3;->t0:Lzs/c;

    .line 1706
    .line 1707
    new-instance v0, Lkp/a;

    .line 1708
    .line 1709
    const/16 v2, 0x47

    .line 1710
    .line 1711
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1712
    .line 1713
    .line 1714
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1715
    .line 1716
    .line 1717
    move-result-object v0

    .line 1718
    new-instance v2, Lzs/c;

    .line 1719
    .line 1720
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1721
    .line 1722
    .line 1723
    move-result-object v0

    .line 1724
    const-string v3, "onDeviceExplicitContentLoadLogEvent"

    .line 1725
    .line 1726
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1727
    .line 1728
    .line 1729
    sput-object v2, Lkp/g3;->u0:Lzs/c;

    .line 1730
    .line 1731
    new-instance v0, Lkp/a;

    .line 1732
    .line 1733
    const/16 v2, 0x48

    .line 1734
    .line 1735
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1736
    .line 1737
    .line 1738
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1739
    .line 1740
    .line 1741
    move-result-object v0

    .line 1742
    new-instance v2, Lzs/c;

    .line 1743
    .line 1744
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1745
    .line 1746
    .line 1747
    move-result-object v0

    .line 1748
    const-string v3, "onDeviceExplicitContentInferenceLogEvent"

    .line 1749
    .line 1750
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1751
    .line 1752
    .line 1753
    sput-object v2, Lkp/g3;->v0:Lzs/c;

    .line 1754
    .line 1755
    new-instance v0, Lkp/a;

    .line 1756
    .line 1757
    const/16 v2, 0x49

    .line 1758
    .line 1759
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1760
    .line 1761
    .line 1762
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1763
    .line 1764
    .line 1765
    move-result-object v0

    .line 1766
    new-instance v2, Lzs/c;

    .line 1767
    .line 1768
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1769
    .line 1770
    .line 1771
    move-result-object v0

    .line 1772
    const-string v3, "aggregatedOnDeviceExplicitContentLogEvent"

    .line 1773
    .line 1774
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1775
    .line 1776
    .line 1777
    sput-object v2, Lkp/g3;->w0:Lzs/c;

    .line 1778
    .line 1779
    new-instance v0, Lkp/a;

    .line 1780
    .line 1781
    const/16 v2, 0x4a

    .line 1782
    .line 1783
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1784
    .line 1785
    .line 1786
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1787
    .line 1788
    .line 1789
    move-result-object v0

    .line 1790
    new-instance v2, Lzs/c;

    .line 1791
    .line 1792
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1793
    .line 1794
    .line 1795
    move-result-object v0

    .line 1796
    const-string v3, "onDeviceFaceMeshCreateLogEvent"

    .line 1797
    .line 1798
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1799
    .line 1800
    .line 1801
    sput-object v2, Lkp/g3;->x0:Lzs/c;

    .line 1802
    .line 1803
    new-instance v0, Lkp/a;

    .line 1804
    .line 1805
    const/16 v2, 0x4b

    .line 1806
    .line 1807
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1808
    .line 1809
    .line 1810
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1811
    .line 1812
    .line 1813
    move-result-object v0

    .line 1814
    new-instance v2, Lzs/c;

    .line 1815
    .line 1816
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1817
    .line 1818
    .line 1819
    move-result-object v0

    .line 1820
    const-string v3, "onDeviceFaceMeshLoadLogEvent"

    .line 1821
    .line 1822
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1823
    .line 1824
    .line 1825
    sput-object v2, Lkp/g3;->y0:Lzs/c;

    .line 1826
    .line 1827
    new-instance v0, Lkp/a;

    .line 1828
    .line 1829
    const/16 v2, 0x4c

    .line 1830
    .line 1831
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1832
    .line 1833
    .line 1834
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1835
    .line 1836
    .line 1837
    move-result-object v0

    .line 1838
    new-instance v2, Lzs/c;

    .line 1839
    .line 1840
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1841
    .line 1842
    .line 1843
    move-result-object v0

    .line 1844
    const-string v3, "onDeviceFaceMeshLogEvent"

    .line 1845
    .line 1846
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1847
    .line 1848
    .line 1849
    sput-object v2, Lkp/g3;->z0:Lzs/c;

    .line 1850
    .line 1851
    new-instance v0, Lkp/a;

    .line 1852
    .line 1853
    const/16 v2, 0x4d

    .line 1854
    .line 1855
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1856
    .line 1857
    .line 1858
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1859
    .line 1860
    .line 1861
    move-result-object v0

    .line 1862
    new-instance v2, Lzs/c;

    .line 1863
    .line 1864
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1865
    .line 1866
    .line 1867
    move-result-object v0

    .line 1868
    const-string v3, "aggregatedOnDeviceFaceMeshLogEvent"

    .line 1869
    .line 1870
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1871
    .line 1872
    .line 1873
    sput-object v2, Lkp/g3;->A0:Lzs/c;

    .line 1874
    .line 1875
    new-instance v0, Lkp/a;

    .line 1876
    .line 1877
    const/16 v2, 0x4e

    .line 1878
    .line 1879
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1880
    .line 1881
    .line 1882
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1883
    .line 1884
    .line 1885
    move-result-object v0

    .line 1886
    new-instance v2, Lzs/c;

    .line 1887
    .line 1888
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1889
    .line 1890
    .line 1891
    move-result-object v0

    .line 1892
    const-string v3, "smartReplyOptionalModuleLogEvent"

    .line 1893
    .line 1894
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1895
    .line 1896
    .line 1897
    sput-object v2, Lkp/g3;->B0:Lzs/c;

    .line 1898
    .line 1899
    new-instance v0, Lkp/a;

    .line 1900
    .line 1901
    const/16 v2, 0x50

    .line 1902
    .line 1903
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1904
    .line 1905
    .line 1906
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1907
    .line 1908
    .line 1909
    move-result-object v0

    .line 1910
    new-instance v2, Lzs/c;

    .line 1911
    .line 1912
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1913
    .line 1914
    .line 1915
    move-result-object v0

    .line 1916
    const-string v3, "textDetectionOptionalModuleLogEvent"

    .line 1917
    .line 1918
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1919
    .line 1920
    .line 1921
    sput-object v2, Lkp/g3;->C0:Lzs/c;

    .line 1922
    .line 1923
    new-instance v0, Lkp/a;

    .line 1924
    .line 1925
    const/16 v2, 0x51

    .line 1926
    .line 1927
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1928
    .line 1929
    .line 1930
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1931
    .line 1932
    .line 1933
    move-result-object v0

    .line 1934
    new-instance v2, Lzs/c;

    .line 1935
    .line 1936
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1937
    .line 1938
    .line 1939
    move-result-object v0

    .line 1940
    const-string v3, "onDeviceImageQualityAnalysisCreateLogEvent"

    .line 1941
    .line 1942
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1943
    .line 1944
    .line 1945
    sput-object v2, Lkp/g3;->D0:Lzs/c;

    .line 1946
    .line 1947
    new-instance v0, Lkp/a;

    .line 1948
    .line 1949
    const/16 v2, 0x52

    .line 1950
    .line 1951
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1952
    .line 1953
    .line 1954
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1955
    .line 1956
    .line 1957
    move-result-object v0

    .line 1958
    new-instance v2, Lzs/c;

    .line 1959
    .line 1960
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1961
    .line 1962
    .line 1963
    move-result-object v0

    .line 1964
    const-string v3, "onDeviceImageQualityAnalysisLoadLogEvent"

    .line 1965
    .line 1966
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1967
    .line 1968
    .line 1969
    sput-object v2, Lkp/g3;->E0:Lzs/c;

    .line 1970
    .line 1971
    new-instance v0, Lkp/a;

    .line 1972
    .line 1973
    const/16 v2, 0x53

    .line 1974
    .line 1975
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 1976
    .line 1977
    .line 1978
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 1979
    .line 1980
    .line 1981
    move-result-object v0

    .line 1982
    new-instance v2, Lzs/c;

    .line 1983
    .line 1984
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 1985
    .line 1986
    .line 1987
    move-result-object v0

    .line 1988
    const-string v3, "onDeviceImageQualityAnalysisLogEvent"

    .line 1989
    .line 1990
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1991
    .line 1992
    .line 1993
    sput-object v2, Lkp/g3;->F0:Lzs/c;

    .line 1994
    .line 1995
    new-instance v0, Lkp/a;

    .line 1996
    .line 1997
    const/16 v2, 0x54

    .line 1998
    .line 1999
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 2000
    .line 2001
    .line 2002
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 2003
    .line 2004
    .line 2005
    move-result-object v0

    .line 2006
    new-instance v2, Lzs/c;

    .line 2007
    .line 2008
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 2009
    .line 2010
    .line 2011
    move-result-object v0

    .line 2012
    const-string v3, "aggregatedOnDeviceImageQualityAnalysisLogEvent"

    .line 2013
    .line 2014
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 2015
    .line 2016
    .line 2017
    sput-object v2, Lkp/g3;->G0:Lzs/c;

    .line 2018
    .line 2019
    new-instance v0, Lkp/a;

    .line 2020
    .line 2021
    const/16 v2, 0x58

    .line 2022
    .line 2023
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 2024
    .line 2025
    .line 2026
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 2027
    .line 2028
    .line 2029
    move-result-object v0

    .line 2030
    new-instance v2, Lzs/c;

    .line 2031
    .line 2032
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 2033
    .line 2034
    .line 2035
    move-result-object v0

    .line 2036
    const-string v3, "imageQualityAnalysisOptionalModuleLogEvent"

    .line 2037
    .line 2038
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 2039
    .line 2040
    .line 2041
    sput-object v2, Lkp/g3;->H0:Lzs/c;

    .line 2042
    .line 2043
    new-instance v0, Lkp/a;

    .line 2044
    .line 2045
    const/16 v2, 0x59

    .line 2046
    .line 2047
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 2048
    .line 2049
    .line 2050
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 2051
    .line 2052
    .line 2053
    move-result-object v0

    .line 2054
    new-instance v2, Lzs/c;

    .line 2055
    .line 2056
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 2057
    .line 2058
    .line 2059
    move-result-object v0

    .line 2060
    const-string v3, "imageCaptioningOptionalModuleLogEvent"

    .line 2061
    .line 2062
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 2063
    .line 2064
    .line 2065
    sput-object v2, Lkp/g3;->I0:Lzs/c;

    .line 2066
    .line 2067
    new-instance v0, Lkp/a;

    .line 2068
    .line 2069
    const/16 v2, 0x5a

    .line 2070
    .line 2071
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 2072
    .line 2073
    .line 2074
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 2075
    .line 2076
    .line 2077
    move-result-object v0

    .line 2078
    new-instance v2, Lzs/c;

    .line 2079
    .line 2080
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 2081
    .line 2082
    .line 2083
    move-result-object v0

    .line 2084
    const-string v3, "onDeviceImageCaptioningCreateLogEvent"

    .line 2085
    .line 2086
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 2087
    .line 2088
    .line 2089
    sput-object v2, Lkp/g3;->J0:Lzs/c;

    .line 2090
    .line 2091
    new-instance v0, Lkp/a;

    .line 2092
    .line 2093
    const/16 v2, 0x5b

    .line 2094
    .line 2095
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 2096
    .line 2097
    .line 2098
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 2099
    .line 2100
    .line 2101
    move-result-object v0

    .line 2102
    new-instance v2, Lzs/c;

    .line 2103
    .line 2104
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 2105
    .line 2106
    .line 2107
    move-result-object v0

    .line 2108
    const-string v3, "onDeviceImageCaptioningLoadLogEvent"

    .line 2109
    .line 2110
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 2111
    .line 2112
    .line 2113
    sput-object v2, Lkp/g3;->K0:Lzs/c;

    .line 2114
    .line 2115
    new-instance v0, Lkp/a;

    .line 2116
    .line 2117
    const/16 v2, 0x5c

    .line 2118
    .line 2119
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 2120
    .line 2121
    .line 2122
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 2123
    .line 2124
    .line 2125
    move-result-object v0

    .line 2126
    new-instance v2, Lzs/c;

    .line 2127
    .line 2128
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 2129
    .line 2130
    .line 2131
    move-result-object v0

    .line 2132
    const-string v3, "onDeviceImageCaptioningInferenceLogEvent"

    .line 2133
    .line 2134
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 2135
    .line 2136
    .line 2137
    sput-object v2, Lkp/g3;->L0:Lzs/c;

    .line 2138
    .line 2139
    new-instance v0, Lkp/a;

    .line 2140
    .line 2141
    const/16 v2, 0x5d

    .line 2142
    .line 2143
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 2144
    .line 2145
    .line 2146
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 2147
    .line 2148
    .line 2149
    move-result-object v0

    .line 2150
    new-instance v1, Lzs/c;

    .line 2151
    .line 2152
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 2153
    .line 2154
    .line 2155
    move-result-object v0

    .line 2156
    const-string v2, "aggregatedOnDeviceImageCaptioningInferenceLogEvent"

    .line 2157
    .line 2158
    invoke-direct {v1, v2, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 2159
    .line 2160
    .line 2161
    sput-object v1, Lkp/g3;->M0:Lzs/c;

    .line 2162
    .line 2163
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p1, Lkp/l7;

    .line 2
    .line 3
    check-cast p2, Lzs/e;

    .line 4
    .line 5
    sget-object p0, Lkp/g3;->b:Lzs/c;

    .line 6
    .line 7
    iget-object v0, p1, Lkp/l7;->a:Lkp/l9;

    .line 8
    .line 9
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 10
    .line 11
    .line 12
    sget-object p0, Lkp/g3;->c:Lzs/c;

    .line 13
    .line 14
    iget-object v0, p1, Lkp/l7;->b:Lkp/k7;

    .line 15
    .line 16
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 17
    .line 18
    .line 19
    sget-object p0, Lkp/g3;->d:Lzs/c;

    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 23
    .line 24
    .line 25
    sget-object p0, Lkp/g3;->e:Lzs/c;

    .line 26
    .line 27
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 28
    .line 29
    .line 30
    sget-object p0, Lkp/g3;->f:Lzs/c;

    .line 31
    .line 32
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 33
    .line 34
    .line 35
    sget-object p0, Lkp/g3;->g:Lzs/c;

    .line 36
    .line 37
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 38
    .line 39
    .line 40
    sget-object p0, Lkp/g3;->h:Lzs/c;

    .line 41
    .line 42
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 43
    .line 44
    .line 45
    sget-object p0, Lkp/g3;->i:Lzs/c;

    .line 46
    .line 47
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 48
    .line 49
    .line 50
    sget-object p0, Lkp/g3;->j:Lzs/c;

    .line 51
    .line 52
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 53
    .line 54
    .line 55
    sget-object p0, Lkp/g3;->k:Lzs/c;

    .line 56
    .line 57
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 58
    .line 59
    .line 60
    sget-object p0, Lkp/g3;->l:Lzs/c;

    .line 61
    .line 62
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 63
    .line 64
    .line 65
    sget-object p0, Lkp/g3;->m:Lzs/c;

    .line 66
    .line 67
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 68
    .line 69
    .line 70
    sget-object p0, Lkp/g3;->n:Lzs/c;

    .line 71
    .line 72
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 73
    .line 74
    .line 75
    sget-object p0, Lkp/g3;->o:Lzs/c;

    .line 76
    .line 77
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 78
    .line 79
    .line 80
    sget-object p0, Lkp/g3;->p:Lzs/c;

    .line 81
    .line 82
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 83
    .line 84
    .line 85
    sget-object p0, Lkp/g3;->q:Lzs/c;

    .line 86
    .line 87
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 88
    .line 89
    .line 90
    sget-object p0, Lkp/g3;->r:Lzs/c;

    .line 91
    .line 92
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 93
    .line 94
    .line 95
    sget-object p0, Lkp/g3;->s:Lzs/c;

    .line 96
    .line 97
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 98
    .line 99
    .line 100
    sget-object p0, Lkp/g3;->t:Lzs/c;

    .line 101
    .line 102
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 103
    .line 104
    .line 105
    sget-object p0, Lkp/g3;->u:Lzs/c;

    .line 106
    .line 107
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 108
    .line 109
    .line 110
    sget-object p0, Lkp/g3;->v:Lzs/c;

    .line 111
    .line 112
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 113
    .line 114
    .line 115
    sget-object p0, Lkp/g3;->w:Lzs/c;

    .line 116
    .line 117
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 118
    .line 119
    .line 120
    sget-object p0, Lkp/g3;->x:Lzs/c;

    .line 121
    .line 122
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 123
    .line 124
    .line 125
    sget-object p0, Lkp/g3;->y:Lzs/c;

    .line 126
    .line 127
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 128
    .line 129
    .line 130
    sget-object p0, Lkp/g3;->z:Lzs/c;

    .line 131
    .line 132
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 133
    .line 134
    .line 135
    sget-object p0, Lkp/g3;->A:Lzs/c;

    .line 136
    .line 137
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 138
    .line 139
    .line 140
    sget-object p0, Lkp/g3;->B:Lzs/c;

    .line 141
    .line 142
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 143
    .line 144
    .line 145
    sget-object p0, Lkp/g3;->C:Lzs/c;

    .line 146
    .line 147
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 148
    .line 149
    .line 150
    sget-object p0, Lkp/g3;->D:Lzs/c;

    .line 151
    .line 152
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 153
    .line 154
    .line 155
    sget-object p0, Lkp/g3;->E:Lzs/c;

    .line 156
    .line 157
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 158
    .line 159
    .line 160
    sget-object p0, Lkp/g3;->F:Lzs/c;

    .line 161
    .line 162
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 163
    .line 164
    .line 165
    sget-object p0, Lkp/g3;->G:Lzs/c;

    .line 166
    .line 167
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 168
    .line 169
    .line 170
    sget-object p0, Lkp/g3;->H:Lzs/c;

    .line 171
    .line 172
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 173
    .line 174
    .line 175
    sget-object p0, Lkp/g3;->I:Lzs/c;

    .line 176
    .line 177
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 178
    .line 179
    .line 180
    sget-object p0, Lkp/g3;->J:Lzs/c;

    .line 181
    .line 182
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 183
    .line 184
    .line 185
    sget-object p0, Lkp/g3;->K:Lzs/c;

    .line 186
    .line 187
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 188
    .line 189
    .line 190
    sget-object p0, Lkp/g3;->L:Lzs/c;

    .line 191
    .line 192
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 193
    .line 194
    .line 195
    sget-object p0, Lkp/g3;->M:Lzs/c;

    .line 196
    .line 197
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 198
    .line 199
    .line 200
    sget-object p0, Lkp/g3;->N:Lzs/c;

    .line 201
    .line 202
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 203
    .line 204
    .line 205
    sget-object p0, Lkp/g3;->O:Lzs/c;

    .line 206
    .line 207
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 208
    .line 209
    .line 210
    sget-object p0, Lkp/g3;->P:Lzs/c;

    .line 211
    .line 212
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 213
    .line 214
    .line 215
    sget-object p0, Lkp/g3;->Q:Lzs/c;

    .line 216
    .line 217
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 218
    .line 219
    .line 220
    sget-object p0, Lkp/g3;->R:Lzs/c;

    .line 221
    .line 222
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 223
    .line 224
    .line 225
    sget-object p0, Lkp/g3;->S:Lzs/c;

    .line 226
    .line 227
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 228
    .line 229
    .line 230
    sget-object p0, Lkp/g3;->T:Lzs/c;

    .line 231
    .line 232
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 233
    .line 234
    .line 235
    sget-object p0, Lkp/g3;->U:Lzs/c;

    .line 236
    .line 237
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 238
    .line 239
    .line 240
    sget-object p0, Lkp/g3;->V:Lzs/c;

    .line 241
    .line 242
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 243
    .line 244
    .line 245
    sget-object p0, Lkp/g3;->W:Lzs/c;

    .line 246
    .line 247
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 248
    .line 249
    .line 250
    sget-object p0, Lkp/g3;->X:Lzs/c;

    .line 251
    .line 252
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 253
    .line 254
    .line 255
    sget-object p0, Lkp/g3;->Y:Lzs/c;

    .line 256
    .line 257
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 258
    .line 259
    .line 260
    sget-object p0, Lkp/g3;->Z:Lzs/c;

    .line 261
    .line 262
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 263
    .line 264
    .line 265
    sget-object p0, Lkp/g3;->a0:Lzs/c;

    .line 266
    .line 267
    iget-object p1, p1, Lkp/l7;->c:Lkp/f7;

    .line 268
    .line 269
    invoke-interface {p2, p0, p1}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 270
    .line 271
    .line 272
    sget-object p0, Lkp/g3;->b0:Lzs/c;

    .line 273
    .line 274
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 275
    .line 276
    .line 277
    sget-object p0, Lkp/g3;->c0:Lzs/c;

    .line 278
    .line 279
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 280
    .line 281
    .line 282
    sget-object p0, Lkp/g3;->d0:Lzs/c;

    .line 283
    .line 284
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 285
    .line 286
    .line 287
    sget-object p0, Lkp/g3;->e0:Lzs/c;

    .line 288
    .line 289
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 290
    .line 291
    .line 292
    sget-object p0, Lkp/g3;->f0:Lzs/c;

    .line 293
    .line 294
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 295
    .line 296
    .line 297
    sget-object p0, Lkp/g3;->g0:Lzs/c;

    .line 298
    .line 299
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 300
    .line 301
    .line 302
    sget-object p0, Lkp/g3;->h0:Lzs/c;

    .line 303
    .line 304
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 305
    .line 306
    .line 307
    sget-object p0, Lkp/g3;->i0:Lzs/c;

    .line 308
    .line 309
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 310
    .line 311
    .line 312
    sget-object p0, Lkp/g3;->j0:Lzs/c;

    .line 313
    .line 314
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 315
    .line 316
    .line 317
    sget-object p0, Lkp/g3;->k0:Lzs/c;

    .line 318
    .line 319
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 320
    .line 321
    .line 322
    sget-object p0, Lkp/g3;->l0:Lzs/c;

    .line 323
    .line 324
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 325
    .line 326
    .line 327
    sget-object p0, Lkp/g3;->m0:Lzs/c;

    .line 328
    .line 329
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 330
    .line 331
    .line 332
    sget-object p0, Lkp/g3;->n0:Lzs/c;

    .line 333
    .line 334
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 335
    .line 336
    .line 337
    sget-object p0, Lkp/g3;->o0:Lzs/c;

    .line 338
    .line 339
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 340
    .line 341
    .line 342
    sget-object p0, Lkp/g3;->p0:Lzs/c;

    .line 343
    .line 344
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 345
    .line 346
    .line 347
    sget-object p0, Lkp/g3;->q0:Lzs/c;

    .line 348
    .line 349
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 350
    .line 351
    .line 352
    sget-object p0, Lkp/g3;->r0:Lzs/c;

    .line 353
    .line 354
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 355
    .line 356
    .line 357
    sget-object p0, Lkp/g3;->s0:Lzs/c;

    .line 358
    .line 359
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 360
    .line 361
    .line 362
    sget-object p0, Lkp/g3;->t0:Lzs/c;

    .line 363
    .line 364
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 365
    .line 366
    .line 367
    sget-object p0, Lkp/g3;->u0:Lzs/c;

    .line 368
    .line 369
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 370
    .line 371
    .line 372
    sget-object p0, Lkp/g3;->v0:Lzs/c;

    .line 373
    .line 374
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 375
    .line 376
    .line 377
    sget-object p0, Lkp/g3;->w0:Lzs/c;

    .line 378
    .line 379
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 380
    .line 381
    .line 382
    sget-object p0, Lkp/g3;->x0:Lzs/c;

    .line 383
    .line 384
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 385
    .line 386
    .line 387
    sget-object p0, Lkp/g3;->y0:Lzs/c;

    .line 388
    .line 389
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 390
    .line 391
    .line 392
    sget-object p0, Lkp/g3;->z0:Lzs/c;

    .line 393
    .line 394
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 395
    .line 396
    .line 397
    sget-object p0, Lkp/g3;->A0:Lzs/c;

    .line 398
    .line 399
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 400
    .line 401
    .line 402
    sget-object p0, Lkp/g3;->B0:Lzs/c;

    .line 403
    .line 404
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 405
    .line 406
    .line 407
    sget-object p0, Lkp/g3;->C0:Lzs/c;

    .line 408
    .line 409
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 410
    .line 411
    .line 412
    sget-object p0, Lkp/g3;->D0:Lzs/c;

    .line 413
    .line 414
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 415
    .line 416
    .line 417
    sget-object p0, Lkp/g3;->E0:Lzs/c;

    .line 418
    .line 419
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 420
    .line 421
    .line 422
    sget-object p0, Lkp/g3;->F0:Lzs/c;

    .line 423
    .line 424
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 425
    .line 426
    .line 427
    sget-object p0, Lkp/g3;->G0:Lzs/c;

    .line 428
    .line 429
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 430
    .line 431
    .line 432
    sget-object p0, Lkp/g3;->H0:Lzs/c;

    .line 433
    .line 434
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 435
    .line 436
    .line 437
    sget-object p0, Lkp/g3;->I0:Lzs/c;

    .line 438
    .line 439
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 440
    .line 441
    .line 442
    sget-object p0, Lkp/g3;->J0:Lzs/c;

    .line 443
    .line 444
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 445
    .line 446
    .line 447
    sget-object p0, Lkp/g3;->K0:Lzs/c;

    .line 448
    .line 449
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 450
    .line 451
    .line 452
    sget-object p0, Lkp/g3;->L0:Lzs/c;

    .line 453
    .line 454
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 455
    .line 456
    .line 457
    sget-object p0, Lkp/g3;->M0:Lzs/c;

    .line 458
    .line 459
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 460
    .line 461
    .line 462
    return-void
.end method
