.class public final synthetic Lhz/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lhz/a;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget p0, p0, Lhz/a;->d:I

    .line 2
    .line 3
    const/16 v0, 0x2d

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x1

    .line 7
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    const/4 v4, 0x3

    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    const-string p0, "VideoPlayer: Start Rendering"

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_0
    const-string p0, "VideoPlayer: LifecycleEffect - Disposed"

    .line 17
    .line 18
    return-object p0

    .line 19
    :pswitch_1
    sget-object p0, Lim/c;->a:Ljm/a;

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_2
    sget-object p0, Lgz0/b0;->Companion:Lgz0/a0;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    invoke-static {}, Lgz0/a0;->a()Lgz0/b0;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_3
    sget-object p0, Lmy0/g;->a:Lmy0/b;

    .line 33
    .line 34
    invoke-interface {p0}, Lmy0/b;->now()Lmy0/f;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-static {p0}, Lkp/t9;->d(Lmy0/f;)Lgz0/p;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :pswitch_4
    sget-object p0, Li91/o4;->a:Ljava/util/List;

    .line 44
    .line 45
    return-object v3

    .line 46
    :pswitch_5
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->j()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :pswitch_6
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->a()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_7
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->H()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0

    .line 61
    :pswitch_8
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->q()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0

    .line 66
    :pswitch_9
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->g()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0

    .line 71
    :pswitch_a
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->B()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    return-object p0

    .line 76
    :pswitch_b
    sget p0, Li50/s;->a:F

    .line 77
    .line 78
    return-object v3

    .line 79
    :pswitch_c
    sget p0, Li40/p1;->a:F

    .line 80
    .line 81
    return-object v3

    .line 82
    :pswitch_d
    sget p0, Li40/o0;->a:F

    .line 83
    .line 84
    return-object v3

    .line 85
    :pswitch_e
    sget p0, Li40/e0;->a:F

    .line 86
    .line 87
    return-object v3

    .line 88
    :pswitch_f
    sget p0, Li40/i;->a:F

    .line 89
    .line 90
    return-object v3

    .line 91
    :pswitch_10
    const-string p0, "No enrollmentFlow was selected for enrollment"

    .line 92
    .line 93
    return-object p0

    .line 94
    :pswitch_11
    new-instance p0, Lhz0/d2;

    .line 95
    .line 96
    new-instance v1, Lbn/c;

    .line 97
    .line 98
    invoke-direct {v1, v4}, Lbn/c;-><init>(I)V

    .line 99
    .line 100
    .line 101
    invoke-direct {p0, v1}, Lhz0/d2;-><init>(Lbn/c;)V

    .line 102
    .line 103
    .line 104
    invoke-static {p0}, Lhz0/z;->f(Lhz0/z;)V

    .line 105
    .line 106
    .line 107
    invoke-static {p0, v0}, Llp/f1;->b(Lhz0/a0;C)V

    .line 108
    .line 109
    .line 110
    invoke-static {p0}, Lhz0/z;->j(Lhz0/z;)V

    .line 111
    .line 112
    .line 113
    new-instance v0, Lhz0/s;

    .line 114
    .line 115
    invoke-interface {p0}, Lhz0/b;->build()Ljz0/d;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    invoke-direct {v0, p0, v2}, Lhz0/s;-><init>(Ljz0/d;I)V

    .line 120
    .line 121
    .line 122
    return-object v0

    .line 123
    :pswitch_12
    new-instance p0, Lhz0/r1;

    .line 124
    .line 125
    new-instance v0, Lbn/c;

    .line 126
    .line 127
    invoke-direct {v0, v4}, Lbn/c;-><init>(I)V

    .line 128
    .line 129
    .line 130
    invoke-direct {p0, v0}, Lhz0/r1;-><init>(Lbn/c;)V

    .line 131
    .line 132
    .line 133
    invoke-static {p0}, Lhz0/y;->h(Lhz0/y;)V

    .line 134
    .line 135
    .line 136
    invoke-static {p0}, Lhz0/y;->i(Lhz0/y;)V

    .line 137
    .line 138
    .line 139
    new-instance v0, Lhz0/s1;

    .line 140
    .line 141
    invoke-interface {p0}, Lhz0/b;->build()Ljz0/d;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    invoke-direct {v0, p0}, Lhz0/s1;-><init>(Ljz0/d;)V

    .line 146
    .line 147
    .line 148
    return-object v0

    .line 149
    :pswitch_13
    new-instance p0, Lhz0/r1;

    .line 150
    .line 151
    new-instance v0, Lbn/c;

    .line 152
    .line 153
    invoke-direct {v0, v4}, Lbn/c;-><init>(I)V

    .line 154
    .line 155
    .line 156
    invoke-direct {p0, v0}, Lhz0/r1;-><init>(Lbn/c;)V

    .line 157
    .line 158
    .line 159
    new-instance v0, Lhz0/t1;

    .line 160
    .line 161
    const/4 v3, 0x4

    .line 162
    invoke-direct {v0, v3}, Lhz0/t1;-><init>(I)V

    .line 163
    .line 164
    .line 165
    new-array v2, v2, [Lay0/k;

    .line 166
    .line 167
    aput-object v0, v2, v1

    .line 168
    .line 169
    new-instance v0, Lhz0/t1;

    .line 170
    .line 171
    const/4 v1, 0x5

    .line 172
    invoke-direct {v0, v1}, Lhz0/t1;-><init>(I)V

    .line 173
    .line 174
    .line 175
    invoke-static {p0, v2, v0}, Llp/f1;->a(Lhz0/a0;[Lay0/k;Lay0/k;)V

    .line 176
    .line 177
    .line 178
    new-instance v0, Lhz0/s1;

    .line 179
    .line 180
    invoke-interface {p0}, Lhz0/b;->build()Ljz0/d;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    invoke-direct {v0, p0}, Lhz0/s1;-><init>(Ljz0/d;)V

    .line 185
    .line 186
    .line 187
    return-object v0

    .line 188
    :pswitch_14
    new-instance p0, Lhz0/r1;

    .line 189
    .line 190
    new-instance v0, Lbn/c;

    .line 191
    .line 192
    invoke-direct {v0, v4}, Lbn/c;-><init>(I)V

    .line 193
    .line 194
    .line 195
    invoke-direct {p0, v0}, Lhz0/r1;-><init>(Lbn/c;)V

    .line 196
    .line 197
    .line 198
    new-instance v0, Lhz0/t1;

    .line 199
    .line 200
    const/4 v3, 0x2

    .line 201
    invoke-direct {v0, v3}, Lhz0/t1;-><init>(I)V

    .line 202
    .line 203
    .line 204
    new-array v2, v2, [Lay0/k;

    .line 205
    .line 206
    aput-object v0, v2, v1

    .line 207
    .line 208
    new-instance v0, Lhz0/t1;

    .line 209
    .line 210
    invoke-direct {v0, v4}, Lhz0/t1;-><init>(I)V

    .line 211
    .line 212
    .line 213
    invoke-static {p0, v2, v0}, Llp/f1;->a(Lhz0/a0;[Lay0/k;Lay0/k;)V

    .line 214
    .line 215
    .line 216
    new-instance v0, Lhz0/s1;

    .line 217
    .line 218
    invoke-interface {p0}, Lhz0/b;->build()Ljz0/d;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    invoke-direct {v0, p0}, Lhz0/s1;-><init>(Ljz0/d;)V

    .line 223
    .line 224
    .line 225
    return-object v0

    .line 226
    :pswitch_15
    new-instance p0, Lhz0/s0;

    .line 227
    .line 228
    new-instance v0, Lbn/c;

    .line 229
    .line 230
    invoke-direct {v0, v4}, Lbn/c;-><init>(I)V

    .line 231
    .line 232
    .line 233
    invoke-direct {p0, v0}, Lhz0/s0;-><init>(Lbn/c;)V

    .line 234
    .line 235
    .line 236
    invoke-static {p0}, Lhz0/x;->k(Lhz0/x;)V

    .line 237
    .line 238
    .line 239
    const/16 v0, 0x3a

    .line 240
    .line 241
    invoke-static {p0, v0}, Llp/f1;->b(Lhz0/a0;C)V

    .line 242
    .line 243
    .line 244
    invoke-static {p0}, Lhz0/x;->o(Lhz0/x;)V

    .line 245
    .line 246
    .line 247
    new-instance v0, Lh70/f;

    .line 248
    .line 249
    const/16 v3, 0x1b

    .line 250
    .line 251
    invoke-direct {v0, v3}, Lh70/f;-><init>(I)V

    .line 252
    .line 253
    .line 254
    new-array v2, v2, [Lay0/k;

    .line 255
    .line 256
    aput-object v0, v2, v1

    .line 257
    .line 258
    new-instance v0, Lh70/f;

    .line 259
    .line 260
    const/16 v1, 0x1c

    .line 261
    .line 262
    invoke-direct {v0, v1}, Lh70/f;-><init>(I)V

    .line 263
    .line 264
    .line 265
    invoke-static {p0, v2, v0}, Llp/f1;->a(Lhz0/a0;[Lay0/k;Lay0/k;)V

    .line 266
    .line 267
    .line 268
    new-instance v0, Lhz0/t0;

    .line 269
    .line 270
    invoke-interface {p0}, Lhz0/b;->build()Ljz0/d;

    .line 271
    .line 272
    .line 273
    move-result-object p0

    .line 274
    invoke-direct {v0, p0}, Lhz0/t0;-><init>(Ljz0/d;)V

    .line 275
    .line 276
    .line 277
    return-object v0

    .line 278
    :pswitch_16
    new-instance p0, Lh70/f;

    .line 279
    .line 280
    const/16 v0, 0x18

    .line 281
    .line 282
    invoke-direct {p0, v0}, Lh70/f;-><init>(I)V

    .line 283
    .line 284
    .line 285
    new-instance v0, Lhz0/p0;

    .line 286
    .line 287
    new-instance v1, Lbn/c;

    .line 288
    .line 289
    invoke-direct {v1, v4}, Lbn/c;-><init>(I)V

    .line 290
    .line 291
    .line 292
    invoke-direct {v0, v1}, Lhz0/p0;-><init>(Lbn/c;)V

    .line 293
    .line 294
    .line 295
    invoke-virtual {p0, v0}, Lh70/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    new-instance p0, Lhz0/q0;

    .line 299
    .line 300
    invoke-interface {v0}, Lhz0/b;->build()Ljz0/d;

    .line 301
    .line 302
    .line 303
    move-result-object v0

    .line 304
    invoke-direct {p0, v0}, Lhz0/q0;-><init>(Ljz0/d;)V

    .line 305
    .line 306
    .line 307
    return-object p0

    .line 308
    :pswitch_17
    new-instance p0, Lhz0/m0;

    .line 309
    .line 310
    new-instance v0, Lbn/c;

    .line 311
    .line 312
    invoke-direct {v0, v4}, Lbn/c;-><init>(I)V

    .line 313
    .line 314
    .line 315
    invoke-direct {p0, v0}, Lhz0/m0;-><init>(Lbn/c;)V

    .line 316
    .line 317
    .line 318
    invoke-static {p0}, Lhz0/z;->f(Lhz0/z;)V

    .line 319
    .line 320
    .line 321
    invoke-static {p0}, Lhz0/z;->j(Lhz0/z;)V

    .line 322
    .line 323
    .line 324
    invoke-static {p0}, Lhz0/v;->p(Lhz0/v;)V

    .line 325
    .line 326
    .line 327
    new-instance v0, Lhz0/n0;

    .line 328
    .line 329
    invoke-interface {p0}, Lhz0/b;->build()Ljz0/d;

    .line 330
    .line 331
    .line 332
    move-result-object p0

    .line 333
    invoke-direct {v0, p0}, Lhz0/n0;-><init>(Ljz0/d;)V

    .line 334
    .line 335
    .line 336
    return-object v0

    .line 337
    :pswitch_18
    new-instance p0, Lhz0/m0;

    .line 338
    .line 339
    new-instance v1, Lbn/c;

    .line 340
    .line 341
    invoke-direct {v1, v4}, Lbn/c;-><init>(I)V

    .line 342
    .line 343
    .line 344
    invoke-direct {p0, v1}, Lhz0/m0;-><init>(Lbn/c;)V

    .line 345
    .line 346
    .line 347
    invoke-static {p0}, Lhz0/z;->f(Lhz0/z;)V

    .line 348
    .line 349
    .line 350
    invoke-static {p0, v0}, Llp/f1;->b(Lhz0/a0;C)V

    .line 351
    .line 352
    .line 353
    invoke-static {p0}, Lhz0/z;->j(Lhz0/z;)V

    .line 354
    .line 355
    .line 356
    invoke-static {p0, v0}, Llp/f1;->b(Lhz0/a0;C)V

    .line 357
    .line 358
    .line 359
    invoke-static {p0}, Lhz0/v;->p(Lhz0/v;)V

    .line 360
    .line 361
    .line 362
    new-instance v0, Lhz0/n0;

    .line 363
    .line 364
    invoke-interface {p0}, Lhz0/b;->build()Ljz0/d;

    .line 365
    .line 366
    .line 367
    move-result-object p0

    .line 368
    invoke-direct {v0, p0}, Lhz0/n0;-><init>(Ljz0/d;)V

    .line 369
    .line 370
    .line 371
    return-object v0

    .line 372
    :pswitch_19
    sget-object p0, Lgz/e;->c:Lgz/e;

    .line 373
    .line 374
    return-object p0

    .line 375
    :pswitch_1a
    sget-object p0, Lgz/f;->c:Lgz/f;

    .line 376
    .line 377
    return-object p0

    .line 378
    :pswitch_1b
    sget-object p0, Lgz/g;->c:Lgz/g;

    .line 379
    .line 380
    return-object p0

    .line 381
    :pswitch_1c
    sget-object p0, Lgz/c;->c:Lgz/c;

    .line 382
    .line 383
    return-object p0

    .line 384
    nop

    .line 385
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
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
