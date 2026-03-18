.class public final La7/s;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final g:La7/s;

.field public static final h:La7/s;

.field public static final i:La7/s;

.field public static final j:La7/s;

.field public static final k:La7/s;

.field public static final l:La7/s;

.field public static final m:La7/s;

.field public static final n:La7/s;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, La7/s;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, La7/s;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, La7/s;->g:La7/s;

    .line 9
    .line 10
    new-instance v0, La7/s;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, La7/s;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, La7/s;->h:La7/s;

    .line 17
    .line 18
    new-instance v0, La7/s;

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-direct {v0, v1, v2}, La7/s;-><init>(II)V

    .line 22
    .line 23
    .line 24
    sput-object v0, La7/s;->i:La7/s;

    .line 25
    .line 26
    new-instance v0, La7/s;

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    invoke-direct {v0, v1, v2}, La7/s;-><init>(II)V

    .line 30
    .line 31
    .line 32
    sput-object v0, La7/s;->j:La7/s;

    .line 33
    .line 34
    new-instance v0, La7/s;

    .line 35
    .line 36
    const/4 v2, 0x4

    .line 37
    invoke-direct {v0, v1, v2}, La7/s;-><init>(II)V

    .line 38
    .line 39
    .line 40
    sput-object v0, La7/s;->k:La7/s;

    .line 41
    .line 42
    new-instance v0, La7/s;

    .line 43
    .line 44
    const/4 v2, 0x5

    .line 45
    invoke-direct {v0, v1, v2}, La7/s;-><init>(II)V

    .line 46
    .line 47
    .line 48
    sput-object v0, La7/s;->l:La7/s;

    .line 49
    .line 50
    new-instance v0, La7/s;

    .line 51
    .line 52
    const/4 v2, 0x6

    .line 53
    invoke-direct {v0, v1, v2}, La7/s;-><init>(II)V

    .line 54
    .line 55
    .line 56
    sput-object v0, La7/s;->m:La7/s;

    .line 57
    .line 58
    new-instance v0, La7/s;

    .line 59
    .line 60
    const/4 v2, 0x7

    .line 61
    invoke-direct {v0, v1, v2}, La7/s;-><init>(II)V

    .line 62
    .line 63
    .line 64
    sput-object v0, La7/s;->n:La7/s;

    .line 65
    .line 66
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, La7/s;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget p0, p0, La7/s;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ly6/p;

    .line 7
    .line 8
    instance-of p0, p1, Ly6/d;

    .line 9
    .line 10
    if-nez p0, :cond_1

    .line 11
    .line 12
    instance-of p0, p1, Lz6/b;

    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    goto :goto_1

    .line 19
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 20
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :pswitch_0
    check-cast p1, Ly6/p;

    .line 26
    .line 27
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_1
    check-cast p1, Ly6/p;

    .line 31
    .line 32
    instance-of p0, p1, Lz6/b;

    .line 33
    .line 34
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_2
    check-cast p1, Ly6/p;

    .line 40
    .line 41
    instance-of p0, p1, Ly6/e;

    .line 42
    .line 43
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_3
    check-cast p1, Ly6/l;

    .line 49
    .line 50
    instance-of p0, p1, La7/d0;

    .line 51
    .line 52
    if-eqz p0, :cond_2

    .line 53
    .line 54
    goto/16 :goto_7

    .line 55
    .line 56
    :cond_2
    invoke-interface {p1}, Ly6/l;->b()Ly6/q;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    new-instance v0, La7/s;

    .line 61
    .line 62
    const/16 v1, 0x8

    .line 63
    .line 64
    const/4 v2, 0x1

    .line 65
    invoke-direct {v0, v2, v1}, La7/s;-><init>(II)V

    .line 66
    .line 67
    .line 68
    invoke-interface {p0, v0}, Ly6/q;->b(Lay0/k;)Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    if-nez p0, :cond_3

    .line 73
    .line 74
    goto/16 :goto_7

    .line 75
    .line 76
    :cond_3
    new-instance p0, Ljava/util/ArrayList;

    .line 77
    .line 78
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 79
    .line 80
    .line 81
    new-instance v0, Ljava/util/ArrayList;

    .line 82
    .line 83
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 84
    .line 85
    .line 86
    invoke-interface {p1}, Ly6/l;->b()Ly6/q;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    sget-object v3, La7/s;->l:La7/s;

    .line 91
    .line 92
    invoke-interface {v1, v3}, Ly6/q;->b(Lay0/k;)Z

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    sget-object v4, Ly6/o;->a:Ly6/o;

    .line 97
    .line 98
    const/4 v5, 0x0

    .line 99
    if-eqz v3, :cond_4

    .line 100
    .line 101
    new-instance v3, Llx0/l;

    .line 102
    .line 103
    invoke-direct {v3, v5, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    sget-object v6, La7/i1;->v:La7/i1;

    .line 107
    .line 108
    invoke-interface {v1, v3, v6}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    check-cast v1, Llx0/l;

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_4
    new-instance v3, Llx0/l;

    .line 116
    .line 117
    invoke-direct {v3, v5, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    move-object v1, v3

    .line 121
    :goto_2
    iget-object v3, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v3, Ly6/e;

    .line 124
    .line 125
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast v1, Ly6/q;

    .line 128
    .line 129
    if-eqz v3, :cond_6

    .line 130
    .line 131
    instance-of v6, v3, Ly6/d;

    .line 132
    .line 133
    if-eqz v6, :cond_5

    .line 134
    .line 135
    new-instance v6, Ly6/m;

    .line 136
    .line 137
    invoke-direct {v6}, Ly6/m;-><init>()V

    .line 138
    .line 139
    .line 140
    invoke-static {v4}, Lkp/p7;->b(Ly6/q;)Ly6/q;

    .line 141
    .line 142
    .line 143
    move-result-object v7

    .line 144
    iput-object v7, v6, Ly6/m;->a:Ly6/q;

    .line 145
    .line 146
    check-cast v3, Ly6/d;

    .line 147
    .line 148
    iget-object v3, v3, Ly6/d;->a:Ly6/a;

    .line 149
    .line 150
    iput-object v3, v6, Ly6/m;->b:Ly6/s;

    .line 151
    .line 152
    const/4 v3, 0x2

    .line 153
    iput v3, v6, Ly6/m;->d:I

    .line 154
    .line 155
    iput-object v5, v6, Ly6/m;->c:Ly6/t;

    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_5
    instance-of v6, v3, Ly6/c;

    .line 159
    .line 160
    if-eqz v6, :cond_6

    .line 161
    .line 162
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    :cond_6
    move-object v6, v5

    .line 166
    :goto_3
    const/4 v3, 0x0

    .line 167
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 168
    .line 169
    .line 170
    move-result-object v3

    .line 171
    sget-object v7, La7/i1;->x:La7/i1;

    .line 172
    .line 173
    invoke-interface {v1, v3, v7}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v3

    .line 177
    check-cast v3, Ljava/lang/Number;

    .line 178
    .line 179
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 180
    .line 181
    .line 182
    move-result v3

    .line 183
    if-le v3, v2, :cond_7

    .line 184
    .line 185
    const-string v3, "GlanceAppWidget"

    .line 186
    .line 187
    const-string v7, "More than one clickable defined on the same GlanceModifier, only the last one will be used."

    .line 188
    .line 189
    invoke-static {v3, v7}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 190
    .line 191
    .line 192
    :cond_7
    sget-object v3, La7/s;->m:La7/s;

    .line 193
    .line 194
    invoke-interface {v1, v3}, Ly6/q;->b(Lay0/k;)Z

    .line 195
    .line 196
    .line 197
    move-result v3

    .line 198
    if-eqz v3, :cond_8

    .line 199
    .line 200
    new-instance v3, Llx0/l;

    .line 201
    .line 202
    invoke-direct {v3, v5, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 203
    .line 204
    .line 205
    sget-object v7, La7/i1;->w:La7/i1;

    .line 206
    .line 207
    invoke-interface {v1, v3, v7}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    check-cast v1, Llx0/l;

    .line 212
    .line 213
    goto :goto_4

    .line 214
    :cond_8
    new-instance v3, Llx0/l;

    .line 215
    .line 216
    invoke-direct {v3, v5, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    move-object v1, v3

    .line 220
    :goto_4
    iget-object v3, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 221
    .line 222
    check-cast v3, Lz6/b;

    .line 223
    .line 224
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 225
    .line 226
    check-cast v1, Ly6/q;

    .line 227
    .line 228
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 229
    .line 230
    .line 231
    if-eqz v3, :cond_9

    .line 232
    .line 233
    new-instance v3, Ly6/a;

    .line 234
    .line 235
    const v7, 0x7f080161

    .line 236
    .line 237
    .line 238
    invoke-direct {v3, v7}, Ly6/a;-><init>(I)V

    .line 239
    .line 240
    .line 241
    new-instance v7, Ly6/m;

    .line 242
    .line 243
    invoke-direct {v7}, Ly6/m;-><init>()V

    .line 244
    .line 245
    .line 246
    invoke-static {v4}, Lkp/p7;->b(Ly6/q;)Ly6/q;

    .line 247
    .line 248
    .line 249
    move-result-object v4

    .line 250
    iput-object v4, v7, Ly6/m;->a:Ly6/q;

    .line 251
    .line 252
    iput-object v3, v7, Ly6/m;->b:Ly6/s;

    .line 253
    .line 254
    goto :goto_5

    .line 255
    :cond_9
    move-object v7, v5

    .line 256
    :goto_5
    sget-object v3, La7/s;->j:La7/s;

    .line 257
    .line 258
    invoke-interface {v1, v3}, Ly6/q;->b(Lay0/k;)Z

    .line 259
    .line 260
    .line 261
    move-result v3

    .line 262
    if-eqz v3, :cond_a

    .line 263
    .line 264
    new-instance v2, La7/f0;

    .line 265
    .line 266
    const/4 v3, 0x3

    .line 267
    invoke-direct {v2, v5, v3}, La7/f0;-><init>(Ly6/q;I)V

    .line 268
    .line 269
    .line 270
    sget-object v3, La7/i1;->q:La7/i1;

    .line 271
    .line 272
    invoke-interface {v1, v2, v3}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v1

    .line 276
    check-cast v1, La7/f0;

    .line 277
    .line 278
    goto :goto_6

    .line 279
    :cond_a
    new-instance v3, La7/f0;

    .line 280
    .line 281
    invoke-direct {v3, v1, v2}, La7/f0;-><init>(Ly6/q;I)V

    .line 282
    .line 283
    .line 284
    move-object v1, v3

    .line 285
    :goto_6
    iget-object v2, v1, La7/f0;->a:Ly6/q;

    .line 286
    .line 287
    iget-object v1, v1, La7/f0;->b:Ly6/q;

    .line 288
    .line 289
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 290
    .line 291
    .line 292
    invoke-static {v1}, Lkp/p7;->b(Ly6/q;)Ly6/q;

    .line 293
    .line 294
    .line 295
    move-result-object v1

    .line 296
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 297
    .line 298
    .line 299
    new-instance v1, Lf7/k;

    .line 300
    .line 301
    invoke-direct {v1}, Lf7/k;-><init>()V

    .line 302
    .line 303
    .line 304
    invoke-static {p0}, Lim/g;->a(Ljava/util/ArrayList;)Ly6/q;

    .line 305
    .line 306
    .line 307
    move-result-object p0

    .line 308
    iput-object p0, v1, Lf7/k;->c:Ly6/q;

    .line 309
    .line 310
    invoke-static {v0}, Lim/g;->a(Ljava/util/ArrayList;)Ly6/q;

    .line 311
    .line 312
    .line 313
    move-result-object p0

    .line 314
    invoke-interface {p1, p0}, Ly6/l;->a(Ly6/q;)V

    .line 315
    .line 316
    .line 317
    iget-object p0, v1, Ly6/n;->b:Ljava/util/ArrayList;

    .line 318
    .line 319
    if-eqz v6, :cond_b

    .line 320
    .line 321
    invoke-virtual {p0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 322
    .line 323
    .line 324
    :cond_b
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 325
    .line 326
    .line 327
    if-eqz v7, :cond_c

    .line 328
    .line 329
    invoke-virtual {p0, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 330
    .line 331
    .line 332
    :cond_c
    move-object p1, v1

    .line 333
    :goto_7
    return-object p1

    .line 334
    :pswitch_4
    check-cast p1, Ly6/p;

    .line 335
    .line 336
    instance-of p0, p1, Lf7/t;

    .line 337
    .line 338
    if-nez p0, :cond_e

    .line 339
    .line 340
    instance-of p0, p1, Lf7/n;

    .line 341
    .line 342
    if-nez p0, :cond_e

    .line 343
    .line 344
    instance-of p0, p1, La7/b0;

    .line 345
    .line 346
    if-eqz p0, :cond_d

    .line 347
    .line 348
    goto :goto_8

    .line 349
    :cond_d
    const/4 p0, 0x0

    .line 350
    goto :goto_9

    .line 351
    :cond_e
    :goto_8
    const/4 p0, 0x1

    .line 352
    :goto_9
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 353
    .line 354
    .line 355
    move-result-object p0

    .line 356
    return-object p0

    .line 357
    :pswitch_5
    check-cast p1, Ly6/p;

    .line 358
    .line 359
    instance-of p0, p1, Lz6/b;

    .line 360
    .line 361
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 362
    .line 363
    .line 364
    move-result-object p0

    .line 365
    return-object p0

    .line 366
    :pswitch_6
    check-cast p1, Lt4/h;

    .line 367
    .line 368
    iget-wide p0, p1, Lt4/h;->a:J

    .line 369
    .line 370
    invoke-static {p0, p1}, Lt4/h;->c(J)F

    .line 371
    .line 372
    .line 373
    move-result p0

    .line 374
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 375
    .line 376
    .line 377
    move-result-object p0

    .line 378
    return-object p0

    .line 379
    :pswitch_7
    check-cast p1, Lt4/h;

    .line 380
    .line 381
    iget-wide p0, p1, Lt4/h;->a:J

    .line 382
    .line 383
    invoke-static {p0, p1}, Lt4/h;->c(J)F

    .line 384
    .line 385
    .line 386
    move-result v0

    .line 387
    invoke-static {p0, p1}, Lt4/h;->b(J)F

    .line 388
    .line 389
    .line 390
    move-result p0

    .line 391
    mul-float/2addr p0, v0

    .line 392
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 393
    .line 394
    .line 395
    move-result-object p0

    .line 396
    return-object p0

    .line 397
    :pswitch_data_0
    .packed-switch 0x0
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
