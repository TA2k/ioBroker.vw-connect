.class public final Lj8/e;
.super Lj8/m;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# instance fields
.field public final A:Z

.field public final h:I

.field public final i:Z

.field public final j:Ljava/lang/String;

.field public final k:Lj8/i;

.field public final l:Z

.field public final m:I

.field public final n:I

.field public final o:I

.field public final p:Z

.field public final q:Z

.field public final r:I

.field public final s:I

.field public final t:Z

.field public final u:I

.field public final v:I

.field public final w:I

.field public final x:I

.field public final y:Z

.field public final z:Z


# direct methods
.method public constructor <init>(ILt7/q0;ILj8/i;IZLj8/d;I)V
    .locals 7

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lj8/m;-><init>(ILt7/q0;I)V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lj8/e;->k:Lj8/i;

    .line 5
    .line 6
    iget-boolean p1, p4, Lj8/i;->x:Z

    .line 7
    .line 8
    iget-object p2, p4, Lt7/u0;->n:Lhr/h0;

    .line 9
    .line 10
    iget-object p3, p4, Lt7/u0;->k:Lhr/h0;

    .line 11
    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    const/16 p1, 0x18

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/16 p1, 0x10

    .line 18
    .line 19
    :goto_0
    const/4 p8, 0x0

    .line 20
    iput-boolean p8, p0, Lj8/e;->p:Z

    .line 21
    .line 22
    iget-object v0, p0, Lj8/m;->g:Lt7/o;

    .line 23
    .line 24
    iget-object v0, v0, Lt7/o;->d:Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {v0}, Lj8/o;->u(Ljava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iput-object v0, p0, Lj8/e;->j:Ljava/lang/String;

    .line 31
    .line 32
    invoke-static {p5, p8}, La8/f;->n(IZ)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iput-boolean v0, p0, Lj8/e;->l:Z

    .line 37
    .line 38
    move v0, p8

    .line 39
    :goto_1
    invoke-virtual {p3}, Ljava/util/AbstractCollection;->size()I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    const v2, 0x7fffffff

    .line 44
    .line 45
    .line 46
    if-ge v0, v1, :cond_2

    .line 47
    .line 48
    iget-object v1, p0, Lj8/m;->g:Lt7/o;

    .line 49
    .line 50
    invoke-interface {p3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    check-cast v3, Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v1, v3, p8}, Lj8/o;->r(Lt7/o;Ljava/lang/String;Z)I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-lez v1, :cond_1

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_2
    move v1, p8

    .line 67
    move v0, v2

    .line 68
    :goto_2
    iput v0, p0, Lj8/e;->n:I

    .line 69
    .line 70
    iput v1, p0, Lj8/e;->m:I

    .line 71
    .line 72
    iget-object p3, p0, Lj8/m;->g:Lt7/o;

    .line 73
    .line 74
    iget p3, p3, Lt7/o;->f:I

    .line 75
    .line 76
    if-eqz p3, :cond_3

    .line 77
    .line 78
    if-nez p3, :cond_3

    .line 79
    .line 80
    move p3, v2

    .line 81
    goto :goto_3

    .line 82
    :cond_3
    invoke-static {p8}, Ljava/lang/Integer;->bitCount(I)I

    .line 83
    .line 84
    .line 85
    move-result p3

    .line 86
    :goto_3
    iput p3, p0, Lj8/e;->o:I

    .line 87
    .line 88
    iget-object p3, p0, Lj8/m;->g:Lt7/o;

    .line 89
    .line 90
    iget v0, p3, Lt7/o;->f:I

    .line 91
    .line 92
    const/4 v1, 0x1

    .line 93
    if-eqz v0, :cond_5

    .line 94
    .line 95
    and-int/2addr v0, v1

    .line 96
    if-eqz v0, :cond_4

    .line 97
    .line 98
    goto :goto_4

    .line 99
    :cond_4
    move v0, p8

    .line 100
    goto :goto_5

    .line 101
    :cond_5
    :goto_4
    move v0, v1

    .line 102
    :goto_5
    iput-boolean v0, p0, Lj8/e;->q:Z

    .line 103
    .line 104
    iget v0, p3, Lt7/o;->e:I

    .line 105
    .line 106
    and-int/2addr v0, v1

    .line 107
    if-eqz v0, :cond_6

    .line 108
    .line 109
    move v0, v1

    .line 110
    goto :goto_6

    .line 111
    :cond_6
    move v0, p8

    .line 112
    :goto_6
    iput-boolean v0, p0, Lj8/e;->t:Z

    .line 113
    .line 114
    iget-object v0, p3, Lt7/o;->n:Ljava/lang/String;

    .line 115
    .line 116
    const/4 v3, 0x2

    .line 117
    const/4 v4, -0x1

    .line 118
    if-nez v0, :cond_7

    .line 119
    .line 120
    goto :goto_9

    .line 121
    :cond_7
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 122
    .line 123
    .line 124
    move-result v5

    .line 125
    sparse-switch v5, :sswitch_data_0

    .line 126
    .line 127
    .line 128
    :goto_7
    move v0, v4

    .line 129
    goto :goto_8

    .line 130
    :sswitch_0
    const-string v5, "audio/iamf"

    .line 131
    .line 132
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    if-nez v0, :cond_8

    .line 137
    .line 138
    goto :goto_7

    .line 139
    :cond_8
    move v0, v3

    .line 140
    goto :goto_8

    .line 141
    :sswitch_1
    const-string v5, "audio/ac4"

    .line 142
    .line 143
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v0

    .line 147
    if-nez v0, :cond_9

    .line 148
    .line 149
    goto :goto_7

    .line 150
    :cond_9
    move v0, v1

    .line 151
    goto :goto_8

    .line 152
    :sswitch_2
    const-string v5, "audio/eac3-joc"

    .line 153
    .line 154
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result v0

    .line 158
    if-nez v0, :cond_a

    .line 159
    .line 160
    goto :goto_7

    .line 161
    :cond_a
    move v0, p8

    .line 162
    :goto_8
    packed-switch v0, :pswitch_data_0

    .line 163
    .line 164
    .line 165
    :goto_9
    move v0, p8

    .line 166
    goto :goto_a

    .line 167
    :pswitch_0
    move v0, v1

    .line 168
    :goto_a
    iput-boolean v0, p0, Lj8/e;->A:Z

    .line 169
    .line 170
    iget v0, p3, Lt7/o;->F:I

    .line 171
    .line 172
    iput v0, p0, Lj8/e;->u:I

    .line 173
    .line 174
    iget v5, p3, Lt7/o;->G:I

    .line 175
    .line 176
    iput v5, p0, Lj8/e;->v:I

    .line 177
    .line 178
    iget v5, p3, Lt7/o;->j:I

    .line 179
    .line 180
    iput v5, p0, Lj8/e;->w:I

    .line 181
    .line 182
    if-eq v5, v4, :cond_b

    .line 183
    .line 184
    iget v6, p4, Lt7/u0;->m:I

    .line 185
    .line 186
    if-gt v5, v6, :cond_d

    .line 187
    .line 188
    :cond_b
    if-eq v0, v4, :cond_c

    .line 189
    .line 190
    iget p4, p4, Lt7/u0;->l:I

    .line 191
    .line 192
    if-gt v0, p4, :cond_d

    .line 193
    .line 194
    :cond_c
    invoke-virtual {p7, p3}, Lj8/d;->apply(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result p3

    .line 198
    if-eqz p3, :cond_d

    .line 199
    .line 200
    move p3, v1

    .line 201
    goto :goto_b

    .line 202
    :cond_d
    move p3, p8

    .line 203
    :goto_b
    iput-boolean p3, p0, Lj8/e;->i:Z

    .line 204
    .line 205
    invoke-static {}, Landroid/content/res/Resources;->getSystem()Landroid/content/res/Resources;

    .line 206
    .line 207
    .line 208
    move-result-object p3

    .line 209
    invoke-virtual {p3}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 210
    .line 211
    .line 212
    move-result-object p3

    .line 213
    invoke-virtual {p3}, Landroid/content/res/Configuration;->getLocales()Landroid/os/LocaleList;

    .line 214
    .line 215
    .line 216
    move-result-object p3

    .line 217
    invoke-virtual {p3}, Landroid/os/LocaleList;->toLanguageTags()Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object p3

    .line 221
    const-string p4, ","

    .line 222
    .line 223
    invoke-virtual {p3, p4, v4}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object p3

    .line 227
    move p4, p8

    .line 228
    :goto_c
    array-length p7, p3

    .line 229
    if-ge p4, p7, :cond_e

    .line 230
    .line 231
    aget-object p7, p3, p4

    .line 232
    .line 233
    invoke-static {p7}, Lw7/w;->E(Ljava/lang/String;)Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object p7

    .line 237
    aput-object p7, p3, p4

    .line 238
    .line 239
    add-int/lit8 p4, p4, 0x1

    .line 240
    .line 241
    goto :goto_c

    .line 242
    :cond_e
    move p4, p8

    .line 243
    :goto_d
    array-length p7, p3

    .line 244
    if-ge p4, p7, :cond_10

    .line 245
    .line 246
    iget-object p7, p0, Lj8/m;->g:Lt7/o;

    .line 247
    .line 248
    aget-object v0, p3, p4

    .line 249
    .line 250
    invoke-static {p7, v0, p8}, Lj8/o;->r(Lt7/o;Ljava/lang/String;Z)I

    .line 251
    .line 252
    .line 253
    move-result p7

    .line 254
    if-lez p7, :cond_f

    .line 255
    .line 256
    goto :goto_e

    .line 257
    :cond_f
    add-int/lit8 p4, p4, 0x1

    .line 258
    .line 259
    goto :goto_d

    .line 260
    :cond_10
    move p7, p8

    .line 261
    move p4, v2

    .line 262
    :goto_e
    iput p4, p0, Lj8/e;->r:I

    .line 263
    .line 264
    iput p7, p0, Lj8/e;->s:I

    .line 265
    .line 266
    move p3, p8

    .line 267
    :goto_f
    invoke-virtual {p2}, Ljava/util/AbstractCollection;->size()I

    .line 268
    .line 269
    .line 270
    move-result p4

    .line 271
    if-ge p3, p4, :cond_12

    .line 272
    .line 273
    iget-object p4, p0, Lj8/m;->g:Lt7/o;

    .line 274
    .line 275
    iget-object p4, p4, Lt7/o;->n:Ljava/lang/String;

    .line 276
    .line 277
    if-eqz p4, :cond_11

    .line 278
    .line 279
    invoke-interface {p2, p3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object p7

    .line 283
    invoke-virtual {p4, p7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 284
    .line 285
    .line 286
    move-result p4

    .line 287
    if-eqz p4, :cond_11

    .line 288
    .line 289
    move v2, p3

    .line 290
    goto :goto_10

    .line 291
    :cond_11
    add-int/lit8 p3, p3, 0x1

    .line 292
    .line 293
    goto :goto_f

    .line 294
    :cond_12
    :goto_10
    iput v2, p0, Lj8/e;->x:I

    .line 295
    .line 296
    and-int/lit16 p2, p5, 0x180

    .line 297
    .line 298
    const/16 p3, 0x80

    .line 299
    .line 300
    if-ne p2, p3, :cond_13

    .line 301
    .line 302
    move p2, v1

    .line 303
    goto :goto_11

    .line 304
    :cond_13
    move p2, p8

    .line 305
    :goto_11
    iput-boolean p2, p0, Lj8/e;->y:Z

    .line 306
    .line 307
    and-int/lit8 p2, p5, 0x40

    .line 308
    .line 309
    const/16 p3, 0x40

    .line 310
    .line 311
    if-ne p2, p3, :cond_14

    .line 312
    .line 313
    move p2, v1

    .line 314
    goto :goto_12

    .line 315
    :cond_14
    move p2, p8

    .line 316
    :goto_12
    iput-boolean p2, p0, Lj8/e;->z:Z

    .line 317
    .line 318
    iget-boolean p2, p0, Lj8/e;->i:Z

    .line 319
    .line 320
    iget-object p3, p0, Lj8/e;->k:Lj8/i;

    .line 321
    .line 322
    iget-boolean p4, p3, Lj8/i;->z:Z

    .line 323
    .line 324
    iget-object p7, p3, Lt7/u0;->o:Lt7/s0;

    .line 325
    .line 326
    invoke-static {p5, p4}, La8/f;->n(IZ)Z

    .line 327
    .line 328
    .line 329
    move-result p4

    .line 330
    if-nez p4, :cond_15

    .line 331
    .line 332
    goto :goto_13

    .line 333
    :cond_15
    if-nez p2, :cond_16

    .line 334
    .line 335
    iget-boolean p4, p3, Lj8/i;->w:Z

    .line 336
    .line 337
    if-nez p4, :cond_16

    .line 338
    .line 339
    goto :goto_13

    .line 340
    :cond_16
    invoke-virtual {p7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 341
    .line 342
    .line 343
    invoke-static {p5, p8}, La8/f;->n(IZ)Z

    .line 344
    .line 345
    .line 346
    move-result p4

    .line 347
    if-eqz p4, :cond_18

    .line 348
    .line 349
    if-eqz p2, :cond_18

    .line 350
    .line 351
    iget-object p2, p0, Lj8/m;->g:Lt7/o;

    .line 352
    .line 353
    iget p2, p2, Lt7/o;->j:I

    .line 354
    .line 355
    if-eq p2, v4, :cond_18

    .line 356
    .line 357
    iget-boolean p2, p3, Lj8/i;->A:Z

    .line 358
    .line 359
    if-nez p2, :cond_17

    .line 360
    .line 361
    if-nez p6, :cond_18

    .line 362
    .line 363
    :cond_17
    and-int/2addr p1, p5

    .line 364
    if-eqz p1, :cond_18

    .line 365
    .line 366
    move p8, v3

    .line 367
    goto :goto_13

    .line 368
    :cond_18
    move p8, v1

    .line 369
    :goto_13
    iput p8, p0, Lj8/e;->h:I

    .line 370
    .line 371
    return-void

    .line 372
    nop

    .line 373
    :sswitch_data_0
    .sparse-switch
        -0x7e929daa -> :sswitch_2
        0xb269699 -> :sswitch_1
        0x59afdf4a -> :sswitch_0
    .end sparse-switch

    .line 374
    .line 375
    .line 376
    .line 377
    .line 378
    .line 379
    .line 380
    .line 381
    .line 382
    .line 383
    .line 384
    .line 385
    .line 386
    .line 387
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget p0, p0, Lj8/e;->h:I

    .line 2
    .line 3
    return p0
.end method

.method public final b(Lj8/m;)Z
    .locals 5

    .line 1
    check-cast p1, Lj8/e;

    .line 2
    .line 3
    iget-object v0, p1, Lj8/m;->g:Lt7/o;

    .line 4
    .line 5
    iget-object v1, p0, Lj8/e;->k:Lj8/i;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, Lj8/m;->g:Lt7/o;

    .line 11
    .line 12
    iget v2, v1, Lt7/o;->F:I

    .line 13
    .line 14
    const/4 v3, -0x1

    .line 15
    if-eq v2, v3, :cond_1

    .line 16
    .line 17
    iget v4, v0, Lt7/o;->F:I

    .line 18
    .line 19
    if-ne v2, v4, :cond_1

    .line 20
    .line 21
    iget-boolean v2, p0, Lj8/e;->p:Z

    .line 22
    .line 23
    if-nez v2, :cond_0

    .line 24
    .line 25
    iget-object v2, v1, Lt7/o;->n:Ljava/lang/String;

    .line 26
    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    iget-object v4, v0, Lt7/o;->n:Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {v2, v4}, Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-eqz v2, :cond_1

    .line 36
    .line 37
    :cond_0
    iget v1, v1, Lt7/o;->G:I

    .line 38
    .line 39
    if-eq v1, v3, :cond_1

    .line 40
    .line 41
    iget v0, v0, Lt7/o;->G:I

    .line 42
    .line 43
    if-ne v1, v0, :cond_1

    .line 44
    .line 45
    iget-boolean v0, p0, Lj8/e;->y:Z

    .line 46
    .line 47
    iget-boolean v1, p1, Lj8/e;->y:Z

    .line 48
    .line 49
    if-ne v0, v1, :cond_1

    .line 50
    .line 51
    iget-boolean p0, p0, Lj8/e;->z:Z

    .line 52
    .line 53
    iget-boolean p1, p1, Lj8/e;->z:Z

    .line 54
    .line 55
    if-ne p0, p1, :cond_1

    .line 56
    .line 57
    const/4 p0, 0x1

    .line 58
    return p0

    .line 59
    :cond_1
    const/4 p0, 0x0

    .line 60
    return p0
.end method

.method public final c(Lj8/e;)I
    .locals 7

    .line 1
    iget-boolean v0, p0, Lj8/e;->l:Z

    .line 2
    .line 3
    iget-boolean v1, p0, Lj8/e;->i:Z

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object v2, Lj8/o;->l:Lhr/w0;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    sget-object v2, Lj8/o;->l:Lhr/w0;

    .line 13
    .line 14
    invoke-virtual {v2}, Lhr/w0;->a()Lhr/w0;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    :goto_0
    iget-boolean v3, p1, Lj8/e;->l:Z

    .line 19
    .line 20
    iget v4, p1, Lj8/e;->w:I

    .line 21
    .line 22
    sget-object v5, Lhr/z;->a:Lhr/x;

    .line 23
    .line 24
    invoke-virtual {v5, v0, v3}, Lhr/x;->c(ZZ)Lhr/z;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    iget v3, p0, Lj8/e;->n:I

    .line 29
    .line 30
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    iget v5, p1, Lj8/e;->n:I

    .line 35
    .line 36
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object v5

    .line 40
    sget-object v6, Lhr/v0;->f:Lhr/v0;

    .line 41
    .line 42
    invoke-virtual {v0, v3, v5, v6}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    iget v3, p0, Lj8/e;->m:I

    .line 47
    .line 48
    iget v5, p1, Lj8/e;->m:I

    .line 49
    .line 50
    invoke-virtual {v0, v3, v5}, Lhr/z;->a(II)Lhr/z;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    iget v3, p0, Lj8/e;->o:I

    .line 55
    .line 56
    iget v5, p1, Lj8/e;->o:I

    .line 57
    .line 58
    invoke-virtual {v0, v3, v5}, Lhr/z;->a(II)Lhr/z;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    iget-boolean v3, p0, Lj8/e;->t:Z

    .line 63
    .line 64
    iget-boolean v5, p1, Lj8/e;->t:Z

    .line 65
    .line 66
    invoke-virtual {v0, v3, v5}, Lhr/z;->c(ZZ)Lhr/z;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    iget-boolean v3, p0, Lj8/e;->q:Z

    .line 71
    .line 72
    iget-boolean v5, p1, Lj8/e;->q:Z

    .line 73
    .line 74
    invoke-virtual {v0, v3, v5}, Lhr/z;->c(ZZ)Lhr/z;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    iget v3, p0, Lj8/e;->r:I

    .line 79
    .line 80
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    iget v5, p1, Lj8/e;->r:I

    .line 85
    .line 86
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 87
    .line 88
    .line 89
    move-result-object v5

    .line 90
    invoke-virtual {v0, v3, v5, v6}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    iget v3, p0, Lj8/e;->s:I

    .line 95
    .line 96
    iget v5, p1, Lj8/e;->s:I

    .line 97
    .line 98
    invoke-virtual {v0, v3, v5}, Lhr/z;->a(II)Lhr/z;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    iget-boolean v3, p1, Lj8/e;->i:Z

    .line 103
    .line 104
    invoke-virtual {v0, v1, v3}, Lhr/z;->c(ZZ)Lhr/z;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    iget v1, p0, Lj8/e;->x:I

    .line 109
    .line 110
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    iget v3, p1, Lj8/e;->x:I

    .line 115
    .line 116
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 117
    .line 118
    .line 119
    move-result-object v3

    .line 120
    invoke-virtual {v0, v1, v3, v6}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    iget-object v1, p0, Lj8/e;->k:Lj8/i;

    .line 125
    .line 126
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 127
    .line 128
    .line 129
    iget-boolean v1, p0, Lj8/e;->y:Z

    .line 130
    .line 131
    iget-boolean v3, p1, Lj8/e;->y:Z

    .line 132
    .line 133
    invoke-virtual {v0, v1, v3}, Lhr/z;->c(ZZ)Lhr/z;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    iget-boolean v1, p0, Lj8/e;->z:Z

    .line 138
    .line 139
    iget-boolean v3, p1, Lj8/e;->z:Z

    .line 140
    .line 141
    invoke-virtual {v0, v1, v3}, Lhr/z;->c(ZZ)Lhr/z;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    iget-boolean v1, p0, Lj8/e;->A:Z

    .line 146
    .line 147
    iget-boolean v3, p1, Lj8/e;->A:Z

    .line 148
    .line 149
    invoke-virtual {v0, v1, v3}, Lhr/z;->c(ZZ)Lhr/z;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    iget v1, p0, Lj8/e;->u:I

    .line 154
    .line 155
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    iget v3, p1, Lj8/e;->u:I

    .line 160
    .line 161
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 162
    .line 163
    .line 164
    move-result-object v3

    .line 165
    invoke-virtual {v0, v1, v3, v2}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    iget v1, p0, Lj8/e;->v:I

    .line 170
    .line 171
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    iget v3, p1, Lj8/e;->v:I

    .line 176
    .line 177
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 178
    .line 179
    .line 180
    move-result-object v3

    .line 181
    invoke-virtual {v0, v1, v3, v2}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    iget-object v1, p0, Lj8/e;->j:Ljava/lang/String;

    .line 186
    .line 187
    iget-object p1, p1, Lj8/e;->j:Ljava/lang/String;

    .line 188
    .line 189
    invoke-static {v1, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result p1

    .line 193
    if-eqz p1, :cond_1

    .line 194
    .line 195
    iget p0, p0, Lj8/e;->w:I

    .line 196
    .line 197
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 202
    .line 203
    .line 204
    move-result-object p1

    .line 205
    invoke-virtual {v0, p0, p1, v2}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    :cond_1
    invoke-virtual {v0}, Lhr/z;->e()I

    .line 210
    .line 211
    .line 212
    move-result p0

    .line 213
    return p0
.end method

.method public final bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lj8/e;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lj8/e;->c(Lj8/e;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
