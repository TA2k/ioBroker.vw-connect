.class public abstract Lda/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lda/j;

.field public static final b:Lda/j;

.field public static final c:Lda/j;

.field public static final d:Lda/j;

.field public static final e:Lda/j;

.field public static final f:Lda/j;

.field public static final g:Lda/j;

.field public static final h:Lda/c;

.field public static final i:Lda/c;

.field public static final j:Lda/c;

.field public static final k:Lda/c;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lda/j;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-direct {v0, v1, v2}, Lda/j;-><init>(IZ)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lda/d;->a:Lda/j;

    .line 9
    .line 10
    new-instance v0, Lda/j;

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lda/j;-><init>(IZ)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lda/d;->b:Lda/j;

    .line 17
    .line 18
    new-instance v0, Lda/j;

    .line 19
    .line 20
    const/4 v1, 0x3

    .line 21
    const/4 v3, 0x0

    .line 22
    invoke-direct {v0, v1, v3}, Lda/j;-><init>(IZ)V

    .line 23
    .line 24
    .line 25
    sput-object v0, Lda/d;->c:Lda/j;

    .line 26
    .line 27
    new-instance v0, Lda/j;

    .line 28
    .line 29
    const/4 v1, 0x2

    .line 30
    invoke-direct {v0, v1, v2}, Lda/j;-><init>(IZ)V

    .line 31
    .line 32
    .line 33
    sput-object v0, Lda/d;->d:Lda/j;

    .line 34
    .line 35
    new-instance v0, Lda/j;

    .line 36
    .line 37
    const/4 v1, 0x4

    .line 38
    invoke-direct {v0, v1, v2}, Lda/j;-><init>(IZ)V

    .line 39
    .line 40
    .line 41
    sput-object v0, Lda/d;->e:Lda/j;

    .line 42
    .line 43
    new-instance v0, Lda/j;

    .line 44
    .line 45
    const/4 v1, 0x6

    .line 46
    invoke-direct {v0, v1, v2}, Lda/j;-><init>(IZ)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lda/d;->f:Lda/j;

    .line 50
    .line 51
    new-instance v0, Lda/j;

    .line 52
    .line 53
    const/4 v1, 0x7

    .line 54
    invoke-direct {v0, v1, v3}, Lda/j;-><init>(IZ)V

    .line 55
    .line 56
    .line 57
    sput-object v0, Lda/d;->g:Lda/j;

    .line 58
    .line 59
    new-instance v0, Lda/c;

    .line 60
    .line 61
    const/4 v1, 0x2

    .line 62
    invoke-direct {v0, v1, v2}, Lda/c;-><init>(IZ)V

    .line 63
    .line 64
    .line 65
    sput-object v0, Lda/d;->h:Lda/c;

    .line 66
    .line 67
    new-instance v0, Lda/c;

    .line 68
    .line 69
    const/4 v1, 0x3

    .line 70
    invoke-direct {v0, v1, v2}, Lda/c;-><init>(IZ)V

    .line 71
    .line 72
    .line 73
    sput-object v0, Lda/d;->i:Lda/c;

    .line 74
    .line 75
    new-instance v0, Lda/c;

    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    invoke-direct {v0, v1, v2}, Lda/c;-><init>(IZ)V

    .line 79
    .line 80
    .line 81
    sput-object v0, Lda/d;->j:Lda/c;

    .line 82
    .line 83
    new-instance v0, Lda/c;

    .line 84
    .line 85
    const/4 v1, 0x1

    .line 86
    invoke-direct {v0, v1, v2}, Lda/c;-><init>(IZ)V

    .line 87
    .line 88
    .line 89
    sput-object v0, Lda/d;->k:Lda/c;

    .line 90
    .line 91
    return-void
.end method

.method public static final a(Lsz0/g;Ljava/util/Map;)Lz9/g0;
    .locals 8

    .line 1
    invoke-interface {p1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ljava/lang/Iterable;

    .line 6
    .line 7
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const/4 v2, 0x0

    .line 16
    const-string v3, "<this>"

    .line 17
    .line 18
    const/4 v4, 0x0

    .line 19
    if-eqz v1, :cond_3

    .line 20
    .line 21
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    move-object v5, v1

    .line 26
    check-cast v5, Lhy0/a0;

    .line 27
    .line 28
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string v6, "kType"

    .line 32
    .line 33
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {p0}, Lsz0/g;->b()Z

    .line 37
    .line 38
    .line 39
    move-result v6

    .line 40
    invoke-interface {v5}, Lhy0/a0;->isMarkedNullable()Z

    .line 41
    .line 42
    .line 43
    move-result v7

    .line 44
    if-eq v6, v7, :cond_1

    .line 45
    .line 46
    move v5, v2

    .line 47
    goto :goto_0

    .line 48
    :cond_1
    sget-object v6, Lxz0/a;->a:Lwq/f;

    .line 49
    .line 50
    invoke-static {v6, v5}, Ljp/mg;->g(Lwq/f;Lhy0/a0;)Lqz0/a;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    if-eqz v5, :cond_2

    .line 55
    .line 56
    invoke-interface {v5}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 57
    .line 58
    .line 59
    move-result-object v5

    .line 60
    invoke-virtual {p0, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    :goto_0
    if-eqz v5, :cond_0

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    new-instance p1, Ljava/lang/StringBuilder;

    .line 68
    .line 69
    const-string v0, "Cannot find KSerializer for ["

    .line 70
    .line 71
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-interface {p0}, Lsz0/g;->h()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string p0, "]. If applicable, custom KSerializers for custom and third-party KType is currently not supported when declared directly on a class field via @Serializable(with = ...). Please use @Serializable or @Serializable(with = ...) on the class or object declaration."

    .line 82
    .line 83
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 91
    .line 92
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw p1

    .line 100
    :cond_3
    move-object v1, v4

    .line 101
    :goto_1
    check-cast v1, Lhy0/a0;

    .line 102
    .line 103
    if-eqz v1, :cond_4

    .line 104
    .line 105
    invoke-interface {p1, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    check-cast p1, Lz9/g0;

    .line 110
    .line 111
    goto :goto_2

    .line 112
    :cond_4
    move-object p1, v4

    .line 113
    :goto_2
    if-eqz p1, :cond_5

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_5
    move-object p1, v4

    .line 117
    :goto_3
    sget-object v0, Lda/j;->r:Lda/j;

    .line 118
    .line 119
    if-nez p1, :cond_14

    .line 120
    .line 121
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-static {p0}, Lda/d;->g(Lsz0/g;)Lda/e;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 129
    .line 130
    .line 131
    move-result p1

    .line 132
    const/16 v1, 0xb

    .line 133
    .line 134
    const/16 v3, 0xa

    .line 135
    .line 136
    const-class v5, Ljava/lang/Enum;

    .line 137
    .line 138
    packed-switch p1, :pswitch_data_0

    .line 139
    .line 140
    .line 141
    :cond_6
    :goto_4
    move-object p1, v0

    .line 142
    goto/16 :goto_7

    .line 143
    .line 144
    :pswitch_0
    invoke-static {p0}, Lda/d;->e(Lsz0/g;)Ljava/lang/Class;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    invoke-virtual {v5, p0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 149
    .line 150
    .line 151
    move-result p1

    .line 152
    if-eqz p1, :cond_6

    .line 153
    .line 154
    new-instance p1, Lda/b;

    .line 155
    .line 156
    invoke-direct {p1, p0}, Lda/b;-><init>(Ljava/lang/Class;)V

    .line 157
    .line 158
    .line 159
    goto/16 :goto_7

    .line 160
    .line 161
    :pswitch_1
    invoke-static {p0}, Lda/d;->e(Lsz0/g;)Ljava/lang/Class;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    const-class p1, Landroid/os/Parcelable;

    .line 166
    .line 167
    invoke-virtual {p1, p0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 168
    .line 169
    .line 170
    move-result p1

    .line 171
    if-eqz p1, :cond_7

    .line 172
    .line 173
    new-instance p1, Lz9/e0;

    .line 174
    .line 175
    invoke-direct {p1, p0}, Lz9/e0;-><init>(Ljava/lang/Class;)V

    .line 176
    .line 177
    .line 178
    goto :goto_5

    .line 179
    :cond_7
    invoke-virtual {v5, p0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 180
    .line 181
    .line 182
    move-result p1

    .line 183
    if-eqz p1, :cond_8

    .line 184
    .line 185
    new-instance p1, Lz9/d0;

    .line 186
    .line 187
    invoke-direct {p1, p0}, Lz9/d0;-><init>(Ljava/lang/Class;)V

    .line 188
    .line 189
    .line 190
    goto :goto_5

    .line 191
    :cond_8
    const-class p1, Ljava/io/Serializable;

    .line 192
    .line 193
    invoke-virtual {p1, p0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 194
    .line 195
    .line 196
    move-result p1

    .line 197
    if-eqz p1, :cond_9

    .line 198
    .line 199
    new-instance p1, Lz9/f0;

    .line 200
    .line 201
    invoke-direct {p1, p0}, Lz9/f0;-><init>(Ljava/lang/Class;)V

    .line 202
    .line 203
    .line 204
    goto :goto_5

    .line 205
    :cond_9
    move-object p1, v4

    .line 206
    :goto_5
    if-nez p1, :cond_14

    .line 207
    .line 208
    goto :goto_4

    .line 209
    :pswitch_2
    invoke-interface {p0, v2}, Lsz0/g;->g(I)Lsz0/g;

    .line 210
    .line 211
    .line 212
    move-result-object p1

    .line 213
    invoke-static {p1}, Lda/d;->g(Lsz0/g;)Lda/e;

    .line 214
    .line 215
    .line 216
    move-result-object p1

    .line 217
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 218
    .line 219
    .line 220
    move-result p1

    .line 221
    if-eqz p1, :cond_11

    .line 222
    .line 223
    const/4 v5, 0x2

    .line 224
    if-eq p1, v5, :cond_10

    .line 225
    .line 226
    const/4 v5, 0x4

    .line 227
    if-eq p1, v5, :cond_f

    .line 228
    .line 229
    const/4 v5, 0x6

    .line 230
    if-eq p1, v5, :cond_e

    .line 231
    .line 232
    const/16 v5, 0x8

    .line 233
    .line 234
    if-eq p1, v5, :cond_d

    .line 235
    .line 236
    const/16 v5, 0x13

    .line 237
    .line 238
    if-eq p1, v5, :cond_c

    .line 239
    .line 240
    if-eq p1, v3, :cond_b

    .line 241
    .line 242
    if-eq p1, v1, :cond_a

    .line 243
    .line 244
    goto :goto_4

    .line 245
    :cond_a
    sget-object p0, Lda/d;->i:Lda/c;

    .line 246
    .line 247
    :goto_6
    move-object p1, p0

    .line 248
    goto/16 :goto_7

    .line 249
    .line 250
    :cond_b
    sget-object p0, Lz9/g0;->p:Lz9/d;

    .line 251
    .line 252
    goto :goto_6

    .line 253
    :cond_c
    new-instance p1, Lda/a;

    .line 254
    .line 255
    invoke-interface {p0, v2}, Lsz0/g;->g(I)Lsz0/g;

    .line 256
    .line 257
    .line 258
    move-result-object p0

    .line 259
    invoke-static {p0}, Lda/d;->e(Lsz0/g;)Ljava/lang/Class;

    .line 260
    .line 261
    .line 262
    move-result-object p0

    .line 263
    invoke-direct {p1, p0}, Lda/a;-><init>(Ljava/lang/Class;)V

    .line 264
    .line 265
    .line 266
    goto/16 :goto_7

    .line 267
    .line 268
    :cond_d
    sget-object p0, Lz9/g0;->g:Lz9/d;

    .line 269
    .line 270
    goto :goto_6

    .line 271
    :cond_e
    sget-object p0, Lz9/g0;->j:Lz9/d;

    .line 272
    .line 273
    goto :goto_6

    .line 274
    :cond_f
    sget-object p0, Lda/d;->k:Lda/c;

    .line 275
    .line 276
    goto :goto_6

    .line 277
    :cond_10
    sget-object p0, Lz9/g0;->m:Lz9/d;

    .line 278
    .line 279
    goto :goto_6

    .line 280
    :cond_11
    sget-object p0, Lz9/g0;->d:Lz9/d;

    .line 281
    .line 282
    goto :goto_6

    .line 283
    :pswitch_3
    invoke-interface {p0, v2}, Lsz0/g;->g(I)Lsz0/g;

    .line 284
    .line 285
    .line 286
    move-result-object p0

    .line 287
    invoke-static {p0}, Lda/d;->g(Lsz0/g;)Lda/e;

    .line 288
    .line 289
    .line 290
    move-result-object p0

    .line 291
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 292
    .line 293
    .line 294
    move-result p0

    .line 295
    if-eq p0, v3, :cond_13

    .line 296
    .line 297
    if-eq p0, v1, :cond_12

    .line 298
    .line 299
    goto/16 :goto_4

    .line 300
    .line 301
    :cond_12
    sget-object p0, Lda/d;->h:Lda/c;

    .line 302
    .line 303
    goto :goto_6

    .line 304
    :cond_13
    sget-object p0, Lz9/g0;->o:Lz9/d;

    .line 305
    .line 306
    goto :goto_6

    .line 307
    :pswitch_4
    sget-object p0, Lz9/g0;->f:Lz9/d;

    .line 308
    .line 309
    goto :goto_6

    .line 310
    :pswitch_5
    sget-object p0, Lz9/g0;->i:Lz9/d;

    .line 311
    .line 312
    goto :goto_6

    .line 313
    :pswitch_6
    sget-object p0, Lda/d;->j:Lda/c;

    .line 314
    .line 315
    goto :goto_6

    .line 316
    :pswitch_7
    sget-object p0, Lz9/g0;->l:Lz9/d;

    .line 317
    .line 318
    goto :goto_6

    .line 319
    :pswitch_8
    sget-object p0, Lz9/g0;->c:Lz9/d;

    .line 320
    .line 321
    goto :goto_6

    .line 322
    :pswitch_9
    sget-object p0, Lz9/g0;->n:Lz9/e;

    .line 323
    .line 324
    goto :goto_6

    .line 325
    :pswitch_a
    sget-object p0, Lda/d;->g:Lda/j;

    .line 326
    .line 327
    goto :goto_6

    .line 328
    :pswitch_b
    sget-object p0, Lda/d;->f:Lda/j;

    .line 329
    .line 330
    goto :goto_6

    .line 331
    :pswitch_c
    sget-object p0, Lz9/g0;->e:Lz9/e;

    .line 332
    .line 333
    goto :goto_6

    .line 334
    :pswitch_d
    sget-object p0, Lda/d;->e:Lda/j;

    .line 335
    .line 336
    goto :goto_6

    .line 337
    :pswitch_e
    sget-object p0, Lz9/g0;->h:Lz9/e;

    .line 338
    .line 339
    goto :goto_6

    .line 340
    :pswitch_f
    sget-object p0, Lda/d;->d:Lda/j;

    .line 341
    .line 342
    goto :goto_6

    .line 343
    :pswitch_10
    sget-object p0, Lda/d;->c:Lda/j;

    .line 344
    .line 345
    goto :goto_6

    .line 346
    :pswitch_11
    sget-object p0, Lda/d;->b:Lda/j;

    .line 347
    .line 348
    goto :goto_6

    .line 349
    :pswitch_12
    sget-object p0, Lz9/g0;->k:Lz9/e;

    .line 350
    .line 351
    goto :goto_6

    .line 352
    :pswitch_13
    sget-object p0, Lda/d;->a:Lda/j;

    .line 353
    .line 354
    goto :goto_6

    .line 355
    :pswitch_14
    sget-object p0, Lz9/g0;->b:Lz9/e;

    .line 356
    .line 357
    goto :goto_6

    .line 358
    :cond_14
    :goto_7
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 359
    .line 360
    .line 361
    move-result p0

    .line 362
    if-eqz p0, :cond_15

    .line 363
    .line 364
    return-object v4

    .line 365
    :cond_15
    return-object p1

    .line 366
    nop

    .line 367
    :pswitch_data_0
    .packed-switch 0x0
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

.method public static final b(Lqz0/a;)I
    .locals 4

    .line 1
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Lsz0/g;->h()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-interface {v1}, Lsz0/g;->d()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, 0x0

    .line 22
    :goto_0
    if-ge v2, v1, :cond_0

    .line 23
    .line 24
    mul-int/lit8 v0, v0, 0x1f

    .line 25
    .line 26
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    invoke-interface {v3, v2}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    add-int/2addr v0, v3

    .line 39
    add-int/lit8 v2, v2, 0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    return v0
.end method

.method public static final c(Lqz0/a;Ljava/util/Map;)Ljava/util/ArrayList;
    .locals 9

    .line 1
    const-string v0, "typeMap"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lqz0/d;

    .line 7
    .line 8
    if-nez v0, :cond_2

    .line 9
    .line 10
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-interface {v0}, Lsz0/g;->d()I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    new-instance v1, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 21
    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    :goto_0
    if-ge v2, v0, :cond_1

    .line 25
    .line 26
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    invoke-interface {v3, v2}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    new-instance v4, Lda/i;

    .line 35
    .line 36
    invoke-direct {v4, p0, v2, p1, v3}, Lda/i;-><init>(Lqz0/a;ILjava/util/Map;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string v5, "name"

    .line 40
    .line 41
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    new-instance v5, Lz9/h;

    .line 45
    .line 46
    new-instance v6, Lz9/j;

    .line 47
    .line 48
    invoke-direct {v6}, Lz9/j;-><init>()V

    .line 49
    .line 50
    .line 51
    invoke-interface {v4, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    iget-object v4, v6, Lz9/j;->a:Lg11/k;

    .line 55
    .line 56
    iget-object v6, v4, Lg11/k;->c:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v6, Lz9/g0;

    .line 59
    .line 60
    if-nez v6, :cond_0

    .line 61
    .line 62
    sget-object v6, Lz9/g0;->n:Lz9/e;

    .line 63
    .line 64
    :cond_0
    new-instance v7, Lz9/i;

    .line 65
    .line 66
    iget-boolean v8, v4, Lg11/k;->a:Z

    .line 67
    .line 68
    iget-boolean v4, v4, Lg11/k;->b:Z

    .line 69
    .line 70
    invoke-direct {v7, v6, v8, v4}, Lz9/i;-><init>(Lz9/g0;ZZ)V

    .line 71
    .line 72
    .line 73
    invoke-direct {v5, v3, v7}, Lz9/h;-><init>(Ljava/lang/String;Lz9/i;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    add-int/lit8 v2, v2, 0x1

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_1
    return-object v1

    .line 83
    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 84
    .line 85
    new-instance v0, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    const-string v1, "Cannot generate NavArguments for polymorphic serializer "

    .line 88
    .line 89
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string p0, ". Arguments can only be generated from concrete classes or objects."

    .line 96
    .line 97
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    throw p1
.end method

.method public static final d(Ljava/lang/Object;Ljava/util/LinkedHashMap;)Ljava/lang/String;
    .locals 7

    .line 1
    const-string v0, "route"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 11
    .line 12
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {v0}, Ljp/mg;->c(Lhy0/d;)Lqz0/a;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    new-instance v1, Lda/h;

    .line 21
    .line 22
    invoke-direct {v1, v0, p1}, Lda/h;-><init>(Lqz0/a;Ljava/util/LinkedHashMap;)V

    .line 23
    .line 24
    .line 25
    move-object v2, v0

    .line 26
    check-cast v2, Lqz0/a;

    .line 27
    .line 28
    invoke-interface {v2, v1, p0}, Lqz0/a;->serialize(Ltz0/d;Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iget-object p0, v1, Lda/h;->d:Ljava/util/LinkedHashMap;

    .line 32
    .line 33
    invoke-static {p0}, Lmx0/x;->u(Ljava/util/Map;)Ljava/util/Map;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 38
    .line 39
    invoke-direct {v1, v0}, Lcom/google/firebase/messaging/w;-><init>(Lqz0/a;)V

    .line 40
    .line 41
    .line 42
    new-instance v2, Lal/d;

    .line 43
    .line 44
    const/16 v3, 0x18

    .line 45
    .line 46
    invoke-direct {v2, v3, p0, v1}, Lal/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    invoke-interface {v0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-interface {p0}, Lsz0/g;->d()I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    const/4 v3, 0x0

    .line 58
    :goto_0
    if-ge v3, p0, :cond_1

    .line 59
    .line 60
    invoke-interface {v0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    invoke-interface {v4, v3}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    invoke-virtual {p1, v4}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v5

    .line 72
    check-cast v5, Lz9/g0;

    .line 73
    .line 74
    if-eqz v5, :cond_0

    .line 75
    .line 76
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    invoke-virtual {v2, v6, v4, v5}, Lal/d;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    add-int/lit8 v3, v3, 0x1

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_0
    const-string p0, "Cannot locate NavType for argument ["

    .line 87
    .line 88
    const/16 p1, 0x5d

    .line 89
    .line 90
    invoke-static {p1, p0, v4}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 95
    .line 96
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    throw p1

    .line 104
    :cond_1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 105
    .line 106
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 107
    .line 108
    .line 109
    iget-object p1, v1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast p1, Ljava/lang/String;

    .line 112
    .line 113
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    iget-object p1, v1, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast p1, Ljava/lang/String;

    .line 119
    .line 120
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    iget-object p1, v1, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast p1, Ljava/lang/String;

    .line 126
    .line 127
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    return-object p0
.end method

.method public static final e(Lsz0/g;)Ljava/lang/Class;
    .locals 4

    .line 1
    invoke-interface {p0}, Lsz0/g;->h()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    const-string v2, "?"

    .line 7
    .line 8
    const-string v3, ""

    .line 9
    .line 10
    invoke-static {v1, v0, v2, v3}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    :try_start_0
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    return-object p0

    .line 19
    :catch_0
    const-string v2, "."

    .line 20
    .line 21
    invoke-static {v0, v2, v1}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    const-string v2, "(\\.+)(?!.*\\.)"

    .line 28
    .line 29
    invoke-static {v2}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    const-string v3, "compile(...)"

    .line 34
    .line 35
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const-string v3, "\\$"

    .line 39
    .line 40
    invoke-virtual {v2, v0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-virtual {v0, v3}, Ljava/util/regex/Matcher;->replaceAll(Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    const-string v2, "replaceAll(...)"

    .line 49
    .line 50
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    :try_start_1
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 54
    .line 55
    .line 56
    move-result-object p0
    :try_end_1
    .catch Ljava/lang/ClassNotFoundException; {:try_start_1 .. :try_end_1} :catch_0

    .line 57
    return-object p0

    .line 58
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    const-string v1, "Cannot find class with name \""

    .line 61
    .line 62
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-interface {p0}, Lsz0/g;->h()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v1, "\". Ensure that the serialName for this argument is the default fully qualified name"

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-interface {p0}, Lsz0/g;->getKind()Lkp/y8;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    instance-of p0, p0, Lsz0/j;

    .line 86
    .line 87
    if-eqz p0, :cond_1

    .line 88
    .line 89
    const-string p0, ".\nIf the build is minified, try annotating the Enum class with \"androidx.annotation.Keep\" to ensure the Enum is not removed."

    .line 90
    .line 91
    invoke-static {v0, p0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 96
    .line 97
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw p0
.end method

.method public static final f(Lsz0/g;)Z
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lsz0/g;->getKind()Lkp/y8;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sget-object v1, Lsz0/k;->b:Lsz0/k;

    .line 11
    .line 12
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    invoke-interface {p0}, Lsz0/g;->isInline()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    invoke-interface {p0}, Lsz0/g;->d()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    const/4 v0, 0x1

    .line 29
    if-ne p0, v0, :cond_0

    .line 30
    .line 31
    return v0

    .line 32
    :cond_0
    const/4 p0, 0x0

    .line 33
    return p0
.end method

.method public static final g(Lsz0/g;)Lda/e;
    .locals 4

    .line 1
    invoke-interface {p0}, Lsz0/g;->h()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    const-string v2, "?"

    .line 7
    .line 8
    const-string v3, ""

    .line 9
    .line 10
    invoke-static {v1, v0, v2, v3}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-interface {p0}, Lsz0/g;->getKind()Lkp/y8;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    sget-object v3, Lsz0/j;->b:Lsz0/j;

    .line 19
    .line 20
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    invoke-interface {p0}, Lsz0/g;->b()Z

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-eqz p0, :cond_0

    .line 31
    .line 32
    sget-object p0, Lda/e;->x:Lda/e;

    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_0
    sget-object p0, Lda/e;->w:Lda/e;

    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_1
    const-string v2, "kotlin.Int"

    .line 39
    .line 40
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_3

    .line 45
    .line 46
    invoke-interface {p0}, Lsz0/g;->b()Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-eqz p0, :cond_2

    .line 51
    .line 52
    sget-object p0, Lda/e;->e:Lda/e;

    .line 53
    .line 54
    return-object p0

    .line 55
    :cond_2
    sget-object p0, Lda/e;->d:Lda/e;

    .line 56
    .line 57
    return-object p0

    .line 58
    :cond_3
    const-string v2, "kotlin.Boolean"

    .line 59
    .line 60
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    if-eqz v2, :cond_5

    .line 65
    .line 66
    invoke-interface {p0}, Lsz0/g;->b()Z

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    if-eqz p0, :cond_4

    .line 71
    .line 72
    sget-object p0, Lda/e;->g:Lda/e;

    .line 73
    .line 74
    return-object p0

    .line 75
    :cond_4
    sget-object p0, Lda/e;->f:Lda/e;

    .line 76
    .line 77
    return-object p0

    .line 78
    :cond_5
    const-string v2, "kotlin.Double"

    .line 79
    .line 80
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    if-eqz v2, :cond_7

    .line 85
    .line 86
    invoke-interface {p0}, Lsz0/g;->b()Z

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    if-eqz p0, :cond_6

    .line 91
    .line 92
    sget-object p0, Lda/e;->i:Lda/e;

    .line 93
    .line 94
    return-object p0

    .line 95
    :cond_6
    sget-object p0, Lda/e;->h:Lda/e;

    .line 96
    .line 97
    return-object p0

    .line 98
    :cond_7
    const-string v2, "kotlin.Float"

    .line 99
    .line 100
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    if-eqz v2, :cond_9

    .line 105
    .line 106
    invoke-interface {p0}, Lsz0/g;->b()Z

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    if-eqz p0, :cond_8

    .line 111
    .line 112
    sget-object p0, Lda/e;->k:Lda/e;

    .line 113
    .line 114
    return-object p0

    .line 115
    :cond_8
    sget-object p0, Lda/e;->j:Lda/e;

    .line 116
    .line 117
    return-object p0

    .line 118
    :cond_9
    const-string v2, "kotlin.Long"

    .line 119
    .line 120
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v2

    .line 124
    if-eqz v2, :cond_b

    .line 125
    .line 126
    invoke-interface {p0}, Lsz0/g;->b()Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    if-eqz p0, :cond_a

    .line 131
    .line 132
    sget-object p0, Lda/e;->m:Lda/e;

    .line 133
    .line 134
    return-object p0

    .line 135
    :cond_a
    sget-object p0, Lda/e;->l:Lda/e;

    .line 136
    .line 137
    return-object p0

    .line 138
    :cond_b
    const-string v2, "kotlin.String"

    .line 139
    .line 140
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result v2

    .line 144
    if-eqz v2, :cond_d

    .line 145
    .line 146
    invoke-interface {p0}, Lsz0/g;->b()Z

    .line 147
    .line 148
    .line 149
    move-result p0

    .line 150
    if-eqz p0, :cond_c

    .line 151
    .line 152
    sget-object p0, Lda/e;->o:Lda/e;

    .line 153
    .line 154
    return-object p0

    .line 155
    :cond_c
    sget-object p0, Lda/e;->n:Lda/e;

    .line 156
    .line 157
    return-object p0

    .line 158
    :cond_d
    const-string p0, "kotlin.IntArray"

    .line 159
    .line 160
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result p0

    .line 164
    if-eqz p0, :cond_e

    .line 165
    .line 166
    sget-object p0, Lda/e;->p:Lda/e;

    .line 167
    .line 168
    return-object p0

    .line 169
    :cond_e
    const-string p0, "kotlin.DoubleArray"

    .line 170
    .line 171
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result p0

    .line 175
    if-eqz p0, :cond_f

    .line 176
    .line 177
    sget-object p0, Lda/e;->r:Lda/e;

    .line 178
    .line 179
    return-object p0

    .line 180
    :cond_f
    const-string p0, "kotlin.BooleanArray"

    .line 181
    .line 182
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result p0

    .line 186
    if-eqz p0, :cond_10

    .line 187
    .line 188
    sget-object p0, Lda/e;->q:Lda/e;

    .line 189
    .line 190
    return-object p0

    .line 191
    :cond_10
    const-string p0, "kotlin.FloatArray"

    .line 192
    .line 193
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result p0

    .line 197
    if-eqz p0, :cond_11

    .line 198
    .line 199
    sget-object p0, Lda/e;->s:Lda/e;

    .line 200
    .line 201
    return-object p0

    .line 202
    :cond_11
    const-string p0, "kotlin.LongArray"

    .line 203
    .line 204
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result p0

    .line 208
    if-eqz p0, :cond_12

    .line 209
    .line 210
    sget-object p0, Lda/e;->t:Lda/e;

    .line 211
    .line 212
    return-object p0

    .line 213
    :cond_12
    const-string p0, "kotlin.Array"

    .line 214
    .line 215
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    move-result p0

    .line 219
    if-eqz p0, :cond_13

    .line 220
    .line 221
    sget-object p0, Lda/e;->u:Lda/e;

    .line 222
    .line 223
    return-object p0

    .line 224
    :cond_13
    const-string p0, "kotlin.collections.ArrayList"

    .line 225
    .line 226
    invoke-static {v0, p0, v1}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 227
    .line 228
    .line 229
    move-result p0

    .line 230
    if-eqz p0, :cond_14

    .line 231
    .line 232
    sget-object p0, Lda/e;->v:Lda/e;

    .line 233
    .line 234
    return-object p0

    .line 235
    :cond_14
    sget-object p0, Lda/e;->y:Lda/e;

    .line 236
    .line 237
    return-object p0
.end method

.method public static final h(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 1
    const-string v0, " could not find any NavType for argument "

    .line 2
    .line 3
    const-string v1, " of type "

    .line 4
    .line 5
    const-string v2, "Route "

    .line 6
    .line 7
    invoke-static {v2, p2, v0, p0, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string p2, " - typeMap received was "

    .line 12
    .line 13
    invoke-static {p0, p1, p2, p3}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
