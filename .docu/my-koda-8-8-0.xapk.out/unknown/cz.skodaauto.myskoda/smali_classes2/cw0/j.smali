.class public final synthetic Lcw0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;


# direct methods
.method public synthetic constructor <init>(ILay0/n;)V
    .locals 0

    .line 1
    const/4 p1, 0x1

    iput p1, p0, Lcw0/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lcw0/j;->e:Lay0/n;

    return-void
.end method

.method public synthetic constructor <init>(Lay0/n;IB)V
    .locals 0

    .line 2
    iput p2, p0, Lcw0/j;->d:I

    iput-object p1, p0, Lcw0/j;->e:Lay0/n;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Lcw0/j;->d:I

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x2

    .line 9
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    const/4 v6, 0x0

    .line 12
    const/4 v7, 0x1

    .line 13
    iget-object v0, v0, Lcw0/j;->e:Lay0/n;

    .line 14
    .line 15
    packed-switch v2, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    move-object/from16 v2, p1

    .line 19
    .line 20
    check-cast v2, Ll2/o;

    .line 21
    .line 22
    check-cast v1, Ljava/lang/Integer;

    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    and-int/lit8 v8, v1, 0x3

    .line 29
    .line 30
    if-eq v8, v4, :cond_0

    .line 31
    .line 32
    move v4, v7

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move v4, v6

    .line 35
    :goto_0
    and-int/2addr v1, v7

    .line 36
    check-cast v2, Ll2/t;

    .line 37
    .line 38
    invoke-virtual {v2, v1, v4}, Ll2/t;->O(IZ)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_1

    .line 43
    .line 44
    new-instance v1, Lcw0/j;

    .line 45
    .line 46
    const/4 v4, 0x4

    .line 47
    invoke-direct {v1, v0, v4, v6}, Lcw0/j;-><init>(Lay0/n;IB)V

    .line 48
    .line 49
    .line 50
    const v0, 0x66d0b3b5

    .line 51
    .line 52
    .line 53
    invoke-static {v0, v2, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    const/16 v1, 0x30

    .line 58
    .line 59
    invoke-static {v3, v0, v2, v1}, Lzb/b;->g(Lx2/s;Lt2/b;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 64
    .line 65
    .line 66
    :goto_1
    return-object v5

    .line 67
    :pswitch_0
    move-object/from16 v2, p1

    .line 68
    .line 69
    check-cast v2, Ll2/o;

    .line 70
    .line 71
    check-cast v1, Ljava/lang/Integer;

    .line 72
    .line 73
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    and-int/lit8 v3, v1, 0x3

    .line 78
    .line 79
    if-eq v3, v4, :cond_2

    .line 80
    .line 81
    move v3, v7

    .line 82
    goto :goto_2

    .line 83
    :cond_2
    move v3, v6

    .line 84
    :goto_2
    and-int/2addr v1, v7

    .line 85
    check-cast v2, Ll2/t;

    .line 86
    .line 87
    invoke-virtual {v2, v1, v3}, Ll2/t;->O(IZ)Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-eqz v1, :cond_3

    .line 92
    .line 93
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    invoke-interface {v0, v2, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_3
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 102
    .line 103
    .line 104
    :goto_3
    return-object v5

    .line 105
    :pswitch_1
    move-object/from16 v2, p1

    .line 106
    .line 107
    check-cast v2, Lu2/b;

    .line 108
    .line 109
    invoke-interface {v0, v2, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    check-cast v0, Ljava/util/List;

    .line 114
    .line 115
    move-object v1, v0

    .line 116
    check-cast v1, Ljava/util/Collection;

    .line 117
    .line 118
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 119
    .line 120
    .line 121
    move-result v4

    .line 122
    :goto_4
    if-ge v6, v4, :cond_6

    .line 123
    .line 124
    invoke-interface {v0, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    if-eqz v5, :cond_5

    .line 129
    .line 130
    iget-object v7, v2, Lu2/b;->e:Lu2/g;

    .line 131
    .line 132
    if-eqz v7, :cond_5

    .line 133
    .line 134
    invoke-interface {v7, v5}, Lu2/g;->d(Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v7

    .line 138
    if-eqz v7, :cond_4

    .line 139
    .line 140
    goto :goto_5

    .line 141
    :cond_4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 142
    .line 143
    const-string v1, "item at index "

    .line 144
    .line 145
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    const-string v1, " can\'t be saved: "

    .line 152
    .line 153
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 164
    .line 165
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    throw v1

    .line 173
    :cond_5
    :goto_5
    add-int/lit8 v6, v6, 0x1

    .line 174
    .line 175
    goto :goto_4

    .line 176
    :cond_6
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 177
    .line 178
    .line 179
    move-result v0

    .line 180
    if-nez v0, :cond_7

    .line 181
    .line 182
    new-instance v3, Ljava/util/ArrayList;

    .line 183
    .line 184
    invoke-direct {v3, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 185
    .line 186
    .line 187
    :cond_7
    return-object v3

    .line 188
    :pswitch_2
    move-object/from16 v2, p1

    .line 189
    .line 190
    check-cast v2, Ll2/o;

    .line 191
    .line 192
    check-cast v1, Ljava/lang/Integer;

    .line 193
    .line 194
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 195
    .line 196
    .line 197
    move-result v1

    .line 198
    and-int/lit8 v3, v1, 0x3

    .line 199
    .line 200
    if-eq v3, v4, :cond_8

    .line 201
    .line 202
    move v3, v7

    .line 203
    goto :goto_6

    .line 204
    :cond_8
    move v3, v6

    .line 205
    :goto_6
    and-int/2addr v1, v7

    .line 206
    check-cast v2, Ll2/t;

    .line 207
    .line 208
    invoke-virtual {v2, v1, v3}, Ll2/t;->O(IZ)Z

    .line 209
    .line 210
    .line 211
    move-result v1

    .line 212
    if-eqz v1, :cond_9

    .line 213
    .line 214
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 215
    .line 216
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v1

    .line 220
    check-cast v1, Lj91/f;

    .line 221
    .line 222
    invoke-virtual {v1}, Lj91/f;->n()Lg4/p0;

    .line 223
    .line 224
    .line 225
    move-result-object v7

    .line 226
    const/16 v20, 0x0

    .line 227
    .line 228
    const v21, 0xff7fff

    .line 229
    .line 230
    .line 231
    const-wide/16 v8, 0x0

    .line 232
    .line 233
    const-wide/16 v10, 0x0

    .line 234
    .line 235
    const/4 v12, 0x0

    .line 236
    const/4 v13, 0x0

    .line 237
    const-wide/16 v14, 0x0

    .line 238
    .line 239
    const/16 v16, 0x3

    .line 240
    .line 241
    const-wide/16 v17, 0x0

    .line 242
    .line 243
    const/16 v19, 0x0

    .line 244
    .line 245
    invoke-static/range {v7 .. v21}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 246
    .line 247
    .line 248
    move-result-object v1

    .line 249
    invoke-static {v1, v0, v2, v6}, Lh2/rb;->a(Lg4/p0;Lay0/n;Ll2/o;I)V

    .line 250
    .line 251
    .line 252
    goto :goto_7

    .line 253
    :cond_9
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 254
    .line 255
    .line 256
    :goto_7
    return-object v5

    .line 257
    :pswitch_3
    move-object/from16 v2, p1

    .line 258
    .line 259
    check-cast v2, Ll2/o;

    .line 260
    .line 261
    check-cast v1, Ljava/lang/Integer;

    .line 262
    .line 263
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 264
    .line 265
    .line 266
    invoke-static {v7}, Ll2/b;->x(I)I

    .line 267
    .line 268
    .line 269
    move-result v1

    .line 270
    invoke-static {v0, v2, v1}, Lh2/wa;->c(Lay0/n;Ll2/o;I)V

    .line 271
    .line 272
    .line 273
    return-object v5

    .line 274
    :pswitch_4
    move-object/from16 v2, p1

    .line 275
    .line 276
    check-cast v2, Ljava/lang/String;

    .line 277
    .line 278
    check-cast v1, Ljava/util/List;

    .line 279
    .line 280
    const-string v3, "key"

    .line 281
    .line 282
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 283
    .line 284
    .line 285
    const-string v3, "values"

    .line 286
    .line 287
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 288
    .line 289
    .line 290
    sget-object v3, Low0/q;->a:Ljava/util/List;

    .line 291
    .line 292
    const-string v3, "Content-Length"

    .line 293
    .line 294
    invoke-virtual {v3, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 295
    .line 296
    .line 297
    move-result v3

    .line 298
    if-eqz v3, :cond_a

    .line 299
    .line 300
    goto :goto_b

    .line 301
    :cond_a
    const-string v3, "Content-Type"

    .line 302
    .line 303
    invoke-virtual {v3, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 304
    .line 305
    .line 306
    move-result v3

    .line 307
    if-eqz v3, :cond_b

    .line 308
    .line 309
    goto :goto_b

    .line 310
    :cond_b
    sget-object v3, Lcw0/k;->a:Ljava/util/Set;

    .line 311
    .line 312
    invoke-interface {v3, v2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 313
    .line 314
    .line 315
    move-result v3

    .line 316
    if-eqz v3, :cond_c

    .line 317
    .line 318
    check-cast v1, Ljava/lang/Iterable;

    .line 319
    .line 320
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 321
    .line 322
    .line 323
    move-result-object v1

    .line 324
    :goto_8
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 325
    .line 326
    .line 327
    move-result v3

    .line 328
    if-eqz v3, :cond_e

    .line 329
    .line 330
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v3

    .line 334
    check-cast v3, Ljava/lang/String;

    .line 335
    .line 336
    invoke-interface {v0, v2, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    goto :goto_8

    .line 340
    :cond_c
    const-string v3, "Cookie"

    .line 341
    .line 342
    invoke-virtual {v3, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 343
    .line 344
    .line 345
    move-result v3

    .line 346
    if-eqz v3, :cond_d

    .line 347
    .line 348
    const-string v3, "; "

    .line 349
    .line 350
    :goto_9
    move-object v7, v3

    .line 351
    goto :goto_a

    .line 352
    :cond_d
    const-string v3, ","

    .line 353
    .line 354
    goto :goto_9

    .line 355
    :goto_a
    move-object v6, v1

    .line 356
    check-cast v6, Ljava/lang/Iterable;

    .line 357
    .line 358
    const/4 v10, 0x0

    .line 359
    const/16 v11, 0x3e

    .line 360
    .line 361
    const/4 v8, 0x0

    .line 362
    const/4 v9, 0x0

    .line 363
    invoke-static/range {v6 .. v11}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 364
    .line 365
    .line 366
    move-result-object v1

    .line 367
    invoke-interface {v0, v2, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 368
    .line 369
    .line 370
    :cond_e
    :goto_b
    return-object v5

    .line 371
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
