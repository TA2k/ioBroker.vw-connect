.class public final synthetic Le2/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/ArrayList;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;I)V
    .locals 0

    .line 1
    iput p2, p0, Le2/j0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le2/j0;->e:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Le2/j0;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lt3/d1;

    .line 11
    .line 12
    const-string v2, "$this$layout"

    .line 13
    .line 14
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v0, v0, Le2/j0;->e:Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    const/4 v3, 0x0

    .line 24
    move v4, v3

    .line 25
    :goto_0
    if-ge v4, v2, :cond_0

    .line 26
    .line 27
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    check-cast v5, Lt3/e1;

    .line 32
    .line 33
    invoke-static {v1, v5, v3, v3}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 34
    .line 35
    .line 36
    add-int/lit8 v4, v4, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object v0

    .line 42
    :pswitch_0
    move-object/from16 v1, p1

    .line 43
    .line 44
    check-cast v1, Ly20/g;

    .line 45
    .line 46
    const-string v2, "prevVehicle"

    .line 47
    .line 48
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    iget-object v0, v0, Le2/j0;->e:Ljava/util/ArrayList;

    .line 52
    .line 53
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    if-eqz v2, :cond_1

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-eqz v2, :cond_3

    .line 69
    .line 70
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    check-cast v2, Ly20/g;

    .line 75
    .line 76
    iget-object v2, v2, Ly20/g;->a:Lss0/d0;

    .line 77
    .line 78
    iget-object v3, v1, Ly20/g;->a:Lss0/d0;

    .line 79
    .line 80
    invoke-virtual {v2, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    if-eqz v2, :cond_2

    .line 85
    .line 86
    const/4 v0, 0x1

    .line 87
    goto :goto_2

    .line 88
    :cond_3
    :goto_1
    const/4 v0, 0x0

    .line 89
    :goto_2
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    return-object v0

    .line 94
    :pswitch_1
    move-object/from16 v1, p1

    .line 95
    .line 96
    check-cast v1, Ljava/lang/Integer;

    .line 97
    .line 98
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    if-eqz v1, :cond_5

    .line 103
    .line 104
    sget-object v2, Lrd0/d0;->b:Ljava/util/List;

    .line 105
    .line 106
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    add-int/lit8 v2, v2, -0x1

    .line 111
    .line 112
    if-ne v1, v2, :cond_4

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_4
    const-string v0, ""

    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_5
    :goto_3
    iget-object v0, v0, Le2/j0;->e:Ljava/util/ArrayList;

    .line 119
    .line 120
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    check-cast v0, Ljava/lang/String;

    .line 125
    .line 126
    :goto_4
    return-object v0

    .line 127
    :pswitch_2
    move-object/from16 v1, p1

    .line 128
    .line 129
    check-cast v1, Ljava/lang/Integer;

    .line 130
    .line 131
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    iget-object v0, v0, Le2/j0;->e:Ljava/util/ArrayList;

    .line 136
    .line 137
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    check-cast v0, Ljava/lang/String;

    .line 142
    .line 143
    return-object v0

    .line 144
    :pswitch_3
    move-object/from16 v1, p1

    .line 145
    .line 146
    check-cast v1, Lt3/d1;

    .line 147
    .line 148
    iget-object v0, v0, Le2/j0;->e:Ljava/util/ArrayList;

    .line 149
    .line 150
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 151
    .line 152
    .line 153
    move-result v2

    .line 154
    const/4 v3, 0x0

    .line 155
    move v4, v3

    .line 156
    :goto_5
    if-ge v4, v2, :cond_6

    .line 157
    .line 158
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v5

    .line 162
    check-cast v5, Lt3/e1;

    .line 163
    .line 164
    invoke-static {v1, v5, v3, v3}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 165
    .line 166
    .line 167
    add-int/lit8 v4, v4, 0x1

    .line 168
    .line 169
    goto :goto_5

    .line 170
    :cond_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 171
    .line 172
    return-object v0

    .line 173
    :pswitch_4
    move-object/from16 v1, p1

    .line 174
    .line 175
    check-cast v1, Lt3/d1;

    .line 176
    .line 177
    iget-object v0, v0, Le2/j0;->e:Ljava/util/ArrayList;

    .line 178
    .line 179
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 180
    .line 181
    .line 182
    move-result v2

    .line 183
    const/4 v4, 0x0

    .line 184
    :goto_6
    if-ge v4, v2, :cond_f

    .line 185
    .line 186
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v5

    .line 190
    check-cast v5, Lp1/d;

    .line 191
    .line 192
    iget-object v6, v5, Lp1/d;->c:Ljava/util/List;

    .line 193
    .line 194
    iget-boolean v7, v5, Lp1/d;->i:Z

    .line 195
    .line 196
    iget v8, v5, Lp1/d;->m:I

    .line 197
    .line 198
    const/high16 v9, -0x80000000

    .line 199
    .line 200
    if-eq v8, v9, :cond_7

    .line 201
    .line 202
    goto :goto_7

    .line 203
    :cond_7
    const-string v8, "position() should be called first"

    .line 204
    .line 205
    invoke-static {v8}, Lj1/b;->a(Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    :goto_7
    invoke-interface {v6}, Ljava/util/List;->size()I

    .line 209
    .line 210
    .line 211
    move-result v8

    .line 212
    const/4 v9, 0x0

    .line 213
    :goto_8
    if-ge v9, v8, :cond_e

    .line 214
    .line 215
    invoke-interface {v6, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v10

    .line 219
    check-cast v10, Lt3/e1;

    .line 220
    .line 221
    iget-object v11, v5, Lp1/d;->k:[I

    .line 222
    .line 223
    mul-int/lit8 v12, v9, 0x2

    .line 224
    .line 225
    aget v13, v11, v12

    .line 226
    .line 227
    add-int/lit8 v12, v12, 0x1

    .line 228
    .line 229
    aget v11, v11, v12

    .line 230
    .line 231
    int-to-long v12, v13

    .line 232
    const/16 v14, 0x20

    .line 233
    .line 234
    shl-long/2addr v12, v14

    .line 235
    move/from16 p1, v4

    .line 236
    .line 237
    int-to-long v3, v11

    .line 238
    const-wide v15, 0xffffffffL

    .line 239
    .line 240
    .line 241
    .line 242
    .line 243
    and-long/2addr v3, v15

    .line 244
    or-long/2addr v3, v12

    .line 245
    iget-boolean v11, v5, Lp1/d;->h:Z

    .line 246
    .line 247
    if-eqz v11, :cond_c

    .line 248
    .line 249
    if-eqz v7, :cond_8

    .line 250
    .line 251
    shr-long v11, v3, v14

    .line 252
    .line 253
    long-to-int v11, v11

    .line 254
    goto :goto_a

    .line 255
    :cond_8
    shr-long v11, v3, v14

    .line 256
    .line 257
    long-to-int v11, v11

    .line 258
    iget v12, v5, Lp1/d;->m:I

    .line 259
    .line 260
    sub-int/2addr v12, v11

    .line 261
    if-eqz v7, :cond_9

    .line 262
    .line 263
    iget v11, v10, Lt3/e1;->e:I

    .line 264
    .line 265
    goto :goto_9

    .line 266
    :cond_9
    iget v11, v10, Lt3/e1;->d:I

    .line 267
    .line 268
    :goto_9
    sub-int v11, v12, v11

    .line 269
    .line 270
    :goto_a
    if-eqz v7, :cond_b

    .line 271
    .line 272
    and-long/2addr v3, v15

    .line 273
    long-to-int v3, v3

    .line 274
    iget v4, v5, Lp1/d;->m:I

    .line 275
    .line 276
    sub-int/2addr v4, v3

    .line 277
    if-eqz v7, :cond_a

    .line 278
    .line 279
    iget v3, v10, Lt3/e1;->e:I

    .line 280
    .line 281
    goto :goto_b

    .line 282
    :cond_a
    iget v3, v10, Lt3/e1;->d:I

    .line 283
    .line 284
    :goto_b
    sub-int/2addr v4, v3

    .line 285
    goto :goto_c

    .line 286
    :cond_b
    and-long/2addr v3, v15

    .line 287
    long-to-int v4, v3

    .line 288
    :goto_c
    int-to-long v11, v11

    .line 289
    shl-long/2addr v11, v14

    .line 290
    int-to-long v3, v4

    .line 291
    and-long/2addr v3, v15

    .line 292
    or-long/2addr v3, v11

    .line 293
    :cond_c
    iget-wide v11, v5, Lp1/d;->d:J

    .line 294
    .line 295
    invoke-static {v3, v4, v11, v12}, Lt4/j;->d(JJ)J

    .line 296
    .line 297
    .line 298
    move-result-wide v3

    .line 299
    if-eqz v7, :cond_d

    .line 300
    .line 301
    invoke-static {v1, v10, v3, v4}, Lt3/d1;->A(Lt3/d1;Lt3/e1;J)V

    .line 302
    .line 303
    .line 304
    goto :goto_d

    .line 305
    :cond_d
    invoke-static {v1, v10, v3, v4}, Lt3/d1;->t(Lt3/d1;Lt3/e1;J)V

    .line 306
    .line 307
    .line 308
    :goto_d
    add-int/lit8 v9, v9, 0x1

    .line 309
    .line 310
    move/from16 v4, p1

    .line 311
    .line 312
    goto :goto_8

    .line 313
    :cond_e
    move/from16 p1, v4

    .line 314
    .line 315
    add-int/lit8 v4, p1, 0x1

    .line 316
    .line 317
    goto/16 :goto_6

    .line 318
    .line 319
    :cond_f
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 320
    .line 321
    return-object v0

    .line 322
    :pswitch_5
    move-object/from16 v1, p1

    .line 323
    .line 324
    check-cast v1, Lt3/d1;

    .line 325
    .line 326
    iget-object v0, v0, Le2/j0;->e:Ljava/util/ArrayList;

    .line 327
    .line 328
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 329
    .line 330
    .line 331
    move-result v2

    .line 332
    const/4 v3, 0x0

    .line 333
    move v4, v3

    .line 334
    :goto_e
    if-ge v4, v2, :cond_10

    .line 335
    .line 336
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    move-result-object v5

    .line 340
    check-cast v5, Lt3/e1;

    .line 341
    .line 342
    invoke-static {v1, v5, v3, v3}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 343
    .line 344
    .line 345
    add-int/lit8 v4, v4, 0x1

    .line 346
    .line 347
    goto :goto_e

    .line 348
    :cond_10
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 349
    .line 350
    return-object v0

    .line 351
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
