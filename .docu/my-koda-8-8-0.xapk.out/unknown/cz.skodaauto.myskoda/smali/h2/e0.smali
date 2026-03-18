.class public final synthetic Lh2/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Ljava/util/ArrayList;

.field public final synthetic e:I

.field public final synthetic f:Ljava/util/ArrayList;

.field public final synthetic g:Lh2/r8;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:I

.field public final synthetic j:Ljava/util/ArrayList;

.field public final synthetic k:Ljava/util/ArrayList;

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;ILjava/util/ArrayList;Lh2/r8;Lay0/a;ILjava/util/ArrayList;Ljava/util/ArrayList;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/e0;->d:Ljava/util/ArrayList;

    .line 5
    .line 6
    iput p2, p0, Lh2/e0;->e:I

    .line 7
    .line 8
    iput-object p3, p0, Lh2/e0;->f:Ljava/util/ArrayList;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/e0;->g:Lh2/r8;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/e0;->h:Lay0/a;

    .line 13
    .line 14
    iput p6, p0, Lh2/e0;->i:I

    .line 15
    .line 16
    iput-object p7, p0, Lh2/e0;->j:Ljava/util/ArrayList;

    .line 17
    .line 18
    iput-object p8, p0, Lh2/e0;->k:Ljava/util/ArrayList;

    .line 19
    .line 20
    iput p9, p0, Lh2/e0;->l:I

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    check-cast p1, Lt3/d1;

    .line 2
    .line 3
    iget-object v0, p0, Lh2/e0;->d:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x1

    .line 11
    const/4 v4, 0x0

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    move-object v1, v2

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lt3/e1;

    .line 21
    .line 22
    iget v1, v1, Lt3/e1;->d:I

    .line 23
    .line 24
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-static {v0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-gt v3, v5, :cond_2

    .line 33
    .line 34
    move v6, v3

    .line 35
    :goto_0
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v7

    .line 39
    check-cast v7, Lt3/e1;

    .line 40
    .line 41
    iget v7, v7, Lt3/e1;->d:I

    .line 42
    .line 43
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 44
    .line 45
    .line 46
    move-result-object v7

    .line 47
    invoke-virtual {v7, v1}, Ljava/lang/Integer;->compareTo(Ljava/lang/Object;)I

    .line 48
    .line 49
    .line 50
    move-result v8

    .line 51
    if-lez v8, :cond_1

    .line 52
    .line 53
    move-object v1, v7

    .line 54
    :cond_1
    if-eq v6, v5, :cond_2

    .line 55
    .line 56
    add-int/lit8 v6, v6, 0x1

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_2
    :goto_1
    if-eqz v1, :cond_3

    .line 60
    .line 61
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    goto :goto_2

    .line 66
    :cond_3
    move v1, v4

    .line 67
    :goto_2
    iget v5, p0, Lh2/e0;->e:I

    .line 68
    .line 69
    sub-int v1, v5, v1

    .line 70
    .line 71
    const/4 v6, 0x2

    .line 72
    div-int/2addr v1, v6

    .line 73
    invoke-static {v4, v1}, Ljava/lang/Math;->max(II)I

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    iget-object v7, p0, Lh2/e0;->f:Ljava/util/ArrayList;

    .line 78
    .line 79
    invoke-virtual {v7}, Ljava/util/ArrayList;->isEmpty()Z

    .line 80
    .line 81
    .line 82
    move-result v8

    .line 83
    if-eqz v8, :cond_4

    .line 84
    .line 85
    move-object v8, v2

    .line 86
    goto :goto_4

    .line 87
    :cond_4
    invoke-virtual {v7, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v8

    .line 91
    check-cast v8, Lt3/e1;

    .line 92
    .line 93
    iget v8, v8, Lt3/e1;->d:I

    .line 94
    .line 95
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 96
    .line 97
    .line 98
    move-result-object v8

    .line 99
    invoke-static {v7}, Ljp/k1;->h(Ljava/util/List;)I

    .line 100
    .line 101
    .line 102
    move-result v9

    .line 103
    if-gt v3, v9, :cond_6

    .line 104
    .line 105
    move v10, v3

    .line 106
    :goto_3
    invoke-virtual {v7, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v11

    .line 110
    check-cast v11, Lt3/e1;

    .line 111
    .line 112
    iget v11, v11, Lt3/e1;->d:I

    .line 113
    .line 114
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object v11

    .line 118
    invoke-virtual {v11, v8}, Ljava/lang/Integer;->compareTo(Ljava/lang/Object;)I

    .line 119
    .line 120
    .line 121
    move-result v12

    .line 122
    if-lez v12, :cond_5

    .line 123
    .line 124
    move-object v8, v11

    .line 125
    :cond_5
    if-eq v10, v9, :cond_6

    .line 126
    .line 127
    add-int/lit8 v10, v10, 0x1

    .line 128
    .line 129
    goto :goto_3

    .line 130
    :cond_6
    :goto_4
    if-eqz v8, :cond_7

    .line 131
    .line 132
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 133
    .line 134
    .line 135
    move-result v8

    .line 136
    goto :goto_5

    .line 137
    :cond_7
    move v8, v4

    .line 138
    :goto_5
    invoke-virtual {v7}, Ljava/util/ArrayList;->isEmpty()Z

    .line 139
    .line 140
    .line 141
    move-result v9

    .line 142
    if-eqz v9, :cond_8

    .line 143
    .line 144
    goto :goto_7

    .line 145
    :cond_8
    invoke-virtual {v7, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    check-cast v2, Lt3/e1;

    .line 150
    .line 151
    iget v2, v2, Lt3/e1;->e:I

    .line 152
    .line 153
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 154
    .line 155
    .line 156
    move-result-object v2

    .line 157
    invoke-static {v7}, Ljp/k1;->h(Ljava/util/List;)I

    .line 158
    .line 159
    .line 160
    move-result v9

    .line 161
    if-gt v3, v9, :cond_a

    .line 162
    .line 163
    move v10, v3

    .line 164
    :goto_6
    invoke-virtual {v7, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v11

    .line 168
    check-cast v11, Lt3/e1;

    .line 169
    .line 170
    iget v11, v11, Lt3/e1;->e:I

    .line 171
    .line 172
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 173
    .line 174
    .line 175
    move-result-object v11

    .line 176
    invoke-virtual {v11, v2}, Ljava/lang/Integer;->compareTo(Ljava/lang/Object;)I

    .line 177
    .line 178
    .line 179
    move-result v12

    .line 180
    if-lez v12, :cond_9

    .line 181
    .line 182
    move-object v2, v11

    .line 183
    :cond_9
    if-eq v10, v9, :cond_a

    .line 184
    .line 185
    add-int/lit8 v10, v10, 0x1

    .line 186
    .line 187
    goto :goto_6

    .line 188
    :cond_a
    :goto_7
    if-eqz v2, :cond_b

    .line 189
    .line 190
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 191
    .line 192
    .line 193
    move-result v2

    .line 194
    goto :goto_8

    .line 195
    :cond_b
    move v2, v4

    .line 196
    :goto_8
    sub-int/2addr v5, v8

    .line 197
    div-int/2addr v5, v6

    .line 198
    iget-object v8, p0, Lh2/e0;->g:Lh2/r8;

    .line 199
    .line 200
    invoke-virtual {v8}, Lh2/r8;->c()Lh2/s8;

    .line 201
    .line 202
    .line 203
    move-result-object v8

    .line 204
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 205
    .line 206
    .line 207
    move-result v8

    .line 208
    if-eqz v8, :cond_d

    .line 209
    .line 210
    if-eq v8, v3, :cond_d

    .line 211
    .line 212
    if-ne v8, v6, :cond_c

    .line 213
    .line 214
    iget-object v3, p0, Lh2/e0;->h:Lay0/a;

    .line 215
    .line 216
    invoke-interface {v3}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v3

    .line 220
    check-cast v3, Ljava/lang/Number;

    .line 221
    .line 222
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 223
    .line 224
    .line 225
    move-result v3

    .line 226
    invoke-static {v3}, Lcy0/a;->i(F)I

    .line 227
    .line 228
    .line 229
    move-result v3

    .line 230
    :goto_9
    sub-int/2addr v3, v2

    .line 231
    goto :goto_a

    .line 232
    :cond_c
    new-instance p0, La8/r0;

    .line 233
    .line 234
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 235
    .line 236
    .line 237
    throw p0

    .line 238
    :cond_d
    iget v3, p0, Lh2/e0;->i:I

    .line 239
    .line 240
    goto :goto_9

    .line 241
    :goto_a
    iget-object v2, p0, Lh2/e0;->j:Ljava/util/ArrayList;

    .line 242
    .line 243
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 244
    .line 245
    .line 246
    move-result v6

    .line 247
    move v8, v4

    .line 248
    :goto_b
    if-ge v8, v6, :cond_e

    .line 249
    .line 250
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v9

    .line 254
    check-cast v9, Lt3/e1;

    .line 255
    .line 256
    iget v10, p0, Lh2/e0;->l:I

    .line 257
    .line 258
    invoke-static {p1, v9, v4, v10}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 259
    .line 260
    .line 261
    add-int/lit8 v8, v8, 0x1

    .line 262
    .line 263
    goto :goto_b

    .line 264
    :cond_e
    iget-object p0, p0, Lh2/e0;->k:Ljava/util/ArrayList;

    .line 265
    .line 266
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 267
    .line 268
    .line 269
    move-result v2

    .line 270
    move v6, v4

    .line 271
    :goto_c
    if-ge v6, v2, :cond_f

    .line 272
    .line 273
    invoke-virtual {p0, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v8

    .line 277
    check-cast v8, Lt3/e1;

    .line 278
    .line 279
    invoke-static {p1, v8, v4, v4}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 280
    .line 281
    .line 282
    add-int/lit8 v6, v6, 0x1

    .line 283
    .line 284
    goto :goto_c

    .line 285
    :cond_f
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 286
    .line 287
    .line 288
    move-result p0

    .line 289
    move v2, v4

    .line 290
    :goto_d
    if-ge v2, p0, :cond_10

    .line 291
    .line 292
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object v6

    .line 296
    check-cast v6, Lt3/e1;

    .line 297
    .line 298
    invoke-static {p1, v6, v1, v4}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 299
    .line 300
    .line 301
    add-int/lit8 v2, v2, 0x1

    .line 302
    .line 303
    goto :goto_d

    .line 304
    :cond_10
    invoke-interface {v7}, Ljava/util/Collection;->size()I

    .line 305
    .line 306
    .line 307
    move-result p0

    .line 308
    :goto_e
    if-ge v4, p0, :cond_11

    .line 309
    .line 310
    invoke-virtual {v7, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    check-cast v0, Lt3/e1;

    .line 315
    .line 316
    invoke-static {p1, v0, v5, v3}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 317
    .line 318
    .line 319
    add-int/lit8 v4, v4, 0x1

    .line 320
    .line 321
    goto :goto_e

    .line 322
    :cond_11
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 323
    .line 324
    return-object p0
.end method
