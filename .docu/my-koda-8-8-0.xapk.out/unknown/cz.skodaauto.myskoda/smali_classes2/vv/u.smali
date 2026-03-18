.class public final Lvv/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:F


# direct methods
.method public constructor <init>(IF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lvv/u;->a:I

    .line 5
    .line 6
    iput p2, p0, Lvv/u;->b:F

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v4, p1

    .line 4
    .line 5
    move-object/from16 v1, p2

    .line 6
    .line 7
    const-string v2, "$this$Layout"

    .line 8
    .line 9
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v2, "measurables"

    .line 13
    .line 14
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    iget v3, v0, Lvv/u;->a:I

    .line 22
    .line 23
    mul-int/lit8 v5, v3, 0x2

    .line 24
    .line 25
    if-ne v2, v5, :cond_d

    .line 26
    .line 27
    check-cast v1, Ljava/lang/Iterable;

    .line 28
    .line 29
    invoke-static {v1}, Lmx0/q;->z(Ljava/lang/Iterable;)Lky0/m;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    if-ltz v3, :cond_c

    .line 34
    .line 35
    if-nez v3, :cond_0

    .line 36
    .line 37
    sget-object v2, Lky0/e;->a:Lky0/e;

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    instance-of v5, v2, Lky0/d;

    .line 41
    .line 42
    if-eqz v5, :cond_1

    .line 43
    .line 44
    check-cast v2, Lky0/d;

    .line 45
    .line 46
    invoke-interface {v2, v3}, Lky0/d;->b(I)Lky0/j;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    goto :goto_0

    .line 51
    :cond_1
    new-instance v5, Lky0/c;

    .line 52
    .line 53
    const/4 v6, 0x1

    .line 54
    invoke-direct {v5, v2, v3, v6}, Lky0/c;-><init>(Lky0/j;II)V

    .line 55
    .line 56
    .line 57
    move-object v2, v5

    .line 58
    :goto_0
    invoke-static {v1}, Lmx0/q;->z(Ljava/lang/Iterable;)Lky0/m;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    invoke-static {v1, v3}, Lky0/l;->d(Lky0/j;I)Lky0/j;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    sget-object v3, Lvv/b;->n:Lvv/b;

    .line 67
    .line 68
    invoke-static {v2, v3}, Lky0/l;->n(Lky0/j;Lay0/k;)Lky0/s;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    invoke-static {v2}, Lky0/l;->p(Lky0/j;)Ljava/util/List;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    move-object v3, v2

    .line 77
    check-cast v3, Ljava/lang/Iterable;

    .line 78
    .line 79
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 80
    .line 81
    .line 82
    move-result-object v5

    .line 83
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    const/4 v6, 0x0

    .line 88
    if-nez v3, :cond_2

    .line 89
    .line 90
    move-object v3, v6

    .line 91
    goto :goto_1

    .line 92
    :cond_2
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 97
    .line 98
    .line 99
    move-result v7

    .line 100
    if-nez v7, :cond_3

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_3
    move-object v7, v3

    .line 104
    check-cast v7, Lt3/e1;

    .line 105
    .line 106
    iget v7, v7, Lt3/e1;->d:I

    .line 107
    .line 108
    :cond_4
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v8

    .line 112
    move-object v9, v8

    .line 113
    check-cast v9, Lt3/e1;

    .line 114
    .line 115
    iget v9, v9, Lt3/e1;->d:I

    .line 116
    .line 117
    if-ge v7, v9, :cond_5

    .line 118
    .line 119
    move-object v3, v8

    .line 120
    move v7, v9

    .line 121
    :cond_5
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 122
    .line 123
    .line 124
    move-result v8

    .line 125
    if-nez v8, :cond_4

    .line 126
    .line 127
    :goto_1
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    check-cast v3, Lt3/e1;

    .line 131
    .line 132
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 133
    .line 134
    .line 135
    move-result v5

    .line 136
    iget v7, v3, Lt3/e1;->d:I

    .line 137
    .line 138
    sub-int/2addr v5, v7

    .line 139
    const/4 v8, 0x0

    .line 140
    if-gez v5, :cond_6

    .line 141
    .line 142
    move v12, v8

    .line 143
    goto :goto_2

    .line 144
    :cond_6
    move v12, v5

    .line 145
    :goto_2
    const/4 v14, 0x0

    .line 146
    const/16 v15, 0xd

    .line 147
    .line 148
    const/4 v11, 0x0

    .line 149
    const/4 v13, 0x0

    .line 150
    move-wide/from16 v9, p3

    .line 151
    .line 152
    invoke-static/range {v9 .. v15}, Lt4/a;->a(JIIIII)J

    .line 153
    .line 154
    .line 155
    move-result-wide v9

    .line 156
    new-instance v5, Lh7/y;

    .line 157
    .line 158
    const/4 v7, 0x1

    .line 159
    invoke-direct {v5, v9, v10, v7}, Lh7/y;-><init>(JI)V

    .line 160
    .line 161
    .line 162
    invoke-static {v1, v5}, Lky0/l;->n(Lky0/j;Lay0/k;)Lky0/s;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    invoke-static {v1}, Lky0/l;->p(Lky0/j;)Ljava/util/List;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    move-object v9, v1

    .line 171
    check-cast v9, Ljava/lang/Iterable;

    .line 172
    .line 173
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 174
    .line 175
    .line 176
    move-result-object v10

    .line 177
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 178
    .line 179
    .line 180
    move-result v5

    .line 181
    if-nez v5, :cond_7

    .line 182
    .line 183
    goto :goto_3

    .line 184
    :cond_7
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v6

    .line 188
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 189
    .line 190
    .line 191
    move-result v5

    .line 192
    if-nez v5, :cond_8

    .line 193
    .line 194
    goto :goto_3

    .line 195
    :cond_8
    move-object v5, v6

    .line 196
    check-cast v5, Lt3/e1;

    .line 197
    .line 198
    iget v5, v5, Lt3/e1;->d:I

    .line 199
    .line 200
    :cond_9
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v7

    .line 204
    move-object v11, v7

    .line 205
    check-cast v11, Lt3/e1;

    .line 206
    .line 207
    iget v11, v11, Lt3/e1;->d:I

    .line 208
    .line 209
    if-ge v5, v11, :cond_a

    .line 210
    .line 211
    move-object v6, v7

    .line 212
    move v5, v11

    .line 213
    :cond_a
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 214
    .line 215
    .line 216
    move-result v7

    .line 217
    if-nez v7, :cond_9

    .line 218
    .line 219
    :goto_3
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    check-cast v6, Lt3/e1;

    .line 223
    .line 224
    iget v5, v3, Lt3/e1;->d:I

    .line 225
    .line 226
    iget v6, v6, Lt3/e1;->d:I

    .line 227
    .line 228
    add-int v7, v5, v6

    .line 229
    .line 230
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 231
    .line 232
    .line 233
    move-result-object v5

    .line 234
    :goto_4
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 235
    .line 236
    .line 237
    move-result v6

    .line 238
    if-eqz v6, :cond_b

    .line 239
    .line 240
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v6

    .line 244
    check-cast v6, Lt3/e1;

    .line 245
    .line 246
    iget v6, v6, Lt3/e1;->e:I

    .line 247
    .line 248
    add-int/2addr v8, v6

    .line 249
    goto :goto_4

    .line 250
    :cond_b
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 251
    .line 252
    .line 253
    move-result v5

    .line 254
    add-int/lit8 v5, v5, -0x1

    .line 255
    .line 256
    iget v6, v0, Lvv/u;->b:F

    .line 257
    .line 258
    invoke-interface {v4, v6}, Lt4/c;->Q(F)I

    .line 259
    .line 260
    .line 261
    move-result v6

    .line 262
    mul-int/2addr v6, v5

    .line 263
    add-int/2addr v8, v6

    .line 264
    new-instance v5, Lvv/t;

    .line 265
    .line 266
    move-object v6, v3

    .line 267
    move-object v3, v1

    .line 268
    iget v1, v0, Lvv/u;->a:I

    .line 269
    .line 270
    move-object v9, v5

    .line 271
    iget v5, v0, Lvv/u;->b:F

    .line 272
    .line 273
    move-object v0, v9

    .line 274
    invoke-direct/range {v0 .. v6}, Lvv/t;-><init>(ILjava/util/List;Ljava/util/List;Lt3/s0;FLt3/e1;)V

    .line 275
    .line 276
    .line 277
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 278
    .line 279
    invoke-interface {v4, v7, v8, v1, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 280
    .line 281
    .line 282
    move-result-object v0

    .line 283
    return-object v0

    .line 284
    :cond_c
    const-string v0, "Requested element count "

    .line 285
    .line 286
    const-string v1, " is less than zero."

    .line 287
    .line 288
    invoke-static {v0, v3, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 289
    .line 290
    .line 291
    move-result-object v0

    .line 292
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 293
    .line 294
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object v0

    .line 298
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    throw v1

    .line 302
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 303
    .line 304
    const-string v1, "Check failed."

    .line 305
    .line 306
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    throw v0
.end method
