.class public final Lh2/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/v0;


# instance fields
.field public final synthetic a:Lh2/r8;

.field public final synthetic b:Lay0/a;


# direct methods
.method public constructor <init>(Lh2/r8;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/f0;->a:Lh2/r8;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/f0;->b:Lay0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    check-cast v1, Ljava/util/ArrayList;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v3

    .line 12
    check-cast v3, Ljava/util/List;

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v5

    .line 19
    check-cast v5, Ljava/util/List;

    .line 20
    .line 21
    const/4 v6, 0x2

    .line 22
    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v6

    .line 26
    check-cast v6, Ljava/util/List;

    .line 27
    .line 28
    const/4 v7, 0x3

    .line 29
    invoke-virtual {v1, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    check-cast v1, Ljava/util/List;

    .line 34
    .line 35
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 36
    .line 37
    .line 38
    move-result v9

    .line 39
    invoke-static/range {p3 .. p4}, Lt4/a;->g(J)I

    .line 40
    .line 41
    .line 42
    move-result v13

    .line 43
    const/16 v19, 0x0

    .line 44
    .line 45
    const/16 v20, 0xa

    .line 46
    .line 47
    const/16 v16, 0x0

    .line 48
    .line 49
    const/16 v17, 0x0

    .line 50
    .line 51
    const/16 v18, 0x0

    .line 52
    .line 53
    move-wide/from16 v14, p3

    .line 54
    .line 55
    invoke-static/range {v14 .. v20}, Lt4/a;->a(JIIIII)J

    .line 56
    .line 57
    .line 58
    move-result-wide v7

    .line 59
    new-instance v10, Ljava/util/ArrayList;

    .line 60
    .line 61
    invoke-interface {v6}, Ljava/util/List;->size()I

    .line 62
    .line 63
    .line 64
    move-result v11

    .line 65
    invoke-direct {v10, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 66
    .line 67
    .line 68
    move-object v11, v6

    .line 69
    check-cast v11, Ljava/util/Collection;

    .line 70
    .line 71
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    .line 72
    .line 73
    .line 74
    move-result v11

    .line 75
    move v12, v2

    .line 76
    :goto_0
    if-ge v12, v11, :cond_0

    .line 77
    .line 78
    invoke-interface {v6, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v14

    .line 82
    check-cast v14, Lt3/p0;

    .line 83
    .line 84
    invoke-interface {v14, v7, v8}, Lt3/p0;->L(J)Lt3/e1;

    .line 85
    .line 86
    .line 87
    move-result-object v14

    .line 88
    invoke-virtual {v10, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    add-int/lit8 v12, v12, 0x1

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_0
    new-instance v15, Ljava/util/ArrayList;

    .line 95
    .line 96
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 97
    .line 98
    .line 99
    move-result v6

    .line 100
    invoke-direct {v15, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 101
    .line 102
    .line 103
    move-object v6, v3

    .line 104
    check-cast v6, Ljava/util/Collection;

    .line 105
    .line 106
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 107
    .line 108
    .line 109
    move-result v6

    .line 110
    move v11, v2

    .line 111
    :goto_1
    if-ge v11, v6, :cond_1

    .line 112
    .line 113
    invoke-interface {v3, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v12

    .line 117
    check-cast v12, Lt3/p0;

    .line 118
    .line 119
    invoke-interface {v12, v7, v8}, Lt3/p0;->L(J)Lt3/e1;

    .line 120
    .line 121
    .line 122
    move-result-object v12

    .line 123
    invoke-virtual {v15, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    add-int/lit8 v11, v11, 0x1

    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_1
    invoke-virtual {v15}, Ljava/util/ArrayList;->isEmpty()Z

    .line 130
    .line 131
    .line 132
    move-result v3

    .line 133
    if-eqz v3, :cond_2

    .line 134
    .line 135
    const/4 v3, 0x0

    .line 136
    goto :goto_3

    .line 137
    :cond_2
    invoke-virtual {v15, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v3

    .line 141
    check-cast v3, Lt3/e1;

    .line 142
    .line 143
    iget v3, v3, Lt3/e1;->e:I

    .line 144
    .line 145
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    invoke-static {v15}, Ljp/k1;->h(Ljava/util/List;)I

    .line 150
    .line 151
    .line 152
    move-result v6

    .line 153
    if-gt v4, v6, :cond_4

    .line 154
    .line 155
    :goto_2
    invoke-virtual {v15, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v11

    .line 159
    check-cast v11, Lt3/e1;

    .line 160
    .line 161
    iget v11, v11, Lt3/e1;->e:I

    .line 162
    .line 163
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 164
    .line 165
    .line 166
    move-result-object v11

    .line 167
    invoke-virtual {v11, v3}, Ljava/lang/Integer;->compareTo(Ljava/lang/Object;)I

    .line 168
    .line 169
    .line 170
    move-result v12

    .line 171
    if-lez v12, :cond_3

    .line 172
    .line 173
    move-object v3, v11

    .line 174
    :cond_3
    if-eq v4, v6, :cond_4

    .line 175
    .line 176
    add-int/lit8 v4, v4, 0x1

    .line 177
    .line 178
    goto :goto_2

    .line 179
    :cond_4
    :goto_3
    if-eqz v3, :cond_5

    .line 180
    .line 181
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 182
    .line 183
    .line 184
    move-result v3

    .line 185
    move/from16 v16, v3

    .line 186
    .line 187
    goto :goto_4

    .line 188
    :cond_5
    move/from16 v16, v2

    .line 189
    .line 190
    :goto_4
    sub-int v26, v13, v16

    .line 191
    .line 192
    const/16 v27, 0x7

    .line 193
    .line 194
    const/16 v23, 0x0

    .line 195
    .line 196
    const/16 v24, 0x0

    .line 197
    .line 198
    const/16 v25, 0x0

    .line 199
    .line 200
    move-wide/from16 v21, v7

    .line 201
    .line 202
    invoke-static/range {v21 .. v27}, Lt4/a;->a(JIIIII)J

    .line 203
    .line 204
    .line 205
    move-result-wide v3

    .line 206
    move-wide/from16 v6, v21

    .line 207
    .line 208
    new-instance v14, Ljava/util/ArrayList;

    .line 209
    .line 210
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 211
    .line 212
    .line 213
    move-result v8

    .line 214
    invoke-direct {v14, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 215
    .line 216
    .line 217
    move-object v8, v5

    .line 218
    check-cast v8, Ljava/util/Collection;

    .line 219
    .line 220
    invoke-interface {v8}, Ljava/util/Collection;->size()I

    .line 221
    .line 222
    .line 223
    move-result v8

    .line 224
    move v11, v2

    .line 225
    :goto_5
    if-ge v11, v8, :cond_6

    .line 226
    .line 227
    invoke-interface {v5, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v12

    .line 231
    check-cast v12, Lt3/p0;

    .line 232
    .line 233
    invoke-interface {v12, v3, v4}, Lt3/p0;->L(J)Lt3/e1;

    .line 234
    .line 235
    .line 236
    move-result-object v12

    .line 237
    invoke-virtual {v14, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    add-int/lit8 v11, v11, 0x1

    .line 241
    .line 242
    goto :goto_5

    .line 243
    :cond_6
    new-instance v3, Ljava/util/ArrayList;

    .line 244
    .line 245
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 246
    .line 247
    .line 248
    move-result v4

    .line 249
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 250
    .line 251
    .line 252
    move-object v4, v1

    .line 253
    check-cast v4, Ljava/util/Collection;

    .line 254
    .line 255
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 256
    .line 257
    .line 258
    move-result v4

    .line 259
    :goto_6
    if-ge v2, v4, :cond_7

    .line 260
    .line 261
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v5

    .line 265
    check-cast v5, Lt3/p0;

    .line 266
    .line 267
    invoke-interface {v5, v6, v7}, Lt3/p0;->L(J)Lt3/e1;

    .line 268
    .line 269
    .line 270
    move-result-object v5

    .line 271
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    add-int/lit8 v2, v2, 0x1

    .line 275
    .line 276
    goto :goto_6

    .line 277
    :cond_7
    new-instance v7, Lh2/e0;

    .line 278
    .line 279
    iget-object v11, v0, Lh2/f0;->a:Lh2/r8;

    .line 280
    .line 281
    iget-object v12, v0, Lh2/f0;->b:Lay0/a;

    .line 282
    .line 283
    move-object v8, v10

    .line 284
    move-object v10, v3

    .line 285
    invoke-direct/range {v7 .. v16}, Lh2/e0;-><init>(Ljava/util/ArrayList;ILjava/util/ArrayList;Lh2/r8;Lay0/a;ILjava/util/ArrayList;Ljava/util/ArrayList;I)V

    .line 286
    .line 287
    .line 288
    sget-object v0, Lmx0/t;->d:Lmx0/t;

    .line 289
    .line 290
    move-object/from16 v1, p1

    .line 291
    .line 292
    invoke-interface {v1, v9, v13, v0, v7}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 293
    .line 294
    .line 295
    move-result-object v0

    .line 296
    return-object v0
.end method
