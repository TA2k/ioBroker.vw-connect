.class public abstract Ljp/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Laa/v;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v2, p0

    .line 2
    .line 3
    move/from16 v7, p2

    .line 4
    .line 5
    move-object/from16 v8, p1

    .line 6
    .line 7
    check-cast v8, Ll2/t;

    .line 8
    .line 9
    const v0, 0x118f13d0

    .line 10
    .line 11
    .line 12
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v8, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const/4 v1, 0x2

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    const/4 v0, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v0, v1

    .line 25
    :goto_0
    or-int/2addr v0, v7

    .line 26
    and-int/lit8 v0, v0, 0x3

    .line 27
    .line 28
    if-ne v0, v1, :cond_2

    .line 29
    .line 30
    invoke-virtual {v8}, Ll2/t;->A()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-nez v0, :cond_1

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 38
    .line 39
    .line 40
    goto/16 :goto_5

    .line 41
    .line 42
    :cond_2
    :goto_1
    invoke-static {v8}, Lu2/m;->f(Ll2/o;)Lu2/e;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    invoke-virtual {v2}, Lz9/j0;->b()Lz9/m;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    iget-object v0, v0, Lz9/m;->e:Lyy0/l1;

    .line 51
    .line 52
    const/4 v9, 0x0

    .line 53
    const/4 v1, 0x1

    .line 54
    invoke-static {v0, v9, v8, v1}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    check-cast v4, Ljava/util/List;

    .line 63
    .line 64
    check-cast v4, Ljava/util/Collection;

    .line 65
    .line 66
    sget-object v5, Lw3/q1;->a:Ll2/u2;

    .line 67
    .line 68
    invoke-virtual {v8, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v5

    .line 72
    check-cast v5, Ljava/lang/Boolean;

    .line 73
    .line 74
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    invoke-virtual {v8, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v6

    .line 82
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v10

    .line 86
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 87
    .line 88
    if-nez v6, :cond_3

    .line 89
    .line 90
    if-ne v10, v11, :cond_7

    .line 91
    .line 92
    :cond_3
    new-instance v10, Lv2/o;

    .line 93
    .line 94
    invoke-direct {v10}, Lv2/o;-><init>()V

    .line 95
    .line 96
    .line 97
    check-cast v4, Ljava/lang/Iterable;

    .line 98
    .line 99
    new-instance v6, Ljava/util/ArrayList;

    .line 100
    .line 101
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 102
    .line 103
    .line 104
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 105
    .line 106
    .line 107
    move-result-object v4

    .line 108
    :cond_4
    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 109
    .line 110
    .line 111
    move-result v12

    .line 112
    if-eqz v12, :cond_6

    .line 113
    .line 114
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v12

    .line 118
    move-object v13, v12

    .line 119
    check-cast v13, Lz9/k;

    .line 120
    .line 121
    if-eqz v5, :cond_5

    .line 122
    .line 123
    goto :goto_3

    .line 124
    :cond_5
    iget-object v13, v13, Lz9/k;->k:Lca/c;

    .line 125
    .line 126
    iget-object v13, v13, Lca/c;->j:Landroidx/lifecycle/z;

    .line 127
    .line 128
    iget-object v13, v13, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 129
    .line 130
    sget-object v14, Landroidx/lifecycle/q;->g:Landroidx/lifecycle/q;

    .line 131
    .line 132
    invoke-virtual {v13, v14}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 133
    .line 134
    .line 135
    move-result v13

    .line 136
    if-ltz v13, :cond_4

    .line 137
    .line 138
    :goto_3
    invoke-virtual {v6, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_6
    invoke-virtual {v10, v6}, Lv2/o;->addAll(Ljava/util/Collection;)Z

    .line 143
    .line 144
    .line 145
    invoke-virtual {v8, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    :cond_7
    check-cast v10, Lv2/o;

    .line 149
    .line 150
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    check-cast v0, Ljava/util/List;

    .line 155
    .line 156
    check-cast v0, Ljava/util/Collection;

    .line 157
    .line 158
    const/4 v12, 0x0

    .line 159
    invoke-static {v10, v0, v8, v12}, Ljp/p0;->b(Ljava/util/List;Ljava/util/Collection;Ll2/o;I)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v2}, Lz9/j0;->b()Lz9/m;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    iget-object v0, v0, Lz9/m;->f:Lyy0/l1;

    .line 167
    .line 168
    invoke-static {v0, v9, v8, v1}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 169
    .line 170
    .line 171
    move-result-object v13

    .line 172
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    if-ne v0, v11, :cond_8

    .line 177
    .line 178
    new-instance v0, Lv2/o;

    .line 179
    .line 180
    invoke-direct {v0}, Lv2/o;-><init>()V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    :cond_8
    move-object v4, v0

    .line 187
    check-cast v4, Lv2/o;

    .line 188
    .line 189
    const v0, -0x15e65d02

    .line 190
    .line 191
    .line 192
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v10}, Lv2/o;->listIterator()Ljava/util/ListIterator;

    .line 196
    .line 197
    .line 198
    move-result-object v10

    .line 199
    :goto_4
    move-object v0, v10

    .line 200
    check-cast v0, Lnx0/a;

    .line 201
    .line 202
    invoke-virtual {v0}, Lnx0/a;->hasNext()Z

    .line 203
    .line 204
    .line 205
    move-result v1

    .line 206
    if-eqz v1, :cond_b

    .line 207
    .line 208
    invoke-virtual {v0}, Lnx0/a;->next()Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v0

    .line 212
    move-object v1, v0

    .line 213
    check-cast v1, Lz9/k;

    .line 214
    .line 215
    iget-object v0, v1, Lz9/k;->e:Lz9/u;

    .line 216
    .line 217
    const-string v5, "null cannot be cast to non-null type androidx.navigation.compose.DialogNavigator.Destination"

    .line 218
    .line 219
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    move-object v5, v0

    .line 223
    check-cast v5, Laa/u;

    .line 224
    .line 225
    invoke-virtual {v8, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 226
    .line 227
    .line 228
    move-result v0

    .line 229
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    move-result v6

    .line 233
    or-int/2addr v0, v6

    .line 234
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object v6

    .line 238
    if-nez v0, :cond_9

    .line 239
    .line 240
    if-ne v6, v11, :cond_a

    .line 241
    .line 242
    :cond_9
    new-instance v6, Laa/k;

    .line 243
    .line 244
    const/4 v0, 0x0

    .line 245
    invoke-direct {v6, v0, v2, v1}, Laa/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v8, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 249
    .line 250
    .line 251
    :cond_a
    move-object v14, v6

    .line 252
    check-cast v14, Lay0/a;

    .line 253
    .line 254
    iget-object v15, v5, Laa/u;->i:Lx4/p;

    .line 255
    .line 256
    new-instance v0, Laa/r;

    .line 257
    .line 258
    const/4 v6, 0x0

    .line 259
    invoke-direct/range {v0 .. v6}, Laa/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 260
    .line 261
    .line 262
    const v1, 0x43541ebc

    .line 263
    .line 264
    .line 265
    invoke-static {v1, v8, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 266
    .line 267
    .line 268
    move-result-object v0

    .line 269
    const/16 v1, 0x180

    .line 270
    .line 271
    invoke-static {v14, v15, v0, v8, v1}, Llp/ge;->a(Lay0/a;Lx4/p;Lt2/b;Ll2/o;I)V

    .line 272
    .line 273
    .line 274
    goto :goto_4

    .line 275
    :cond_b
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 276
    .line 277
    .line 278
    invoke-interface {v13}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    move-object v6, v0

    .line 283
    check-cast v6, Ljava/util/Set;

    .line 284
    .line 285
    invoke-virtual {v8, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    move-result v0

    .line 289
    invoke-virtual {v8, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 290
    .line 291
    .line 292
    move-result v1

    .line 293
    or-int/2addr v0, v1

    .line 294
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object v1

    .line 298
    if-nez v0, :cond_c

    .line 299
    .line 300
    if-ne v1, v11, :cond_d

    .line 301
    .line 302
    :cond_c
    new-instance v0, Laa/s;

    .line 303
    .line 304
    const/4 v1, 0x0

    .line 305
    move-object v3, v2

    .line 306
    move-object v5, v9

    .line 307
    move-object v2, v13

    .line 308
    invoke-direct/range {v0 .. v5}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 309
    .line 310
    .line 311
    move-object v2, v3

    .line 312
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 313
    .line 314
    .line 315
    move-object v1, v0

    .line 316
    :cond_d
    check-cast v1, Lay0/n;

    .line 317
    .line 318
    invoke-static {v6, v4, v1, v8}, Ll2/l0;->e(Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 319
    .line 320
    .line 321
    :goto_5
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 322
    .line 323
    .line 324
    move-result-object v0

    .line 325
    if-eqz v0, :cond_e

    .line 326
    .line 327
    new-instance v1, La71/a0;

    .line 328
    .line 329
    const/4 v3, 0x1

    .line 330
    invoke-direct {v1, v2, v7, v3}, La71/a0;-><init>(Ljava/lang/Object;II)V

    .line 331
    .line 332
    .line 333
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 334
    .line 335
    :cond_e
    return-void
.end method

.method public static final b(Ljava/util/List;Ljava/util/Collection;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0x5baa69c3

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p3

    .line 19
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    const/16 v1, 0x20

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    const/16 v1, 0x10

    .line 29
    .line 30
    :goto_1
    or-int/2addr v0, v1

    .line 31
    and-int/lit8 v0, v0, 0x13

    .line 32
    .line 33
    const/16 v1, 0x12

    .line 34
    .line 35
    if-ne v0, v1, :cond_3

    .line 36
    .line 37
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_2

    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_2
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 45
    .line 46
    .line 47
    goto :goto_4

    .line 48
    :cond_3
    :goto_2
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 49
    .line 50
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    check-cast v0, Ljava/lang/Boolean;

    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    move-object v1, p1

    .line 61
    check-cast v1, Ljava/lang/Iterable;

    .line 62
    .line 63
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_6

    .line 72
    .line 73
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    check-cast v2, Lz9/k;

    .line 78
    .line 79
    iget-object v3, v2, Lz9/k;->k:Lca/c;

    .line 80
    .line 81
    iget-object v3, v3, Lca/c;->j:Landroidx/lifecycle/z;

    .line 82
    .line 83
    invoke-virtual {p2, v0}, Ll2/t;->h(Z)Z

    .line 84
    .line 85
    .line 86
    move-result v4

    .line 87
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v5

    .line 91
    or-int/2addr v4, v5

    .line 92
    invoke-virtual {p2, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v5

    .line 96
    or-int/2addr v4, v5

    .line 97
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v5

    .line 101
    if-nez v4, :cond_4

    .line 102
    .line 103
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 104
    .line 105
    if-ne v5, v4, :cond_5

    .line 106
    .line 107
    :cond_4
    new-instance v5, Laa/l;

    .line 108
    .line 109
    const/4 v4, 0x0

    .line 110
    invoke-direct {v5, v2, v0, p0, v4}, Laa/l;-><init>(Ljava/lang/Object;ZLjava/lang/Object;I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p2, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    :cond_5
    check-cast v5, Lay0/k;

    .line 117
    .line 118
    invoke-static {v3, v5, p2}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 119
    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_6
    :goto_4
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 123
    .line 124
    .line 125
    move-result-object p2

    .line 126
    if-eqz p2, :cond_7

    .line 127
    .line 128
    new-instance v0, Laa/m;

    .line 129
    .line 130
    const/4 v1, 0x0

    .line 131
    invoke-direct {v0, p3, v1, p0, p1}, Laa/m;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 135
    .line 136
    :cond_7
    return-void
.end method

.method public static final c(Ll70/t;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ll70/t;->a:Ljava/math/BigDecimal;

    .line 7
    .line 8
    iget-object p0, p0, Ll70/t;->b:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {v0, p0}, Ljp/p0;->e(Ljava/math/BigDecimal;Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static final d(Ll70/u;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ll70/u;->a:Ljava/math/BigDecimal;

    .line 7
    .line 8
    iget-object p0, p0, Ll70/u;->b:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {v0, p0}, Ljp/p0;->e(Ljava/math/BigDecimal;Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static final e(Ljava/math/BigDecimal;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Lol0/a;

    .line 2
    .line 3
    invoke-static {p0}, Ljp/p0;->k(Ljava/math/BigDecimal;)Ljava/math/BigDecimal;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v1, "round(...)"

    .line 8
    .line 9
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-direct {v0, p0, p1}, Lol0/a;-><init>(Ljava/math/BigDecimal;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const/4 p0, 0x3

    .line 16
    invoke-static {v0, p0}, Ljp/qd;->a(Lol0/a;I)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static final f(Ljava/math/BigDecimal;Ll70/h;Ljava/lang/String;Lqr0/s;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "fuelType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "currencyCode"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "unitsType"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-static {p0, p1, p3}, Ljp/p0;->j(Ljava/math/BigDecimal;Ll70/h;Lqr0/s;)Ljava/math/BigDecimal;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-static {p0, p2}, Ljp/p0;->e(Ljava/math/BigDecimal;Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-static {p1, p3}, Ljp/p0;->i(Ll70/h;Lqr0/s;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    const-string p2, "/"

    .line 29
    .line 30
    invoke-static {p0, p2, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public static final g(Ll70/t;Lqr0/s;Ll70/h;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ll70/t;->c:Ljava/math/BigDecimal;

    .line 7
    .line 8
    iget-object p0, p0, Ll70/t;->b:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {v0, p2, p0, p1}, Ljp/p0;->f(Ljava/math/BigDecimal;Ll70/h;Ljava/lang/String;Lqr0/s;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static h(Landroidx/lifecycle/h1;)Lz9/n;
    .locals 3

    .line 1
    sget-object v0, Lz9/o;->a:Lp7/d;

    .line 2
    .line 3
    sget-object v1, Lp7/a;->b:Lp7/a;

    .line 4
    .line 5
    const-string v2, "factory"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "extras"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v2, Lcom/google/firebase/messaging/w;

    .line 16
    .line 17
    invoke-direct {v2, p0, v0, v1}, Lcom/google/firebase/messaging/w;-><init>(Landroidx/lifecycle/h1;Landroidx/lifecycle/e1;Lp7/c;)V

    .line 18
    .line 19
    .line 20
    const-class p0, Lz9/n;

    .line 21
    .line 22
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    const-string v0, "modelClass"

    .line 29
    .line 30
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-interface {p0}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    const-string v1, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    .line 40
    .line 41
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-virtual {v2, p0, v0}, Lcom/google/firebase/messaging/w;->l(Lhy0/d;Ljava/lang/String;)Landroidx/lifecycle/b1;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    check-cast p0, Lz9/n;

    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 53
    .line 54
    const-string v0, "Local and anonymous classes can not be ViewModels"

    .line 55
    .line 56
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0
.end method

.method public static final i(Ll70/h;Lqr0/s;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "unitsType"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_2

    .line 16
    .line 17
    const/4 p1, 0x1

    .line 18
    if-eq p0, p1, :cond_1

    .line 19
    .line 20
    const/4 p1, 0x2

    .line 21
    if-ne p0, p1, :cond_0

    .line 22
    .line 23
    sget-object p0, Lqr0/k;->d:Lqr0/k;

    .line 24
    .line 25
    invoke-static {p0}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_0
    new-instance p0, La8/r0;

    .line 31
    .line 32
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 33
    .line 34
    .line 35
    throw p0

    .line 36
    :cond_1
    sget-object p0, Lqr0/o;->f:Lqr0/o;

    .line 37
    .line 38
    invoke-static {p0}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :cond_2
    sget-object p0, Lqr0/s;->f:Lqr0/s;

    .line 44
    .line 45
    if-ne p1, p0, :cond_3

    .line 46
    .line 47
    sget-object p0, Lqr0/t;->d:Lqr0/t;

    .line 48
    .line 49
    invoke-static {p0}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :cond_3
    sget-object p0, Lqr0/t;->e:Lqr0/t;

    .line 55
    .line 56
    invoke-static {p0}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0
.end method

.method public static final j(Ljava/math/BigDecimal;Ll70/h;Lqr0/s;)Ljava/math/BigDecimal;
    .locals 4

    .line 1
    const-string v0, "fuelType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "unitsType"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Ll70/h;->d:Ll70/h;

    .line 12
    .line 13
    if-ne p1, v0, :cond_0

    .line 14
    .line 15
    sget-object p1, Lqr0/s;->f:Lqr0/s;

    .line 16
    .line 17
    if-ne p2, p1, :cond_0

    .line 18
    .line 19
    new-instance p1, Ljava/math/BigDecimal;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/math/BigDecimal;->doubleValue()D

    .line 22
    .line 23
    .line 24
    move-result-wide v0

    .line 25
    const-wide v2, 0x400e488509bf9c63L    # 3.78541

    .line 26
    .line 27
    .line 28
    .line 29
    .line 30
    mul-double/2addr v0, v2

    .line 31
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-direct {p1, p0}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    return-object p1

    .line 39
    :cond_0
    return-object p0
.end method

.method public static final k(Ljava/math/BigDecimal;)Ljava/math/BigDecimal;
    .locals 5

    .line 1
    invoke-virtual {p0}, Ljava/math/BigDecimal;->longValue()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    cmp-long v2, v2, v0

    .line 8
    .line 9
    const-wide/16 v3, 0xa

    .line 10
    .line 11
    if-gtz v2, :cond_0

    .line 12
    .line 13
    cmp-long v2, v0, v3

    .line 14
    .line 15
    if-gez v2, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x3

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    cmp-long v2, v3, v0

    .line 20
    .line 21
    if-gtz v2, :cond_1

    .line 22
    .line 23
    const-wide/16 v2, 0x64

    .line 24
    .line 25
    cmp-long v0, v0, v2

    .line 26
    .line 27
    if-gez v0, :cond_1

    .line 28
    .line 29
    const/4 v0, 0x2

    .line 30
    goto :goto_0

    .line 31
    :cond_1
    const/4 v0, 0x0

    .line 32
    :goto_0
    sget-object v1, Ljava/math/RoundingMode;->HALF_UP:Ljava/math/RoundingMode;

    .line 33
    .line 34
    invoke-virtual {p0, v0, v1}, Ljava/math/BigDecimal;->setScale(ILjava/math/RoundingMode;)Ljava/math/BigDecimal;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-virtual {p0}, Ljava/math/BigDecimal;->stripTrailingZeros()Ljava/math/BigDecimal;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method
