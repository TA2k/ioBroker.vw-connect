.class public final Lh40/u3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/x3;


# direct methods
.method public synthetic constructor <init>(Lh40/x3;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh40/u3;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/u3;->e:Lh40/x3;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    iget-object v3, v0, Lh40/u3;->e:Lh40/x3;

    .line 8
    .line 9
    iget-object v4, v3, Lh40/x3;->u:Lij0/a;

    .line 10
    .line 11
    instance-of v5, v2, Lh40/t3;

    .line 12
    .line 13
    if-eqz v5, :cond_0

    .line 14
    .line 15
    move-object v5, v2

    .line 16
    check-cast v5, Lh40/t3;

    .line 17
    .line 18
    iget v6, v5, Lh40/t3;->f:I

    .line 19
    .line 20
    const/high16 v7, -0x80000000

    .line 21
    .line 22
    and-int v8, v6, v7

    .line 23
    .line 24
    if-eqz v8, :cond_0

    .line 25
    .line 26
    sub-int/2addr v6, v7

    .line 27
    iput v6, v5, Lh40/t3;->f:I

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    new-instance v5, Lh40/t3;

    .line 31
    .line 32
    invoke-direct {v5, v0, v2}, Lh40/t3;-><init>(Lh40/u3;Lkotlin/coroutines/Continuation;)V

    .line 33
    .line 34
    .line 35
    :goto_0
    iget-object v0, v5, Lh40/t3;->d:Ljava/lang/Object;

    .line 36
    .line 37
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    iget v6, v5, Lh40/t3;->f:I

    .line 40
    .line 41
    const/4 v7, 0x0

    .line 42
    const/4 v8, 0x1

    .line 43
    if-eqz v6, :cond_2

    .line 44
    .line 45
    if-ne v6, v8, :cond_1

    .line 46
    .line 47
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    goto/16 :goto_1

    .line 51
    .line 52
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw v0

    .line 60
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    instance-of v0, v1, Lne0/e;

    .line 64
    .line 65
    if-eqz v0, :cond_3

    .line 66
    .line 67
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    move-object v4, v0

    .line 72
    check-cast v4, Lh40/s3;

    .line 73
    .line 74
    const/16 v28, 0x0

    .line 75
    .line 76
    const v29, 0x1ffffdf

    .line 77
    .line 78
    .line 79
    const/4 v5, 0x0

    .line 80
    const/4 v6, 0x0

    .line 81
    const/4 v7, 0x0

    .line 82
    const/4 v8, 0x0

    .line 83
    const/4 v9, 0x0

    .line 84
    const/4 v10, 0x0

    .line 85
    const/4 v11, 0x0

    .line 86
    const/4 v12, 0x0

    .line 87
    const/4 v13, 0x0

    .line 88
    const/4 v14, 0x0

    .line 89
    const/4 v15, 0x0

    .line 90
    const/16 v16, 0x0

    .line 91
    .line 92
    const/16 v17, 0x0

    .line 93
    .line 94
    const/16 v18, 0x0

    .line 95
    .line 96
    const/16 v19, 0x0

    .line 97
    .line 98
    const/16 v20, 0x0

    .line 99
    .line 100
    const/16 v21, 0x0

    .line 101
    .line 102
    const/16 v22, 0x0

    .line 103
    .line 104
    const/16 v23, 0x0

    .line 105
    .line 106
    const/16 v24, 0x0

    .line 107
    .line 108
    const/16 v25, 0x0

    .line 109
    .line 110
    const/16 v26, 0x0

    .line 111
    .line 112
    const/16 v27, 0x0

    .line 113
    .line 114
    invoke-static/range {v4 .. v29}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 119
    .line 120
    .line 121
    goto/16 :goto_2

    .line 122
    .line 123
    :cond_3
    instance-of v0, v1, Lne0/c;

    .line 124
    .line 125
    if-eqz v0, :cond_5

    .line 126
    .line 127
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    move-object v9, v0

    .line 132
    check-cast v9, Lh40/s3;

    .line 133
    .line 134
    const/16 v33, 0x0

    .line 135
    .line 136
    const v34, 0x1ffffdf

    .line 137
    .line 138
    .line 139
    const/4 v10, 0x0

    .line 140
    const/4 v11, 0x0

    .line 141
    const/4 v12, 0x0

    .line 142
    const/4 v13, 0x0

    .line 143
    const/4 v14, 0x0

    .line 144
    const/4 v15, 0x0

    .line 145
    const/16 v16, 0x0

    .line 146
    .line 147
    const/16 v17, 0x0

    .line 148
    .line 149
    const/16 v18, 0x0

    .line 150
    .line 151
    const/16 v19, 0x0

    .line 152
    .line 153
    const/16 v20, 0x0

    .line 154
    .line 155
    const/16 v21, 0x0

    .line 156
    .line 157
    const/16 v22, 0x0

    .line 158
    .line 159
    const/16 v23, 0x0

    .line 160
    .line 161
    const/16 v24, 0x0

    .line 162
    .line 163
    const/16 v25, 0x0

    .line 164
    .line 165
    const/16 v26, 0x0

    .line 166
    .line 167
    const/16 v27, 0x0

    .line 168
    .line 169
    const/16 v28, 0x0

    .line 170
    .line 171
    const/16 v29, 0x0

    .line 172
    .line 173
    const/16 v30, 0x0

    .line 174
    .line 175
    const/16 v31, 0x0

    .line 176
    .line 177
    const/16 v32, 0x0

    .line 178
    .line 179
    invoke-static/range {v9 .. v34}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 184
    .line 185
    .line 186
    iget-object v0, v3, Lh40/x3;->t:Lrq0/f;

    .line 187
    .line 188
    new-instance v1, Lsq0/c;

    .line 189
    .line 190
    const/4 v6, 0x0

    .line 191
    new-array v9, v6, [Ljava/lang/Object;

    .line 192
    .line 193
    move-object v10, v4

    .line 194
    check-cast v10, Ljj0/f;

    .line 195
    .line 196
    const v11, 0x7f120c90

    .line 197
    .line 198
    .line 199
    invoke-virtual {v10, v11, v9}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v9

    .line 203
    new-array v10, v6, [Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v4, Ljj0/f;

    .line 206
    .line 207
    const v11, 0x7f12038b

    .line 208
    .line 209
    .line 210
    invoke-virtual {v4, v11, v10}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v4

    .line 214
    const/4 v10, 0x4

    .line 215
    invoke-direct {v1, v10, v9, v4, v7}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    iput v8, v5, Lh40/t3;->f:I

    .line 219
    .line 220
    invoke-virtual {v0, v1, v6, v5}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    if-ne v0, v2, :cond_4

    .line 225
    .line 226
    return-object v2

    .line 227
    :cond_4
    :goto_1
    check-cast v0, Lsq0/d;

    .line 228
    .line 229
    sget-object v1, Lsq0/d;->d:Lsq0/d;

    .line 230
    .line 231
    if-ne v0, v1, :cond_6

    .line 232
    .line 233
    invoke-static {v3}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    new-instance v1, Lh40/q3;

    .line 238
    .line 239
    const/4 v2, 0x2

    .line 240
    invoke-direct {v1, v3, v7, v2}, Lh40/q3;-><init>(Lh40/x3;Lkotlin/coroutines/Continuation;I)V

    .line 241
    .line 242
    .line 243
    const/4 v2, 0x3

    .line 244
    invoke-static {v0, v7, v7, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 245
    .line 246
    .line 247
    goto :goto_2

    .line 248
    :cond_5
    instance-of v0, v1, Lne0/d;

    .line 249
    .line 250
    if-eqz v0, :cond_7

    .line 251
    .line 252
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    move-object v4, v0

    .line 257
    check-cast v4, Lh40/s3;

    .line 258
    .line 259
    const/16 v28, 0x0

    .line 260
    .line 261
    const v29, 0x1ffffdf

    .line 262
    .line 263
    .line 264
    const/4 v5, 0x0

    .line 265
    const/4 v6, 0x0

    .line 266
    const/4 v7, 0x0

    .line 267
    const/4 v8, 0x0

    .line 268
    const/4 v9, 0x0

    .line 269
    const/4 v10, 0x1

    .line 270
    const/4 v11, 0x0

    .line 271
    const/4 v12, 0x0

    .line 272
    const/4 v13, 0x0

    .line 273
    const/4 v14, 0x0

    .line 274
    const/4 v15, 0x0

    .line 275
    const/16 v16, 0x0

    .line 276
    .line 277
    const/16 v17, 0x0

    .line 278
    .line 279
    const/16 v18, 0x0

    .line 280
    .line 281
    const/16 v19, 0x0

    .line 282
    .line 283
    const/16 v20, 0x0

    .line 284
    .line 285
    const/16 v21, 0x0

    .line 286
    .line 287
    const/16 v22, 0x0

    .line 288
    .line 289
    const/16 v23, 0x0

    .line 290
    .line 291
    const/16 v24, 0x0

    .line 292
    .line 293
    const/16 v25, 0x0

    .line 294
    .line 295
    const/16 v26, 0x0

    .line 296
    .line 297
    const/16 v27, 0x0

    .line 298
    .line 299
    invoke-static/range {v4 .. v29}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 300
    .line 301
    .line 302
    move-result-object v0

    .line 303
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 304
    .line 305
    .line 306
    :cond_6
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 307
    .line 308
    return-object v0

    .line 309
    :cond_7
    new-instance v0, La8/r0;

    .line 310
    .line 311
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 312
    .line 313
    .line 314
    throw v0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh40/u3;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lne0/s;

    .line 11
    .line 12
    instance-of v2, v1, Lne0/d;

    .line 13
    .line 14
    iget-object v0, v0, Lh40/u3;->e:Lh40/x3;

    .line 15
    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    move-object v2, v1

    .line 23
    check-cast v2, Lh40/s3;

    .line 24
    .line 25
    const/16 v26, 0x0

    .line 26
    .line 27
    const v27, 0x1fdffff

    .line 28
    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    const/4 v4, 0x0

    .line 32
    const/4 v5, 0x0

    .line 33
    const/4 v6, 0x0

    .line 34
    const/4 v7, 0x0

    .line 35
    const/4 v8, 0x0

    .line 36
    const/4 v9, 0x0

    .line 37
    const/4 v10, 0x0

    .line 38
    const/4 v11, 0x0

    .line 39
    const/4 v12, 0x0

    .line 40
    const/4 v13, 0x0

    .line 41
    const/4 v14, 0x0

    .line 42
    const/4 v15, 0x0

    .line 43
    const/16 v16, 0x0

    .line 44
    .line 45
    const/16 v17, 0x0

    .line 46
    .line 47
    const/16 v18, 0x0

    .line 48
    .line 49
    const/16 v19, 0x0

    .line 50
    .line 51
    const/16 v20, 0x1

    .line 52
    .line 53
    const/16 v21, 0x0

    .line 54
    .line 55
    const/16 v22, 0x0

    .line 56
    .line 57
    const/16 v23, 0x0

    .line 58
    .line 59
    const/16 v24, 0x0

    .line 60
    .line 61
    const/16 v25, 0x0

    .line 62
    .line 63
    invoke-static/range {v2 .. v27}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 68
    .line 69
    .line 70
    goto/16 :goto_0

    .line 71
    .line 72
    :cond_0
    instance-of v2, v1, Lne0/e;

    .line 73
    .line 74
    if-eqz v2, :cond_2

    .line 75
    .line 76
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    move-object v3, v2

    .line 81
    check-cast v3, Lh40/s3;

    .line 82
    .line 83
    const/16 v27, 0x0

    .line 84
    .line 85
    const v28, 0x1fdffff

    .line 86
    .line 87
    .line 88
    const/4 v4, 0x0

    .line 89
    const/4 v5, 0x0

    .line 90
    const/4 v6, 0x0

    .line 91
    const/4 v7, 0x0

    .line 92
    const/4 v8, 0x0

    .line 93
    const/4 v9, 0x0

    .line 94
    const/4 v10, 0x0

    .line 95
    const/4 v11, 0x0

    .line 96
    const/4 v12, 0x0

    .line 97
    const/4 v13, 0x0

    .line 98
    const/4 v14, 0x0

    .line 99
    const/4 v15, 0x0

    .line 100
    const/16 v16, 0x0

    .line 101
    .line 102
    const/16 v17, 0x0

    .line 103
    .line 104
    const/16 v18, 0x0

    .line 105
    .line 106
    const/16 v19, 0x0

    .line 107
    .line 108
    const/16 v20, 0x0

    .line 109
    .line 110
    const/16 v21, 0x0

    .line 111
    .line 112
    const/16 v22, 0x0

    .line 113
    .line 114
    const/16 v23, 0x0

    .line 115
    .line 116
    const/16 v24, 0x0

    .line 117
    .line 118
    const/16 v25, 0x0

    .line 119
    .line 120
    const/16 v26, 0x0

    .line 121
    .line 122
    invoke-static/range {v3 .. v28}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 127
    .line 128
    .line 129
    check-cast v1, Lne0/e;

    .line 130
    .line 131
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v1, Lcq0/n;

    .line 134
    .line 135
    if-eqz v1, :cond_1

    .line 136
    .line 137
    iget-object v0, v0, Lh40/x3;->G:Lf40/z2;

    .line 138
    .line 139
    invoke-virtual {v0, v1}, Lf40/z2;->a(Lcq0/n;)V

    .line 140
    .line 141
    .line 142
    goto :goto_0

    .line 143
    :cond_1
    iget-object v0, v0, Lh40/x3;->y:Lf40/y2;

    .line 144
    .line 145
    iget-object v0, v0, Lf40/y2;->a:Lf40/f1;

    .line 146
    .line 147
    check-cast v0, Liy/b;

    .line 148
    .line 149
    sget-object v1, Lly/b;->e3:Lly/b;

    .line 150
    .line 151
    invoke-interface {v0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 152
    .line 153
    .line 154
    goto :goto_0

    .line 155
    :cond_2
    instance-of v2, v1, Lne0/c;

    .line 156
    .line 157
    if-eqz v2, :cond_3

    .line 158
    .line 159
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 160
    .line 161
    .line 162
    move-result-object v2

    .line 163
    move-object v3, v2

    .line 164
    check-cast v3, Lh40/s3;

    .line 165
    .line 166
    const/16 v27, 0x0

    .line 167
    .line 168
    const v28, 0x1fdffff

    .line 169
    .line 170
    .line 171
    const/4 v4, 0x0

    .line 172
    const/4 v5, 0x0

    .line 173
    const/4 v6, 0x0

    .line 174
    const/4 v7, 0x0

    .line 175
    const/4 v8, 0x0

    .line 176
    const/4 v9, 0x0

    .line 177
    const/4 v10, 0x0

    .line 178
    const/4 v11, 0x0

    .line 179
    const/4 v12, 0x0

    .line 180
    const/4 v13, 0x0

    .line 181
    const/4 v14, 0x0

    .line 182
    const/4 v15, 0x0

    .line 183
    const/16 v16, 0x0

    .line 184
    .line 185
    const/16 v17, 0x0

    .line 186
    .line 187
    const/16 v18, 0x0

    .line 188
    .line 189
    const/16 v19, 0x0

    .line 190
    .line 191
    const/16 v20, 0x0

    .line 192
    .line 193
    const/16 v21, 0x0

    .line 194
    .line 195
    const/16 v22, 0x0

    .line 196
    .line 197
    const/16 v23, 0x0

    .line 198
    .line 199
    const/16 v24, 0x0

    .line 200
    .line 201
    const/16 v25, 0x0

    .line 202
    .line 203
    const/16 v26, 0x0

    .line 204
    .line 205
    invoke-static/range {v3 .. v28}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 206
    .line 207
    .line 208
    move-result-object v2

    .line 209
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 210
    .line 211
    .line 212
    check-cast v1, Lne0/c;

    .line 213
    .line 214
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 215
    .line 216
    .line 217
    move-result-object v2

    .line 218
    new-instance v3, Lh40/w3;

    .line 219
    .line 220
    const/4 v4, 0x1

    .line 221
    const/4 v5, 0x0

    .line 222
    invoke-direct {v3, v4, v0, v1, v5}, Lh40/w3;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 223
    .line 224
    .line 225
    const/4 v0, 0x3

    .line 226
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 227
    .line 228
    .line 229
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 230
    .line 231
    return-object v0

    .line 232
    :cond_3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 233
    .line 234
    .line 235
    new-instance v0, La8/r0;

    .line 236
    .line 237
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 238
    .line 239
    .line 240
    throw v0

    .line 241
    :pswitch_0
    move-object/from16 v1, p1

    .line 242
    .line 243
    check-cast v1, Lne0/s;

    .line 244
    .line 245
    instance-of v2, v1, Lne0/d;

    .line 246
    .line 247
    iget-object v0, v0, Lh40/u3;->e:Lh40/x3;

    .line 248
    .line 249
    if-eqz v2, :cond_4

    .line 250
    .line 251
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 252
    .line 253
    .line 254
    move-result-object v1

    .line 255
    move-object v2, v1

    .line 256
    check-cast v2, Lh40/s3;

    .line 257
    .line 258
    const/16 v26, 0x0

    .line 259
    .line 260
    const v27, 0x1fffffd

    .line 261
    .line 262
    .line 263
    const/4 v3, 0x0

    .line 264
    const/4 v4, 0x1

    .line 265
    const/4 v5, 0x0

    .line 266
    const/4 v6, 0x0

    .line 267
    const/4 v7, 0x0

    .line 268
    const/4 v8, 0x0

    .line 269
    const/4 v9, 0x0

    .line 270
    const/4 v10, 0x0

    .line 271
    const/4 v11, 0x0

    .line 272
    const/4 v12, 0x0

    .line 273
    const/4 v13, 0x0

    .line 274
    const/4 v14, 0x0

    .line 275
    const/4 v15, 0x0

    .line 276
    const/16 v16, 0x0

    .line 277
    .line 278
    const/16 v17, 0x0

    .line 279
    .line 280
    const/16 v18, 0x0

    .line 281
    .line 282
    const/16 v19, 0x0

    .line 283
    .line 284
    const/16 v20, 0x0

    .line 285
    .line 286
    const/16 v21, 0x0

    .line 287
    .line 288
    const/16 v22, 0x0

    .line 289
    .line 290
    const/16 v23, 0x0

    .line 291
    .line 292
    const/16 v24, 0x0

    .line 293
    .line 294
    const/16 v25, 0x0

    .line 295
    .line 296
    invoke-static/range {v2 .. v27}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 297
    .line 298
    .line 299
    move-result-object v1

    .line 300
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 301
    .line 302
    .line 303
    goto/16 :goto_1

    .line 304
    .line 305
    :cond_4
    instance-of v2, v1, Lne0/e;

    .line 306
    .line 307
    if-eqz v2, :cond_5

    .line 308
    .line 309
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 310
    .line 311
    .line 312
    move-result-object v2

    .line 313
    move-object v3, v2

    .line 314
    check-cast v3, Lh40/s3;

    .line 315
    .line 316
    sget-object v27, Lh40/r3;->d:Lh40/r3;

    .line 317
    .line 318
    check-cast v1, Lne0/e;

    .line 319
    .line 320
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 321
    .line 322
    check-cast v1, Lfe0/a;

    .line 323
    .line 324
    const-string v2, "<this>"

    .line 325
    .line 326
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    new-instance v2, Lh40/g0;

    .line 330
    .line 331
    iget-object v4, v1, Lfe0/a;->b:Ljava/lang/String;

    .line 332
    .line 333
    iget-object v1, v1, Lfe0/a;->c:Ljava/lang/String;

    .line 334
    .line 335
    invoke-direct {v2, v4, v1}, Lh40/g0;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 336
    .line 337
    .line 338
    const/16 v26, 0x0

    .line 339
    .line 340
    const v28, 0xbfdffd

    .line 341
    .line 342
    .line 343
    const/4 v4, 0x0

    .line 344
    const/4 v5, 0x0

    .line 345
    const/4 v6, 0x0

    .line 346
    const/4 v7, 0x0

    .line 347
    const/4 v8, 0x0

    .line 348
    const/4 v9, 0x0

    .line 349
    const/4 v10, 0x0

    .line 350
    const/4 v11, 0x0

    .line 351
    const/4 v12, 0x0

    .line 352
    const/4 v13, 0x0

    .line 353
    const/4 v14, 0x0

    .line 354
    const/4 v15, 0x0

    .line 355
    const/16 v16, 0x0

    .line 356
    .line 357
    const/16 v18, 0x0

    .line 358
    .line 359
    const/16 v19, 0x0

    .line 360
    .line 361
    const/16 v20, 0x0

    .line 362
    .line 363
    const/16 v21, 0x0

    .line 364
    .line 365
    const/16 v22, 0x0

    .line 366
    .line 367
    const/16 v23, 0x0

    .line 368
    .line 369
    const/16 v24, 0x0

    .line 370
    .line 371
    const/16 v25, 0x1

    .line 372
    .line 373
    move-object/from16 v17, v2

    .line 374
    .line 375
    invoke-static/range {v3 .. v28}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 376
    .line 377
    .line 378
    move-result-object v1

    .line 379
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 380
    .line 381
    .line 382
    goto :goto_1

    .line 383
    :cond_5
    instance-of v2, v1, Lne0/c;

    .line 384
    .line 385
    if-eqz v2, :cond_6

    .line 386
    .line 387
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 388
    .line 389
    .line 390
    move-result-object v2

    .line 391
    move-object v3, v2

    .line 392
    check-cast v3, Lh40/s3;

    .line 393
    .line 394
    check-cast v1, Lne0/c;

    .line 395
    .line 396
    iget-object v2, v0, Lh40/x3;->u:Lij0/a;

    .line 397
    .line 398
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 399
    .line 400
    .line 401
    move-result-object v18

    .line 402
    const/16 v27, 0x0

    .line 403
    .line 404
    const v28, 0x1ffbffd

    .line 405
    .line 406
    .line 407
    const/4 v4, 0x0

    .line 408
    const/4 v5, 0x0

    .line 409
    const/4 v6, 0x0

    .line 410
    const/4 v7, 0x0

    .line 411
    const/4 v8, 0x0

    .line 412
    const/4 v9, 0x0

    .line 413
    const/4 v10, 0x0

    .line 414
    const/4 v11, 0x0

    .line 415
    const/4 v12, 0x0

    .line 416
    const/4 v13, 0x0

    .line 417
    const/4 v14, 0x0

    .line 418
    const/4 v15, 0x0

    .line 419
    const/16 v16, 0x0

    .line 420
    .line 421
    const/16 v17, 0x0

    .line 422
    .line 423
    const/16 v19, 0x0

    .line 424
    .line 425
    const/16 v20, 0x0

    .line 426
    .line 427
    const/16 v21, 0x0

    .line 428
    .line 429
    const/16 v22, 0x0

    .line 430
    .line 431
    const/16 v23, 0x0

    .line 432
    .line 433
    const/16 v24, 0x0

    .line 434
    .line 435
    const/16 v25, 0x0

    .line 436
    .line 437
    const/16 v26, 0x0

    .line 438
    .line 439
    invoke-static/range {v3 .. v28}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 440
    .line 441
    .line 442
    move-result-object v1

    .line 443
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 444
    .line 445
    .line 446
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 447
    .line 448
    return-object v0

    .line 449
    :cond_6
    new-instance v0, La8/r0;

    .line 450
    .line 451
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 452
    .line 453
    .line 454
    throw v0

    .line 455
    :pswitch_1
    move-object/from16 v1, p1

    .line 456
    .line 457
    check-cast v1, Lne0/s;

    .line 458
    .line 459
    instance-of v2, v1, Lne0/e;

    .line 460
    .line 461
    iget-object v0, v0, Lh40/u3;->e:Lh40/x3;

    .line 462
    .line 463
    if-eqz v2, :cond_7

    .line 464
    .line 465
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 466
    .line 467
    .line 468
    move-result-object v1

    .line 469
    move-object v2, v1

    .line 470
    check-cast v2, Lh40/s3;

    .line 471
    .line 472
    const/16 v26, 0x0

    .line 473
    .line 474
    const v27, 0x1fff7ff

    .line 475
    .line 476
    .line 477
    const/4 v3, 0x0

    .line 478
    const/4 v4, 0x0

    .line 479
    const/4 v5, 0x0

    .line 480
    const/4 v6, 0x0

    .line 481
    const/4 v7, 0x0

    .line 482
    const/4 v8, 0x0

    .line 483
    const/4 v9, 0x0

    .line 484
    const/4 v10, 0x0

    .line 485
    const/4 v11, 0x0

    .line 486
    const/4 v12, 0x0

    .line 487
    const/4 v13, 0x0

    .line 488
    const/4 v14, 0x0

    .line 489
    const/4 v15, 0x0

    .line 490
    const/16 v16, 0x0

    .line 491
    .line 492
    const/16 v17, 0x0

    .line 493
    .line 494
    const/16 v18, 0x0

    .line 495
    .line 496
    const/16 v19, 0x0

    .line 497
    .line 498
    const/16 v20, 0x0

    .line 499
    .line 500
    const/16 v21, 0x0

    .line 501
    .line 502
    const/16 v22, 0x0

    .line 503
    .line 504
    const/16 v23, 0x0

    .line 505
    .line 506
    const/16 v24, 0x0

    .line 507
    .line 508
    const/16 v25, 0x0

    .line 509
    .line 510
    invoke-static/range {v2 .. v27}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 511
    .line 512
    .line 513
    move-result-object v1

    .line 514
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 515
    .line 516
    .line 517
    iget-object v0, v0, Lh40/x3;->j:Lf40/a3;

    .line 518
    .line 519
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 520
    .line 521
    .line 522
    goto/16 :goto_2

    .line 523
    .line 524
    :cond_7
    instance-of v2, v1, Lne0/c;

    .line 525
    .line 526
    if-eqz v2, :cond_8

    .line 527
    .line 528
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 529
    .line 530
    .line 531
    move-result-object v2

    .line 532
    move-object v3, v2

    .line 533
    check-cast v3, Lh40/s3;

    .line 534
    .line 535
    const/16 v27, 0x0

    .line 536
    .line 537
    const v28, 0x1fff7ff

    .line 538
    .line 539
    .line 540
    const/4 v4, 0x0

    .line 541
    const/4 v5, 0x0

    .line 542
    const/4 v6, 0x0

    .line 543
    const/4 v7, 0x0

    .line 544
    const/4 v8, 0x0

    .line 545
    const/4 v9, 0x0

    .line 546
    const/4 v10, 0x0

    .line 547
    const/4 v11, 0x0

    .line 548
    const/4 v12, 0x0

    .line 549
    const/4 v13, 0x0

    .line 550
    const/4 v14, 0x0

    .line 551
    const/4 v15, 0x0

    .line 552
    const/16 v16, 0x0

    .line 553
    .line 554
    const/16 v17, 0x0

    .line 555
    .line 556
    const/16 v18, 0x0

    .line 557
    .line 558
    const/16 v19, 0x0

    .line 559
    .line 560
    const/16 v20, 0x0

    .line 561
    .line 562
    const/16 v21, 0x0

    .line 563
    .line 564
    const/16 v22, 0x0

    .line 565
    .line 566
    const/16 v23, 0x0

    .line 567
    .line 568
    const/16 v24, 0x0

    .line 569
    .line 570
    const/16 v25, 0x0

    .line 571
    .line 572
    const/16 v26, 0x0

    .line 573
    .line 574
    invoke-static/range {v3 .. v28}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 575
    .line 576
    .line 577
    move-result-object v2

    .line 578
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 579
    .line 580
    .line 581
    iget-object v0, v0, Lh40/x3;->p:Lf40/a4;

    .line 582
    .line 583
    check-cast v1, Lne0/c;

    .line 584
    .line 585
    invoke-virtual {v0, v1}, Lf40/a4;->a(Lne0/c;)V

    .line 586
    .line 587
    .line 588
    goto :goto_2

    .line 589
    :cond_8
    instance-of v1, v1, Lne0/d;

    .line 590
    .line 591
    if-eqz v1, :cond_9

    .line 592
    .line 593
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 594
    .line 595
    .line 596
    move-result-object v1

    .line 597
    move-object v2, v1

    .line 598
    check-cast v2, Lh40/s3;

    .line 599
    .line 600
    const/16 v26, 0x0

    .line 601
    .line 602
    const v27, 0x1fff7ff

    .line 603
    .line 604
    .line 605
    const/4 v3, 0x0

    .line 606
    const/4 v4, 0x0

    .line 607
    const/4 v5, 0x0

    .line 608
    const/4 v6, 0x0

    .line 609
    const/4 v7, 0x0

    .line 610
    const/4 v8, 0x0

    .line 611
    const/4 v9, 0x0

    .line 612
    const/4 v10, 0x0

    .line 613
    const/4 v11, 0x0

    .line 614
    const/4 v12, 0x0

    .line 615
    const/4 v13, 0x0

    .line 616
    const/4 v14, 0x1

    .line 617
    const/4 v15, 0x0

    .line 618
    const/16 v16, 0x0

    .line 619
    .line 620
    const/16 v17, 0x0

    .line 621
    .line 622
    const/16 v18, 0x0

    .line 623
    .line 624
    const/16 v19, 0x0

    .line 625
    .line 626
    const/16 v20, 0x0

    .line 627
    .line 628
    const/16 v21, 0x0

    .line 629
    .line 630
    const/16 v22, 0x0

    .line 631
    .line 632
    const/16 v23, 0x0

    .line 633
    .line 634
    const/16 v24, 0x0

    .line 635
    .line 636
    const/16 v25, 0x0

    .line 637
    .line 638
    invoke-static/range {v2 .. v27}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 639
    .line 640
    .line 641
    move-result-object v1

    .line 642
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 643
    .line 644
    .line 645
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 646
    .line 647
    return-object v0

    .line 648
    :cond_9
    new-instance v0, La8/r0;

    .line 649
    .line 650
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 651
    .line 652
    .line 653
    throw v0

    .line 654
    :pswitch_2
    move-object/from16 v1, p1

    .line 655
    .line 656
    check-cast v1, Lne0/s;

    .line 657
    .line 658
    move-object/from16 v2, p2

    .line 659
    .line 660
    invoke-virtual {v0, v1, v2}, Lh40/u3;->b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 661
    .line 662
    .line 663
    move-result-object v0

    .line 664
    return-object v0

    .line 665
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
