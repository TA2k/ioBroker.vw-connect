.class public final Lbz/n;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lzy/j;

.field public final i:Lzy/p;

.field public final j:Lcs0/l;

.field public final k:Lzy/q;

.field public final l:Lzy/z;

.field public final m:Lzy/t;

.field public final n:Lzy/a0;

.field public final o:Lzy/y;

.field public final p:Ltr0/b;

.field public final q:Lij0/a;

.field public r:Ljava/util/List;


# direct methods
.method public constructor <init>(Lzy/j;Lzy/p;Lcs0/l;Lzy/q;Lzy/z;Lzy/t;Lzy/a0;Lzy/y;Ltr0/b;Lij0/a;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lbz/j;

    .line 4
    .line 5
    const/16 v2, 0x7f

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    and-int/2addr v2, v3

    .line 9
    if-eqz v2, :cond_0

    .line 10
    .line 11
    move v2, v3

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v2, 0x0

    .line 14
    :goto_0
    const v4, 0x7f12002e

    .line 15
    .line 16
    .line 17
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    const v4, 0x7f12002f

    .line 22
    .line 23
    .line 24
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 25
    .line 26
    .line 27
    move-result-object v6

    .line 28
    const v4, 0x7f120032

    .line 29
    .line 30
    .line 31
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object v7

    .line 35
    const v4, 0x7f120033

    .line 36
    .line 37
    .line 38
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 39
    .line 40
    .line 41
    move-result-object v8

    .line 42
    const v4, 0x7f120034

    .line 43
    .line 44
    .line 45
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 46
    .line 47
    .line 48
    move-result-object v9

    .line 49
    const v4, 0x7f120035

    .line 50
    .line 51
    .line 52
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 53
    .line 54
    .line 55
    move-result-object v10

    .line 56
    const v4, 0x7f120036

    .line 57
    .line 58
    .line 59
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 60
    .line 61
    .line 62
    move-result-object v11

    .line 63
    const v4, 0x7f120037

    .line 64
    .line 65
    .line 66
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 67
    .line 68
    .line 69
    move-result-object v12

    .line 70
    const v4, 0x7f120038

    .line 71
    .line 72
    .line 73
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 74
    .line 75
    .line 76
    move-result-object v13

    .line 77
    const v4, 0x7f120039

    .line 78
    .line 79
    .line 80
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 81
    .line 82
    .line 83
    move-result-object v14

    .line 84
    const v4, 0x7f120030

    .line 85
    .line 86
    .line 87
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 88
    .line 89
    .line 90
    move-result-object v15

    .line 91
    const v4, 0x7f120031

    .line 92
    .line 93
    .line 94
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 95
    .line 96
    .line 97
    move-result-object v16

    .line 98
    filled-new-array/range {v5 .. v16}, [Ljava/lang/Integer;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    invoke-static {v4}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 103
    .line 104
    .line 105
    move-result-object v4

    .line 106
    const/16 v5, 0x7f

    .line 107
    .line 108
    and-int/lit8 v5, v5, 0x8

    .line 109
    .line 110
    if-eqz v5, :cond_1

    .line 111
    .line 112
    const/4 v3, 0x0

    .line 113
    :cond_1
    move v5, v3

    .line 114
    const/4 v9, 0x0

    .line 115
    const/4 v6, 0x0

    .line 116
    move-object v3, v4

    .line 117
    const/4 v4, 0x0

    .line 118
    const/4 v7, 0x0

    .line 119
    const/4 v8, 0x0

    .line 120
    invoke-direct/range {v1 .. v8}, Lbz/j;-><init>(ZLjava/util/List;Lql0/g;ZLbz/h;Lbz/i;Lqp0/o;)V

    .line 121
    .line 122
    .line 123
    invoke-direct {v0, v1}, Lql0/j;-><init>(Lql0/h;)V

    .line 124
    .line 125
    .line 126
    move-object/from16 v1, p1

    .line 127
    .line 128
    iput-object v1, v0, Lbz/n;->h:Lzy/j;

    .line 129
    .line 130
    move-object/from16 v1, p2

    .line 131
    .line 132
    iput-object v1, v0, Lbz/n;->i:Lzy/p;

    .line 133
    .line 134
    move-object/from16 v1, p3

    .line 135
    .line 136
    iput-object v1, v0, Lbz/n;->j:Lcs0/l;

    .line 137
    .line 138
    move-object/from16 v1, p4

    .line 139
    .line 140
    iput-object v1, v0, Lbz/n;->k:Lzy/q;

    .line 141
    .line 142
    move-object/from16 v1, p5

    .line 143
    .line 144
    iput-object v1, v0, Lbz/n;->l:Lzy/z;

    .line 145
    .line 146
    move-object/from16 v1, p6

    .line 147
    .line 148
    iput-object v1, v0, Lbz/n;->m:Lzy/t;

    .line 149
    .line 150
    move-object/from16 v1, p7

    .line 151
    .line 152
    iput-object v1, v0, Lbz/n;->n:Lzy/a0;

    .line 153
    .line 154
    move-object/from16 v1, p8

    .line 155
    .line 156
    iput-object v1, v0, Lbz/n;->o:Lzy/y;

    .line 157
    .line 158
    move-object/from16 v1, p9

    .line 159
    .line 160
    iput-object v1, v0, Lbz/n;->p:Ltr0/b;

    .line 161
    .line 162
    move-object/from16 v1, p10

    .line 163
    .line 164
    iput-object v1, v0, Lbz/n;->q:Lij0/a;

    .line 165
    .line 166
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    new-instance v2, La50/c;

    .line 171
    .line 172
    const/16 v3, 0xf

    .line 173
    .line 174
    invoke-direct {v2, v0, v9, v3}, La50/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 175
    .line 176
    .line 177
    const/4 v0, 0x3

    .line 178
    invoke-static {v1, v9, v9, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 179
    .line 180
    .line 181
    return-void
.end method

.method public static final h(Lbz/n;Lqp0/o;Lrx0/c;)Ljava/lang/Object;
    .locals 18

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
    iget-object v3, v0, Lbz/n;->q:Lij0/a;

    .line 8
    .line 9
    instance-of v4, v2, Lbz/m;

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    move-object v4, v2

    .line 14
    check-cast v4, Lbz/m;

    .line 15
    .line 16
    iget v5, v4, Lbz/m;->h:I

    .line 17
    .line 18
    const/high16 v6, -0x80000000

    .line 19
    .line 20
    and-int v7, v5, v6

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    sub-int/2addr v5, v6

    .line 25
    iput v5, v4, Lbz/m;->h:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v4, Lbz/m;

    .line 29
    .line 30
    invoke-direct {v4, v0, v2}, Lbz/m;-><init>(Lbz/n;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v2, v4, Lbz/m;->f:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v6, v4, Lbz/m;->h:I

    .line 38
    .line 39
    const/4 v7, 0x1

    .line 40
    if-eqz v6, :cond_2

    .line 41
    .line 42
    if-ne v6, v7, :cond_1

    .line 43
    .line 44
    iget-object v1, v4, Lbz/m;->e:Lqp0/o;

    .line 45
    .line 46
    iget-object v4, v4, Lbz/m;->d:Lqp0/o;

    .line 47
    .line 48
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    move-object v10, v4

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v0

    .line 61
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iget-object v2, v1, Lqp0/o;->a:Ljava/util/List;

    .line 65
    .line 66
    iput-object v2, v0, Lbz/n;->r:Ljava/util/List;

    .line 67
    .line 68
    iget-object v2, v0, Lbz/n;->j:Lcs0/l;

    .line 69
    .line 70
    iput-object v1, v4, Lbz/m;->d:Lqp0/o;

    .line 71
    .line 72
    iput-object v1, v4, Lbz/m;->e:Lqp0/o;

    .line 73
    .line 74
    iput v7, v4, Lbz/m;->h:I

    .line 75
    .line 76
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v2, v4}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    if-ne v2, v5, :cond_3

    .line 84
    .line 85
    return-object v5

    .line 86
    :cond_3
    move-object v10, v1

    .line 87
    :goto_1
    check-cast v2, Lqr0/s;

    .line 88
    .line 89
    invoke-static {v1, v2, v3}, Lkp/a6;->b(Lqp0/o;Lqr0/s;Lij0/a;)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    iget-object v2, v0, Lbz/n;->r:Ljava/util/List;

    .line 94
    .line 95
    const-string v4, "waypoints"

    .line 96
    .line 97
    const/4 v5, 0x0

    .line 98
    if-eqz v2, :cond_11

    .line 99
    .line 100
    invoke-static {v2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    check-cast v2, Lqp0/b0;

    .line 105
    .line 106
    if-eqz v2, :cond_4

    .line 107
    .line 108
    iget-object v2, v2, Lqp0/b0;->e:Lbl0/a;

    .line 109
    .line 110
    if-eqz v2, :cond_4

    .line 111
    .line 112
    iget-object v2, v2, Lbl0/a;->d:Ljava/lang/String;

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_4
    move-object v2, v5

    .line 116
    :goto_2
    iget-object v6, v0, Lbz/n;->r:Ljava/util/List;

    .line 117
    .line 118
    if-eqz v6, :cond_10

    .line 119
    .line 120
    invoke-static {v6}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v6

    .line 124
    check-cast v6, Lqp0/b0;

    .line 125
    .line 126
    if-eqz v6, :cond_5

    .line 127
    .line 128
    iget-object v6, v6, Lqp0/b0;->e:Lbl0/a;

    .line 129
    .line 130
    if-eqz v6, :cond_5

    .line 131
    .line 132
    iget-object v6, v6, Lbl0/a;->d:Ljava/lang/String;

    .line 133
    .line 134
    goto :goto_3

    .line 135
    :cond_5
    move-object v6, v5

    .line 136
    :goto_3
    iget-object v7, v0, Lbz/n;->r:Ljava/util/List;

    .line 137
    .line 138
    if-eqz v7, :cond_f

    .line 139
    .line 140
    check-cast v7, Ljava/lang/Iterable;

    .line 141
    .line 142
    new-instance v4, Ljava/util/ArrayList;

    .line 143
    .line 144
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 145
    .line 146
    .line 147
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 148
    .line 149
    .line 150
    move-result-object v7

    .line 151
    :cond_6
    :goto_4
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 152
    .line 153
    .line 154
    move-result v8

    .line 155
    if-eqz v8, :cond_e

    .line 156
    .line 157
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v8

    .line 161
    check-cast v8, Lqp0/b0;

    .line 162
    .line 163
    iget-object v9, v8, Lqp0/b0;->m:Lqp0/z;

    .line 164
    .line 165
    if-eqz v9, :cond_d

    .line 166
    .line 167
    iget-object v11, v9, Lqp0/z;->c:Ljava/net/URL;

    .line 168
    .line 169
    if-eqz v11, :cond_7

    .line 170
    .line 171
    invoke-static {v11}, Ljp/sf;->h(Ljava/net/URL;)Landroid/net/Uri;

    .line 172
    .line 173
    .line 174
    move-result-object v11

    .line 175
    move-object v13, v11

    .line 176
    goto :goto_5

    .line 177
    :cond_7
    move-object v13, v5

    .line 178
    :goto_5
    iget-object v11, v9, Lqp0/z;->b:Ljava/lang/Float;

    .line 179
    .line 180
    const/4 v12, 0x0

    .line 181
    const v14, 0x7f1201aa

    .line 182
    .line 183
    .line 184
    if-eqz v11, :cond_9

    .line 185
    .line 186
    invoke-virtual {v11}, Ljava/lang/Number;->floatValue()F

    .line 187
    .line 188
    .line 189
    move-result v15

    .line 190
    const/16 v16, 0x0

    .line 191
    .line 192
    cmpl-float v15, v15, v16

    .line 193
    .line 194
    if-lez v15, :cond_8

    .line 195
    .line 196
    goto :goto_6

    .line 197
    :cond_8
    move-object v11, v5

    .line 198
    :goto_6
    if-eqz v11, :cond_9

    .line 199
    .line 200
    invoke-virtual {v11}, Ljava/lang/Float;->floatValue()F

    .line 201
    .line 202
    .line 203
    move-result v11

    .line 204
    invoke-static {v11}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v11

    .line 208
    if-nez v11, :cond_a

    .line 209
    .line 210
    :cond_9
    new-array v11, v12, [Ljava/lang/Object;

    .line 211
    .line 212
    move-object v15, v3

    .line 213
    check-cast v15, Ljj0/f;

    .line 214
    .line 215
    invoke-virtual {v15, v14, v11}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v11

    .line 219
    :cond_a
    iget-object v15, v8, Lqp0/b0;->b:Ljava/lang/String;

    .line 220
    .line 221
    if-nez v15, :cond_b

    .line 222
    .line 223
    const-string v15, ""

    .line 224
    .line 225
    :cond_b
    iget-object v9, v9, Lqp0/z;->d:Ljava/lang/String;

    .line 226
    .line 227
    if-nez v9, :cond_c

    .line 228
    .line 229
    new-array v9, v12, [Ljava/lang/Object;

    .line 230
    .line 231
    move-object v12, v3

    .line 232
    check-cast v12, Ljj0/f;

    .line 233
    .line 234
    invoke-virtual {v12, v14, v9}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object v9

    .line 238
    :cond_c
    move-object/from16 v16, v9

    .line 239
    .line 240
    iget-object v8, v8, Lqp0/b0;->a:Ljava/lang/String;

    .line 241
    .line 242
    new-instance v12, Lbz/k;

    .line 243
    .line 244
    move-object/from16 v17, v8

    .line 245
    .line 246
    move-object v14, v11

    .line 247
    invoke-direct/range {v12 .. v17}, Lbz/k;-><init>(Landroid/net/Uri;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    goto :goto_7

    .line 251
    :cond_d
    move-object v12, v5

    .line 252
    :goto_7
    if-eqz v12, :cond_6

    .line 253
    .line 254
    invoke-virtual {v4, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 255
    .line 256
    .line 257
    goto :goto_4

    .line 258
    :cond_e
    new-instance v8, Lbz/h;

    .line 259
    .line 260
    invoke-direct {v8, v1, v4, v2, v6}, Lbz/h;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;)V

    .line 261
    .line 262
    .line 263
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 264
    .line 265
    .line 266
    move-result-object v1

    .line 267
    move-object v4, v1

    .line 268
    check-cast v4, Lbz/j;

    .line 269
    .line 270
    const/4 v9, 0x0

    .line 271
    const/16 v11, 0x22

    .line 272
    .line 273
    const/4 v5, 0x0

    .line 274
    const/4 v6, 0x0

    .line 275
    const/4 v7, 0x0

    .line 276
    invoke-static/range {v4 .. v11}, Lbz/j;->a(Lbz/j;ZLql0/g;ZLbz/h;Lbz/i;Lqp0/o;I)Lbz/j;

    .line 277
    .line 278
    .line 279
    move-result-object v1

    .line 280
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 281
    .line 282
    .line 283
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 284
    .line 285
    return-object v0

    .line 286
    :cond_f
    invoke-static {v4}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    throw v5

    .line 290
    :cond_10
    invoke-static {v4}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    throw v5

    .line 294
    :cond_11
    invoke-static {v4}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 295
    .line 296
    .line 297
    throw v5
.end method
