.class public final Lc00/a1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc00/k1;


# direct methods
.method public synthetic constructor <init>(Lc00/k1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc00/a1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/a1;->e:Lc00/k1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b(Llx0/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 27

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
    instance-of v3, v2, Lc00/z0;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lc00/z0;

    .line 13
    .line 14
    iget v4, v3, Lc00/z0;->g:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lc00/z0;->g:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lc00/z0;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Lc00/z0;-><init>(Lc00/a1;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lc00/z0;->e:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lc00/z0;->g:I

    .line 36
    .line 37
    const/4 v6, 0x0

    .line 38
    const/4 v7, 0x1

    .line 39
    iget-object v0, v0, Lc00/a1;->e:Lc00/k1;

    .line 40
    .line 41
    if-eqz v5, :cond_2

    .line 42
    .line 43
    if-ne v5, v7, :cond_1

    .line 44
    .line 45
    iget-object v1, v3, Lc00/z0;->d:Ljava/util/List;

    .line 46
    .line 47
    check-cast v1, Ljava/util/List;

    .line 48
    .line 49
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto/16 :goto_3

    .line 53
    .line 54
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 55
    .line 56
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 57
    .line 58
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw v0

    .line 62
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget-object v2, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v2, Lne0/s;

    .line 68
    .line 69
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v1, Ljava/util/List;

    .line 72
    .line 73
    instance-of v5, v2, Lne0/c;

    .line 74
    .line 75
    const/4 v8, 0x0

    .line 76
    if-eqz v5, :cond_3

    .line 77
    .line 78
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 79
    .line 80
    .line 81
    move-result-object v5

    .line 82
    check-cast v5, Lc00/y0;

    .line 83
    .line 84
    iget-boolean v5, v5, Lc00/y0;->r:Z

    .line 85
    .line 86
    if-nez v5, :cond_3

    .line 87
    .line 88
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    move-object v9, v1

    .line 93
    check-cast v9, Lc00/y0;

    .line 94
    .line 95
    const/16 v25, 0x0

    .line 96
    .line 97
    const v26, 0x5ffff

    .line 98
    .line 99
    .line 100
    const/4 v10, 0x0

    .line 101
    const/4 v11, 0x0

    .line 102
    const/4 v12, 0x0

    .line 103
    const/4 v13, 0x0

    .line 104
    const/4 v14, 0x0

    .line 105
    const/4 v15, 0x0

    .line 106
    const/16 v16, 0x0

    .line 107
    .line 108
    const/16 v17, 0x0

    .line 109
    .line 110
    const/16 v18, 0x0

    .line 111
    .line 112
    const/16 v19, 0x0

    .line 113
    .line 114
    const/16 v20, 0x0

    .line 115
    .line 116
    const/16 v21, 0x0

    .line 117
    .line 118
    const/16 v22, 0x0

    .line 119
    .line 120
    const/16 v23, 0x0

    .line 121
    .line 122
    const/16 v24, 0x0

    .line 123
    .line 124
    invoke-static/range {v9 .. v26}, Lc00/y0;->a(Lc00/y0;ZZZLc00/u0;Lc00/w0;Lc00/x0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lc00/v0;Llf0/i;ZZLqr0/q;Lqr0/q;ZI)Lc00/y0;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 129
    .line 130
    .line 131
    iget-object v1, v0, Lc00/k1;->m:Llb0/b;

    .line 132
    .line 133
    new-instance v2, Llb0/a;

    .line 134
    .line 135
    invoke-direct {v2, v8}, Llb0/a;-><init>(Z)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v1, v2}, Llb0/b;->a(Llb0/a;)Lzy0/j;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    invoke-static {v1, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 147
    .line 148
    .line 149
    goto/16 :goto_5

    .line 150
    .line 151
    :cond_3
    move-object v5, v1

    .line 152
    check-cast v5, Ljava/lang/Iterable;

    .line 153
    .line 154
    instance-of v9, v5, Ljava/util/Collection;

    .line 155
    .line 156
    if-eqz v9, :cond_4

    .line 157
    .line 158
    move-object v9, v5

    .line 159
    check-cast v9, Ljava/util/Collection;

    .line 160
    .line 161
    invoke-interface {v9}, Ljava/util/Collection;->isEmpty()Z

    .line 162
    .line 163
    .line 164
    move-result v9

    .line 165
    if-eqz v9, :cond_4

    .line 166
    .line 167
    goto :goto_2

    .line 168
    :cond_4
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 169
    .line 170
    .line 171
    move-result-object v5

    .line 172
    :cond_5
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 173
    .line 174
    .line 175
    move-result v9

    .line 176
    if-eqz v9, :cond_7

    .line 177
    .line 178
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v9

    .line 182
    check-cast v9, Lcn0/c;

    .line 183
    .line 184
    sget-object v10, Lcn0/a;->d:Lcn0/a;

    .line 185
    .line 186
    sget-object v11, Lcn0/a;->e:Lcn0/a;

    .line 187
    .line 188
    sget-object v12, Lcn0/a;->f:Lcn0/a;

    .line 189
    .line 190
    sget-object v13, Lcn0/a;->g:Lcn0/a;

    .line 191
    .line 192
    sget-object v14, Lcn0/a;->h:Lcn0/a;

    .line 193
    .line 194
    filled-new-array {v10, v11, v12, v13, v14}, [Lcn0/a;

    .line 195
    .line 196
    .line 197
    move-result-object v10

    .line 198
    invoke-static {v10}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 199
    .line 200
    .line 201
    move-result-object v10

    .line 202
    check-cast v10, Ljava/lang/Iterable;

    .line 203
    .line 204
    if-eqz v9, :cond_6

    .line 205
    .line 206
    iget-object v11, v9, Lcn0/c;->e:Lcn0/a;

    .line 207
    .line 208
    goto :goto_1

    .line 209
    :cond_6
    move-object v11, v6

    .line 210
    :goto_1
    invoke-static {v10, v11}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 211
    .line 212
    .line 213
    move-result v10

    .line 214
    if-eqz v10, :cond_5

    .line 215
    .line 216
    invoke-static {v9}, Ljp/sd;->c(Lcn0/c;)Z

    .line 217
    .line 218
    .line 219
    move-result v9

    .line 220
    if-eqz v9, :cond_5

    .line 221
    .line 222
    move v8, v7

    .line 223
    :cond_7
    :goto_2
    move-object v5, v1

    .line 224
    check-cast v5, Ljava/util/List;

    .line 225
    .line 226
    iput-object v5, v3, Lc00/z0;->d:Ljava/util/List;

    .line 227
    .line 228
    iput v7, v3, Lc00/z0;->g:I

    .line 229
    .line 230
    invoke-static {v0, v2, v8, v3}, Lc00/k1;->j(Lc00/k1;Lne0/s;ZLrx0/c;)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v2

    .line 234
    if-ne v2, v4, :cond_8

    .line 235
    .line 236
    return-object v4

    .line 237
    :cond_8
    :goto_3
    check-cast v1, Ljava/lang/Iterable;

    .line 238
    .line 239
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 240
    .line 241
    .line 242
    move-result-object v1

    .line 243
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 244
    .line 245
    .line 246
    move-result v2

    .line 247
    if-eqz v2, :cond_9

    .line 248
    .line 249
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v2

    .line 253
    check-cast v2, Lcn0/c;

    .line 254
    .line 255
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 256
    .line 257
    .line 258
    move-result-object v3

    .line 259
    new-instance v4, La7/o;

    .line 260
    .line 261
    const/16 v5, 0x12

    .line 262
    .line 263
    invoke-direct {v4, v5, v2, v0, v6}, La7/o;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 264
    .line 265
    .line 266
    const/4 v2, 0x3

    .line 267
    invoke-static {v3, v6, v6, v4, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 268
    .line 269
    .line 270
    goto :goto_4

    .line 271
    :cond_9
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 272
    .line 273
    return-object v0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Lc00/a1;->d:I

    .line 6
    .line 7
    packed-switch v2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object/from16 v2, p1

    .line 11
    .line 12
    check-cast v2, Lne0/t;

    .line 13
    .line 14
    instance-of v3, v2, Lne0/c;

    .line 15
    .line 16
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    iget-object v0, v0, Lc00/a1;->e:Lc00/k1;

    .line 19
    .line 20
    if-eqz v3, :cond_0

    .line 21
    .line 22
    check-cast v2, Lne0/c;

    .line 23
    .line 24
    invoke-static {v0, v2, v1}, Lc00/k1;->h(Lc00/k1;Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 29
    .line 30
    if-ne v0, v1, :cond_1

    .line 31
    .line 32
    move-object v4, v0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    instance-of v1, v2, Lne0/e;

    .line 35
    .line 36
    if-eqz v1, :cond_2

    .line 37
    .line 38
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    check-cast v1, Lc00/y0;

    .line 43
    .line 44
    iget-object v2, v0, Lc00/k1;->j:Lij0/a;

    .line 45
    .line 46
    sget-object v3, Lcn0/a;->e:Lcn0/a;

    .line 47
    .line 48
    invoke-static {v1, v2, v3}, Ljp/ec;->e(Lc00/y0;Lij0/a;Lcn0/a;)Lc00/y0;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 53
    .line 54
    .line 55
    :cond_1
    :goto_0
    return-object v4

    .line 56
    :cond_2
    new-instance v0, La8/r0;

    .line 57
    .line 58
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 59
    .line 60
    .line 61
    throw v0

    .line 62
    :pswitch_0
    move-object/from16 v2, p1

    .line 63
    .line 64
    check-cast v2, Lne0/t;

    .line 65
    .line 66
    instance-of v3, v2, Lne0/c;

    .line 67
    .line 68
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    iget-object v0, v0, Lc00/a1;->e:Lc00/k1;

    .line 71
    .line 72
    if-eqz v3, :cond_3

    .line 73
    .line 74
    check-cast v2, Lne0/c;

    .line 75
    .line 76
    invoke-static {v0, v2, v1}, Lc00/k1;->h(Lc00/k1;Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 81
    .line 82
    if-ne v0, v1, :cond_4

    .line 83
    .line 84
    move-object v4, v0

    .line 85
    goto :goto_1

    .line 86
    :cond_3
    instance-of v1, v2, Lne0/e;

    .line 87
    .line 88
    if-eqz v1, :cond_5

    .line 89
    .line 90
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    check-cast v1, Lc00/y0;

    .line 95
    .line 96
    iget-object v2, v0, Lc00/k1;->j:Lij0/a;

    .line 97
    .line 98
    sget-object v3, Lcn0/a;->h:Lcn0/a;

    .line 99
    .line 100
    invoke-static {v1, v2, v3}, Ljp/ec;->e(Lc00/y0;Lij0/a;Lcn0/a;)Lc00/y0;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 105
    .line 106
    .line 107
    :cond_4
    :goto_1
    return-object v4

    .line 108
    :cond_5
    new-instance v0, La8/r0;

    .line 109
    .line 110
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 111
    .line 112
    .line 113
    throw v0

    .line 114
    :pswitch_1
    move-object/from16 v2, p1

    .line 115
    .line 116
    check-cast v2, Lne0/s;

    .line 117
    .line 118
    instance-of v3, v2, Lne0/c;

    .line 119
    .line 120
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    iget-object v0, v0, Lc00/a1;->e:Lc00/k1;

    .line 123
    .line 124
    if-eqz v3, :cond_6

    .line 125
    .line 126
    check-cast v2, Lne0/c;

    .line 127
    .line 128
    invoke-static {v0, v2, v1}, Lc00/k1;->h(Lc00/k1;Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 133
    .line 134
    if-ne v0, v1, :cond_8

    .line 135
    .line 136
    move-object v4, v0

    .line 137
    goto :goto_2

    .line 138
    :cond_6
    sget-object v1, Lne0/d;->a:Lne0/d;

    .line 139
    .line 140
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result v1

    .line 144
    if-eqz v1, :cond_7

    .line 145
    .line 146
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    move-object v5, v1

    .line 151
    check-cast v5, Lc00/y0;

    .line 152
    .line 153
    const/16 v21, 0x0

    .line 154
    .line 155
    const v22, 0x7fffe

    .line 156
    .line 157
    .line 158
    const/4 v6, 0x1

    .line 159
    const/4 v7, 0x0

    .line 160
    const/4 v8, 0x0

    .line 161
    const/4 v9, 0x0

    .line 162
    const/4 v10, 0x0

    .line 163
    const/4 v11, 0x0

    .line 164
    const/4 v12, 0x0

    .line 165
    const/4 v13, 0x0

    .line 166
    const/4 v14, 0x0

    .line 167
    const/4 v15, 0x0

    .line 168
    const/16 v16, 0x0

    .line 169
    .line 170
    const/16 v17, 0x0

    .line 171
    .line 172
    const/16 v18, 0x0

    .line 173
    .line 174
    const/16 v19, 0x0

    .line 175
    .line 176
    const/16 v20, 0x0

    .line 177
    .line 178
    invoke-static/range {v5 .. v22}, Lc00/y0;->a(Lc00/y0;ZZZLc00/u0;Lc00/w0;Lc00/x0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lc00/v0;Llf0/i;ZZLqr0/q;Lqr0/q;ZI)Lc00/y0;

    .line 179
    .line 180
    .line 181
    move-result-object v1

    .line 182
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 183
    .line 184
    .line 185
    goto :goto_2

    .line 186
    :cond_7
    instance-of v1, v2, Lne0/e;

    .line 187
    .line 188
    if-eqz v1, :cond_9

    .line 189
    .line 190
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    move-object v5, v1

    .line 195
    check-cast v5, Lc00/y0;

    .line 196
    .line 197
    const/16 v21, 0x0

    .line 198
    .line 199
    const v22, 0x7fffe

    .line 200
    .line 201
    .line 202
    const/4 v6, 0x0

    .line 203
    const/4 v7, 0x0

    .line 204
    const/4 v8, 0x0

    .line 205
    const/4 v9, 0x0

    .line 206
    const/4 v10, 0x0

    .line 207
    const/4 v11, 0x0

    .line 208
    const/4 v12, 0x0

    .line 209
    const/4 v13, 0x0

    .line 210
    const/4 v14, 0x0

    .line 211
    const/4 v15, 0x0

    .line 212
    const/16 v16, 0x0

    .line 213
    .line 214
    const/16 v17, 0x0

    .line 215
    .line 216
    const/16 v18, 0x0

    .line 217
    .line 218
    const/16 v19, 0x0

    .line 219
    .line 220
    const/16 v20, 0x0

    .line 221
    .line 222
    invoke-static/range {v5 .. v22}, Lc00/y0;->a(Lc00/y0;ZZZLc00/u0;Lc00/w0;Lc00/x0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lc00/v0;Llf0/i;ZZLqr0/q;Lqr0/q;ZI)Lc00/y0;

    .line 223
    .line 224
    .line 225
    move-result-object v1

    .line 226
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 227
    .line 228
    .line 229
    :cond_8
    :goto_2
    return-object v4

    .line 230
    :cond_9
    new-instance v0, La8/r0;

    .line 231
    .line 232
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 233
    .line 234
    .line 235
    throw v0

    .line 236
    :pswitch_2
    move-object/from16 v2, p1

    .line 237
    .line 238
    check-cast v2, Lne0/t;

    .line 239
    .line 240
    instance-of v3, v2, Lne0/e;

    .line 241
    .line 242
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 243
    .line 244
    iget-object v0, v0, Lc00/a1;->e:Lc00/k1;

    .line 245
    .line 246
    if-eqz v3, :cond_a

    .line 247
    .line 248
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 249
    .line 250
    .line 251
    move-result-object v1

    .line 252
    check-cast v1, Lc00/y0;

    .line 253
    .line 254
    iget-object v2, v0, Lc00/k1;->j:Lij0/a;

    .line 255
    .line 256
    sget-object v3, Lcn0/a;->f:Lcn0/a;

    .line 257
    .line 258
    invoke-static {v1, v2, v3}, Ljp/ec;->e(Lc00/y0;Lij0/a;Lcn0/a;)Lc00/y0;

    .line 259
    .line 260
    .line 261
    move-result-object v1

    .line 262
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 263
    .line 264
    .line 265
    goto :goto_3

    .line 266
    :cond_a
    instance-of v3, v2, Lne0/c;

    .line 267
    .line 268
    if-eqz v3, :cond_c

    .line 269
    .line 270
    check-cast v2, Lne0/c;

    .line 271
    .line 272
    invoke-static {v0, v2, v1}, Lc00/k1;->h(Lc00/k1;Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v0

    .line 276
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 277
    .line 278
    if-ne v0, v1, :cond_b

    .line 279
    .line 280
    move-object v4, v0

    .line 281
    :cond_b
    :goto_3
    return-object v4

    .line 282
    :cond_c
    new-instance v0, La8/r0;

    .line 283
    .line 284
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 285
    .line 286
    .line 287
    throw v0

    .line 288
    :pswitch_3
    move-object/from16 v2, p1

    .line 289
    .line 290
    check-cast v2, Lne0/t;

    .line 291
    .line 292
    instance-of v3, v2, Lne0/e;

    .line 293
    .line 294
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 295
    .line 296
    iget-object v0, v0, Lc00/a1;->e:Lc00/k1;

    .line 297
    .line 298
    if-eqz v3, :cond_d

    .line 299
    .line 300
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 301
    .line 302
    .line 303
    move-result-object v1

    .line 304
    check-cast v1, Lc00/y0;

    .line 305
    .line 306
    iget-object v2, v0, Lc00/k1;->j:Lij0/a;

    .line 307
    .line 308
    sget-object v3, Lcn0/a;->g:Lcn0/a;

    .line 309
    .line 310
    invoke-static {v1, v2, v3}, Ljp/ec;->e(Lc00/y0;Lij0/a;Lcn0/a;)Lc00/y0;

    .line 311
    .line 312
    .line 313
    move-result-object v1

    .line 314
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 315
    .line 316
    .line 317
    goto :goto_4

    .line 318
    :cond_d
    instance-of v3, v2, Lne0/c;

    .line 319
    .line 320
    if-eqz v3, :cond_f

    .line 321
    .line 322
    check-cast v2, Lne0/c;

    .line 323
    .line 324
    invoke-static {v0, v2, v1}, Lc00/k1;->h(Lc00/k1;Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object v0

    .line 328
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 329
    .line 330
    if-ne v0, v1, :cond_e

    .line 331
    .line 332
    move-object v4, v0

    .line 333
    :cond_e
    :goto_4
    return-object v4

    .line 334
    :cond_f
    new-instance v0, La8/r0;

    .line 335
    .line 336
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 337
    .line 338
    .line 339
    throw v0

    .line 340
    :pswitch_4
    move-object/from16 v2, p1

    .line 341
    .line 342
    check-cast v2, Lne0/t;

    .line 343
    .line 344
    instance-of v3, v2, Lne0/c;

    .line 345
    .line 346
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 347
    .line 348
    iget-object v0, v0, Lc00/a1;->e:Lc00/k1;

    .line 349
    .line 350
    if-eqz v3, :cond_10

    .line 351
    .line 352
    check-cast v2, Lne0/c;

    .line 353
    .line 354
    invoke-static {v0, v2, v1}, Lc00/k1;->h(Lc00/k1;Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v0

    .line 358
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 359
    .line 360
    if-ne v0, v1, :cond_11

    .line 361
    .line 362
    move-object v4, v0

    .line 363
    goto :goto_5

    .line 364
    :cond_10
    instance-of v1, v2, Lne0/e;

    .line 365
    .line 366
    if-eqz v1, :cond_12

    .line 367
    .line 368
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 369
    .line 370
    .line 371
    move-result-object v1

    .line 372
    check-cast v1, Lc00/y0;

    .line 373
    .line 374
    iget-object v2, v0, Lc00/k1;->j:Lij0/a;

    .line 375
    .line 376
    sget-object v3, Lcn0/a;->d:Lcn0/a;

    .line 377
    .line 378
    invoke-static {v1, v2, v3}, Ljp/ec;->e(Lc00/y0;Lij0/a;Lcn0/a;)Lc00/y0;

    .line 379
    .line 380
    .line 381
    move-result-object v1

    .line 382
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 383
    .line 384
    .line 385
    :cond_11
    :goto_5
    return-object v4

    .line 386
    :cond_12
    new-instance v0, La8/r0;

    .line 387
    .line 388
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 389
    .line 390
    .line 391
    throw v0

    .line 392
    :pswitch_5
    move-object/from16 v2, p1

    .line 393
    .line 394
    check-cast v2, Llx0/l;

    .line 395
    .line 396
    invoke-virtual {v0, v2, v1}, Lc00/a1;->b(Llx0/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 397
    .line 398
    .line 399
    move-result-object v0

    .line 400
    return-object v0

    .line 401
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
