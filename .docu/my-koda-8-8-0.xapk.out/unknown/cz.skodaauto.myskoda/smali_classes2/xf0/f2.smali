.class public final Lxf0/f2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lxf0/f2;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lxf0/f2;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lxf0/f2;->g:Ljava/lang/Object;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lxf0/f2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lxf0/f2;

    .line 7
    .line 8
    iget-object v1, p0, Lxf0/f2;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lyy0/j;

    .line 11
    .line 12
    iget-object p0, p0, Lxf0/f2;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lkotlin/jvm/internal/f0;

    .line 15
    .line 16
    const/4 v2, 0x3

    .line 17
    invoke-direct {v0, v2, v1, p0, p1}, Lxf0/f2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 18
    .line 19
    .line 20
    return-object v0

    .line 21
    :pswitch_0
    new-instance v0, Lxf0/f2;

    .line 22
    .line 23
    iget-object v1, p0, Lxf0/f2;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v1, Ly80/b;

    .line 26
    .line 27
    iget-object p0, p0, Lxf0/f2;->g:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Lb90/r;

    .line 30
    .line 31
    const/4 v2, 0x2

    .line 32
    invoke-direct {v0, v2, v1, p0, p1}, Lxf0/f2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 33
    .line 34
    .line 35
    return-object v0

    .line 36
    :pswitch_1
    new-instance v0, Lxf0/f2;

    .line 37
    .line 38
    iget-object v1, p0, Lxf0/f2;->f:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v1, Ly1/f;

    .line 41
    .line 42
    iget-object p0, p0, Lxf0/f2;->g:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, La2/k;

    .line 45
    .line 46
    const/4 v2, 0x1

    .line 47
    invoke-direct {v0, v2, v1, p0, p1}, Lxf0/f2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 48
    .line 49
    .line 50
    return-object v0

    .line 51
    :pswitch_2
    new-instance v0, Lxf0/f2;

    .line 52
    .line 53
    iget-object v1, p0, Lxf0/f2;->f:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v1, Ll2/b1;

    .line 56
    .line 57
    iget-object p0, p0, Lxf0/f2;->g:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p0, Lay0/a;

    .line 60
    .line 61
    const/4 v2, 0x0

    .line 62
    invoke-direct {v0, v2, v1, p0, p1}, Lxf0/f2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 63
    .line 64
    .line 65
    return-object v0

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lxf0/f2;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lxf0/f2;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lxf0/f2;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lxf0/f2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Lxf0/f2;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lxf0/f2;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lxf0/f2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Lxf0/f2;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Lxf0/f2;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Lxf0/f2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_2
    invoke-virtual {p0, p1}, Lxf0/f2;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Lxf0/f2;

    .line 52
    .line 53
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    invoke-virtual {p0, p1}, Lxf0/f2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lxf0/f2;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lxf0/f2;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lkotlin/jvm/internal/f0;

    .line 11
    .line 12
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v3, v0, Lxf0/f2;->e:I

    .line 15
    .line 16
    const/4 v4, 0x0

    .line 17
    const/4 v5, 0x1

    .line 18
    if-eqz v3, :cond_1

    .line 19
    .line 20
    if-ne v3, v5, :cond_0

    .line 21
    .line 22
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 29
    .line 30
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw v0

    .line 34
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object v3, v0, Lxf0/f2;->f:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v3, Lyy0/j;

    .line 40
    .line 41
    sget-object v6, Lzy0/c;->b:Lj51/i;

    .line 42
    .line 43
    iget-object v7, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 44
    .line 45
    if-ne v7, v6, :cond_2

    .line 46
    .line 47
    move-object v7, v4

    .line 48
    :cond_2
    iput v5, v0, Lxf0/f2;->e:I

    .line 49
    .line 50
    invoke-interface {v3, v7, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    if-ne v0, v2, :cond_3

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    :goto_0
    iput-object v4, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 58
    .line 59
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    :goto_1
    return-object v2

    .line 62
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 63
    .line 64
    iget v2, v0, Lxf0/f2;->e:I

    .line 65
    .line 66
    const/4 v3, 0x2

    .line 67
    const/4 v4, 0x1

    .line 68
    if-eqz v2, :cond_6

    .line 69
    .line 70
    if-eq v2, v4, :cond_5

    .line 71
    .line 72
    if-ne v2, v3, :cond_4

    .line 73
    .line 74
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    move-object/from16 v0, p1

    .line 78
    .line 79
    goto/16 :goto_1c

    .line 80
    .line 81
    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 82
    .line 83
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 84
    .line 85
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw v0

    .line 89
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    move-object/from16 v2, p1

    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_6
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    iget-object v2, v0, Lxf0/f2;->f:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v2, Ly80/b;

    .line 101
    .line 102
    iget-object v2, v2, Ly80/b;->b:Lti0/a;

    .line 103
    .line 104
    iput v4, v0, Lxf0/f2;->e:I

    .line 105
    .line 106
    invoke-interface {v2, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    if-ne v2, v1, :cond_7

    .line 111
    .line 112
    goto/16 :goto_1b

    .line 113
    .line 114
    :cond_7
    :goto_2
    check-cast v2, Lcz/myskoda/api/bff_test_drive/v2/TestDriveApi;

    .line 115
    .line 116
    iget-object v5, v0, Lxf0/f2;->g:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast v5, Lb90/r;

    .line 119
    .line 120
    const-string v6, "<this>"

    .line 121
    .line 122
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    new-instance v7, Ljava/util/ArrayList;

    .line 126
    .line 127
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 128
    .line 129
    .line 130
    iget-object v8, v5, Lb90/r;->a:Lb90/g;

    .line 131
    .line 132
    iget-object v9, v5, Lb90/r;->b:Lb90/g;

    .line 133
    .line 134
    iget-object v10, v5, Lb90/r;->c:Lb90/g;

    .line 135
    .line 136
    iget-object v11, v5, Lb90/r;->d:Lb90/g;

    .line 137
    .line 138
    iget-object v12, v5, Lb90/r;->f:Lb90/g;

    .line 139
    .line 140
    iget-object v5, v5, Lb90/r;->e:Lb90/a;

    .line 141
    .line 142
    const/16 v23, 0x0

    .line 143
    .line 144
    if-eqz v5, :cond_8

    .line 145
    .line 146
    iget-object v13, v5, Lb90/a;->b:Lb90/g;

    .line 147
    .line 148
    goto :goto_3

    .line 149
    :cond_8
    move-object/from16 v13, v23

    .line 150
    .line 151
    :goto_3
    if-eqz v5, :cond_9

    .line 152
    .line 153
    iget-object v14, v5, Lb90/a;->c:Lb90/g;

    .line 154
    .line 155
    goto :goto_4

    .line 156
    :cond_9
    move-object/from16 v14, v23

    .line 157
    .line 158
    :goto_4
    if-eqz v5, :cond_a

    .line 159
    .line 160
    iget-object v15, v5, Lb90/a;->d:Lb90/g;

    .line 161
    .line 162
    goto :goto_5

    .line 163
    :cond_a
    move-object/from16 v15, v23

    .line 164
    .line 165
    :goto_5
    if-eqz v5, :cond_b

    .line 166
    .line 167
    iget-object v3, v5, Lb90/a;->e:Lb90/g;

    .line 168
    .line 169
    move-object/from16 v16, v3

    .line 170
    .line 171
    goto :goto_6

    .line 172
    :cond_b
    move-object/from16 v16, v23

    .line 173
    .line 174
    :goto_6
    if-eqz v5, :cond_c

    .line 175
    .line 176
    iget-object v3, v5, Lb90/a;->f:Lb90/g;

    .line 177
    .line 178
    move-object/from16 v17, v3

    .line 179
    .line 180
    goto :goto_7

    .line 181
    :cond_c
    move-object/from16 v17, v23

    .line 182
    .line 183
    :goto_7
    if-eqz v5, :cond_d

    .line 184
    .line 185
    iget-object v3, v5, Lb90/a;->g:Lb90/g;

    .line 186
    .line 187
    move-object/from16 v18, v3

    .line 188
    .line 189
    goto :goto_8

    .line 190
    :cond_d
    move-object/from16 v18, v23

    .line 191
    .line 192
    :goto_8
    if-eqz v5, :cond_e

    .line 193
    .line 194
    iget-object v3, v5, Lb90/a;->h:Lb90/g;

    .line 195
    .line 196
    move-object/from16 v19, v3

    .line 197
    .line 198
    goto :goto_9

    .line 199
    :cond_e
    move-object/from16 v19, v23

    .line 200
    .line 201
    :goto_9
    if-eqz v5, :cond_f

    .line 202
    .line 203
    iget-object v3, v5, Lb90/a;->i:Lb90/g;

    .line 204
    .line 205
    move-object/from16 v20, v3

    .line 206
    .line 207
    goto :goto_a

    .line 208
    :cond_f
    move-object/from16 v20, v23

    .line 209
    .line 210
    :goto_a
    if-eqz v5, :cond_10

    .line 211
    .line 212
    iget-object v3, v5, Lb90/a;->j:Lb90/g;

    .line 213
    .line 214
    move-object/from16 v21, v3

    .line 215
    .line 216
    goto :goto_b

    .line 217
    :cond_10
    move-object/from16 v21, v23

    .line 218
    .line 219
    :goto_b
    if-eqz v5, :cond_11

    .line 220
    .line 221
    iget-object v3, v5, Lb90/a;->k:Lb90/g;

    .line 222
    .line 223
    move-object/from16 v22, v3

    .line 224
    .line 225
    goto :goto_c

    .line 226
    :cond_11
    move-object/from16 v22, v23

    .line 227
    .line 228
    :goto_c
    filled-new-array/range {v8 .. v22}, [Lb90/g;

    .line 229
    .line 230
    .line 231
    move-result-object v3

    .line 232
    const/4 v8, 0x0

    .line 233
    move v9, v8

    .line 234
    :goto_d
    sget-object v10, Lmx0/s;->d:Lmx0/s;

    .line 235
    .line 236
    const/16 v11, 0xf

    .line 237
    .line 238
    if-ge v9, v11, :cond_15

    .line 239
    .line 240
    aget-object v11, v3, v9

    .line 241
    .line 242
    if-eqz v11, :cond_14

    .line 243
    .line 244
    invoke-virtual {v11}, Lb90/g;->b()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v12

    .line 248
    check-cast v12, Ljava/lang/CharSequence;

    .line 249
    .line 250
    if-eqz v12, :cond_14

    .line 251
    .line 252
    invoke-static {v12}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 253
    .line 254
    .line 255
    move-result v12

    .line 256
    if-eqz v12, :cond_12

    .line 257
    .line 258
    goto :goto_e

    .line 259
    :cond_12
    invoke-virtual {v11}, Lb90/g;->a()Lb90/p;

    .line 260
    .line 261
    .line 262
    move-result-object v12

    .line 263
    iget-object v14, v12, Lb90/p;->a:Ljava/lang/String;

    .line 264
    .line 265
    invoke-virtual {v11}, Lb90/g;->b()Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object v11

    .line 269
    check-cast v11, Ljava/lang/String;

    .line 270
    .line 271
    if-eqz v11, :cond_13

    .line 272
    .line 273
    invoke-static {v11}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 274
    .line 275
    .line 276
    move-result-object v10

    .line 277
    :cond_13
    move-object v15, v10

    .line 278
    new-instance v13, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestFieldDto;

    .line 279
    .line 280
    const/16 v16, 0x0

    .line 281
    .line 282
    const/16 v17, 0x4

    .line 283
    .line 284
    const/16 v18, 0x0

    .line 285
    .line 286
    invoke-direct/range {v13 .. v18}, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestFieldDto;-><init>(Ljava/lang/String;Ljava/util/List;ZILkotlin/jvm/internal/g;)V

    .line 287
    .line 288
    .line 289
    invoke-virtual {v7, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 290
    .line 291
    .line 292
    :cond_14
    :goto_e
    add-int/lit8 v9, v9, 0x1

    .line 293
    .line 294
    goto :goto_d

    .line 295
    :cond_15
    if-eqz v5, :cond_16

    .line 296
    .line 297
    iget-object v3, v5, Lb90/a;->a:Lb90/g;

    .line 298
    .line 299
    goto :goto_f

    .line 300
    :cond_16
    move-object/from16 v3, v23

    .line 301
    .line 302
    :goto_f
    if-eqz v5, :cond_17

    .line 303
    .line 304
    iget-object v9, v5, Lb90/a;->l:Lb90/g;

    .line 305
    .line 306
    goto :goto_10

    .line 307
    :cond_17
    move-object/from16 v9, v23

    .line 308
    .line 309
    :goto_10
    if-eqz v5, :cond_18

    .line 310
    .line 311
    iget-object v11, v5, Lb90/a;->m:Lb90/g;

    .line 312
    .line 313
    goto :goto_11

    .line 314
    :cond_18
    move-object/from16 v11, v23

    .line 315
    .line 316
    :goto_11
    if-eqz v5, :cond_19

    .line 317
    .line 318
    iget-object v12, v5, Lb90/a;->o:Lb90/g;

    .line 319
    .line 320
    goto :goto_12

    .line 321
    :cond_19
    move-object/from16 v12, v23

    .line 322
    .line 323
    :goto_12
    filled-new-array {v3, v9, v11, v12}, [Lb90/g;

    .line 324
    .line 325
    .line 326
    move-result-object v3

    .line 327
    move v9, v8

    .line 328
    :goto_13
    const/4 v11, 0x4

    .line 329
    if-ge v9, v11, :cond_1e

    .line 330
    .line 331
    aget-object v11, v3, v9

    .line 332
    .line 333
    if-eqz v11, :cond_1d

    .line 334
    .line 335
    invoke-virtual {v11}, Lb90/g;->b()Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object v12

    .line 339
    check-cast v12, Lb90/b;

    .line 340
    .line 341
    if-eqz v12, :cond_1a

    .line 342
    .line 343
    iget-object v12, v12, Lb90/b;->a:Ljava/lang/String;

    .line 344
    .line 345
    goto :goto_14

    .line 346
    :cond_1a
    move-object/from16 v12, v23

    .line 347
    .line 348
    :goto_14
    if-eqz v12, :cond_1d

    .line 349
    .line 350
    invoke-static {v12}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 351
    .line 352
    .line 353
    move-result v12

    .line 354
    if-eqz v12, :cond_1b

    .line 355
    .line 356
    goto :goto_16

    .line 357
    :cond_1b
    invoke-virtual {v11}, Lb90/g;->a()Lb90/p;

    .line 358
    .line 359
    .line 360
    move-result-object v12

    .line 361
    iget-object v14, v12, Lb90/p;->a:Ljava/lang/String;

    .line 362
    .line 363
    invoke-virtual {v11}, Lb90/g;->b()Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    move-result-object v11

    .line 367
    check-cast v11, Lb90/b;

    .line 368
    .line 369
    if-eqz v11, :cond_1c

    .line 370
    .line 371
    iget-object v11, v11, Lb90/b;->a:Ljava/lang/String;

    .line 372
    .line 373
    invoke-static {v11}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 374
    .line 375
    .line 376
    move-result-object v11

    .line 377
    move-object v15, v11

    .line 378
    goto :goto_15

    .line 379
    :cond_1c
    move-object v15, v10

    .line 380
    :goto_15
    new-instance v13, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestFieldDto;

    .line 381
    .line 382
    const/16 v16, 0x0

    .line 383
    .line 384
    const/16 v17, 0x4

    .line 385
    .line 386
    const/16 v18, 0x0

    .line 387
    .line 388
    invoke-direct/range {v13 .. v18}, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestFieldDto;-><init>(Ljava/lang/String;Ljava/util/List;ZILkotlin/jvm/internal/g;)V

    .line 389
    .line 390
    .line 391
    invoke-virtual {v7, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 392
    .line 393
    .line 394
    :cond_1d
    :goto_16
    add-int/lit8 v9, v9, 0x1

    .line 395
    .line 396
    goto :goto_13

    .line 397
    :cond_1e
    const/16 v3, 0xa

    .line 398
    .line 399
    if-eqz v5, :cond_20

    .line 400
    .line 401
    iget-object v9, v5, Lb90/a;->n:Lb90/g;

    .line 402
    .line 403
    if-eqz v9, :cond_20

    .line 404
    .line 405
    invoke-virtual {v9}, Lb90/g;->b()Ljava/lang/Object;

    .line 406
    .line 407
    .line 408
    move-result-object v11

    .line 409
    check-cast v11, Ljava/util/Set;

    .line 410
    .line 411
    if-eqz v11, :cond_20

    .line 412
    .line 413
    check-cast v11, Ljava/util/Collection;

    .line 414
    .line 415
    invoke-interface {v11}, Ljava/util/Collection;->isEmpty()Z

    .line 416
    .line 417
    .line 418
    move-result v11

    .line 419
    xor-int/2addr v11, v4

    .line 420
    if-ne v11, v4, :cond_20

    .line 421
    .line 422
    invoke-virtual {v9}, Lb90/g;->a()Lb90/p;

    .line 423
    .line 424
    .line 425
    move-result-object v11

    .line 426
    iget-object v11, v11, Lb90/p;->a:Ljava/lang/String;

    .line 427
    .line 428
    invoke-virtual {v9}, Lb90/g;->b()Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object v9

    .line 432
    check-cast v9, Ljava/util/Set;

    .line 433
    .line 434
    if-eqz v9, :cond_1f

    .line 435
    .line 436
    check-cast v9, Ljava/lang/Iterable;

    .line 437
    .line 438
    new-instance v10, Ljava/util/ArrayList;

    .line 439
    .line 440
    invoke-static {v9, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 441
    .line 442
    .line 443
    move-result v12

    .line 444
    invoke-direct {v10, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 445
    .line 446
    .line 447
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 448
    .line 449
    .line 450
    move-result-object v9

    .line 451
    :goto_17
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 452
    .line 453
    .line 454
    move-result v12

    .line 455
    if-eqz v12, :cond_1f

    .line 456
    .line 457
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 458
    .line 459
    .line 460
    move-result-object v12

    .line 461
    check-cast v12, Lb90/b;

    .line 462
    .line 463
    iget-object v12, v12, Lb90/b;->a:Ljava/lang/String;

    .line 464
    .line 465
    invoke-virtual {v10, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 466
    .line 467
    .line 468
    goto :goto_17

    .line 469
    :cond_1f
    new-instance v9, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestFieldDto;

    .line 470
    .line 471
    invoke-direct {v9, v11, v10, v4}, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestFieldDto;-><init>(Ljava/lang/String;Ljava/util/List;Z)V

    .line 472
    .line 473
    .line 474
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 475
    .line 476
    .line 477
    :cond_20
    new-instance v9, Ljava/util/ArrayList;

    .line 478
    .line 479
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 480
    .line 481
    .line 482
    if-eqz v5, :cond_22

    .line 483
    .line 484
    iget-object v10, v5, Lb90/a;->p:Ljava/util/Set;

    .line 485
    .line 486
    check-cast v10, Ljava/lang/Iterable;

    .line 487
    .line 488
    new-instance v11, Ljava/util/ArrayList;

    .line 489
    .line 490
    invoke-static {v10, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 491
    .line 492
    .line 493
    move-result v12

    .line 494
    invoke-direct {v11, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 495
    .line 496
    .line 497
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 498
    .line 499
    .line 500
    move-result-object v10

    .line 501
    :goto_18
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 502
    .line 503
    .line 504
    move-result v12

    .line 505
    if-eqz v12, :cond_21

    .line 506
    .line 507
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 508
    .line 509
    .line 510
    move-result-object v12

    .line 511
    check-cast v12, Lb90/k;

    .line 512
    .line 513
    invoke-static {v12, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 514
    .line 515
    .line 516
    new-instance v13, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestConsentDto;

    .line 517
    .line 518
    iget-object v12, v12, Lb90/k;->a:Ljava/lang/String;

    .line 519
    .line 520
    invoke-direct {v13, v12, v4}, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestConsentDto;-><init>(Ljava/lang/String;Z)V

    .line 521
    .line 522
    .line 523
    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 524
    .line 525
    .line 526
    goto :goto_18

    .line 527
    :cond_21
    invoke-virtual {v9, v11}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 528
    .line 529
    .line 530
    :cond_22
    if-eqz v5, :cond_24

    .line 531
    .line 532
    iget-object v10, v5, Lb90/a;->q:Ljava/util/Set;

    .line 533
    .line 534
    check-cast v10, Ljava/lang/Iterable;

    .line 535
    .line 536
    new-instance v11, Ljava/util/ArrayList;

    .line 537
    .line 538
    invoke-static {v10, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 539
    .line 540
    .line 541
    move-result v12

    .line 542
    invoke-direct {v11, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 543
    .line 544
    .line 545
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 546
    .line 547
    .line 548
    move-result-object v10

    .line 549
    :goto_19
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 550
    .line 551
    .line 552
    move-result v12

    .line 553
    if-eqz v12, :cond_23

    .line 554
    .line 555
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 556
    .line 557
    .line 558
    move-result-object v12

    .line 559
    check-cast v12, Lb90/k;

    .line 560
    .line 561
    invoke-static {v12, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 562
    .line 563
    .line 564
    new-instance v13, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestConsentDto;

    .line 565
    .line 566
    iget-object v12, v12, Lb90/k;->a:Ljava/lang/String;

    .line 567
    .line 568
    invoke-direct {v13, v12, v8}, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestConsentDto;-><init>(Ljava/lang/String;Z)V

    .line 569
    .line 570
    .line 571
    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 572
    .line 573
    .line 574
    goto :goto_19

    .line 575
    :cond_23
    invoke-virtual {v9, v11}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 576
    .line 577
    .line 578
    :cond_24
    if-eqz v5, :cond_26

    .line 579
    .line 580
    iget-object v5, v5, Lb90/a;->r:Ljava/util/Set;

    .line 581
    .line 582
    if-eqz v5, :cond_26

    .line 583
    .line 584
    check-cast v5, Ljava/lang/Iterable;

    .line 585
    .line 586
    new-instance v8, Ljava/util/ArrayList;

    .line 587
    .line 588
    invoke-static {v5, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 589
    .line 590
    .line 591
    move-result v3

    .line 592
    invoke-direct {v8, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 593
    .line 594
    .line 595
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 596
    .line 597
    .line 598
    move-result-object v3

    .line 599
    :goto_1a
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 600
    .line 601
    .line 602
    move-result v5

    .line 603
    if-eqz v5, :cond_25

    .line 604
    .line 605
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 606
    .line 607
    .line 608
    move-result-object v5

    .line 609
    check-cast v5, Lb90/k;

    .line 610
    .line 611
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 612
    .line 613
    .line 614
    new-instance v10, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestConsentDto;

    .line 615
    .line 616
    iget-object v5, v5, Lb90/k;->a:Ljava/lang/String;

    .line 617
    .line 618
    invoke-direct {v10, v5, v4}, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestConsentDto;-><init>(Ljava/lang/String;Z)V

    .line 619
    .line 620
    .line 621
    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 622
    .line 623
    .line 624
    goto :goto_1a

    .line 625
    :cond_25
    invoke-virtual {v9, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 626
    .line 627
    .line 628
    :cond_26
    new-instance v3, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestDto;

    .line 629
    .line 630
    invoke-static {v7}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 631
    .line 632
    .line 633
    move-result-object v4

    .line 634
    invoke-static {v9}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 635
    .line 636
    .line 637
    move-result-object v5

    .line 638
    invoke-direct {v3, v4, v5}, Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestDto;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 639
    .line 640
    .line 641
    const/4 v4, 0x2

    .line 642
    iput v4, v0, Lxf0/f2;->e:I

    .line 643
    .line 644
    invoke-interface {v2, v3, v0}, Lcz/myskoda/api/bff_test_drive/v2/TestDriveApi;->submitTestDriveRequest(Lcz/myskoda/api/bff_test_drive/v2/TestDriveRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 645
    .line 646
    .line 647
    move-result-object v0

    .line 648
    if-ne v0, v1, :cond_27

    .line 649
    .line 650
    :goto_1b
    move-object v0, v1

    .line 651
    :cond_27
    :goto_1c
    return-object v0

    .line 652
    :pswitch_1
    iget-object v1, v0, Lxf0/f2;->f:Ljava/lang/Object;

    .line 653
    .line 654
    check-cast v1, Ly1/f;

    .line 655
    .line 656
    iget-object v2, v1, Ly1/f;->e:Lv2/r;

    .line 657
    .line 658
    iget-object v3, v1, Ly1/f;->a:Landroid/view/View;

    .line 659
    .line 660
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 661
    .line 662
    iget v5, v0, Lxf0/f2;->e:I

    .line 663
    .line 664
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 665
    .line 666
    const/4 v7, 0x0

    .line 667
    const/4 v8, 0x1

    .line 668
    if-eqz v5, :cond_29

    .line 669
    .line 670
    if-ne v5, v8, :cond_28

    .line 671
    .line 672
    :try_start_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 673
    .line 674
    .line 675
    goto/16 :goto_22

    .line 676
    .line 677
    :catchall_0
    move-exception v0

    .line 678
    goto/16 :goto_24

    .line 679
    .line 680
    :cond_28
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 681
    .line 682
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 683
    .line 684
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 685
    .line 686
    .line 687
    throw v0

    .line 688
    :cond_29
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 689
    .line 690
    .line 691
    new-instance v5, Ly1/e;

    .line 692
    .line 693
    invoke-direct {v5}, Ly1/e;-><init>()V

    .line 694
    .line 695
    .line 696
    iget-object v9, v0, Lxf0/f2;->g:Ljava/lang/Object;

    .line 697
    .line 698
    check-cast v9, La2/k;

    .line 699
    .line 700
    new-instance v10, Ly1/d;

    .line 701
    .line 702
    new-instance v11, Ly1/b;

    .line 703
    .line 704
    const/4 v12, 0x0

    .line 705
    invoke-direct {v11, v1, v9, v12}, Ly1/b;-><init>(Ly1/f;La2/k;I)V

    .line 706
    .line 707
    .line 708
    new-instance v12, Ly1/b;

    .line 709
    .line 710
    const/4 v13, 0x1

    .line 711
    invoke-direct {v12, v1, v9, v13}, Ly1/b;-><init>(Ly1/f;La2/k;I)V

    .line 712
    .line 713
    .line 714
    invoke-direct {v10, v5, v11, v12, v3}, Ly1/d;-><init>(Ly1/e;Ly1/b;Ly1/b;Landroid/view/View;)V

    .line 715
    .line 716
    .line 717
    iget-object v9, v1, Ly1/f;->b:Lay0/k;

    .line 718
    .line 719
    if-eqz v9, :cond_2b

    .line 720
    .line 721
    invoke-interface {v9, v10}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 722
    .line 723
    .line 724
    move-result-object v9

    .line 725
    check-cast v9, Ly1/d;

    .line 726
    .line 727
    if-nez v9, :cond_2a

    .line 728
    .line 729
    goto :goto_1d

    .line 730
    :cond_2a
    move-object v10, v9

    .line 731
    :cond_2b
    :goto_1d
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 732
    .line 733
    .line 734
    move-result-object v9

    .line 735
    invoke-virtual {v3}, Landroid/view/View;->getHandler()Landroid/os/Handler;

    .line 736
    .line 737
    .line 738
    move-result-object v11

    .line 739
    if-eqz v11, :cond_2c

    .line 740
    .line 741
    invoke-virtual {v11}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 742
    .line 743
    .line 744
    move-result-object v11

    .line 745
    goto :goto_1e

    .line 746
    :cond_2c
    move-object v11, v7

    .line 747
    :goto_1e
    if-eq v9, v11, :cond_2e

    .line 748
    .line 749
    iget-object v9, v1, Ly1/f;->i:La8/y0;

    .line 750
    .line 751
    if-nez v9, :cond_2d

    .line 752
    .line 753
    new-instance v9, La8/y0;

    .line 754
    .line 755
    const/16 v11, 0x1a

    .line 756
    .line 757
    invoke-direct {v9, v1, v10, v5, v11}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 758
    .line 759
    .line 760
    iput-object v9, v1, Ly1/f;->i:La8/y0;

    .line 761
    .line 762
    :cond_2d
    invoke-virtual {v3, v9}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 763
    .line 764
    .line 765
    goto :goto_20

    .line 766
    :cond_2e
    new-instance v9, Ly1/l;

    .line 767
    .line 768
    invoke-direct {v9, v10}, Ly1/l;-><init>(Ly1/d;)V

    .line 769
    .line 770
    .line 771
    invoke-virtual {v3, v9, v8}, Landroid/view/View;->startActionMode(Landroid/view/ActionMode$Callback;I)Landroid/view/ActionMode;

    .line 772
    .line 773
    .line 774
    move-result-object v9

    .line 775
    if-nez v9, :cond_2f

    .line 776
    .line 777
    :goto_1f
    move-object v4, v6

    .line 778
    goto :goto_23

    .line 779
    :cond_2f
    iput-object v9, v1, Ly1/f;->h:Landroid/view/ActionMode;

    .line 780
    .line 781
    :goto_20
    :try_start_1
    iput v8, v0, Lxf0/f2;->e:I

    .line 782
    .line 783
    iget-object v5, v5, Ly1/e;->a:Lxy0/j;

    .line 784
    .line 785
    invoke-virtual {v5, v0}, Lxy0/j;->r(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 786
    .line 787
    .line 788
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 789
    if-ne v0, v4, :cond_30

    .line 790
    .line 791
    goto :goto_21

    .line 792
    :cond_30
    move-object v0, v6

    .line 793
    :goto_21
    if-ne v0, v4, :cond_31

    .line 794
    .line 795
    goto :goto_23

    .line 796
    :cond_31
    :goto_22
    invoke-virtual {v2}, Lv2/r;->a()V

    .line 797
    .line 798
    .line 799
    iget-object v0, v1, Ly1/f;->h:Landroid/view/ActionMode;

    .line 800
    .line 801
    if-eqz v0, :cond_32

    .line 802
    .line 803
    invoke-virtual {v0}, Landroid/view/ActionMode;->finish()V

    .line 804
    .line 805
    .line 806
    :cond_32
    iget-object v0, v1, Ly1/f;->i:La8/y0;

    .line 807
    .line 808
    if-eqz v0, :cond_33

    .line 809
    .line 810
    invoke-virtual {v3, v0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 811
    .line 812
    .line 813
    :cond_33
    iput-object v7, v1, Ly1/f;->h:Landroid/view/ActionMode;

    .line 814
    .line 815
    goto :goto_1f

    .line 816
    :goto_23
    return-object v4

    .line 817
    :goto_24
    invoke-virtual {v2}, Lv2/r;->a()V

    .line 818
    .line 819
    .line 820
    iget-object v2, v1, Ly1/f;->h:Landroid/view/ActionMode;

    .line 821
    .line 822
    if-eqz v2, :cond_34

    .line 823
    .line 824
    invoke-virtual {v2}, Landroid/view/ActionMode;->finish()V

    .line 825
    .line 826
    .line 827
    :cond_34
    iget-object v2, v1, Ly1/f;->i:La8/y0;

    .line 828
    .line 829
    if-eqz v2, :cond_35

    .line 830
    .line 831
    invoke-virtual {v3, v2}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 832
    .line 833
    .line 834
    :cond_35
    iput-object v7, v1, Ly1/f;->h:Landroid/view/ActionMode;

    .line 835
    .line 836
    throw v0

    .line 837
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 838
    .line 839
    iget v2, v0, Lxf0/f2;->e:I

    .line 840
    .line 841
    const/4 v3, 0x1

    .line 842
    if-eqz v2, :cond_37

    .line 843
    .line 844
    if-ne v2, v3, :cond_36

    .line 845
    .line 846
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 847
    .line 848
    .line 849
    goto :goto_25

    .line 850
    :cond_36
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 851
    .line 852
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 853
    .line 854
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 855
    .line 856
    .line 857
    throw v0

    .line 858
    :cond_37
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 859
    .line 860
    .line 861
    iget-object v2, v0, Lxf0/f2;->f:Ljava/lang/Object;

    .line 862
    .line 863
    check-cast v2, Ll2/b1;

    .line 864
    .line 865
    iget-object v4, v0, Lxf0/f2;->g:Ljava/lang/Object;

    .line 866
    .line 867
    check-cast v4, Lay0/a;

    .line 868
    .line 869
    iput v3, v0, Lxf0/f2;->e:I

    .line 870
    .line 871
    invoke-static {v2, v4, v0}, Lxf0/y1;->v(Ll2/b1;Lay0/a;Lrx0/c;)Ljava/lang/Object;

    .line 872
    .line 873
    .line 874
    move-result-object v0

    .line 875
    if-ne v0, v1, :cond_38

    .line 876
    .line 877
    goto :goto_26

    .line 878
    :cond_38
    :goto_25
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 879
    .line 880
    :goto_26
    return-object v1

    .line 881
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
