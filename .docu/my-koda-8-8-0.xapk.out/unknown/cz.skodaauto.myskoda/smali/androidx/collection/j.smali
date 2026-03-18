.class public final Landroidx/collection/j;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic e:I

.field public f:[J

.field public g:I

.field public h:I

.field public i:I

.field public j:I

.field public k:J

.field public l:I

.field public synthetic m:Ljava/lang/Object;

.field public n:Ljava/lang/Object;

.field public final synthetic o:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Landroidx/collection/j;->e:I

    .line 2
    .line 3
    iput-object p1, p0, Landroidx/collection/j;->o:Ljava/lang/Object;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Landroidx/collection/j;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Landroidx/collection/j;

    .line 7
    .line 8
    iget-object p0, p0, Landroidx/collection/j;->o:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Ln2/d;

    .line 11
    .line 12
    const/4 v1, 0x3

    .line 13
    invoke-direct {v0, p0, p2, v1}, Landroidx/collection/j;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Landroidx/collection/j;

    .line 20
    .line 21
    iget-object p0, p0, Landroidx/collection/j;->o:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Landroidx/collection/e1;

    .line 24
    .line 25
    const/4 v1, 0x2

    .line 26
    invoke-direct {v0, p0, p2, v1}, Landroidx/collection/j;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_1
    new-instance v0, Landroidx/collection/j;

    .line 33
    .line 34
    iget-object p0, p0, Landroidx/collection/j;->o:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Landroidx/collection/k;

    .line 37
    .line 38
    const/4 v1, 0x1

    .line 39
    invoke-direct {v0, p0, p2, v1}, Landroidx/collection/j;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    iput-object p1, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 43
    .line 44
    return-object v0

    .line 45
    :pswitch_2
    new-instance v0, Landroidx/collection/j;

    .line 46
    .line 47
    iget-object p0, p0, Landroidx/collection/j;->o:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p0, Landroidx/collection/k;

    .line 50
    .line 51
    const/4 v1, 0x0

    .line 52
    invoke-direct {v0, p0, p2, v1}, Landroidx/collection/j;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    iput-object p1, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 56
    .line 57
    return-object v0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/j;->e:I

    .line 2
    .line 3
    check-cast p1, Lky0/k;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Landroidx/collection/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Landroidx/collection/j;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Landroidx/collection/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Landroidx/collection/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Landroidx/collection/j;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Landroidx/collection/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Landroidx/collection/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Landroidx/collection/j;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Landroidx/collection/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Landroidx/collection/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Landroidx/collection/j;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Landroidx/collection/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Landroidx/collection/j;->e:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v8, v0, Landroidx/collection/j;->o:Ljava/lang/Object;

    .line 8
    .line 9
    const-string v9, "call to \'resume\' before \'invoke\' with coroutine"

    .line 10
    .line 11
    const/4 v10, 0x1

    .line 12
    const/16 v11, 0x8

    .line 13
    .line 14
    const/4 v14, 0x0

    .line 15
    packed-switch v1, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 19
    .line 20
    iget v15, v0, Landroidx/collection/j;->l:I

    .line 21
    .line 22
    if-eqz v15, :cond_1

    .line 23
    .line 24
    if-ne v15, v10, :cond_0

    .line 25
    .line 26
    iget v8, v0, Landroidx/collection/j;->j:I

    .line 27
    .line 28
    iget v9, v0, Landroidx/collection/j;->i:I

    .line 29
    .line 30
    const-wide/16 v15, 0x80

    .line 31
    .line 32
    iget-wide v3, v0, Landroidx/collection/j;->k:J

    .line 33
    .line 34
    const-wide/16 v17, 0xff

    .line 35
    .line 36
    iget v5, v0, Landroidx/collection/j;->h:I

    .line 37
    .line 38
    iget v6, v0, Landroidx/collection/j;->g:I

    .line 39
    .line 40
    const/16 v19, 0x7

    .line 41
    .line 42
    iget-object v7, v0, Landroidx/collection/j;->f:[J

    .line 43
    .line 44
    const-wide v20, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    iget-object v12, v0, Landroidx/collection/j;->n:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v12, [Ljava/lang/Object;

    .line 52
    .line 53
    iget-object v13, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v13, Lky0/k;

    .line 56
    .line 57
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto/16 :goto_2

    .line 61
    .line 62
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 63
    .line 64
    invoke-direct {v0, v9}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw v0

    .line 68
    :cond_1
    const-wide/16 v15, 0x80

    .line 69
    .line 70
    const-wide/16 v17, 0xff

    .line 71
    .line 72
    const/16 v19, 0x7

    .line 73
    .line 74
    const-wide v20, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 75
    .line 76
    .line 77
    .line 78
    .line 79
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    iget-object v3, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v3, Lky0/k;

    .line 85
    .line 86
    check-cast v8, Ln2/d;

    .line 87
    .line 88
    iget-object v4, v8, Ln2/d;->d:Landroidx/collection/r0;

    .line 89
    .line 90
    iget-object v5, v4, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 91
    .line 92
    iget-object v4, v4, Landroidx/collection/r0;->a:[J

    .line 93
    .line 94
    array-length v6, v4

    .line 95
    add-int/lit8 v6, v6, -0x2

    .line 96
    .line 97
    if-ltz v6, :cond_5

    .line 98
    .line 99
    move v7, v14

    .line 100
    :goto_0
    aget-wide v8, v4, v7

    .line 101
    .line 102
    not-long v12, v8

    .line 103
    shl-long v12, v12, v19

    .line 104
    .line 105
    and-long/2addr v12, v8

    .line 106
    and-long v12, v12, v20

    .line 107
    .line 108
    cmp-long v12, v12, v20

    .line 109
    .line 110
    if-eqz v12, :cond_4

    .line 111
    .line 112
    sub-int v12, v7, v6

    .line 113
    .line 114
    not-int v12, v12

    .line 115
    ushr-int/lit8 v12, v12, 0x1f

    .line 116
    .line 117
    rsub-int/lit8 v12, v12, 0x8

    .line 118
    .line 119
    move-object v13, v3

    .line 120
    move/from16 v24, v7

    .line 121
    .line 122
    move-object v7, v4

    .line 123
    move-wide v3, v8

    .line 124
    move v9, v12

    .line 125
    move v8, v14

    .line 126
    move-object v12, v5

    .line 127
    move/from16 v5, v24

    .line 128
    .line 129
    :goto_1
    if-ge v8, v9, :cond_3

    .line 130
    .line 131
    and-long v22, v3, v17

    .line 132
    .line 133
    cmp-long v22, v22, v15

    .line 134
    .line 135
    if-gez v22, :cond_2

    .line 136
    .line 137
    shl-int/lit8 v2, v5, 0x3

    .line 138
    .line 139
    add-int/2addr v2, v8

    .line 140
    aget-object v2, v12, v2

    .line 141
    .line 142
    iput-object v13, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 143
    .line 144
    iput-object v12, v0, Landroidx/collection/j;->n:Ljava/lang/Object;

    .line 145
    .line 146
    iput-object v7, v0, Landroidx/collection/j;->f:[J

    .line 147
    .line 148
    iput v6, v0, Landroidx/collection/j;->g:I

    .line 149
    .line 150
    iput v5, v0, Landroidx/collection/j;->h:I

    .line 151
    .line 152
    iput-wide v3, v0, Landroidx/collection/j;->k:J

    .line 153
    .line 154
    iput v9, v0, Landroidx/collection/j;->i:I

    .line 155
    .line 156
    iput v8, v0, Landroidx/collection/j;->j:I

    .line 157
    .line 158
    iput v10, v0, Landroidx/collection/j;->l:I

    .line 159
    .line 160
    invoke-virtual {v13, v2, v0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 161
    .line 162
    .line 163
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 164
    .line 165
    move-object v2, v1

    .line 166
    goto :goto_3

    .line 167
    :cond_2
    :goto_2
    shr-long/2addr v3, v11

    .line 168
    add-int/2addr v8, v10

    .line 169
    goto :goto_1

    .line 170
    :cond_3
    if-ne v9, v11, :cond_5

    .line 171
    .line 172
    move-object v4, v7

    .line 173
    move-object v3, v13

    .line 174
    move v7, v5

    .line 175
    move-object v5, v12

    .line 176
    :cond_4
    if-eq v7, v6, :cond_5

    .line 177
    .line 178
    add-int/lit8 v7, v7, 0x1

    .line 179
    .line 180
    goto :goto_0

    .line 181
    :cond_5
    :goto_3
    return-object v2

    .line 182
    :pswitch_0
    const-wide/16 v15, 0x80

    .line 183
    .line 184
    const-wide/16 v17, 0xff

    .line 185
    .line 186
    const/16 v19, 0x7

    .line 187
    .line 188
    const-wide v20, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 189
    .line 190
    .line 191
    .line 192
    .line 193
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 194
    .line 195
    iget v3, v0, Landroidx/collection/j;->l:I

    .line 196
    .line 197
    if-eqz v3, :cond_7

    .line 198
    .line 199
    if-ne v3, v10, :cond_6

    .line 200
    .line 201
    iget v3, v0, Landroidx/collection/j;->j:I

    .line 202
    .line 203
    iget v4, v0, Landroidx/collection/j;->i:I

    .line 204
    .line 205
    iget-wide v5, v0, Landroidx/collection/j;->k:J

    .line 206
    .line 207
    iget v7, v0, Landroidx/collection/j;->h:I

    .line 208
    .line 209
    iget v8, v0, Landroidx/collection/j;->g:I

    .line 210
    .line 211
    iget-object v9, v0, Landroidx/collection/j;->f:[J

    .line 212
    .line 213
    iget-object v12, v0, Landroidx/collection/j;->n:Ljava/lang/Object;

    .line 214
    .line 215
    check-cast v12, [Ljava/lang/Object;

    .line 216
    .line 217
    iget-object v13, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 218
    .line 219
    check-cast v13, Lky0/k;

    .line 220
    .line 221
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    goto :goto_6

    .line 225
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 226
    .line 227
    invoke-direct {v0, v9}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    throw v0

    .line 231
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    iget-object v3, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 235
    .line 236
    check-cast v3, Lky0/k;

    .line 237
    .line 238
    check-cast v8, Landroidx/collection/e1;

    .line 239
    .line 240
    iget-object v4, v8, Landroidx/collection/e1;->e:Ljava/lang/Object;

    .line 241
    .line 242
    check-cast v4, Landroidx/collection/q0;

    .line 243
    .line 244
    iget-object v5, v4, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 245
    .line 246
    iget-object v4, v4, Landroidx/collection/q0;->a:[J

    .line 247
    .line 248
    array-length v6, v4

    .line 249
    add-int/lit8 v6, v6, -0x2

    .line 250
    .line 251
    if-ltz v6, :cond_b

    .line 252
    .line 253
    move v7, v14

    .line 254
    :goto_4
    aget-wide v8, v4, v7

    .line 255
    .line 256
    not-long v12, v8

    .line 257
    shl-long v12, v12, v19

    .line 258
    .line 259
    and-long/2addr v12, v8

    .line 260
    and-long v12, v12, v20

    .line 261
    .line 262
    cmp-long v12, v12, v20

    .line 263
    .line 264
    if-eqz v12, :cond_a

    .line 265
    .line 266
    sub-int v12, v7, v6

    .line 267
    .line 268
    not-int v12, v12

    .line 269
    ushr-int/lit8 v12, v12, 0x1f

    .line 270
    .line 271
    rsub-int/lit8 v12, v12, 0x8

    .line 272
    .line 273
    move-object v13, v3

    .line 274
    move v3, v14

    .line 275
    move-wide/from16 v24, v8

    .line 276
    .line 277
    move-object v9, v4

    .line 278
    move v8, v6

    .line 279
    move v4, v12

    .line 280
    move-object v12, v5

    .line 281
    move-wide/from16 v5, v24

    .line 282
    .line 283
    :goto_5
    if-ge v3, v4, :cond_9

    .line 284
    .line 285
    and-long v22, v5, v17

    .line 286
    .line 287
    cmp-long v22, v22, v15

    .line 288
    .line 289
    if-gez v22, :cond_8

    .line 290
    .line 291
    shl-int/lit8 v2, v7, 0x3

    .line 292
    .line 293
    add-int/2addr v2, v3

    .line 294
    aget-object v2, v12, v2

    .line 295
    .line 296
    iput-object v13, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 297
    .line 298
    iput-object v12, v0, Landroidx/collection/j;->n:Ljava/lang/Object;

    .line 299
    .line 300
    iput-object v9, v0, Landroidx/collection/j;->f:[J

    .line 301
    .line 302
    iput v8, v0, Landroidx/collection/j;->g:I

    .line 303
    .line 304
    iput v7, v0, Landroidx/collection/j;->h:I

    .line 305
    .line 306
    iput-wide v5, v0, Landroidx/collection/j;->k:J

    .line 307
    .line 308
    iput v4, v0, Landroidx/collection/j;->i:I

    .line 309
    .line 310
    iput v3, v0, Landroidx/collection/j;->j:I

    .line 311
    .line 312
    iput v10, v0, Landroidx/collection/j;->l:I

    .line 313
    .line 314
    invoke-virtual {v13, v2, v0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 315
    .line 316
    .line 317
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 318
    .line 319
    move-object v2, v1

    .line 320
    goto :goto_7

    .line 321
    :cond_8
    :goto_6
    shr-long/2addr v5, v11

    .line 322
    add-int/2addr v3, v10

    .line 323
    goto :goto_5

    .line 324
    :cond_9
    if-ne v4, v11, :cond_b

    .line 325
    .line 326
    move v6, v8

    .line 327
    move-object v4, v9

    .line 328
    move-object v5, v12

    .line 329
    move-object v3, v13

    .line 330
    :cond_a
    if-eq v7, v6, :cond_b

    .line 331
    .line 332
    add-int/lit8 v7, v7, 0x1

    .line 333
    .line 334
    goto :goto_4

    .line 335
    :cond_b
    :goto_7
    return-object v2

    .line 336
    :pswitch_1
    const-wide/16 v15, 0x80

    .line 337
    .line 338
    const-wide/16 v17, 0xff

    .line 339
    .line 340
    const/16 v19, 0x7

    .line 341
    .line 342
    const-wide v20, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 343
    .line 344
    .line 345
    .line 346
    .line 347
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 348
    .line 349
    iget v3, v0, Landroidx/collection/j;->l:I

    .line 350
    .line 351
    if-eqz v3, :cond_d

    .line 352
    .line 353
    if-ne v3, v10, :cond_c

    .line 354
    .line 355
    iget v3, v0, Landroidx/collection/j;->j:I

    .line 356
    .line 357
    iget v4, v0, Landroidx/collection/j;->i:I

    .line 358
    .line 359
    iget-wide v5, v0, Landroidx/collection/j;->k:J

    .line 360
    .line 361
    iget v7, v0, Landroidx/collection/j;->h:I

    .line 362
    .line 363
    iget v8, v0, Landroidx/collection/j;->g:I

    .line 364
    .line 365
    iget-object v9, v0, Landroidx/collection/j;->f:[J

    .line 366
    .line 367
    iget-object v12, v0, Landroidx/collection/j;->n:Ljava/lang/Object;

    .line 368
    .line 369
    check-cast v12, [Ljava/lang/Object;

    .line 370
    .line 371
    iget-object v13, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 372
    .line 373
    check-cast v13, Lky0/k;

    .line 374
    .line 375
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 376
    .line 377
    .line 378
    goto :goto_a

    .line 379
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 380
    .line 381
    invoke-direct {v0, v9}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 382
    .line 383
    .line 384
    throw v0

    .line 385
    :cond_d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 386
    .line 387
    .line 388
    iget-object v3, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 389
    .line 390
    check-cast v3, Lky0/k;

    .line 391
    .line 392
    check-cast v8, Landroidx/collection/k;

    .line 393
    .line 394
    iget-object v4, v8, Landroidx/collection/k;->e:Landroidx/collection/q0;

    .line 395
    .line 396
    iget-object v5, v4, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 397
    .line 398
    iget-object v4, v4, Landroidx/collection/q0;->a:[J

    .line 399
    .line 400
    array-length v6, v4

    .line 401
    add-int/lit8 v6, v6, -0x2

    .line 402
    .line 403
    if-ltz v6, :cond_11

    .line 404
    .line 405
    move v7, v14

    .line 406
    :goto_8
    aget-wide v8, v4, v7

    .line 407
    .line 408
    not-long v12, v8

    .line 409
    shl-long v12, v12, v19

    .line 410
    .line 411
    and-long/2addr v12, v8

    .line 412
    and-long v12, v12, v20

    .line 413
    .line 414
    cmp-long v12, v12, v20

    .line 415
    .line 416
    if-eqz v12, :cond_10

    .line 417
    .line 418
    sub-int v12, v7, v6

    .line 419
    .line 420
    not-int v12, v12

    .line 421
    ushr-int/lit8 v12, v12, 0x1f

    .line 422
    .line 423
    rsub-int/lit8 v12, v12, 0x8

    .line 424
    .line 425
    move-object v13, v3

    .line 426
    move v3, v14

    .line 427
    move-wide/from16 v24, v8

    .line 428
    .line 429
    move-object v9, v4

    .line 430
    move v8, v6

    .line 431
    move v4, v12

    .line 432
    move-object v12, v5

    .line 433
    move-wide/from16 v5, v24

    .line 434
    .line 435
    :goto_9
    if-ge v3, v4, :cond_f

    .line 436
    .line 437
    and-long v22, v5, v17

    .line 438
    .line 439
    cmp-long v22, v22, v15

    .line 440
    .line 441
    if-gez v22, :cond_e

    .line 442
    .line 443
    shl-int/lit8 v2, v7, 0x3

    .line 444
    .line 445
    add-int/2addr v2, v3

    .line 446
    aget-object v2, v12, v2

    .line 447
    .line 448
    iput-object v13, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 449
    .line 450
    iput-object v12, v0, Landroidx/collection/j;->n:Ljava/lang/Object;

    .line 451
    .line 452
    iput-object v9, v0, Landroidx/collection/j;->f:[J

    .line 453
    .line 454
    iput v8, v0, Landroidx/collection/j;->g:I

    .line 455
    .line 456
    iput v7, v0, Landroidx/collection/j;->h:I

    .line 457
    .line 458
    iput-wide v5, v0, Landroidx/collection/j;->k:J

    .line 459
    .line 460
    iput v4, v0, Landroidx/collection/j;->i:I

    .line 461
    .line 462
    iput v3, v0, Landroidx/collection/j;->j:I

    .line 463
    .line 464
    iput v10, v0, Landroidx/collection/j;->l:I

    .line 465
    .line 466
    invoke-virtual {v13, v2, v0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 467
    .line 468
    .line 469
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 470
    .line 471
    move-object v2, v1

    .line 472
    goto :goto_b

    .line 473
    :cond_e
    :goto_a
    shr-long/2addr v5, v11

    .line 474
    add-int/2addr v3, v10

    .line 475
    goto :goto_9

    .line 476
    :cond_f
    if-ne v4, v11, :cond_11

    .line 477
    .line 478
    move v6, v8

    .line 479
    move-object v4, v9

    .line 480
    move-object v5, v12

    .line 481
    move-object v3, v13

    .line 482
    :cond_10
    if-eq v7, v6, :cond_11

    .line 483
    .line 484
    add-int/lit8 v7, v7, 0x1

    .line 485
    .line 486
    goto :goto_8

    .line 487
    :cond_11
    :goto_b
    return-object v2

    .line 488
    :pswitch_2
    const-wide/16 v15, 0x80

    .line 489
    .line 490
    const-wide/16 v17, 0xff

    .line 491
    .line 492
    const/16 v19, 0x7

    .line 493
    .line 494
    const-wide v20, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 495
    .line 496
    .line 497
    .line 498
    .line 499
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 500
    .line 501
    iget v3, v0, Landroidx/collection/j;->l:I

    .line 502
    .line 503
    if-eqz v3, :cond_13

    .line 504
    .line 505
    if-ne v3, v10, :cond_12

    .line 506
    .line 507
    iget v3, v0, Landroidx/collection/j;->j:I

    .line 508
    .line 509
    iget v4, v0, Landroidx/collection/j;->i:I

    .line 510
    .line 511
    iget-wide v5, v0, Landroidx/collection/j;->k:J

    .line 512
    .line 513
    iget v7, v0, Landroidx/collection/j;->h:I

    .line 514
    .line 515
    iget v8, v0, Landroidx/collection/j;->g:I

    .line 516
    .line 517
    iget-object v9, v0, Landroidx/collection/j;->f:[J

    .line 518
    .line 519
    iget-object v12, v0, Landroidx/collection/j;->n:Ljava/lang/Object;

    .line 520
    .line 521
    check-cast v12, Landroidx/collection/k;

    .line 522
    .line 523
    iget-object v13, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 524
    .line 525
    check-cast v13, Lky0/k;

    .line 526
    .line 527
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 528
    .line 529
    .line 530
    move/from16 v24, v8

    .line 531
    .line 532
    move v8, v7

    .line 533
    move v7, v11

    .line 534
    move-object v11, v9

    .line 535
    move v9, v10

    .line 536
    move/from16 v10, v24

    .line 537
    .line 538
    goto/16 :goto_e

    .line 539
    .line 540
    :cond_12
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 541
    .line 542
    invoke-direct {v0, v9}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 543
    .line 544
    .line 545
    throw v0

    .line 546
    :cond_13
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 547
    .line 548
    .line 549
    iget-object v3, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 550
    .line 551
    check-cast v3, Lky0/k;

    .line 552
    .line 553
    check-cast v8, Landroidx/collection/k;

    .line 554
    .line 555
    iget-object v4, v8, Landroidx/collection/k;->e:Landroidx/collection/q0;

    .line 556
    .line 557
    iget-object v4, v4, Landroidx/collection/q0;->a:[J

    .line 558
    .line 559
    array-length v5, v4

    .line 560
    add-int/lit8 v5, v5, -0x2

    .line 561
    .line 562
    if-ltz v5, :cond_17

    .line 563
    .line 564
    move v6, v14

    .line 565
    :goto_c
    aget-wide v12, v4, v6

    .line 566
    .line 567
    move v7, v11

    .line 568
    not-long v10, v12

    .line 569
    shl-long v10, v10, v19

    .line 570
    .line 571
    and-long/2addr v10, v12

    .line 572
    and-long v10, v10, v20

    .line 573
    .line 574
    cmp-long v10, v10, v20

    .line 575
    .line 576
    if-eqz v10, :cond_16

    .line 577
    .line 578
    sub-int v10, v6, v5

    .line 579
    .line 580
    not-int v10, v10

    .line 581
    ushr-int/lit8 v10, v10, 0x1f

    .line 582
    .line 583
    rsub-int/lit8 v11, v10, 0x8

    .line 584
    .line 585
    move v10, v11

    .line 586
    move-object v11, v4

    .line 587
    move v4, v10

    .line 588
    move v10, v5

    .line 589
    move-wide/from16 v24, v12

    .line 590
    .line 591
    move-object v13, v3

    .line 592
    move-object v12, v8

    .line 593
    move v3, v14

    .line 594
    move v8, v6

    .line 595
    move-wide/from16 v5, v24

    .line 596
    .line 597
    :goto_d
    if-ge v3, v4, :cond_15

    .line 598
    .line 599
    and-long v22, v5, v17

    .line 600
    .line 601
    cmp-long v22, v22, v15

    .line 602
    .line 603
    if-gez v22, :cond_14

    .line 604
    .line 605
    shl-int/lit8 v2, v8, 0x3

    .line 606
    .line 607
    add-int/2addr v2, v3

    .line 608
    new-instance v7, Landroidx/collection/x;

    .line 609
    .line 610
    iget-object v15, v12, Landroidx/collection/k;->e:Landroidx/collection/q0;

    .line 611
    .line 612
    iget-object v9, v15, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 613
    .line 614
    aget-object v9, v9, v2

    .line 615
    .line 616
    iget-object v15, v15, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 617
    .line 618
    aget-object v2, v15, v2

    .line 619
    .line 620
    invoke-direct {v7, v14, v9, v2}, Landroidx/collection/x;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 621
    .line 622
    .line 623
    iput-object v13, v0, Landroidx/collection/j;->m:Ljava/lang/Object;

    .line 624
    .line 625
    iput-object v12, v0, Landroidx/collection/j;->n:Ljava/lang/Object;

    .line 626
    .line 627
    iput-object v11, v0, Landroidx/collection/j;->f:[J

    .line 628
    .line 629
    iput v10, v0, Landroidx/collection/j;->g:I

    .line 630
    .line 631
    iput v8, v0, Landroidx/collection/j;->h:I

    .line 632
    .line 633
    iput-wide v5, v0, Landroidx/collection/j;->k:J

    .line 634
    .line 635
    iput v4, v0, Landroidx/collection/j;->i:I

    .line 636
    .line 637
    iput v3, v0, Landroidx/collection/j;->j:I

    .line 638
    .line 639
    const/4 v9, 0x1

    .line 640
    iput v9, v0, Landroidx/collection/j;->l:I

    .line 641
    .line 642
    invoke-virtual {v13, v7, v0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 643
    .line 644
    .line 645
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 646
    .line 647
    move-object v2, v1

    .line 648
    goto :goto_10

    .line 649
    :cond_14
    const/4 v9, 0x1

    .line 650
    :goto_e
    shr-long/2addr v5, v7

    .line 651
    add-int/2addr v3, v9

    .line 652
    goto :goto_d

    .line 653
    :cond_15
    const/4 v9, 0x1

    .line 654
    if-ne v4, v7, :cond_17

    .line 655
    .line 656
    move v6, v8

    .line 657
    move v5, v10

    .line 658
    move-object v4, v11

    .line 659
    move-object v8, v12

    .line 660
    move-object v3, v13

    .line 661
    goto :goto_f

    .line 662
    :cond_16
    const/4 v9, 0x1

    .line 663
    :goto_f
    if-eq v6, v5, :cond_17

    .line 664
    .line 665
    add-int/lit8 v6, v6, 0x1

    .line 666
    .line 667
    move v11, v7

    .line 668
    move v10, v9

    .line 669
    goto :goto_c

    .line 670
    :cond_17
    :goto_10
    return-object v2

    .line 671
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
