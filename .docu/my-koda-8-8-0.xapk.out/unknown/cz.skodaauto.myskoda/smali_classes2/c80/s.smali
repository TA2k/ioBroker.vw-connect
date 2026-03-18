.class public final Lc80/s;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:J

.field public f:I

.field public synthetic g:J

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(JLql0/j;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Lc80/s;->d:I

    iput-wide p1, p0, Lc80/s;->g:J

    iput-object p3, p0, Lc80/s;->h:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lc1/c;JJLkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lc80/s;->d:I

    .line 2
    iput-object p1, p0, Lc80/s;->h:Ljava/lang/Object;

    iput-wide p2, p0, Lc80/s;->e:J

    iput-wide p4, p0, Lc80/s;->g:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lg1/u2;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lc80/s;->d:I

    .line 3
    iput-object p1, p0, Lc80/s;->h:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 9

    .line 1
    iget v0, p0, Lc80/s;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lc80/s;

    .line 7
    .line 8
    iget-wide v2, p0, Lc80/s;->g:J

    .line 9
    .line 10
    iget-object p0, p0, Lc80/s;->h:Ljava/lang/Object;

    .line 11
    .line 12
    move-object v4, p0

    .line 13
    check-cast v4, Lw40/j;

    .line 14
    .line 15
    const/4 v6, 0x3

    .line 16
    move-object v5, p2

    .line 17
    invoke-direct/range {v1 .. v6}, Lc80/s;-><init>(JLql0/j;Lkotlin/coroutines/Continuation;I)V

    .line 18
    .line 19
    .line 20
    return-object v1

    .line 21
    :pswitch_0
    move-object v5, p2

    .line 22
    new-instance v2, Lc80/s;

    .line 23
    .line 24
    iget-object p1, p0, Lc80/s;->h:Ljava/lang/Object;

    .line 25
    .line 26
    move-object v3, p1

    .line 27
    check-cast v3, Lc1/c;

    .line 28
    .line 29
    move-object v6, v5

    .line 30
    iget-wide v4, p0, Lc80/s;->e:J

    .line 31
    .line 32
    move-object v8, v6

    .line 33
    iget-wide v6, p0, Lc80/s;->g:J

    .line 34
    .line 35
    invoke-direct/range {v2 .. v8}, Lc80/s;-><init>(Lc1/c;JJLkotlin/coroutines/Continuation;)V

    .line 36
    .line 37
    .line 38
    return-object v2

    .line 39
    :pswitch_1
    move-object v5, p2

    .line 40
    new-instance p2, Lc80/s;

    .line 41
    .line 42
    iget-object p0, p0, Lc80/s;->h:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Lg1/u2;

    .line 45
    .line 46
    invoke-direct {p2, p0, v5}, Lc80/s;-><init>(Lg1/u2;Lkotlin/coroutines/Continuation;)V

    .line 47
    .line 48
    .line 49
    check-cast p1, Lt4/q;

    .line 50
    .line 51
    iget-wide p0, p1, Lt4/q;->a:J

    .line 52
    .line 53
    iput-wide p0, p2, Lc80/s;->g:J

    .line 54
    .line 55
    return-object p2

    .line 56
    :pswitch_2
    move-object v5, p2

    .line 57
    new-instance v2, Lc80/s;

    .line 58
    .line 59
    iget-wide v3, p0, Lc80/s;->g:J

    .line 60
    .line 61
    iget-object p0, p0, Lc80/s;->h:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p0, Lc80/t;

    .line 64
    .line 65
    const/4 v7, 0x0

    .line 66
    move-object v6, v5

    .line 67
    move-object v5, p0

    .line 68
    invoke-direct/range {v2 .. v7}, Lc80/s;-><init>(JLql0/j;Lkotlin/coroutines/Continuation;I)V

    .line 69
    .line 70
    .line 71
    return-object v2

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lc80/s;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lc80/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc80/s;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc80/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lvy0/b0;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lc80/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lc80/s;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lc80/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lt4/q;

    .line 41
    .line 42
    iget-wide v0, p1, Lt4/q;->a:J

    .line 43
    .line 44
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    new-instance p1, Lc80/s;

    .line 47
    .line 48
    iget-object p0, p0, Lc80/s;->h:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p0, Lg1/u2;

    .line 51
    .line 52
    invoke-direct {p1, p0, p2}, Lc80/s;-><init>(Lg1/u2;Lkotlin/coroutines/Continuation;)V

    .line 53
    .line 54
    .line 55
    iput-wide v0, p1, Lc80/s;->g:J

    .line 56
    .line 57
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 58
    .line 59
    invoke-virtual {p1, p0}, Lc80/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    :pswitch_2
    check-cast p1, Lvy0/b0;

    .line 65
    .line 66
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 67
    .line 68
    invoke-virtual {p0, p1, p2}, Lc80/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    check-cast p0, Lc80/s;

    .line 73
    .line 74
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 75
    .line 76
    invoke-virtual {p0, p1}, Lc80/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v5, p0

    .line 2
    .line 3
    iget v0, v5, Lc80/s;->d:I

    .line 4
    .line 5
    const/4 v7, 0x0

    .line 6
    const/4 v8, 0x2

    .line 7
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    iget-object v10, v5, Lc80/s;->h:Ljava/lang/Object;

    .line 13
    .line 14
    packed-switch v0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    move-object v0, v10

    .line 18
    check-cast v0, Lw40/j;

    .line 19
    .line 20
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    iget v4, v5, Lc80/s;->f:I

    .line 23
    .line 24
    if-eqz v4, :cond_2

    .line 25
    .line 26
    if-eq v4, v2, :cond_1

    .line 27
    .line 28
    if-ne v4, v8, :cond_0

    .line 29
    .line 30
    iget-wide v10, v5, Lc80/s;->e:J

    .line 31
    .line 32
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    move-object v2, v3

    .line 36
    goto/16 :goto_4

    .line 37
    .line 38
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 39
    .line 40
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw v0

    .line 44
    :cond_1
    iget-wide v10, v5, Lc80/s;->e:J

    .line 45
    .line 46
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    move-object v2, v3

    .line 50
    goto :goto_2

    .line 51
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-wide v10, v5, Lc80/s;->g:J

    .line 55
    .line 56
    :goto_0
    sget v1, Lw40/j;->n:I

    .line 57
    .line 58
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    move-object v12, v1

    .line 63
    check-cast v12, Lw40/i;

    .line 64
    .line 65
    iget-object v1, v0, Lw40/j;->k:Lij0/a;

    .line 66
    .line 67
    invoke-static {v10, v11, v1, v7, v8}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v14

    .line 71
    sget v1, Lmy0/c;->g:I

    .line 72
    .line 73
    const/16 v1, 0xf

    .line 74
    .line 75
    sget-object v4, Lmy0/e;->i:Lmy0/e;

    .line 76
    .line 77
    invoke-static {v1, v4}, Lmy0/h;->s(ILmy0/e;)J

    .line 78
    .line 79
    .line 80
    move-result-wide v7

    .line 81
    const/16 v1, 0x3b

    .line 82
    .line 83
    sget-object v4, Lmy0/e;->h:Lmy0/e;

    .line 84
    .line 85
    move-object/from16 v19, v3

    .line 86
    .line 87
    invoke-static {v1, v4}, Lmy0/h;->s(ILmy0/e;)J

    .line 88
    .line 89
    .line 90
    move-result-wide v2

    .line 91
    invoke-static {v7, v8, v2, v3}, Lmy0/c;->k(JJ)J

    .line 92
    .line 93
    .line 94
    move-result-wide v1

    .line 95
    invoke-static {v10, v11, v1, v2}, Lmy0/c;->c(JJ)I

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    if-gtz v1, :cond_3

    .line 100
    .line 101
    const/16 v16, 0x1

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_3
    const/16 v16, 0x0

    .line 105
    .line 106
    :goto_1
    const/16 v17, 0x5

    .line 107
    .line 108
    const/4 v13, 0x0

    .line 109
    const/4 v15, 0x0

    .line 110
    invoke-static/range {v12 .. v17}, Lw40/i;->a(Lw40/i;Ljava/lang/String;Ljava/lang/String;ZZI)Lw40/i;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 115
    .line 116
    .line 117
    sget-wide v1, Lw40/j;->m:J

    .line 118
    .line 119
    invoke-static {v10, v11, v1, v2}, Lmy0/c;->j(JJ)J

    .line 120
    .line 121
    .line 122
    move-result-wide v3

    .line 123
    invoke-static {v1, v2}, Lmy0/c;->e(J)J

    .line 124
    .line 125
    .line 126
    move-result-wide v1

    .line 127
    iput-wide v3, v5, Lc80/s;->e:J

    .line 128
    .line 129
    const/4 v6, 0x1

    .line 130
    iput v6, v5, Lc80/s;->f:I

    .line 131
    .line 132
    invoke-static {v1, v2, v5}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    move-object/from16 v2, v19

    .line 137
    .line 138
    if-ne v1, v2, :cond_4

    .line 139
    .line 140
    goto :goto_3

    .line 141
    :cond_4
    move-wide v10, v3

    .line 142
    :goto_2
    invoke-static {v10, v11}, Lmy0/c;->e(J)J

    .line 143
    .line 144
    .line 145
    move-result-wide v3

    .line 146
    const-wide/16 v7, 0x0

    .line 147
    .line 148
    cmp-long v1, v3, v7

    .line 149
    .line 150
    if-gtz v1, :cond_5

    .line 151
    .line 152
    iget-object v1, v0, Lw40/j;->j:Lnn0/m;

    .line 153
    .line 154
    iput-wide v10, v5, Lc80/s;->e:J

    .line 155
    .line 156
    const/4 v3, 0x2

    .line 157
    iput v3, v5, Lc80/s;->f:I

    .line 158
    .line 159
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 160
    .line 161
    .line 162
    invoke-virtual {v1, v5}, Lnn0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    if-ne v1, v2, :cond_5

    .line 167
    .line 168
    :goto_3
    move-object v9, v2

    .line 169
    goto :goto_5

    .line 170
    :cond_5
    :goto_4
    invoke-static {v10, v11}, Lmy0/c;->i(J)Z

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    if-nez v1, :cond_6

    .line 175
    .line 176
    :goto_5
    return-object v9

    .line 177
    :cond_6
    move-object v3, v2

    .line 178
    const/4 v2, 0x1

    .line 179
    const/4 v7, 0x0

    .line 180
    const/4 v8, 0x2

    .line 181
    goto :goto_0

    .line 182
    :pswitch_0
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 183
    .line 184
    iget v0, v5, Lc80/s;->f:I

    .line 185
    .line 186
    const/4 v8, 0x6

    .line 187
    const/16 v11, 0x3e8

    .line 188
    .line 189
    const/4 v12, 0x0

    .line 190
    if-eqz v0, :cond_9

    .line 191
    .line 192
    const/4 v6, 0x1

    .line 193
    if-eq v0, v6, :cond_8

    .line 194
    .line 195
    const/4 v3, 0x2

    .line 196
    if-ne v0, v3, :cond_7

    .line 197
    .line 198
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    goto :goto_8

    .line 202
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 203
    .line 204
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    throw v0

    .line 208
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    goto :goto_6

    .line 212
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 213
    .line 214
    .line 215
    move-object v0, v10

    .line 216
    check-cast v0, Lc1/c;

    .line 217
    .line 218
    iget-wide v1, v5, Lc80/s;->e:J

    .line 219
    .line 220
    new-instance v3, Le3/s;

    .line 221
    .line 222
    invoke-direct {v3, v1, v2}, Le3/s;-><init>(J)V

    .line 223
    .line 224
    .line 225
    const/4 v1, 0x0

    .line 226
    invoke-static {v11, v1, v12, v8}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 227
    .line 228
    .line 229
    move-result-object v2

    .line 230
    const/4 v6, 0x1

    .line 231
    iput v6, v5, Lc80/s;->f:I

    .line 232
    .line 233
    move-object v1, v3

    .line 234
    const/4 v3, 0x0

    .line 235
    const/4 v4, 0x0

    .line 236
    const/16 v6, 0xc

    .line 237
    .line 238
    invoke-static/range {v0 .. v6}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v0

    .line 242
    if-ne v0, v7, :cond_a

    .line 243
    .line 244
    goto :goto_7

    .line 245
    :cond_a
    :goto_6
    move-object v0, v10

    .line 246
    check-cast v0, Lc1/c;

    .line 247
    .line 248
    iget-wide v1, v5, Lc80/s;->g:J

    .line 249
    .line 250
    new-instance v3, Le3/s;

    .line 251
    .line 252
    invoke-direct {v3, v1, v2}, Le3/s;-><init>(J)V

    .line 253
    .line 254
    .line 255
    const/4 v1, 0x0

    .line 256
    invoke-static {v11, v1, v12, v8}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 257
    .line 258
    .line 259
    move-result-object v2

    .line 260
    const/4 v1, 0x2

    .line 261
    iput v1, v5, Lc80/s;->f:I

    .line 262
    .line 263
    move-object v1, v3

    .line 264
    const/4 v3, 0x0

    .line 265
    const/4 v4, 0x0

    .line 266
    const/16 v6, 0xc

    .line 267
    .line 268
    invoke-static/range {v0 .. v6}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    if-ne v0, v7, :cond_b

    .line 273
    .line 274
    :goto_7
    move-object v9, v7

    .line 275
    :cond_b
    :goto_8
    return-object v9

    .line 276
    :pswitch_1
    check-cast v10, Lg1/u2;

    .line 277
    .line 278
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 279
    .line 280
    iget v0, v5, Lc80/s;->f:I

    .line 281
    .line 282
    const/4 v2, 0x3

    .line 283
    if-eqz v0, :cond_f

    .line 284
    .line 285
    const/4 v6, 0x1

    .line 286
    if-eq v0, v6, :cond_e

    .line 287
    .line 288
    const/4 v3, 0x2

    .line 289
    if-eq v0, v3, :cond_d

    .line 290
    .line 291
    if-ne v0, v2, :cond_c

    .line 292
    .line 293
    iget-wide v0, v5, Lc80/s;->e:J

    .line 294
    .line 295
    iget-wide v2, v5, Lc80/s;->g:J

    .line 296
    .line 297
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 298
    .line 299
    .line 300
    move-wide v8, v2

    .line 301
    move-wide v3, v0

    .line 302
    move-object/from16 v0, p1

    .line 303
    .line 304
    goto :goto_b

    .line 305
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 306
    .line 307
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    throw v0

    .line 311
    :cond_d
    iget-wide v0, v5, Lc80/s;->e:J

    .line 312
    .line 313
    iget-wide v3, v5, Lc80/s;->g:J

    .line 314
    .line 315
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 316
    .line 317
    .line 318
    move-object/from16 v6, p1

    .line 319
    .line 320
    move-wide v8, v3

    .line 321
    goto :goto_a

    .line 322
    :cond_e
    iget-wide v0, v5, Lc80/s;->g:J

    .line 323
    .line 324
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 325
    .line 326
    .line 327
    move-object/from16 v3, p1

    .line 328
    .line 329
    goto :goto_9

    .line 330
    :cond_f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 331
    .line 332
    .line 333
    iget-wide v0, v5, Lc80/s;->g:J

    .line 334
    .line 335
    iget-object v3, v10, Lg1/u2;->f:Lo3/d;

    .line 336
    .line 337
    iput-wide v0, v5, Lc80/s;->g:J

    .line 338
    .line 339
    const/4 v6, 0x1

    .line 340
    iput v6, v5, Lc80/s;->f:I

    .line 341
    .line 342
    invoke-virtual {v3, v0, v1, v5}, Lo3/d;->b(JLrx0/c;)Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object v3

    .line 346
    if-ne v3, v7, :cond_10

    .line 347
    .line 348
    goto :goto_c

    .line 349
    :cond_10
    :goto_9
    check-cast v3, Lt4/q;

    .line 350
    .line 351
    iget-wide v3, v3, Lt4/q;->a:J

    .line 352
    .line 353
    invoke-static {v0, v1, v3, v4}, Lt4/q;->d(JJ)J

    .line 354
    .line 355
    .line 356
    move-result-wide v3

    .line 357
    iput-wide v0, v5, Lc80/s;->g:J

    .line 358
    .line 359
    iput-wide v3, v5, Lc80/s;->e:J

    .line 360
    .line 361
    const/4 v6, 0x2

    .line 362
    iput v6, v5, Lc80/s;->f:I

    .line 363
    .line 364
    invoke-virtual {v10, v3, v4, v5}, Lg1/u2;->a(JLrx0/c;)Ljava/lang/Object;

    .line 365
    .line 366
    .line 367
    move-result-object v6

    .line 368
    if-ne v6, v7, :cond_11

    .line 369
    .line 370
    goto :goto_c

    .line 371
    :cond_11
    move-wide v8, v0

    .line 372
    move-wide v0, v3

    .line 373
    :goto_a
    check-cast v6, Lt4/q;

    .line 374
    .line 375
    iget-wide v3, v6, Lt4/q;->a:J

    .line 376
    .line 377
    iget-object v6, v10, Lg1/u2;->f:Lo3/d;

    .line 378
    .line 379
    invoke-static {v0, v1, v3, v4}, Lt4/q;->d(JJ)J

    .line 380
    .line 381
    .line 382
    move-result-wide v0

    .line 383
    iput-wide v8, v5, Lc80/s;->g:J

    .line 384
    .line 385
    iput-wide v3, v5, Lc80/s;->e:J

    .line 386
    .line 387
    iput v2, v5, Lc80/s;->f:I

    .line 388
    .line 389
    move-wide v1, v0

    .line 390
    move-object v0, v6

    .line 391
    invoke-virtual/range {v0 .. v5}, Lo3/d;->a(JJLrx0/c;)Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v0

    .line 395
    if-ne v0, v7, :cond_12

    .line 396
    .line 397
    goto :goto_c

    .line 398
    :cond_12
    :goto_b
    check-cast v0, Lt4/q;

    .line 399
    .line 400
    iget-wide v0, v0, Lt4/q;->a:J

    .line 401
    .line 402
    invoke-static {v3, v4, v0, v1}, Lt4/q;->d(JJ)J

    .line 403
    .line 404
    .line 405
    move-result-wide v0

    .line 406
    invoke-static {v8, v9, v0, v1}, Lt4/q;->d(JJ)J

    .line 407
    .line 408
    .line 409
    move-result-wide v0

    .line 410
    new-instance v7, Lt4/q;

    .line 411
    .line 412
    invoke-direct {v7, v0, v1}, Lt4/q;-><init>(J)V

    .line 413
    .line 414
    .line 415
    :goto_c
    return-object v7

    .line 416
    :pswitch_2
    check-cast v10, Lc80/t;

    .line 417
    .line 418
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 419
    .line 420
    iget v2, v5, Lc80/s;->f:I

    .line 421
    .line 422
    if-eqz v2, :cond_14

    .line 423
    .line 424
    const/4 v6, 0x1

    .line 425
    if-ne v2, v6, :cond_13

    .line 426
    .line 427
    iget-wide v1, v5, Lc80/s;->e:J

    .line 428
    .line 429
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 430
    .line 431
    .line 432
    const/4 v6, 0x1

    .line 433
    goto :goto_d

    .line 434
    :cond_13
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 435
    .line 436
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 437
    .line 438
    .line 439
    throw v0

    .line 440
    :cond_14
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 441
    .line 442
    .line 443
    iget-wide v1, v5, Lc80/s;->g:J

    .line 444
    .line 445
    :cond_15
    sget v3, Lc80/t;->p:I

    .line 446
    .line 447
    invoke-virtual {v10}, Lql0/j;->a()Lql0/h;

    .line 448
    .line 449
    .line 450
    move-result-object v3

    .line 451
    move-object v11, v3

    .line 452
    check-cast v11, Lc80/r;

    .line 453
    .line 454
    iget-object v3, v10, Lc80/t;->h:Lij0/a;

    .line 455
    .line 456
    const/4 v4, 0x4

    .line 457
    const/4 v6, 0x1

    .line 458
    invoke-static {v1, v2, v3, v6, v4}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 459
    .line 460
    .line 461
    move-result-object v4

    .line 462
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 463
    .line 464
    .line 465
    move-result-object v4

    .line 466
    check-cast v3, Ljj0/f;

    .line 467
    .line 468
    const v7, 0x7f121250

    .line 469
    .line 470
    .line 471
    invoke-virtual {v3, v7, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 472
    .line 473
    .line 474
    move-result-object v14

    .line 475
    const/16 v17, 0x0

    .line 476
    .line 477
    const/16 v18, 0x3fb

    .line 478
    .line 479
    const/4 v12, 0x0

    .line 480
    const/4 v13, 0x0

    .line 481
    const/4 v15, 0x0

    .line 482
    const/16 v16, 0x0

    .line 483
    .line 484
    invoke-static/range {v11 .. v18}, Lc80/r;->a(Lc80/r;Ljava/util/List;ZLjava/lang/String;ZLql0/g;Ljava/lang/String;I)Lc80/r;

    .line 485
    .line 486
    .line 487
    move-result-object v3

    .line 488
    invoke-virtual {v10, v3}, Lql0/j;->g(Lql0/h;)V

    .line 489
    .line 490
    .line 491
    sget-wide v3, Lc80/t;->o:J

    .line 492
    .line 493
    invoke-static {v1, v2, v3, v4}, Lmy0/c;->j(JJ)J

    .line 494
    .line 495
    .line 496
    move-result-wide v1

    .line 497
    invoke-static {v3, v4}, Lmy0/c;->e(J)J

    .line 498
    .line 499
    .line 500
    move-result-wide v3

    .line 501
    iput-wide v1, v5, Lc80/s;->e:J

    .line 502
    .line 503
    const/4 v6, 0x1

    .line 504
    iput v6, v5, Lc80/s;->f:I

    .line 505
    .line 506
    invoke-static {v3, v4, v5}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 507
    .line 508
    .line 509
    move-result-object v3

    .line 510
    if-ne v3, v0, :cond_16

    .line 511
    .line 512
    move-object v9, v0

    .line 513
    goto :goto_e

    .line 514
    :cond_16
    :goto_d
    invoke-static {v1, v2}, Lmy0/c;->i(J)Z

    .line 515
    .line 516
    .line 517
    move-result v3

    .line 518
    if-nez v3, :cond_15

    .line 519
    .line 520
    invoke-virtual {v10}, Lc80/t;->h()V

    .line 521
    .line 522
    .line 523
    :goto_e
    return-object v9

    .line 524
    nop

    .line 525
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
