.class public final Lg1/s0;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic e:I

.field public f:Ljava/lang/Object;

.field public g:I

.field public synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Llx0/e;

.field public final synthetic k:Llx0/e;

.field public final synthetic l:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lay0/n;Lay0/a;Lay0/a;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p6, p0, Lg1/s0;->e:I

    iput-object p1, p0, Lg1/s0;->i:Ljava/lang/Object;

    iput-object p2, p0, Lg1/s0;->j:Llx0/e;

    iput-object p3, p0, Lg1/s0;->k:Llx0/e;

    iput-object p4, p0, Lg1/s0;->l:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lvy0/b0;Lay0/o;Lay0/k;Lg1/z1;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lg1/s0;->e:I

    .line 2
    iput-object p1, p0, Lg1/s0;->i:Ljava/lang/Object;

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lg1/s0;->j:Llx0/e;

    iput-object p3, p0, Lg1/s0;->k:Llx0/e;

    iput-object p4, p0, Lg1/s0;->l:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 9

    .line 1
    iget v0, p0, Lg1/s0;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lg1/s0;

    .line 7
    .line 8
    iget-object v0, p0, Lg1/s0;->i:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, v0

    .line 11
    check-cast v2, Lvy0/b0;

    .line 12
    .line 13
    iget-object v0, p0, Lg1/s0;->j:Llx0/e;

    .line 14
    .line 15
    move-object v3, v0

    .line 16
    check-cast v3, Lrx0/i;

    .line 17
    .line 18
    iget-object v0, p0, Lg1/s0;->k:Llx0/e;

    .line 19
    .line 20
    move-object v4, v0

    .line 21
    check-cast v4, Lay0/k;

    .line 22
    .line 23
    iget-object p0, p0, Lg1/s0;->l:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v5, p0

    .line 26
    check-cast v5, Lg1/z1;

    .line 27
    .line 28
    move-object v6, p2

    .line 29
    invoke-direct/range {v1 .. v6}, Lg1/s0;-><init>(Lvy0/b0;Lay0/o;Lay0/k;Lg1/z1;Lkotlin/coroutines/Continuation;)V

    .line 30
    .line 31
    .line 32
    iput-object p1, v1, Lg1/s0;->h:Ljava/lang/Object;

    .line 33
    .line 34
    return-object v1

    .line 35
    :pswitch_0
    move-object v7, p2

    .line 36
    new-instance v2, Lg1/s0;

    .line 37
    .line 38
    iget-object p2, p0, Lg1/s0;->i:Ljava/lang/Object;

    .line 39
    .line 40
    move-object v3, p2

    .line 41
    check-cast v3, Li40/e1;

    .line 42
    .line 43
    iget-object p2, p0, Lg1/s0;->j:Llx0/e;

    .line 44
    .line 45
    move-object v4, p2

    .line 46
    check-cast v4, Li40/k0;

    .line 47
    .line 48
    iget-object p2, p0, Lg1/s0;->k:Llx0/e;

    .line 49
    .line 50
    move-object v5, p2

    .line 51
    check-cast v5, Li91/i;

    .line 52
    .line 53
    iget-object p0, p0, Lg1/s0;->l:Ljava/lang/Object;

    .line 54
    .line 55
    move-object v6, p0

    .line 56
    check-cast v6, Li91/i;

    .line 57
    .line 58
    const/4 v8, 0x1

    .line 59
    invoke-direct/range {v2 .. v8}, Lg1/s0;-><init>(Lay0/k;Lay0/n;Lay0/a;Lay0/a;Lkotlin/coroutines/Continuation;I)V

    .line 60
    .line 61
    .line 62
    iput-object p1, v2, Lg1/s0;->h:Ljava/lang/Object;

    .line 63
    .line 64
    return-object v2

    .line 65
    :pswitch_1
    move-object v7, p2

    .line 66
    new-instance v2, Lg1/s0;

    .line 67
    .line 68
    iget-object p2, p0, Lg1/s0;->i:Ljava/lang/Object;

    .line 69
    .line 70
    move-object v3, p2

    .line 71
    check-cast v3, Laa/c0;

    .line 72
    .line 73
    iget-object p2, p0, Lg1/s0;->j:Llx0/e;

    .line 74
    .line 75
    move-object v4, p2

    .line 76
    check-cast v4, Lal/c;

    .line 77
    .line 78
    iget-object p2, p0, Lg1/s0;->k:Llx0/e;

    .line 79
    .line 80
    move-object v5, p2

    .line 81
    check-cast v5, Le41/b;

    .line 82
    .line 83
    iget-object p0, p0, Lg1/s0;->l:Ljava/lang/Object;

    .line 84
    .line 85
    move-object v6, p0

    .line 86
    check-cast v6, Le41/b;

    .line 87
    .line 88
    const/4 v8, 0x0

    .line 89
    invoke-direct/range {v2 .. v8}, Lg1/s0;-><init>(Lay0/k;Lay0/n;Lay0/a;Lay0/a;Lkotlin/coroutines/Continuation;I)V

    .line 90
    .line 91
    .line 92
    iput-object p1, v2, Lg1/s0;->h:Ljava/lang/Object;

    .line 93
    .line 94
    return-object v2

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lg1/s0;->e:I

    .line 2
    .line 3
    check-cast p1, Lp3/i0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lg1/s0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg1/s0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg1/s0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lg1/s0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lg1/s0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lg1/s0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lg1/s0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lg1/s0;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lg1/s0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
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
    iget v0, v5, Lg1/s0;->e:I

    .line 4
    .line 5
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v7, v5, Lg1/s0;->k:Llx0/e;

    .line 8
    .line 9
    iget-object v1, v5, Lg1/s0;->j:Llx0/e;

    .line 10
    .line 11
    const/4 v8, 0x3

    .line 12
    const/4 v2, 0x0

    .line 13
    const-string v3, "call to \'resume\' before \'invoke\' with coroutine"

    .line 14
    .line 15
    const/4 v9, 0x0

    .line 16
    iget-object v10, v5, Lg1/s0;->l:Ljava/lang/Object;

    .line 17
    .line 18
    const/4 v4, 0x2

    .line 19
    iget-object v11, v5, Lg1/s0;->i:Ljava/lang/Object;

    .line 20
    .line 21
    const/4 v12, 0x1

    .line 22
    packed-switch v0, :pswitch_data_0

    .line 23
    .line 24
    .line 25
    check-cast v11, Lvy0/b0;

    .line 26
    .line 27
    check-cast v10, Lg1/z1;

    .line 28
    .line 29
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v13, v5, Lg1/s0;->g:I

    .line 32
    .line 33
    if-eqz v13, :cond_2

    .line 34
    .line 35
    if-eq v13, v12, :cond_1

    .line 36
    .line 37
    if-ne v13, v4, :cond_0

    .line 38
    .line 39
    iget-object v0, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Lvy0/i1;

    .line 42
    .line 43
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    move-object/from16 v1, p1

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw v0

    .line 55
    :cond_1
    iget-object v3, v5, Lg1/s0;->f:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v3, Lvy0/x1;

    .line 58
    .line 59
    iget-object v8, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v8, Lp3/i0;

    .line 62
    .line 63
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    move-object v13, v8

    .line 67
    move-object/from16 v8, p1

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    iget-object v3, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v3, Lp3/i0;

    .line 76
    .line 77
    sget-object v13, Lg1/g3;->a:Lg1/e1;

    .line 78
    .line 79
    sget-object v13, Lvy0/c0;->g:Lvy0/c0;

    .line 80
    .line 81
    new-instance v14, Lg1/a3;

    .line 82
    .line 83
    invoke-direct {v14, v10, v9, v2}, Lg1/a3;-><init>(Lg1/z1;Lkotlin/coroutines/Continuation;I)V

    .line 84
    .line 85
    .line 86
    invoke-static {v11, v9, v13, v14, v12}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 87
    .line 88
    .line 89
    move-result-object v13

    .line 90
    iput-object v3, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 91
    .line 92
    iput-object v13, v5, Lg1/s0;->f:Ljava/lang/Object;

    .line 93
    .line 94
    iput v12, v5, Lg1/s0;->g:I

    .line 95
    .line 96
    invoke-static {v3, v5, v8}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v8

    .line 100
    if-ne v8, v0, :cond_3

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_3
    move-object/from16 v18, v13

    .line 104
    .line 105
    move-object v13, v3

    .line 106
    move-object/from16 v3, v18

    .line 107
    .line 108
    :goto_0
    check-cast v8, Lp3/t;

    .line 109
    .line 110
    invoke-virtual {v8}, Lp3/t;->a()V

    .line 111
    .line 112
    .line 113
    check-cast v1, Lrx0/i;

    .line 114
    .line 115
    sget-object v14, Lg1/g3;->a:Lg1/e1;

    .line 116
    .line 117
    if-eq v1, v14, :cond_4

    .line 118
    .line 119
    new-instance v14, Lg1/y2;

    .line 120
    .line 121
    invoke-direct {v14, v1, v10, v8, v9}, Lg1/y2;-><init>(Lay0/o;Lg1/z1;Lp3/t;Lkotlin/coroutines/Continuation;)V

    .line 122
    .line 123
    .line 124
    invoke-static {v11, v3, v14}, Lg1/g3;->g(Lvy0/b0;Lvy0/i1;Lay0/n;)Lvy0/x1;

    .line 125
    .line 126
    .line 127
    :cond_4
    iput-object v3, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 128
    .line 129
    iput-object v9, v5, Lg1/s0;->f:Ljava/lang/Object;

    .line 130
    .line 131
    iput v4, v5, Lg1/s0;->g:I

    .line 132
    .line 133
    sget-object v1, Lp3/l;->e:Lp3/l;

    .line 134
    .line 135
    invoke-static {v13, v1, v5}, Lg1/g3;->i(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    if-ne v1, v0, :cond_5

    .line 140
    .line 141
    :goto_1
    move-object v6, v0

    .line 142
    goto :goto_3

    .line 143
    :cond_5
    move-object v0, v3

    .line 144
    :goto_2
    check-cast v1, Lp3/t;

    .line 145
    .line 146
    if-nez v1, :cond_6

    .line 147
    .line 148
    new-instance v1, Lg1/z2;

    .line 149
    .line 150
    invoke-direct {v1, v10, v9, v2}, Lg1/z2;-><init>(Lg1/z1;Lkotlin/coroutines/Continuation;I)V

    .line 151
    .line 152
    .line 153
    invoke-static {v11, v0, v1}, Lg1/g3;->g(Lvy0/b0;Lvy0/i1;Lay0/n;)Lvy0/x1;

    .line 154
    .line 155
    .line 156
    goto :goto_3

    .line 157
    :cond_6
    invoke-virtual {v1}, Lp3/t;->a()V

    .line 158
    .line 159
    .line 160
    new-instance v2, Lg1/z2;

    .line 161
    .line 162
    invoke-direct {v2, v10, v9, v12}, Lg1/z2;-><init>(Lg1/z1;Lkotlin/coroutines/Continuation;I)V

    .line 163
    .line 164
    .line 165
    invoke-static {v11, v0, v2}, Lg1/g3;->g(Lvy0/b0;Lvy0/i1;Lay0/n;)Lvy0/x1;

    .line 166
    .line 167
    .line 168
    check-cast v7, Lay0/k;

    .line 169
    .line 170
    iget-wide v0, v1, Lp3/t;->c:J

    .line 171
    .line 172
    new-instance v2, Ld3/b;

    .line 173
    .line 174
    invoke-direct {v2, v0, v1}, Ld3/b;-><init>(J)V

    .line 175
    .line 176
    .line 177
    invoke-interface {v7, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    :goto_3
    return-object v6

    .line 181
    :pswitch_0
    move-object v13, v1

    .line 182
    check-cast v13, Li40/k0;

    .line 183
    .line 184
    sget-object v14, Lqx0/a;->d:Lqx0/a;

    .line 185
    .line 186
    iget v0, v5, Lg1/s0;->g:I

    .line 187
    .line 188
    if-eqz v0, :cond_a

    .line 189
    .line 190
    if-eq v0, v12, :cond_9

    .line 191
    .line 192
    if-eq v0, v4, :cond_8

    .line 193
    .line 194
    if-ne v0, v8, :cond_7

    .line 195
    .line 196
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    move-object/from16 v0, p1

    .line 200
    .line 201
    goto/16 :goto_7

    .line 202
    .line 203
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 204
    .line 205
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    throw v0

    .line 209
    :cond_8
    iget-object v0, v5, Lg1/s0;->f:Ljava/lang/Object;

    .line 210
    .line 211
    check-cast v0, Lkotlin/jvm/internal/c0;

    .line 212
    .line 213
    iget-object v1, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 214
    .line 215
    check-cast v1, Lp3/i0;

    .line 216
    .line 217
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 218
    .line 219
    .line 220
    move-object v2, v1

    .line 221
    move-object/from16 v1, p1

    .line 222
    .line 223
    goto :goto_5

    .line 224
    :cond_9
    iget-object v0, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 225
    .line 226
    check-cast v0, Lp3/i0;

    .line 227
    .line 228
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    move-object/from16 v1, p1

    .line 232
    .line 233
    goto :goto_4

    .line 234
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 235
    .line 236
    .line 237
    iget-object v0, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v0, Lp3/i0;

    .line 240
    .line 241
    iput-object v0, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 242
    .line 243
    iput v12, v5, Lg1/s0;->g:I

    .line 244
    .line 245
    invoke-static {v0, v5, v4}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v1

    .line 249
    if-ne v1, v14, :cond_b

    .line 250
    .line 251
    goto :goto_6

    .line 252
    :cond_b
    :goto_4
    check-cast v1, Lp3/t;

    .line 253
    .line 254
    new-instance v15, Lkotlin/jvm/internal/c0;

    .line 255
    .line 256
    invoke-direct {v15}, Ljava/lang/Object;-><init>()V

    .line 257
    .line 258
    .line 259
    iget-wide v2, v1, Lp3/t;->a:J

    .line 260
    .line 261
    iget v1, v1, Lp3/t;->i:I

    .line 262
    .line 263
    new-instance v8, Lg1/r0;

    .line 264
    .line 265
    invoke-direct {v8, v15, v12}, Lg1/r0;-><init>(Lkotlin/jvm/internal/c0;I)V

    .line 266
    .line 267
    .line 268
    iput-object v0, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 269
    .line 270
    iput-object v15, v5, Lg1/s0;->f:Ljava/lang/Object;

    .line 271
    .line 272
    iput v4, v5, Lg1/s0;->g:I

    .line 273
    .line 274
    move-wide/from16 v18, v2

    .line 275
    .line 276
    move v3, v1

    .line 277
    move-wide/from16 v1, v18

    .line 278
    .line 279
    move-object v4, v8

    .line 280
    invoke-static/range {v0 .. v5}, Lg1/w0;->d(Lp3/i0;JILg1/r0;Lrx0/a;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v1

    .line 284
    if-ne v1, v14, :cond_c

    .line 285
    .line 286
    goto :goto_6

    .line 287
    :cond_c
    move-object v2, v0

    .line 288
    move-object v0, v15

    .line 289
    :goto_5
    check-cast v1, Lp3/t;

    .line 290
    .line 291
    if-eqz v1, :cond_f

    .line 292
    .line 293
    check-cast v11, Li40/e1;

    .line 294
    .line 295
    iget-object v3, v11, Li40/e1;->e:Ljava/lang/Object;

    .line 296
    .line 297
    check-cast v3, Li91/l1;

    .line 298
    .line 299
    invoke-virtual {v3}, Li91/l1;->f()V

    .line 300
    .line 301
    .line 302
    iget v0, v0, Lkotlin/jvm/internal/c0;->d:F

    .line 303
    .line 304
    new-instance v3, Ljava/lang/Float;

    .line 305
    .line 306
    invoke-direct {v3, v0}, Ljava/lang/Float;-><init>(F)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v13, v1, v3}, Li40/k0;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    iget-wide v0, v1, Lp3/t;->a:J

    .line 313
    .line 314
    new-instance v3, Le81/w;

    .line 315
    .line 316
    const/16 v4, 0xc

    .line 317
    .line 318
    invoke-direct {v3, v13, v4}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 319
    .line 320
    .line 321
    iput-object v9, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 322
    .line 323
    iput-object v9, v5, Lg1/s0;->f:Ljava/lang/Object;

    .line 324
    .line 325
    const/4 v4, 0x3

    .line 326
    iput v4, v5, Lg1/s0;->g:I

    .line 327
    .line 328
    invoke-static {v2, v0, v1, v3, v5}, Lg1/w0;->i(Lp3/i0;JLe81/w;Lrx0/a;)Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object v0

    .line 332
    if-ne v0, v14, :cond_d

    .line 333
    .line 334
    :goto_6
    move-object v6, v14

    .line 335
    goto :goto_8

    .line 336
    :cond_d
    :goto_7
    check-cast v0, Ljava/lang/Boolean;

    .line 337
    .line 338
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 339
    .line 340
    .line 341
    move-result v0

    .line 342
    if-eqz v0, :cond_e

    .line 343
    .line 344
    check-cast v7, Li91/i;

    .line 345
    .line 346
    invoke-virtual {v7}, Li91/i;->invoke()Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    goto :goto_8

    .line 350
    :cond_e
    check-cast v10, Li91/i;

    .line 351
    .line 352
    invoke-virtual {v10}, Li91/i;->invoke()Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    :cond_f
    :goto_8
    return-object v6

    .line 356
    :pswitch_1
    move-object v8, v1

    .line 357
    check-cast v8, Lal/c;

    .line 358
    .line 359
    sget-object v13, Lqx0/a;->d:Lqx0/a;

    .line 360
    .line 361
    iget v0, v5, Lg1/s0;->g:I

    .line 362
    .line 363
    if-eqz v0, :cond_13

    .line 364
    .line 365
    if-eq v0, v12, :cond_12

    .line 366
    .line 367
    if-eq v0, v4, :cond_11

    .line 368
    .line 369
    const/4 v4, 0x3

    .line 370
    if-ne v0, v4, :cond_10

    .line 371
    .line 372
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 373
    .line 374
    .line 375
    move-object/from16 v0, p1

    .line 376
    .line 377
    goto/16 :goto_c

    .line 378
    .line 379
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 380
    .line 381
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 382
    .line 383
    .line 384
    throw v0

    .line 385
    :cond_11
    iget-object v0, v5, Lg1/s0;->f:Ljava/lang/Object;

    .line 386
    .line 387
    check-cast v0, Lkotlin/jvm/internal/c0;

    .line 388
    .line 389
    iget-object v1, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 390
    .line 391
    check-cast v1, Lp3/i0;

    .line 392
    .line 393
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 394
    .line 395
    .line 396
    move-object v2, v1

    .line 397
    move-object/from16 v1, p1

    .line 398
    .line 399
    goto :goto_a

    .line 400
    :cond_12
    iget-object v0, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 401
    .line 402
    check-cast v0, Lp3/i0;

    .line 403
    .line 404
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 405
    .line 406
    .line 407
    move-object/from16 v1, p1

    .line 408
    .line 409
    goto :goto_9

    .line 410
    :cond_13
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 411
    .line 412
    .line 413
    iget-object v0, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 414
    .line 415
    check-cast v0, Lp3/i0;

    .line 416
    .line 417
    iput-object v0, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 418
    .line 419
    iput v12, v5, Lg1/s0;->g:I

    .line 420
    .line 421
    invoke-static {v0, v5, v4}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 422
    .line 423
    .line 424
    move-result-object v1

    .line 425
    if-ne v1, v13, :cond_14

    .line 426
    .line 427
    goto/16 :goto_b

    .line 428
    .line 429
    :cond_14
    :goto_9
    check-cast v1, Lp3/t;

    .line 430
    .line 431
    new-instance v12, Lkotlin/jvm/internal/c0;

    .line 432
    .line 433
    invoke-direct {v12}, Ljava/lang/Object;-><init>()V

    .line 434
    .line 435
    .line 436
    iget-wide v14, v1, Lp3/t;->a:J

    .line 437
    .line 438
    iget v3, v1, Lp3/t;->i:I

    .line 439
    .line 440
    new-instance v1, Lg1/r0;

    .line 441
    .line 442
    invoke-direct {v1, v12, v2}, Lg1/r0;-><init>(Lkotlin/jvm/internal/c0;I)V

    .line 443
    .line 444
    .line 445
    iput-object v0, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 446
    .line 447
    iput-object v12, v5, Lg1/s0;->f:Ljava/lang/Object;

    .line 448
    .line 449
    iput v4, v5, Lg1/s0;->g:I

    .line 450
    .line 451
    move-object v4, v1

    .line 452
    move-wide v1, v14

    .line 453
    invoke-static/range {v0 .. v5}, Lg1/w0;->b(Lp3/i0;JILg1/r0;Lrx0/a;)Ljava/lang/Object;

    .line 454
    .line 455
    .line 456
    move-result-object v1

    .line 457
    if-ne v1, v13, :cond_15

    .line 458
    .line 459
    goto :goto_b

    .line 460
    :cond_15
    move-object v2, v0

    .line 461
    move-object v0, v12

    .line 462
    :goto_a
    check-cast v1, Lp3/t;

    .line 463
    .line 464
    if-eqz v1, :cond_18

    .line 465
    .line 466
    check-cast v11, Laa/c0;

    .line 467
    .line 468
    iget-wide v3, v1, Lp3/t;->c:J

    .line 469
    .line 470
    iget-object v11, v11, Laa/c0;->e:Lay0/k;

    .line 471
    .line 472
    invoke-static {v3, v4}, Ld3/b;->e(J)F

    .line 473
    .line 474
    .line 475
    move-result v12

    .line 476
    invoke-static {v3, v4}, Ld3/b;->f(J)F

    .line 477
    .line 478
    .line 479
    move-result v3

    .line 480
    invoke-static {v12}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 481
    .line 482
    .line 483
    move-result v4

    .line 484
    int-to-long v14, v4

    .line 485
    invoke-static {v3}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 486
    .line 487
    .line 488
    move-result v3

    .line 489
    int-to-long v3, v3

    .line 490
    const/16 v12, 0x20

    .line 491
    .line 492
    shl-long/2addr v14, v12

    .line 493
    const-wide v16, 0xffffffffL

    .line 494
    .line 495
    .line 496
    .line 497
    .line 498
    and-long v3, v3, v16

    .line 499
    .line 500
    or-long/2addr v3, v14

    .line 501
    new-instance v12, Lpw/g;

    .line 502
    .line 503
    invoke-direct {v12, v3, v4}, Lpw/g;-><init>(J)V

    .line 504
    .line 505
    .line 506
    invoke-interface {v11, v12}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 507
    .line 508
    .line 509
    iget v0, v0, Lkotlin/jvm/internal/c0;->d:F

    .line 510
    .line 511
    new-instance v3, Ljava/lang/Float;

    .line 512
    .line 513
    invoke-direct {v3, v0}, Ljava/lang/Float;-><init>(F)V

    .line 514
    .line 515
    .line 516
    invoke-virtual {v8, v1, v3}, Lal/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 517
    .line 518
    .line 519
    iget-wide v0, v1, Lp3/t;->a:J

    .line 520
    .line 521
    new-instance v3, Le81/w;

    .line 522
    .line 523
    const/16 v4, 0xb

    .line 524
    .line 525
    invoke-direct {v3, v8, v4}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 526
    .line 527
    .line 528
    iput-object v9, v5, Lg1/s0;->h:Ljava/lang/Object;

    .line 529
    .line 530
    iput-object v9, v5, Lg1/s0;->f:Ljava/lang/Object;

    .line 531
    .line 532
    const/4 v4, 0x3

    .line 533
    iput v4, v5, Lg1/s0;->g:I

    .line 534
    .line 535
    invoke-static {v2, v0, v1, v3, v5}, Lg1/w0;->f(Lp3/i0;JLay0/k;Lrx0/a;)Ljava/lang/Object;

    .line 536
    .line 537
    .line 538
    move-result-object v0

    .line 539
    if-ne v0, v13, :cond_16

    .line 540
    .line 541
    :goto_b
    move-object v6, v13

    .line 542
    goto :goto_d

    .line 543
    :cond_16
    :goto_c
    check-cast v0, Ljava/lang/Boolean;

    .line 544
    .line 545
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 546
    .line 547
    .line 548
    move-result v0

    .line 549
    if-eqz v0, :cond_17

    .line 550
    .line 551
    check-cast v7, Le41/b;

    .line 552
    .line 553
    invoke-virtual {v7}, Le41/b;->invoke()Ljava/lang/Object;

    .line 554
    .line 555
    .line 556
    goto :goto_d

    .line 557
    :cond_17
    check-cast v10, Le41/b;

    .line 558
    .line 559
    invoke-virtual {v10}, Le41/b;->invoke()Ljava/lang/Object;

    .line 560
    .line 561
    .line 562
    :cond_18
    :goto_d
    return-object v6

    .line 563
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
