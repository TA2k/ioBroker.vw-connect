.class public final Lc00/r1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Z

.field public final synthetic g:J

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lc00/t1;JZLkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lc00/r1;->d:I

    .line 1
    iput-object p1, p0, Lc00/r1;->h:Ljava/lang/Object;

    iput-wide p2, p0, Lc00/r1;->g:J

    iput-boolean p4, p0, Lc00/r1;->f:Z

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(ZJLhg/x;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lc00/r1;->d:I

    .line 2
    iput-boolean p1, p0, Lc00/r1;->f:Z

    iput-wide p2, p0, Lc00/r1;->g:J

    iput-object p4, p0, Lc00/r1;->h:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(ZLw4/g;JLkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lc00/r1;->d:I

    .line 3
    iput-boolean p1, p0, Lc00/r1;->f:Z

    iput-object p2, p0, Lc00/r1;->h:Ljava/lang/Object;

    iput-wide p3, p0, Lc00/r1;->g:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    iget p1, p0, Lc00/r1;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lc00/r1;

    .line 7
    .line 8
    iget-object p1, p0, Lc00/r1;->h:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, p1

    .line 11
    check-cast v2, Lw4/g;

    .line 12
    .line 13
    iget-wide v3, p0, Lc00/r1;->g:J

    .line 14
    .line 15
    iget-boolean v1, p0, Lc00/r1;->f:Z

    .line 16
    .line 17
    move-object v5, p2

    .line 18
    invoke-direct/range {v0 .. v5}, Lc00/r1;-><init>(ZLw4/g;JLkotlin/coroutines/Continuation;)V

    .line 19
    .line 20
    .line 21
    return-object v0

    .line 22
    :pswitch_0
    move-object v6, p2

    .line 23
    new-instance v1, Lc00/r1;

    .line 24
    .line 25
    iget-object p1, p0, Lc00/r1;->h:Ljava/lang/Object;

    .line 26
    .line 27
    move-object v5, p1

    .line 28
    check-cast v5, Lhg/x;

    .line 29
    .line 30
    iget-boolean v2, p0, Lc00/r1;->f:Z

    .line 31
    .line 32
    iget-wide v3, p0, Lc00/r1;->g:J

    .line 33
    .line 34
    invoke-direct/range {v1 .. v6}, Lc00/r1;-><init>(ZJLhg/x;Lkotlin/coroutines/Continuation;)V

    .line 35
    .line 36
    .line 37
    return-object v1

    .line 38
    :pswitch_1
    move-object v6, p2

    .line 39
    new-instance v1, Lc00/r1;

    .line 40
    .line 41
    iget-object p1, p0, Lc00/r1;->h:Ljava/lang/Object;

    .line 42
    .line 43
    move-object v2, p1

    .line 44
    check-cast v2, Lc00/t1;

    .line 45
    .line 46
    iget-wide v3, p0, Lc00/r1;->g:J

    .line 47
    .line 48
    iget-boolean v5, p0, Lc00/r1;->f:Z

    .line 49
    .line 50
    invoke-direct/range {v1 .. v6}, Lc00/r1;-><init>(Lc00/t1;JZLkotlin/coroutines/Continuation;)V

    .line 51
    .line 52
    .line 53
    return-object v1

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lc00/r1;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lc00/r1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc00/r1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc00/r1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc00/r1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lc00/r1;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lc00/r1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lc00/r1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lc00/r1;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lc00/r1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 17

    .line 1
    move-object/from16 v5, p0

    .line 2
    .line 3
    iget v0, v5, Lc00/r1;->d:I

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v5, Lc00/r1;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lw4/g;

    .line 11
    .line 12
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v1, v5, Lc00/r1;->e:I

    .line 15
    .line 16
    const/4 v2, 0x2

    .line 17
    const/4 v3, 0x1

    .line 18
    if-eqz v1, :cond_2

    .line 19
    .line 20
    if-eq v1, v3, :cond_1

    .line 21
    .line 22
    if-ne v1, v2, :cond_0

    .line 23
    .line 24
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    move-object/from16 v0, p1

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 33
    .line 34
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw v0

    .line 38
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    move-object/from16 v0, p1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    iget-boolean v1, v5, Lc00/r1;->f:Z

    .line 48
    .line 49
    if-nez v1, :cond_4

    .line 50
    .line 51
    iget-object v0, v0, Lw4/g;->d:Lo3/d;

    .line 52
    .line 53
    iput v3, v5, Lc00/r1;->e:I

    .line 54
    .line 55
    const-wide/16 v1, 0x0

    .line 56
    .line 57
    iget-wide v3, v5, Lc00/r1;->g:J

    .line 58
    .line 59
    invoke-virtual/range {v0 .. v5}, Lo3/d;->a(JJLrx0/c;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    if-ne v0, v6, :cond_3

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    :goto_0
    check-cast v0, Lt4/q;

    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_4
    iget-object v0, v0, Lw4/g;->d:Lo3/d;

    .line 73
    .line 74
    iput v2, v5, Lc00/r1;->e:I

    .line 75
    .line 76
    iget-wide v1, v5, Lc00/r1;->g:J

    .line 77
    .line 78
    const-wide/16 v3, 0x0

    .line 79
    .line 80
    invoke-virtual/range {v0 .. v5}, Lo3/d;->a(JJLrx0/c;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    if-ne v0, v6, :cond_5

    .line 85
    .line 86
    goto :goto_3

    .line 87
    :cond_5
    :goto_1
    check-cast v0, Lt4/q;

    .line 88
    .line 89
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    :goto_2
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    :goto_3
    return-object v6

    .line 95
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 96
    .line 97
    iget v1, v5, Lc00/r1;->e:I

    .line 98
    .line 99
    const/4 v2, 0x1

    .line 100
    if-eqz v1, :cond_7

    .line 101
    .line 102
    if-ne v1, v2, :cond_6

    .line 103
    .line 104
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto :goto_4

    .line 108
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 109
    .line 110
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 111
    .line 112
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw v0

    .line 116
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    iget-boolean v1, v5, Lc00/r1;->f:Z

    .line 120
    .line 121
    if-nez v1, :cond_8

    .line 122
    .line 123
    iput v2, v5, Lc00/r1;->e:I

    .line 124
    .line 125
    iget-wide v1, v5, Lc00/r1;->g:J

    .line 126
    .line 127
    invoke-static {v1, v2, v5}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    if-ne v1, v0, :cond_8

    .line 132
    .line 133
    goto :goto_5

    .line 134
    :cond_8
    :goto_4
    iget-object v0, v5, Lc00/r1;->h:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v0, Lhg/x;

    .line 137
    .line 138
    const/4 v1, 0x0

    .line 139
    invoke-virtual {v0, v1, v1}, Lhg/x;->b(IZ)V

    .line 140
    .line 141
    .line 142
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 143
    .line 144
    :goto_5
    return-object v0

    .line 145
    :pswitch_1
    iget-object v0, v5, Lc00/r1;->h:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v0, Lc00/t1;

    .line 148
    .line 149
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 150
    .line 151
    iget v2, v5, Lc00/r1;->e:I

    .line 152
    .line 153
    const/4 v3, 0x1

    .line 154
    if-eqz v2, :cond_a

    .line 155
    .line 156
    if-ne v2, v3, :cond_9

    .line 157
    .line 158
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    goto/16 :goto_8

    .line 162
    .line 163
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 164
    .line 165
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 166
    .line 167
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    throw v0

    .line 171
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 175
    .line 176
    .line 177
    const-wide/16 v6, 0x1

    .line 178
    .line 179
    iget-wide v8, v5, Lc00/r1;->g:J

    .line 180
    .line 181
    cmp-long v2, v8, v6

    .line 182
    .line 183
    if-nez v2, :cond_b

    .line 184
    .line 185
    const-string v2, "air_conditioning_plans_card_plan_1_switch"

    .line 186
    .line 187
    goto :goto_6

    .line 188
    :cond_b
    const-string v2, "air_conditioning_plans_card_plan_2_switch"

    .line 189
    .line 190
    :goto_6
    new-instance v4, Lac0/g;

    .line 191
    .line 192
    const/4 v6, 0x1

    .line 193
    iget-boolean v7, v5, Lc00/r1;->f:Z

    .line 194
    .line 195
    invoke-direct {v4, v2, v7, v6}, Lac0/g;-><init>(Ljava/lang/String;ZI)V

    .line 196
    .line 197
    .line 198
    invoke-static {v0, v4}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 199
    .line 200
    .line 201
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 202
    .line 203
    .line 204
    move-result-object v2

    .line 205
    check-cast v2, Lc00/n1;

    .line 206
    .line 207
    iget-object v2, v2, Lc00/n1;->d:Ljava/util/List;

    .line 208
    .line 209
    check-cast v2, Ljava/lang/Iterable;

    .line 210
    .line 211
    new-instance v4, Ljava/util/ArrayList;

    .line 212
    .line 213
    const/16 v6, 0xa

    .line 214
    .line 215
    invoke-static {v2, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 216
    .line 217
    .line 218
    move-result v6

    .line 219
    invoke-direct {v4, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 220
    .line 221
    .line 222
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 223
    .line 224
    .line 225
    move-result-object v2

    .line 226
    :goto_7
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 227
    .line 228
    .line 229
    move-result v6

    .line 230
    if-eqz v6, :cond_d

    .line 231
    .line 232
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v6

    .line 236
    move-object v10, v6

    .line 237
    check-cast v10, Lao0/c;

    .line 238
    .line 239
    iget-wide v11, v10, Lao0/c;->a:J

    .line 240
    .line 241
    cmp-long v6, v11, v8

    .line 242
    .line 243
    if-nez v6, :cond_c

    .line 244
    .line 245
    const/4 v15, 0x0

    .line 246
    const/16 v16, 0x3d

    .line 247
    .line 248
    iget-boolean v11, v5, Lc00/r1;->f:Z

    .line 249
    .line 250
    const/4 v12, 0x0

    .line 251
    const/4 v13, 0x0

    .line 252
    const/4 v14, 0x0

    .line 253
    invoke-static/range {v10 .. v16}, Lao0/c;->a(Lao0/c;ZLjava/time/LocalTime;Lao0/f;Ljava/util/Set;ZI)Lao0/c;

    .line 254
    .line 255
    .line 256
    move-result-object v10

    .line 257
    :cond_c
    invoke-virtual {v4, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    goto :goto_7

    .line 261
    :cond_d
    iget-object v2, v0, Lc00/t1;->p:Llb0/u;

    .line 262
    .line 263
    invoke-virtual {v2, v4}, Llb0/u;->a(Ljava/util/List;)Lyy0/m1;

    .line 264
    .line 265
    .line 266
    move-result-object v2

    .line 267
    new-instance v4, Lc00/q1;

    .line 268
    .line 269
    invoke-direct {v4, v0, v8, v9, v7}, Lc00/q1;-><init>(Lc00/t1;JZ)V

    .line 270
    .line 271
    .line 272
    iput v3, v5, Lc00/r1;->e:I

    .line 273
    .line 274
    invoke-virtual {v2, v4, v5}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v0

    .line 278
    if-ne v0, v1, :cond_e

    .line 279
    .line 280
    goto :goto_9

    .line 281
    :cond_e
    :goto_8
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 282
    .line 283
    :goto_9
    return-object v1

    .line 284
    nop

    .line 285
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
