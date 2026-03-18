.class public final Lv00/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lv00/i;


# direct methods
.method public synthetic constructor <init>(Lv00/i;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lv00/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lv00/b;->f:Lv00/i;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lv00/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lv00/b;

    .line 7
    .line 8
    iget-object p0, p0, Lv00/b;->f:Lv00/i;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lv00/b;-><init>(Lv00/i;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lv00/b;

    .line 16
    .line 17
    iget-object p0, p0, Lv00/b;->f:Lv00/i;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lv00/b;-><init>(Lv00/i;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lv00/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Lv00/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lv00/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lv00/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lv00/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lv00/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lv00/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lv00/b;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lv00/b;->e:I

    .line 11
    .line 12
    const/4 v3, 0x2

    .line 13
    const/4 v4, 0x1

    .line 14
    iget-object v5, v0, Lv00/b;->f:Lv00/i;

    .line 15
    .line 16
    if-eqz v2, :cond_2

    .line 17
    .line 18
    if-eq v2, v4, :cond_1

    .line 19
    .line 20
    if-ne v2, v3, :cond_0

    .line 21
    .line 22
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    goto/16 :goto_3

    .line 26
    .line 27
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw v0

    .line 35
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    move-object/from16 v2, p1

    .line 39
    .line 40
    goto/16 :goto_2

    .line 41
    .line 42
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    move-object v6, v2

    .line 50
    check-cast v6, Lv00/h;

    .line 51
    .line 52
    sget-object v17, Lv00/e;->a:Lv00/e;

    .line 53
    .line 54
    const/16 v18, 0x7ff

    .line 55
    .line 56
    const/4 v7, 0x0

    .line 57
    const/4 v8, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    const/4 v10, 0x0

    .line 60
    const/4 v11, 0x0

    .line 61
    const/4 v12, 0x0

    .line 62
    const/4 v13, 0x0

    .line 63
    const/4 v14, 0x0

    .line 64
    const/4 v15, 0x0

    .line 65
    const/16 v16, 0x0

    .line 66
    .line 67
    invoke-static/range {v6 .. v18}, Lv00/h;->a(Lv00/h;Ljava/lang/String;ZZLjava/lang/String;ZLmh0/b;ILjava/util/List;ZZLv00/g;I)Lv00/h;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    invoke-virtual {v5, v2}, Lql0/j;->g(Lql0/h;)V

    .line 72
    .line 73
    .line 74
    iget-object v2, v5, Lv00/i;->p:Lt00/j;

    .line 75
    .line 76
    new-instance v6, Lu00/b;

    .line 77
    .line 78
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 79
    .line 80
    .line 81
    move-result-object v7

    .line 82
    check-cast v7, Lv00/h;

    .line 83
    .line 84
    iget-object v7, v7, Lv00/h;->f:Lmh0/b;

    .line 85
    .line 86
    sget-object v8, Lmh0/b;->m:Lmh0/b;

    .line 87
    .line 88
    if-ne v7, v8, :cond_4

    .line 89
    .line 90
    new-instance v7, Lmh0/a;

    .line 91
    .line 92
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 93
    .line 94
    .line 95
    move-result-object v8

    .line 96
    check-cast v8, Lv00/h;

    .line 97
    .line 98
    iget-boolean v8, v8, Lv00/h;->e:Z

    .line 99
    .line 100
    if-eqz v8, :cond_3

    .line 101
    .line 102
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 103
    .line 104
    .line 105
    move-result-object v8

    .line 106
    check-cast v8, Lv00/h;

    .line 107
    .line 108
    iget-object v8, v8, Lv00/h;->a:Ljava/lang/String;

    .line 109
    .line 110
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 111
    .line 112
    .line 113
    move-result v8

    .line 114
    if-lez v8, :cond_3

    .line 115
    .line 116
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 117
    .line 118
    .line 119
    move-result-object v8

    .line 120
    check-cast v8, Lv00/h;

    .line 121
    .line 122
    iget-object v8, v8, Lv00/h;->a:Ljava/lang/String;

    .line 123
    .line 124
    goto :goto_0

    .line 125
    :cond_3
    const-string v8, "[APP LOGS]"

    .line 126
    .line 127
    :goto_0
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 128
    .line 129
    .line 130
    move-result-object v9

    .line 131
    check-cast v9, Lv00/h;

    .line 132
    .line 133
    iget-object v9, v9, Lv00/h;->f:Lmh0/b;

    .line 134
    .line 135
    invoke-direct {v7, v8, v4, v9, v4}, Lmh0/a;-><init>(Ljava/lang/String;ILmh0/b;Z)V

    .line 136
    .line 137
    .line 138
    goto :goto_1

    .line 139
    :cond_4
    new-instance v7, Lmh0/a;

    .line 140
    .line 141
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 142
    .line 143
    .line 144
    move-result-object v8

    .line 145
    check-cast v8, Lv00/h;

    .line 146
    .line 147
    iget-object v8, v8, Lv00/h;->a:Ljava/lang/String;

    .line 148
    .line 149
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 150
    .line 151
    .line 152
    move-result-object v9

    .line 153
    check-cast v9, Lv00/h;

    .line 154
    .line 155
    iget v9, v9, Lv00/h;->g:I

    .line 156
    .line 157
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 158
    .line 159
    .line 160
    move-result-object v10

    .line 161
    check-cast v10, Lv00/h;

    .line 162
    .line 163
    iget-object v10, v10, Lv00/h;->f:Lmh0/b;

    .line 164
    .line 165
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 166
    .line 167
    .line 168
    move-result-object v11

    .line 169
    check-cast v11, Lv00/h;

    .line 170
    .line 171
    iget-boolean v11, v11, Lv00/h;->j:Z

    .line 172
    .line 173
    invoke-direct {v7, v8, v9, v10, v11}, Lmh0/a;-><init>(Ljava/lang/String;ILmh0/b;Z)V

    .line 174
    .line 175
    .line 176
    :goto_1
    iget-object v8, v5, Lv00/i;->h:Lij0/a;

    .line 177
    .line 178
    const/4 v9, 0x0

    .line 179
    new-array v9, v9, [Ljava/lang/Object;

    .line 180
    .line 181
    check-cast v8, Ljj0/f;

    .line 182
    .line 183
    const v10, 0x7f120326

    .line 184
    .line 185
    .line 186
    invoke-virtual {v8, v10, v9}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v8

    .line 190
    invoke-direct {v6, v7, v8}, Lu00/b;-><init>(Lmh0/a;Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    iput v4, v0, Lv00/b;->e:I

    .line 194
    .line 195
    invoke-virtual {v2, v6, v0}, Lt00/j;->b(Lu00/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v2

    .line 199
    if-ne v2, v1, :cond_5

    .line 200
    .line 201
    goto :goto_4

    .line 202
    :cond_5
    :goto_2
    check-cast v2, Lyy0/i;

    .line 203
    .line 204
    new-instance v4, Lv00/a;

    .line 205
    .line 206
    const/4 v6, 0x1

    .line 207
    invoke-direct {v4, v5, v6}, Lv00/a;-><init>(Lv00/i;I)V

    .line 208
    .line 209
    .line 210
    iput v3, v0, Lv00/b;->e:I

    .line 211
    .line 212
    invoke-interface {v2, v4, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    if-ne v0, v1, :cond_6

    .line 217
    .line 218
    goto :goto_4

    .line 219
    :cond_6
    :goto_3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 220
    .line 221
    :goto_4
    return-object v1

    .line 222
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 223
    .line 224
    iget v2, v0, Lv00/b;->e:I

    .line 225
    .line 226
    const/4 v3, 0x1

    .line 227
    if-eqz v2, :cond_8

    .line 228
    .line 229
    if-ne v2, v3, :cond_7

    .line 230
    .line 231
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    goto :goto_5

    .line 235
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 236
    .line 237
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 238
    .line 239
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    throw v0

    .line 243
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 244
    .line 245
    .line 246
    iget-object v2, v0, Lv00/b;->f:Lv00/i;

    .line 247
    .line 248
    iget-object v4, v2, Lv00/i;->j:Llh0/e;

    .line 249
    .line 250
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v4

    .line 254
    check-cast v4, Lyy0/i;

    .line 255
    .line 256
    new-instance v5, Lv00/a;

    .line 257
    .line 258
    const/4 v6, 0x0

    .line 259
    invoke-direct {v5, v2, v6}, Lv00/a;-><init>(Lv00/i;I)V

    .line 260
    .line 261
    .line 262
    iput v3, v0, Lv00/b;->e:I

    .line 263
    .line 264
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v0

    .line 268
    if-ne v0, v1, :cond_9

    .line 269
    .line 270
    goto :goto_6

    .line 271
    :cond_9
    :goto_5
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 272
    .line 273
    :goto_6
    return-object v1

    .line 274
    nop

    .line 275
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
