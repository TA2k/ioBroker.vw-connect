.class public final Ln90/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ln90/k;


# direct methods
.method public synthetic constructor <init>(Ln90/k;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ln90/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln90/e;->f:Ln90/k;

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
    iget p1, p0, Ln90/e;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ln90/e;

    .line 7
    .line 8
    iget-object p0, p0, Ln90/e;->f:Ln90/k;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ln90/e;-><init>(Ln90/k;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ln90/e;

    .line 16
    .line 17
    iget-object p0, p0, Ln90/e;->f:Ln90/k;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ln90/e;-><init>(Ln90/k;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ln90/e;

    .line 25
    .line 26
    iget-object p0, p0, Ln90/e;->f:Ln90/k;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ln90/e;-><init>(Ln90/k;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ln90/e;->d:I

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
    invoke-virtual {p0, p1, p2}, Ln90/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ln90/e;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ln90/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ln90/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ln90/e;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ln90/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ln90/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ln90/e;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ln90/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 37

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ln90/e;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Ln90/e;->e:I

    .line 11
    .line 12
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    const/4 v4, 0x2

    .line 15
    const/4 v5, 0x1

    .line 16
    iget-object v6, v0, Ln90/e;->f:Ln90/k;

    .line 17
    .line 18
    if-eqz v2, :cond_2

    .line 19
    .line 20
    if-eq v2, v5, :cond_1

    .line 21
    .line 22
    if-ne v2, v4, :cond_0

    .line 23
    .line 24
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    goto/16 :goto_1

    .line 28
    .line 29
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 32
    .line 33
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw v0

    .line 37
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    move-object/from16 v2, p1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iget-object v2, v6, Ln90/k;->y:Lk90/f;

    .line 47
    .line 48
    iput v5, v0, Ln90/e;->e:I

    .line 49
    .line 50
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v2, v0}, Lk90/f;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    if-ne v2, v1, :cond_3

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    :goto_0
    check-cast v2, Ljava/lang/Boolean;

    .line 61
    .line 62
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-nez v2, :cond_5

    .line 67
    .line 68
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    move-object v7, v2

    .line 73
    check-cast v7, Ln90/h;

    .line 74
    .line 75
    const/16 v35, 0x1

    .line 76
    .line 77
    const v36, 0x7ffffff

    .line 78
    .line 79
    .line 80
    const/4 v8, 0x0

    .line 81
    const/4 v9, 0x0

    .line 82
    const/4 v10, 0x0

    .line 83
    const/4 v11, 0x0

    .line 84
    const/4 v12, 0x0

    .line 85
    const/4 v13, 0x0

    .line 86
    const/4 v14, 0x0

    .line 87
    const/4 v15, 0x0

    .line 88
    const/16 v16, 0x0

    .line 89
    .line 90
    const/16 v17, 0x0

    .line 91
    .line 92
    const/16 v18, 0x0

    .line 93
    .line 94
    const/16 v19, 0x0

    .line 95
    .line 96
    const/16 v20, 0x0

    .line 97
    .line 98
    const/16 v21, 0x0

    .line 99
    .line 100
    const/16 v22, 0x0

    .line 101
    .line 102
    const/16 v23, 0x0

    .line 103
    .line 104
    const/16 v24, 0x0

    .line 105
    .line 106
    const/16 v25, 0x0

    .line 107
    .line 108
    const/16 v26, 0x0

    .line 109
    .line 110
    const/16 v27, 0x0

    .line 111
    .line 112
    const/16 v28, 0x0

    .line 113
    .line 114
    const/16 v29, 0x0

    .line 115
    .line 116
    const/16 v30, 0x0

    .line 117
    .line 118
    const/16 v31, 0x0

    .line 119
    .line 120
    const/16 v32, 0x0

    .line 121
    .line 122
    const/16 v33, 0x0

    .line 123
    .line 124
    const/16 v34, 0x0

    .line 125
    .line 126
    invoke-static/range {v7 .. v36}, Ln90/h;->a(Ln90/h;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZLjava/util/ArrayList;Lql0/g;Ln90/f;Ln90/g;ZZZIZI)Ln90/h;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    invoke-virtual {v6, v2}, Lql0/j;->g(Lql0/h;)V

    .line 131
    .line 132
    .line 133
    iput v4, v0, Ln90/e;->e:I

    .line 134
    .line 135
    const-wide/16 v4, 0xbb8

    .line 136
    .line 137
    invoke-static {v4, v5, v0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    if-ne v0, v1, :cond_4

    .line 142
    .line 143
    goto :goto_2

    .line 144
    :cond_4
    :goto_1
    invoke-virtual {v6}, Ln90/k;->k()V

    .line 145
    .line 146
    .line 147
    :cond_5
    move-object v1, v3

    .line 148
    :goto_2
    return-object v1

    .line 149
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 150
    .line 151
    iget v2, v0, Ln90/e;->e:I

    .line 152
    .line 153
    const/4 v3, 0x1

    .line 154
    if-eqz v2, :cond_7

    .line 155
    .line 156
    if-ne v2, v3, :cond_6

    .line 157
    .line 158
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    goto :goto_3

    .line 162
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 163
    .line 164
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 165
    .line 166
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    throw v0

    .line 170
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    iget-object v2, v0, Ln90/e;->f:Ln90/k;

    .line 174
    .line 175
    iget-object v4, v2, Ln90/k;->t:Lk90/d;

    .line 176
    .line 177
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v4

    .line 181
    check-cast v4, Lyy0/i;

    .line 182
    .line 183
    new-instance v5, Ln90/c;

    .line 184
    .line 185
    const/4 v6, 0x3

    .line 186
    invoke-direct {v5, v2, v6}, Ln90/c;-><init>(Ln90/k;I)V

    .line 187
    .line 188
    .line 189
    iput v3, v0, Ln90/e;->e:I

    .line 190
    .line 191
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    if-ne v0, v1, :cond_8

    .line 196
    .line 197
    goto :goto_4

    .line 198
    :cond_8
    :goto_3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 199
    .line 200
    :goto_4
    return-object v1

    .line 201
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 202
    .line 203
    iget v2, v0, Ln90/e;->e:I

    .line 204
    .line 205
    iget-object v3, v0, Ln90/e;->f:Ln90/k;

    .line 206
    .line 207
    const/4 v4, 0x2

    .line 208
    const/4 v5, 0x1

    .line 209
    if-eqz v2, :cond_b

    .line 210
    .line 211
    if-eq v2, v5, :cond_a

    .line 212
    .line 213
    if-ne v2, v4, :cond_9

    .line 214
    .line 215
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    goto :goto_6

    .line 219
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 220
    .line 221
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 222
    .line 223
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    throw v0

    .line 227
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 228
    .line 229
    .line 230
    move-object/from16 v2, p1

    .line 231
    .line 232
    goto :goto_5

    .line 233
    :cond_b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    iget-object v2, v3, Ln90/k;->z:Lgf0/c;

    .line 237
    .line 238
    iput v5, v0, Ln90/e;->e:I

    .line 239
    .line 240
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 241
    .line 242
    .line 243
    iget-object v2, v2, Lgf0/c;->a:Lgf0/b;

    .line 244
    .line 245
    check-cast v2, Ldf0/a;

    .line 246
    .line 247
    iget-object v2, v2, Ldf0/a;->b:Lyy0/c2;

    .line 248
    .line 249
    if-ne v2, v1, :cond_c

    .line 250
    .line 251
    goto :goto_7

    .line 252
    :cond_c
    :goto_5
    check-cast v2, Lyy0/i;

    .line 253
    .line 254
    new-instance v5, Ln90/c;

    .line 255
    .line 256
    const/4 v6, 0x1

    .line 257
    invoke-direct {v5, v3, v6}, Ln90/c;-><init>(Ln90/k;I)V

    .line 258
    .line 259
    .line 260
    iput v4, v0, Ln90/e;->e:I

    .line 261
    .line 262
    invoke-interface {v2, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v0

    .line 266
    if-ne v0, v1, :cond_d

    .line 267
    .line 268
    goto :goto_7

    .line 269
    :cond_d
    :goto_6
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 270
    .line 271
    :goto_7
    return-object v1

    .line 272
    nop

    .line 273
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
