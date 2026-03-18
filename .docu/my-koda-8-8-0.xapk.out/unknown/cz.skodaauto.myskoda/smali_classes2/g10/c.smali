.class public final Lg10/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lg10/f;


# direct methods
.method public synthetic constructor <init>(Lkotlin/coroutines/Continuation;Lg10/f;I)V
    .locals 0

    .line 1
    iput p3, p0, Lg10/c;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lg10/c;->h:Lg10/f;

    .line 4
    .line 5
    const/4 p2, 0x3

    .line 6
    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lg10/c;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    new-instance v0, Lg10/c;

    .line 11
    .line 12
    iget-object p0, p0, Lg10/c;->h:Lg10/f;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-direct {v0, p3, p0, v1}, Lg10/c;-><init>(Lkotlin/coroutines/Continuation;Lg10/f;I)V

    .line 16
    .line 17
    .line 18
    iput-object p1, v0, Lg10/c;->f:Lyy0/j;

    .line 19
    .line 20
    iput-object p2, v0, Lg10/c;->g:Ljava/lang/Object;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Lg10/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_0
    new-instance v0, Lg10/c;

    .line 30
    .line 31
    iget-object p0, p0, Lg10/c;->h:Lg10/f;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-direct {v0, p3, p0, v1}, Lg10/c;-><init>(Lkotlin/coroutines/Continuation;Lg10/f;I)V

    .line 35
    .line 36
    .line 37
    iput-object p1, v0, Lg10/c;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object p2, v0, Lg10/c;->g:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lg10/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lg10/c;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lg10/c;->e:I

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v2, :cond_1

    .line 14
    .line 15
    if-ne v2, v3, :cond_0

    .line 16
    .line 17
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw v0

    .line 29
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object v2, v0, Lg10/c;->f:Lyy0/j;

    .line 33
    .line 34
    iget-object v4, v0, Lg10/c;->g:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v4, Lne0/t;

    .line 37
    .line 38
    instance-of v5, v4, Lne0/e;

    .line 39
    .line 40
    if-eqz v5, :cond_3

    .line 41
    .line 42
    check-cast v4, Lne0/e;

    .line 43
    .line 44
    iget-object v4, v4, Lne0/e;->a:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v4, Lss0/u;

    .line 47
    .line 48
    iget-object v4, v4, Lss0/u;->h:Ljava/lang/String;

    .line 49
    .line 50
    if-eqz v4, :cond_2

    .line 51
    .line 52
    iget-object v5, v0, Lg10/c;->h:Lg10/f;

    .line 53
    .line 54
    iget-object v5, v5, Lg10/f;->o:Le10/b;

    .line 55
    .line 56
    invoke-virtual {v5, v4}, Le10/b;->a(Ljava/lang/String;)Lyy0/i;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    goto :goto_0

    .line 61
    :cond_2
    new-instance v5, Lne0/c;

    .line 62
    .line 63
    new-instance v6, Ljava/lang/Exception;

    .line 64
    .line 65
    const-string v4, "Dealer id is not available"

    .line 66
    .line 67
    invoke-direct {v6, v4}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const/4 v9, 0x0

    .line 71
    const/16 v10, 0x1e

    .line 72
    .line 73
    const/4 v7, 0x0

    .line 74
    const/4 v8, 0x0

    .line 75
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 76
    .line 77
    .line 78
    new-instance v4, Lyy0/m;

    .line 79
    .line 80
    const/4 v6, 0x0

    .line 81
    invoke-direct {v4, v5, v6}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 82
    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_3
    instance-of v5, v4, Lne0/c;

    .line 86
    .line 87
    if-eqz v5, :cond_5

    .line 88
    .line 89
    new-instance v5, Lyy0/m;

    .line 90
    .line 91
    const/4 v6, 0x0

    .line 92
    invoke-direct {v5, v4, v6}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 93
    .line 94
    .line 95
    move-object v4, v5

    .line 96
    :goto_0
    const/4 v5, 0x0

    .line 97
    iput-object v5, v0, Lg10/c;->f:Lyy0/j;

    .line 98
    .line 99
    iput-object v5, v0, Lg10/c;->g:Ljava/lang/Object;

    .line 100
    .line 101
    iput v3, v0, Lg10/c;->e:I

    .line 102
    .line 103
    invoke-static {v2, v4, v0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    if-ne v0, v1, :cond_4

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_4
    :goto_1
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 111
    .line 112
    :goto_2
    return-object v1

    .line 113
    :cond_5
    new-instance v0, La8/r0;

    .line 114
    .line 115
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 116
    .line 117
    .line 118
    throw v0

    .line 119
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 120
    .line 121
    iget v2, v0, Lg10/c;->e:I

    .line 122
    .line 123
    const/4 v3, 0x1

    .line 124
    if-eqz v2, :cond_7

    .line 125
    .line 126
    if-ne v2, v3, :cond_6

    .line 127
    .line 128
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    goto/16 :goto_4

    .line 132
    .line 133
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 134
    .line 135
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 136
    .line 137
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    throw v0

    .line 141
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    iget-object v2, v0, Lg10/c;->f:Lyy0/j;

    .line 145
    .line 146
    iget-object v4, v0, Lg10/c;->g:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v4, Lne0/t;

    .line 149
    .line 150
    instance-of v5, v4, Lne0/e;

    .line 151
    .line 152
    if-eqz v5, :cond_9

    .line 153
    .line 154
    check-cast v4, Lne0/e;

    .line 155
    .line 156
    iget-object v4, v4, Lne0/e;->a:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v4, Lss0/u;

    .line 159
    .line 160
    iget-object v4, v4, Lss0/u;->h:Ljava/lang/String;

    .line 161
    .line 162
    iget-object v5, v0, Lg10/c;->h:Lg10/f;

    .line 163
    .line 164
    if-eqz v4, :cond_8

    .line 165
    .line 166
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 167
    .line 168
    .line 169
    move-result-object v6

    .line 170
    move-object v7, v6

    .line 171
    check-cast v7, Lg10/d;

    .line 172
    .line 173
    const/16 v18, 0x0

    .line 174
    .line 175
    const/16 v19, 0x3ff

    .line 176
    .line 177
    const/4 v8, 0x0

    .line 178
    const/4 v9, 0x0

    .line 179
    const/4 v10, 0x0

    .line 180
    const/4 v11, 0x0

    .line 181
    const/4 v12, 0x0

    .line 182
    const/4 v13, 0x0

    .line 183
    const/4 v14, 0x0

    .line 184
    const/4 v15, 0x0

    .line 185
    const/16 v16, 0x0

    .line 186
    .line 187
    const/16 v17, 0x0

    .line 188
    .line 189
    invoke-static/range {v7 .. v19}, Lg10/d;->a(Lg10/d;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZI)Lg10/d;

    .line 190
    .line 191
    .line 192
    move-result-object v6

    .line 193
    invoke-virtual {v5, v6}, Lql0/j;->g(Lql0/h;)V

    .line 194
    .line 195
    .line 196
    iget-object v5, v5, Lg10/f;->i:Le10/d;

    .line 197
    .line 198
    invoke-virtual {v5, v4}, Le10/d;->a(Ljava/lang/String;)Lyy0/i;

    .line 199
    .line 200
    .line 201
    move-result-object v4

    .line 202
    goto :goto_3

    .line 203
    :cond_8
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 204
    .line 205
    .line 206
    move-result-object v4

    .line 207
    move-object v6, v4

    .line 208
    check-cast v6, Lg10/d;

    .line 209
    .line 210
    const/16 v17, 0x1

    .line 211
    .line 212
    const/16 v18, 0x3ff

    .line 213
    .line 214
    const/4 v7, 0x0

    .line 215
    const/4 v8, 0x0

    .line 216
    const/4 v9, 0x0

    .line 217
    const/4 v10, 0x0

    .line 218
    const/4 v11, 0x0

    .line 219
    const/4 v12, 0x0

    .line 220
    const/4 v13, 0x0

    .line 221
    const/4 v14, 0x0

    .line 222
    const/4 v15, 0x0

    .line 223
    const/16 v16, 0x0

    .line 224
    .line 225
    invoke-static/range {v6 .. v18}, Lg10/d;->a(Lg10/d;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZI)Lg10/d;

    .line 226
    .line 227
    .line 228
    move-result-object v4

    .line 229
    invoke-virtual {v5, v4}, Lql0/j;->g(Lql0/h;)V

    .line 230
    .line 231
    .line 232
    new-instance v6, Lne0/c;

    .line 233
    .line 234
    new-instance v7, Ljava/lang/Exception;

    .line 235
    .line 236
    const-string v4, "Dealer id is not available"

    .line 237
    .line 238
    invoke-direct {v7, v4}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    const/4 v10, 0x0

    .line 242
    const/16 v11, 0x1e

    .line 243
    .line 244
    const/4 v8, 0x0

    .line 245
    const/4 v9, 0x0

    .line 246
    invoke-direct/range {v6 .. v11}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 247
    .line 248
    .line 249
    new-instance v4, Lyy0/m;

    .line 250
    .line 251
    const/4 v5, 0x0

    .line 252
    invoke-direct {v4, v6, v5}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 253
    .line 254
    .line 255
    goto :goto_3

    .line 256
    :cond_9
    instance-of v5, v4, Lne0/c;

    .line 257
    .line 258
    if-eqz v5, :cond_b

    .line 259
    .line 260
    new-instance v5, Lyy0/m;

    .line 261
    .line 262
    const/4 v6, 0x0

    .line 263
    invoke-direct {v5, v4, v6}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 264
    .line 265
    .line 266
    move-object v4, v5

    .line 267
    :goto_3
    const/4 v5, 0x0

    .line 268
    iput-object v5, v0, Lg10/c;->f:Lyy0/j;

    .line 269
    .line 270
    iput-object v5, v0, Lg10/c;->g:Ljava/lang/Object;

    .line 271
    .line 272
    iput v3, v0, Lg10/c;->e:I

    .line 273
    .line 274
    invoke-static {v2, v4, v0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v0

    .line 278
    if-ne v0, v1, :cond_a

    .line 279
    .line 280
    goto :goto_5

    .line 281
    :cond_a
    :goto_4
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 282
    .line 283
    :goto_5
    return-object v1

    .line 284
    :cond_b
    new-instance v0, La8/r0;

    .line 285
    .line 286
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 287
    .line 288
    .line 289
    throw v0

    .line 290
    nop

    .line 291
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
