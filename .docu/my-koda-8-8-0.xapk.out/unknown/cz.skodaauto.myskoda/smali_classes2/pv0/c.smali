.class public final Lpv0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lpv0/g;


# direct methods
.method public synthetic constructor <init>(Lpv0/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Lpv0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lpv0/c;->e:Lpv0/g;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b(Lss0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 21

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
    instance-of v3, v2, Lpv0/b;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lpv0/b;

    .line 13
    .line 14
    iget v4, v3, Lpv0/b;->k:I

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
    iput v4, v3, Lpv0/b;->k:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lpv0/b;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Lpv0/b;-><init>(Lpv0/c;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lpv0/b;->i:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lpv0/b;->k:I

    .line 36
    .line 37
    const/4 v6, 0x2

    .line 38
    iget-object v0, v0, Lpv0/c;->e:Lpv0/g;

    .line 39
    .line 40
    const/4 v7, 0x1

    .line 41
    const/4 v8, 0x0

    .line 42
    if-eqz v5, :cond_3

    .line 43
    .line 44
    if-eq v5, v7, :cond_2

    .line 45
    .line 46
    if-ne v5, v6, :cond_1

    .line 47
    .line 48
    iget v1, v3, Lpv0/b;->h:I

    .line 49
    .line 50
    iget v4, v3, Lpv0/b;->g:I

    .line 51
    .line 52
    iget v5, v3, Lpv0/b;->f:I

    .line 53
    .line 54
    iget-object v6, v3, Lpv0/b;->e:Lne0/t;

    .line 55
    .line 56
    iget-object v3, v3, Lpv0/b;->d:Lss0/b;

    .line 57
    .line 58
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto/16 :goto_6

    .line 62
    .line 63
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 64
    .line 65
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 66
    .line 67
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw v0

    .line 71
    :cond_2
    iget v1, v3, Lpv0/b;->h:I

    .line 72
    .line 73
    iget v5, v3, Lpv0/b;->g:I

    .line 74
    .line 75
    iget v9, v3, Lpv0/b;->f:I

    .line 76
    .line 77
    iget-object v10, v3, Lpv0/b;->d:Lss0/b;

    .line 78
    .line 79
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    move/from16 v20, v9

    .line 83
    .line 84
    move v9, v1

    .line 85
    move-object v1, v10

    .line 86
    move/from16 v10, v20

    .line 87
    .line 88
    goto :goto_4

    .line 89
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    if-eqz v1, :cond_4

    .line 93
    .line 94
    sget-object v2, Lss0/e;->H1:Lss0/e;

    .line 95
    .line 96
    invoke-static {v1, v2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 97
    .line 98
    .line 99
    move-result v2

    .line 100
    goto :goto_1

    .line 101
    :cond_4
    move v2, v8

    .line 102
    :goto_1
    if-eqz v1, :cond_5

    .line 103
    .line 104
    sget-object v5, Lss0/e;->r:Lss0/e;

    .line 105
    .line 106
    invoke-static {v1, v5}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 107
    .line 108
    .line 109
    move-result v5

    .line 110
    goto :goto_2

    .line 111
    :cond_5
    move v5, v8

    .line 112
    :goto_2
    if-eqz v1, :cond_6

    .line 113
    .line 114
    sget-object v9, Lss0/e;->x:Lss0/e;

    .line 115
    .line 116
    invoke-static {v1, v9}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 117
    .line 118
    .line 119
    move-result v9

    .line 120
    goto :goto_3

    .line 121
    :cond_6
    move v9, v8

    .line 122
    :goto_3
    iget-object v10, v0, Lpv0/g;->p:Lgb0/h;

    .line 123
    .line 124
    iput-object v1, v3, Lpv0/b;->d:Lss0/b;

    .line 125
    .line 126
    iput v2, v3, Lpv0/b;->f:I

    .line 127
    .line 128
    iput v5, v3, Lpv0/b;->g:I

    .line 129
    .line 130
    iput v9, v3, Lpv0/b;->h:I

    .line 131
    .line 132
    iput v7, v3, Lpv0/b;->k:I

    .line 133
    .line 134
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 135
    .line 136
    .line 137
    invoke-virtual {v10, v3}, Lgb0/h;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v10

    .line 141
    if-ne v10, v4, :cond_7

    .line 142
    .line 143
    goto :goto_5

    .line 144
    :cond_7
    move-object/from16 v20, v10

    .line 145
    .line 146
    move v10, v2

    .line 147
    move-object/from16 v2, v20

    .line 148
    .line 149
    :goto_4
    check-cast v2, Lne0/t;

    .line 150
    .line 151
    iget-object v11, v0, Lpv0/g;->t:Lhh0/a;

    .line 152
    .line 153
    sget-object v12, Lih0/a;->n:Lih0/a;

    .line 154
    .line 155
    iput-object v1, v3, Lpv0/b;->d:Lss0/b;

    .line 156
    .line 157
    iput-object v2, v3, Lpv0/b;->e:Lne0/t;

    .line 158
    .line 159
    iput v10, v3, Lpv0/b;->f:I

    .line 160
    .line 161
    iput v5, v3, Lpv0/b;->g:I

    .line 162
    .line 163
    iput v9, v3, Lpv0/b;->h:I

    .line 164
    .line 165
    iput v6, v3, Lpv0/b;->k:I

    .line 166
    .line 167
    invoke-virtual {v11, v12, v3}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v3

    .line 171
    if-ne v3, v4, :cond_8

    .line 172
    .line 173
    :goto_5
    return-object v4

    .line 174
    :cond_8
    move-object v6, v2

    .line 175
    move-object v2, v3

    .line 176
    move v4, v5

    .line 177
    move v5, v10

    .line 178
    move-object v3, v1

    .line 179
    move v1, v9

    .line 180
    :goto_6
    check-cast v2, Ljava/lang/Boolean;

    .line 181
    .line 182
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 183
    .line 184
    .line 185
    move-result v2

    .line 186
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 187
    .line 188
    .line 189
    move-result-object v9

    .line 190
    move-object v10, v9

    .line 191
    check-cast v10, Lpv0/f;

    .line 192
    .line 193
    if-eqz v3, :cond_9

    .line 194
    .line 195
    sget-object v9, Lss0/e;->S1:Lss0/e;

    .line 196
    .line 197
    invoke-static {v3, v9}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 198
    .line 199
    .line 200
    move-result v9

    .line 201
    move v11, v9

    .line 202
    goto :goto_7

    .line 203
    :cond_9
    move v11, v8

    .line 204
    :goto_7
    if-nez v5, :cond_b

    .line 205
    .line 206
    if-nez v4, :cond_b

    .line 207
    .line 208
    if-eqz v1, :cond_a

    .line 209
    .line 210
    goto :goto_8

    .line 211
    :cond_a
    move v12, v8

    .line 212
    goto :goto_9

    .line 213
    :cond_b
    :goto_8
    move v12, v7

    .line 214
    :goto_9
    instance-of v1, v6, Lne0/e;

    .line 215
    .line 216
    if-eqz v1, :cond_c

    .line 217
    .line 218
    move-object v4, v6

    .line 219
    check-cast v4, Lne0/e;

    .line 220
    .line 221
    iget-object v4, v4, Lne0/e;->a:Ljava/lang/Object;

    .line 222
    .line 223
    sget-object v5, Lhb0/a;->d:Lhb0/a;

    .line 224
    .line 225
    if-ne v4, v5, :cond_c

    .line 226
    .line 227
    move v13, v7

    .line 228
    goto :goto_a

    .line 229
    :cond_c
    move v13, v8

    .line 230
    :goto_a
    if-eqz v1, :cond_d

    .line 231
    .line 232
    check-cast v6, Lne0/e;

    .line 233
    .line 234
    iget-object v1, v6, Lne0/e;->a:Ljava/lang/Object;

    .line 235
    .line 236
    sget-object v4, Lhb0/a;->d:Lhb0/a;

    .line 237
    .line 238
    if-eq v1, v4, :cond_e

    .line 239
    .line 240
    :cond_d
    if-eqz v3, :cond_f

    .line 241
    .line 242
    sget-object v1, Lss0/e;->x1:Lss0/e;

    .line 243
    .line 244
    invoke-static {v3, v1}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 245
    .line 246
    .line 247
    move-result v1

    .line 248
    if-ne v1, v7, :cond_f

    .line 249
    .line 250
    :cond_e
    move/from16 v16, v7

    .line 251
    .line 252
    goto :goto_b

    .line 253
    :cond_f
    move/from16 v16, v8

    .line 254
    .line 255
    :goto_b
    if-eqz v2, :cond_11

    .line 256
    .line 257
    if-eqz v3, :cond_10

    .line 258
    .line 259
    sget-object v1, Lss0/e;->Z:Lss0/e;

    .line 260
    .line 261
    invoke-static {v3, v1}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 262
    .line 263
    .line 264
    move-result v1

    .line 265
    goto :goto_c

    .line 266
    :cond_10
    move v1, v8

    .line 267
    :goto_c
    if-eqz v1, :cond_11

    .line 268
    .line 269
    move v15, v7

    .line 270
    goto :goto_d

    .line 271
    :cond_11
    move v15, v8

    .line 272
    :goto_d
    const/16 v18, 0x0

    .line 273
    .line 274
    const/16 v19, 0x1c8

    .line 275
    .line 276
    const/4 v14, 0x0

    .line 277
    const/16 v17, 0x0

    .line 278
    .line 279
    invoke-static/range {v10 .. v19}, Lpv0/f;->a(Lpv0/f;ZZZZZZLjava/lang/String;ZI)Lpv0/f;

    .line 280
    .line 281
    .line 282
    move-result-object v1

    .line 283
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 284
    .line 285
    .line 286
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 287
    .line 288
    return-object v0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lpv0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lmp0/a;

    .line 7
    .line 8
    sget-object p2, Lmp0/a;->e:Lmp0/a;

    .line 9
    .line 10
    if-ne p1, p2, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Lpv0/c;->e:Lpv0/g;

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    move-object v0, p1

    .line 19
    check-cast v0, Lpv0/f;

    .line 20
    .line 21
    const/4 v8, 0x1

    .line 22
    const/16 v9, 0x17f

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v5, 0x0

    .line 29
    const/4 v6, 0x0

    .line 30
    const/4 v7, 0x0

    .line 31
    invoke-static/range {v0 .. v9}, Lpv0/f;->a(Lpv0/f;ZZZZZZLjava/lang/String;ZI)Lpv0/f;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_0
    check-cast p1, Lss0/b;

    .line 42
    .line 43
    invoke-virtual {p0, p1, p2}, Lpv0/c;->b(Lss0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
