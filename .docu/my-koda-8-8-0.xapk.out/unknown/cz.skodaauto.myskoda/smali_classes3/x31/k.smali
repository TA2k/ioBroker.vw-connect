.class public final Lx31/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Ljava/util/List;

.field public e:Ljava/util/List;

.field public f:I

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lx31/n;

.field public final synthetic i:Z

.field public final synthetic j:I


# direct methods
.method public constructor <init>(ILkotlin/coroutines/Continuation;Lx31/n;Z)V
    .locals 0

    .line 1
    iput-object p3, p0, Lx31/k;->h:Lx31/n;

    .line 2
    .line 3
    iput-boolean p4, p0, Lx31/k;->i:Z

    .line 4
    .line 5
    iput p1, p0, Lx31/k;->j:I

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, Lx31/k;

    .line 2
    .line 3
    iget-boolean v1, p0, Lx31/k;->i:Z

    .line 4
    .line 5
    iget v2, p0, Lx31/k;->j:I

    .line 6
    .line 7
    iget-object p0, p0, Lx31/k;->h:Lx31/n;

    .line 8
    .line 9
    invoke-direct {v0, v2, p2, p0, v1}, Lx31/k;-><init>(ILkotlin/coroutines/Continuation;Lx31/n;Z)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Lx31/k;->g:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lx31/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lx31/k;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lx31/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v2, v0, Lx31/k;->h:Lx31/n;

    .line 4
    .line 5
    iget-object v7, v2, Lq41/b;->d:Lyy0/c2;

    .line 6
    .line 7
    iget-object v1, v0, Lx31/k;->g:Ljava/lang/Object;

    .line 8
    .line 9
    move-object v8, v1

    .line 10
    check-cast v8, Lvy0/b0;

    .line 11
    .line 12
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v1, v0, Lx31/k;->f:I

    .line 15
    .line 16
    const/4 v10, 0x0

    .line 17
    const/4 v11, 0x3

    .line 18
    const/4 v3, 0x2

    .line 19
    iget-boolean v4, v0, Lx31/k;->i:Z

    .line 20
    .line 21
    const/4 v12, 0x1

    .line 22
    const/4 v5, 0x0

    .line 23
    if-eqz v1, :cond_4

    .line 24
    .line 25
    if-eq v1, v12, :cond_3

    .line 26
    .line 27
    if-eq v1, v3, :cond_1

    .line 28
    .line 29
    if-ne v1, v11, :cond_0

    .line 30
    .line 31
    iget-object v1, v0, Lx31/k;->e:Ljava/util/List;

    .line 32
    .line 33
    check-cast v1, Ljava/util/List;

    .line 34
    .line 35
    iget-object v0, v0, Lx31/k;->d:Ljava/util/List;

    .line 36
    .line 37
    check-cast v0, Ljava/util/List;

    .line 38
    .line 39
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    move-object/from16 v19, v0

    .line 43
    .line 44
    move-object/from16 v20, v1

    .line 45
    .line 46
    move-object/from16 v0, p1

    .line 47
    .line 48
    goto/16 :goto_3

    .line 49
    .line 50
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw v0

    .line 58
    :cond_1
    iget-object v1, v0, Lx31/k;->d:Ljava/util/List;

    .line 59
    .line 60
    check-cast v1, Ljava/util/List;

    .line 61
    .line 62
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    move-object/from16 v3, p1

    .line 66
    .line 67
    :cond_2
    move-object v13, v1

    .line 68
    goto :goto_1

    .line 69
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    move-object/from16 v1, p1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    :cond_5
    invoke-virtual {v7}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    move-object v13, v1

    .line 83
    check-cast v13, Lx31/o;

    .line 84
    .line 85
    const/16 v25, 0x0

    .line 86
    .line 87
    const/16 v26, 0x2ff8

    .line 88
    .line 89
    const/4 v14, 0x1

    .line 90
    const/4 v15, 0x1

    .line 91
    const/16 v16, 0x1

    .line 92
    .line 93
    const/16 v17, 0x0

    .line 94
    .line 95
    const/16 v18, 0x0

    .line 96
    .line 97
    const/16 v19, 0x0

    .line 98
    .line 99
    const/16 v20, 0x0

    .line 100
    .line 101
    const/16 v21, 0x0

    .line 102
    .line 103
    const/16 v22, 0x0

    .line 104
    .line 105
    const/16 v23, 0x0

    .line 106
    .line 107
    const/16 v24, 0x0

    .line 108
    .line 109
    invoke-static/range {v13 .. v26}, Lx31/o;->a(Lx31/o;ZZZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Ll4/v;Ljava/lang/String;I)Lx31/o;

    .line 110
    .line 111
    .line 112
    move-result-object v6

    .line 113
    invoke-virtual {v7, v1, v6}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v1

    .line 117
    if-eqz v1, :cond_5

    .line 118
    .line 119
    new-instance v1, Lx31/m;

    .line 120
    .line 121
    invoke-direct {v1, v12, v5, v2, v4}, Lx31/m;-><init>(ILkotlin/coroutines/Continuation;Lx31/n;Z)V

    .line 122
    .line 123
    .line 124
    invoke-static {v8, v5, v1, v11}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    iput-object v8, v0, Lx31/k;->g:Ljava/lang/Object;

    .line 129
    .line 130
    iput v12, v0, Lx31/k;->f:I

    .line 131
    .line 132
    invoke-virtual {v1, v0}, Lvy0/p1;->y(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 137
    .line 138
    if-ne v1, v9, :cond_6

    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_6
    :goto_0
    check-cast v1, Ljava/util/List;

    .line 142
    .line 143
    new-instance v6, Lx31/m;

    .line 144
    .line 145
    invoke-direct {v6, v10, v5, v2, v4}, Lx31/m;-><init>(ILkotlin/coroutines/Continuation;Lx31/n;Z)V

    .line 146
    .line 147
    .line 148
    invoke-static {v8, v5, v6, v11}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 149
    .line 150
    .line 151
    move-result-object v6

    .line 152
    iput-object v8, v0, Lx31/k;->g:Ljava/lang/Object;

    .line 153
    .line 154
    move-object v13, v1

    .line 155
    check-cast v13, Ljava/util/List;

    .line 156
    .line 157
    iput-object v13, v0, Lx31/k;->d:Ljava/util/List;

    .line 158
    .line 159
    iput v3, v0, Lx31/k;->f:I

    .line 160
    .line 161
    invoke-virtual {v6, v0}, Lvy0/p1;->y(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v3

    .line 165
    if-ne v3, v9, :cond_2

    .line 166
    .line 167
    goto :goto_2

    .line 168
    :goto_1
    move-object v14, v3

    .line 169
    check-cast v14, Ljava/util/List;

    .line 170
    .line 171
    new-instance v1, Lhg/n;

    .line 172
    .line 173
    const/4 v6, 0x2

    .line 174
    move v3, v4

    .line 175
    iget v4, v0, Lx31/k;->j:I

    .line 176
    .line 177
    invoke-direct/range {v1 .. v6}, Lhg/n;-><init>(Landroidx/lifecycle/b1;ZILkotlin/coroutines/Continuation;I)V

    .line 178
    .line 179
    .line 180
    invoke-static {v8, v5, v1, v11}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    iput-object v5, v0, Lx31/k;->g:Ljava/lang/Object;

    .line 185
    .line 186
    move-object v3, v13

    .line 187
    check-cast v3, Ljava/util/List;

    .line 188
    .line 189
    iput-object v3, v0, Lx31/k;->d:Ljava/util/List;

    .line 190
    .line 191
    move-object v3, v14

    .line 192
    check-cast v3, Ljava/util/List;

    .line 193
    .line 194
    iput-object v3, v0, Lx31/k;->e:Ljava/util/List;

    .line 195
    .line 196
    iput v11, v0, Lx31/k;->f:I

    .line 197
    .line 198
    invoke-virtual {v1, v0}, Lvy0/p1;->y(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    if-ne v0, v9, :cond_7

    .line 203
    .line 204
    :goto_2
    return-object v9

    .line 205
    :cond_7
    move-object/from16 v19, v13

    .line 206
    .line 207
    move-object/from16 v20, v14

    .line 208
    .line 209
    :goto_3
    check-cast v0, Ljava/util/List;

    .line 210
    .line 211
    invoke-static {v2, v0, v12}, Lx31/n;->b(Lx31/n;Ljava/util/List;Z)Ljava/util/ArrayList;

    .line 212
    .line 213
    .line 214
    move-result-object v21

    .line 215
    invoke-static {v2, v0, v10}, Lx31/n;->b(Lx31/n;Ljava/util/List;Z)Ljava/util/ArrayList;

    .line 216
    .line 217
    .line 218
    move-result-object v22

    .line 219
    :goto_4
    invoke-virtual {v7}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v1

    .line 223
    move-object v13, v1

    .line 224
    check-cast v13, Lx31/o;

    .line 225
    .line 226
    const-string v25, "1500"

    .line 227
    .line 228
    const/16 v26, 0x1c08

    .line 229
    .line 230
    const/4 v14, 0x0

    .line 231
    const/4 v15, 0x0

    .line 232
    const/16 v16, 0x0

    .line 233
    .line 234
    const/16 v17, 0x0

    .line 235
    .line 236
    const/16 v24, 0x0

    .line 237
    .line 238
    move-object/from16 v23, v21

    .line 239
    .line 240
    move-object/from16 v18, v0

    .line 241
    .line 242
    invoke-static/range {v13 .. v26}, Lx31/o;->a(Lx31/o;ZZZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Ll4/v;Ljava/lang/String;I)Lx31/o;

    .line 243
    .line 244
    .line 245
    move-result-object v0

    .line 246
    invoke-virtual {v7, v1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 247
    .line 248
    .line 249
    move-result v0

    .line 250
    if-eqz v0, :cond_8

    .line 251
    .line 252
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 253
    .line 254
    return-object v0

    .line 255
    :cond_8
    move-object/from16 v0, v18

    .line 256
    .line 257
    goto :goto_4
.end method
