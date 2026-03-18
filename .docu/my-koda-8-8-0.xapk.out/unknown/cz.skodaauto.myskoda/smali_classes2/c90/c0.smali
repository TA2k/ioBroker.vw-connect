.class public final Lc90/c0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lfo0/b;

.field public final i:Lfo0/c;

.field public final j:Ltr0/b;

.field public final k:Lnr0/f;

.field public final l:La90/v;

.field public final m:La90/t;

.field public final n:La90/g;

.field public final o:Lij0/a;

.field public final p:La90/b;

.field public final q:Lfj0/i;


# direct methods
.method public constructor <init>(Lfo0/b;Lfo0/c;Ltr0/b;Lnr0/f;La90/v;La90/t;La90/g;Lij0/a;La90/b;Lfj0/i;)V
    .locals 5

    .line 1
    new-instance v0, Lc90/z;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    const/4 v3, 0x1

    .line 7
    const/4 v4, 0x0

    .line 8
    invoke-direct {v0, v3, v4, v1, v2}, Lc90/z;-><init>(ZLql0/g;ZLjava/util/List;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lc90/c0;->h:Lfo0/b;

    .line 15
    .line 16
    iput-object p2, p0, Lc90/c0;->i:Lfo0/c;

    .line 17
    .line 18
    iput-object p3, p0, Lc90/c0;->j:Ltr0/b;

    .line 19
    .line 20
    iput-object p4, p0, Lc90/c0;->k:Lnr0/f;

    .line 21
    .line 22
    iput-object p5, p0, Lc90/c0;->l:La90/v;

    .line 23
    .line 24
    iput-object p6, p0, Lc90/c0;->m:La90/t;

    .line 25
    .line 26
    iput-object p7, p0, Lc90/c0;->n:La90/g;

    .line 27
    .line 28
    iput-object p8, p0, Lc90/c0;->o:Lij0/a;

    .line 29
    .line 30
    iput-object p9, p0, Lc90/c0;->p:La90/b;

    .line 31
    .line 32
    iput-object p10, p0, Lc90/c0;->q:Lfj0/i;

    .line 33
    .line 34
    new-instance p1, Lc90/y;

    .line 35
    .line 36
    const/4 p2, 0x0

    .line 37
    invoke-direct {p1, p0, v4, p2}, Lc90/y;-><init>(Lc90/c0;Lkotlin/coroutines/Continuation;I)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 41
    .line 42
    .line 43
    new-instance p1, Lc90/y;

    .line 44
    .line 45
    const/4 p2, 0x1

    .line 46
    invoke-direct {p1, p0, v4, p2}, Lc90/y;-><init>(Lc90/c0;Lkotlin/coroutines/Continuation;I)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public static final h(Lc90/c0;Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 17

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
    instance-of v3, v2, Lc90/b0;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lc90/b0;

    .line 13
    .line 14
    iget v4, v3, Lc90/b0;->g:I

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
    iput v4, v3, Lc90/b0;->g:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lc90/b0;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Lc90/b0;-><init>(Lc90/c0;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lc90/b0;->e:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lc90/b0;->g:I

    .line 36
    .line 37
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    const/4 v7, 0x1

    .line 40
    if-eqz v5, :cond_2

    .line 41
    .line 42
    if-ne v5, v7, :cond_1

    .line 43
    .line 44
    iget-object v1, v3, Lc90/b0;->d:Lne0/e;

    .line 45
    .line 46
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
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
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    instance-of v2, v1, Lne0/d;

    .line 62
    .line 63
    if-eqz v2, :cond_3

    .line 64
    .line 65
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    move-object v7, v1

    .line 70
    check-cast v7, Lc90/z;

    .line 71
    .line 72
    const/4 v11, 0x0

    .line 73
    const/16 v12, 0xb

    .line 74
    .line 75
    const/4 v8, 0x0

    .line 76
    const/4 v9, 0x0

    .line 77
    const/4 v10, 0x1

    .line 78
    invoke-static/range {v7 .. v12}, Lc90/z;->a(Lc90/z;ZLql0/g;ZLjava/util/ArrayList;I)Lc90/z;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 83
    .line 84
    .line 85
    return-object v6

    .line 86
    :cond_3
    instance-of v2, v1, Lne0/e;

    .line 87
    .line 88
    if-eqz v2, :cond_5

    .line 89
    .line 90
    iget-object v2, v0, Lc90/c0;->p:La90/b;

    .line 91
    .line 92
    move-object v5, v1

    .line 93
    check-cast v5, Lne0/e;

    .line 94
    .line 95
    iput-object v5, v3, Lc90/b0;->d:Lne0/e;

    .line 96
    .line 97
    iput v7, v3, Lc90/b0;->g:I

    .line 98
    .line 99
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v2, v3}, La90/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    if-ne v2, v4, :cond_4

    .line 107
    .line 108
    return-object v4

    .line 109
    :cond_4
    :goto_1
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    move-object v7, v2

    .line 114
    check-cast v7, Lc90/z;

    .line 115
    .line 116
    check-cast v1, Lne0/e;

    .line 117
    .line 118
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast v1, Lb90/f;

    .line 121
    .line 122
    invoke-static {v1}, Ljp/ka;->d(Lb90/f;)Ljava/util/List;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    check-cast v1, Ljava/lang/Iterable;

    .line 127
    .line 128
    sget-object v2, Lb90/d;->h:Lb90/d;

    .line 129
    .line 130
    invoke-static {v1, v2}, Lmx0/q;->W(Ljava/lang/Iterable;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 131
    .line 132
    .line 133
    move-result-object v11

    .line 134
    const/4 v12, 0x3

    .line 135
    const/4 v8, 0x0

    .line 136
    const/4 v9, 0x0

    .line 137
    const/4 v10, 0x0

    .line 138
    invoke-static/range {v7 .. v12}, Lc90/z;->a(Lc90/z;ZLql0/g;ZLjava/util/ArrayList;I)Lc90/z;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 143
    .line 144
    .line 145
    return-object v6

    .line 146
    :cond_5
    instance-of v2, v1, Lne0/c;

    .line 147
    .line 148
    if-eqz v2, :cond_7

    .line 149
    .line 150
    move-object v8, v1

    .line 151
    check-cast v8, Lne0/c;

    .line 152
    .line 153
    iget-object v1, v0, Lc90/c0;->o:Lij0/a;

    .line 154
    .line 155
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 156
    .line 157
    .line 158
    move-result-object v2

    .line 159
    check-cast v2, Lc90/z;

    .line 160
    .line 161
    iget-object v3, v8, Lne0/c;->e:Lne0/b;

    .line 162
    .line 163
    sget-object v4, Lc90/a0;->a:[I

    .line 164
    .line 165
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 166
    .line 167
    .line 168
    move-result v3

    .line 169
    aget v3, v4, v3

    .line 170
    .line 171
    if-ne v3, v7, :cond_6

    .line 172
    .line 173
    invoke-static {v8, v1}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    :goto_2
    move-object v11, v1

    .line 178
    goto :goto_3

    .line 179
    :cond_6
    iget-object v9, v0, Lc90/c0;->o:Lij0/a;

    .line 180
    .line 181
    const/4 v3, 0x0

    .line 182
    new-array v4, v3, [Ljava/lang/Object;

    .line 183
    .line 184
    move-object v5, v9

    .line 185
    check-cast v5, Ljj0/f;

    .line 186
    .line 187
    const v7, 0x7f1212c9

    .line 188
    .line 189
    .line 190
    invoke-virtual {v5, v7, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v10

    .line 194
    new-array v4, v3, [Ljava/lang/Object;

    .line 195
    .line 196
    check-cast v1, Ljj0/f;

    .line 197
    .line 198
    const v5, 0x7f1212c8

    .line 199
    .line 200
    .line 201
    invoke-virtual {v1, v5, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object v11

    .line 205
    const v4, 0x7f12038b

    .line 206
    .line 207
    .line 208
    new-array v5, v3, [Ljava/lang/Object;

    .line 209
    .line 210
    invoke-virtual {v1, v4, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v12

    .line 214
    const v4, 0x7f120373

    .line 215
    .line 216
    .line 217
    new-array v3, v3, [Ljava/lang/Object;

    .line 218
    .line 219
    invoke-virtual {v1, v4, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v13

    .line 223
    const/4 v15, 0x0

    .line 224
    const/16 v16, 0x60

    .line 225
    .line 226
    const/4 v14, 0x0

    .line 227
    invoke-static/range {v8 .. v16}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 228
    .line 229
    .line 230
    move-result-object v1

    .line 231
    goto :goto_2

    .line 232
    :goto_3
    const/4 v13, 0x0

    .line 233
    const/16 v14, 0x9

    .line 234
    .line 235
    const/4 v10, 0x0

    .line 236
    const/4 v12, 0x0

    .line 237
    move-object v9, v2

    .line 238
    invoke-static/range {v9 .. v14}, Lc90/z;->a(Lc90/z;ZLql0/g;ZLjava/util/ArrayList;I)Lc90/z;

    .line 239
    .line 240
    .line 241
    move-result-object v1

    .line 242
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 243
    .line 244
    .line 245
    return-object v6

    .line 246
    :cond_7
    new-instance v0, La8/r0;

    .line 247
    .line 248
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 249
    .line 250
    .line 251
    throw v0
.end method
