.class public final Lm6/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:Ljava/lang/Object;

.field public e:Ljava/io/Serializable;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Ljava/util/Iterator;

.field public i:I

.field public j:I

.field public final synthetic k:Lm6/w;

.field public final synthetic l:Lcom/google/firebase/messaging/w;


# direct methods
.method public constructor <init>(Lm6/w;Lcom/google/firebase/messaging/w;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lm6/k;->k:Lm6/w;

    .line 2
    .line 3
    iput-object p2, p0, Lm6/k;->l:Lcom/google/firebase/messaging/w;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Lm6/k;

    .line 2
    .line 3
    iget-object v1, p0, Lm6/k;->k:Lm6/w;

    .line 4
    .line 5
    iget-object p0, p0, Lm6/k;->l:Lcom/google/firebase/messaging/w;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p1}, Lm6/k;-><init>(Lm6/w;Lcom/google/firebase/messaging/w;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lm6/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lm6/k;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lm6/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lm6/k;->j:I

    .line 4
    .line 5
    iget-object v2, p0, Lm6/k;->l:Lcom/google/firebase/messaging/w;

    .line 6
    .line 7
    const/4 v3, 0x4

    .line 8
    const/4 v4, 0x3

    .line 9
    const/4 v5, 0x2

    .line 10
    iget-object v6, p0, Lm6/k;->k:Lm6/w;

    .line 11
    .line 12
    const/4 v7, 0x1

    .line 13
    const/4 v8, 0x0

    .line 14
    if-eqz v1, :cond_4

    .line 15
    .line 16
    if-eq v1, v7, :cond_3

    .line 17
    .line 18
    if-eq v1, v5, :cond_2

    .line 19
    .line 20
    if-eq v1, v4, :cond_1

    .line 21
    .line 22
    if-ne v1, v3, :cond_0

    .line 23
    .line 24
    iget v0, p0, Lm6/k;->i:I

    .line 25
    .line 26
    iget-object p0, p0, Lm6/k;->d:Ljava/lang/Object;

    .line 27
    .line 28
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    goto/16 :goto_6

    .line 32
    .line 33
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 36
    .line 37
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :cond_1
    iget-object v1, p0, Lm6/k;->f:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v1, Lez0/a;

    .line 44
    .line 45
    iget-object v2, p0, Lm6/k;->e:Ljava/io/Serializable;

    .line 46
    .line 47
    check-cast v2, Lkotlin/jvm/internal/f0;

    .line 48
    .line 49
    iget-object v4, p0, Lm6/k;->d:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v4, Lkotlin/jvm/internal/b0;

    .line 52
    .line 53
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto/16 :goto_3

    .line 57
    .line 58
    :cond_2
    iget-object v1, p0, Lm6/k;->h:Ljava/util/Iterator;

    .line 59
    .line 60
    iget-object v9, p0, Lm6/k;->g:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v9, Lm6/j;

    .line 63
    .line 64
    iget-object v10, p0, Lm6/k;->f:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v10, Lkotlin/jvm/internal/f0;

    .line 67
    .line 68
    iget-object v11, p0, Lm6/k;->e:Ljava/io/Serializable;

    .line 69
    .line 70
    check-cast v11, Lkotlin/jvm/internal/b0;

    .line 71
    .line 72
    iget-object v12, p0, Lm6/k;->d:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v12, Lez0/a;

    .line 75
    .line 76
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_3
    iget-object v1, p0, Lm6/k;->g:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v1, Lkotlin/jvm/internal/f0;

    .line 83
    .line 84
    iget-object v9, p0, Lm6/k;->f:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast v9, Lkotlin/jvm/internal/f0;

    .line 87
    .line 88
    iget-object v10, p0, Lm6/k;->e:Ljava/io/Serializable;

    .line 89
    .line 90
    check-cast v10, Lkotlin/jvm/internal/b0;

    .line 91
    .line 92
    iget-object v11, p0, Lm6/k;->d:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v11, Lez0/a;

    .line 95
    .line 96
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 104
    .line 105
    .line 106
    move-result-object v11

    .line 107
    new-instance v10, Lkotlin/jvm/internal/b0;

    .line 108
    .line 109
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 110
    .line 111
    .line 112
    new-instance v1, Lkotlin/jvm/internal/f0;

    .line 113
    .line 114
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 115
    .line 116
    .line 117
    iput-object v11, p0, Lm6/k;->d:Ljava/lang/Object;

    .line 118
    .line 119
    iput-object v10, p0, Lm6/k;->e:Ljava/io/Serializable;

    .line 120
    .line 121
    iput-object v1, p0, Lm6/k;->f:Ljava/lang/Object;

    .line 122
    .line 123
    iput-object v1, p0, Lm6/k;->g:Ljava/lang/Object;

    .line 124
    .line 125
    iput v7, p0, Lm6/k;->j:I

    .line 126
    .line 127
    invoke-static {v6, v7, p0}, Lm6/w;->f(Lm6/w;ZLrx0/c;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    if-ne p1, v0, :cond_5

    .line 132
    .line 133
    goto/16 :goto_5

    .line 134
    .line 135
    :cond_5
    move-object v9, v1

    .line 136
    :goto_0
    check-cast p1, Lm6/d;

    .line 137
    .line 138
    iget-object p1, p1, Lm6/d;->b:Ljava/lang/Object;

    .line 139
    .line 140
    iput-object p1, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 141
    .line 142
    new-instance p1, Lm6/j;

    .line 143
    .line 144
    invoke-direct {p1, v11, v10, v9, v6}, Lm6/j;-><init>(Lez0/a;Lkotlin/jvm/internal/b0;Lkotlin/jvm/internal/f0;Lm6/w;)V

    .line 145
    .line 146
    .line 147
    iget-object v1, v2, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v1, Ljava/util/List;

    .line 150
    .line 151
    if-eqz v1, :cond_8

    .line 152
    .line 153
    check-cast v1, Ljava/lang/Iterable;

    .line 154
    .line 155
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    move-object v12, v11

    .line 160
    move-object v11, v10

    .line 161
    move-object v10, v9

    .line 162
    move-object v9, p1

    .line 163
    :cond_6
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 164
    .line 165
    .line 166
    move-result p1

    .line 167
    if-eqz p1, :cond_7

    .line 168
    .line 169
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    check-cast p1, Lay0/n;

    .line 174
    .line 175
    iput-object v12, p0, Lm6/k;->d:Ljava/lang/Object;

    .line 176
    .line 177
    iput-object v11, p0, Lm6/k;->e:Ljava/io/Serializable;

    .line 178
    .line 179
    iput-object v10, p0, Lm6/k;->f:Ljava/lang/Object;

    .line 180
    .line 181
    iput-object v9, p0, Lm6/k;->g:Ljava/lang/Object;

    .line 182
    .line 183
    iput-object v1, p0, Lm6/k;->h:Ljava/util/Iterator;

    .line 184
    .line 185
    iput v5, p0, Lm6/k;->j:I

    .line 186
    .line 187
    invoke-interface {p1, v9, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object p1

    .line 191
    if-ne p1, v0, :cond_6

    .line 192
    .line 193
    goto :goto_5

    .line 194
    :cond_7
    move-object v9, v10

    .line 195
    move-object v10, v11

    .line 196
    move-object v1, v12

    .line 197
    goto :goto_2

    .line 198
    :cond_8
    move-object v1, v11

    .line 199
    :goto_2
    iput-object v8, v2, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 200
    .line 201
    iput-object v10, p0, Lm6/k;->d:Ljava/lang/Object;

    .line 202
    .line 203
    iput-object v9, p0, Lm6/k;->e:Ljava/io/Serializable;

    .line 204
    .line 205
    iput-object v1, p0, Lm6/k;->f:Ljava/lang/Object;

    .line 206
    .line 207
    iput-object v8, p0, Lm6/k;->g:Ljava/lang/Object;

    .line 208
    .line 209
    iput-object v8, p0, Lm6/k;->h:Ljava/util/Iterator;

    .line 210
    .line 211
    iput v4, p0, Lm6/k;->j:I

    .line 212
    .line 213
    invoke-interface {v1, p0}, Lez0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object p1

    .line 217
    if-ne p1, v0, :cond_9

    .line 218
    .line 219
    goto :goto_5

    .line 220
    :cond_9
    move-object v2, v9

    .line 221
    move-object v4, v10

    .line 222
    :goto_3
    :try_start_0
    iput-boolean v7, v4, Lkotlin/jvm/internal/b0;->d:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 223
    .line 224
    invoke-interface {v1, v8}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 225
    .line 226
    .line 227
    iget-object p1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 228
    .line 229
    if-eqz p1, :cond_a

    .line 230
    .line 231
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 232
    .line 233
    .line 234
    move-result v1

    .line 235
    goto :goto_4

    .line 236
    :cond_a
    const/4 v1, 0x0

    .line 237
    :goto_4
    invoke-virtual {v6}, Lm6/w;->g()Lm6/i0;

    .line 238
    .line 239
    .line 240
    move-result-object v2

    .line 241
    iput-object p1, p0, Lm6/k;->d:Ljava/lang/Object;

    .line 242
    .line 243
    iput-object v8, p0, Lm6/k;->e:Ljava/io/Serializable;

    .line 244
    .line 245
    iput-object v8, p0, Lm6/k;->f:Ljava/lang/Object;

    .line 246
    .line 247
    iput v1, p0, Lm6/k;->i:I

    .line 248
    .line 249
    iput v3, p0, Lm6/k;->j:I

    .line 250
    .line 251
    invoke-interface {v2, p0}, Lm6/i0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    if-ne p0, v0, :cond_b

    .line 256
    .line 257
    :goto_5
    return-object v0

    .line 258
    :cond_b
    move-object v0, p1

    .line 259
    move-object p1, p0

    .line 260
    move-object p0, v0

    .line 261
    move v0, v1

    .line 262
    :goto_6
    check-cast p1, Ljava/lang/Number;

    .line 263
    .line 264
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 265
    .line 266
    .line 267
    move-result p1

    .line 268
    new-instance v1, Lm6/d;

    .line 269
    .line 270
    invoke-direct {v1, p0, v0, p1}, Lm6/d;-><init>(Ljava/lang/Object;II)V

    .line 271
    .line 272
    .line 273
    return-object v1

    .line 274
    :catchall_0
    move-exception p0

    .line 275
    invoke-interface {v1, v8}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 276
    .line 277
    .line 278
    throw p0
.end method
