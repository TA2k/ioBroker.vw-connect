.class public final Lzq0/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ll2/t2;Luu/g;Lqu/c;Ljava/util/List;Lay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lzq0/a;->d:I

    .line 1
    iput-object p1, p0, Lzq0/a;->f:Ljava/lang/Object;

    iput-object p2, p0, Lzq0/a;->g:Ljava/lang/Object;

    iput-object p3, p0, Lzq0/a;->h:Ljava/lang/Object;

    iput-object p4, p0, Lzq0/a;->i:Ljava/lang/Object;

    iput-object p5, p0, Lzq0/a;->j:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lzq0/e;Ljava/lang/String;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lzq0/a;->d:I

    .line 2
    iput-object p1, p0, Lzq0/a;->g:Ljava/lang/Object;

    iput-object p2, p0, Lzq0/a;->h:Ljava/lang/Object;

    iput-object p3, p0, Lzq0/a;->j:Ljava/lang/Object;

    iput-object p4, p0, Lzq0/a;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget v0, p0, Lzq0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lzq0/a;

    .line 7
    .line 8
    iget-object p1, p0, Lzq0/a;->f:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, p1

    .line 11
    check-cast v2, Ll2/t2;

    .line 12
    .line 13
    iget-object p1, p0, Lzq0/a;->g:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, p1

    .line 16
    check-cast v3, Luu/g;

    .line 17
    .line 18
    iget-object p1, p0, Lzq0/a;->h:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v4, p1

    .line 21
    check-cast v4, Lqu/c;

    .line 22
    .line 23
    iget-object p1, p0, Lzq0/a;->i:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v5, p1

    .line 26
    check-cast v5, Ljava/util/List;

    .line 27
    .line 28
    iget-object p0, p0, Lzq0/a;->j:Ljava/lang/Object;

    .line 29
    .line 30
    move-object v6, p0

    .line 31
    check-cast v6, Lay0/k;

    .line 32
    .line 33
    move-object v7, p2

    .line 34
    invoke-direct/range {v1 .. v7}, Lzq0/a;-><init>(Ll2/t2;Luu/g;Lqu/c;Ljava/util/List;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 35
    .line 36
    .line 37
    return-object v1

    .line 38
    :pswitch_0
    move-object v7, p2

    .line 39
    new-instance v2, Lzq0/a;

    .line 40
    .line 41
    iget-object p2, p0, Lzq0/a;->g:Ljava/lang/Object;

    .line 42
    .line 43
    move-object v3, p2

    .line 44
    check-cast v3, Lzq0/e;

    .line 45
    .line 46
    iget-object p2, p0, Lzq0/a;->h:Ljava/lang/Object;

    .line 47
    .line 48
    move-object v4, p2

    .line 49
    check-cast v4, Ljava/lang/String;

    .line 50
    .line 51
    iget-object p2, p0, Lzq0/a;->j:Ljava/lang/Object;

    .line 52
    .line 53
    move-object v5, p2

    .line 54
    check-cast v5, Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 55
    .line 56
    iget-object p0, p0, Lzq0/a;->i:Ljava/lang/Object;

    .line 57
    .line 58
    move-object v6, p0

    .line 59
    check-cast v6, Ljava/lang/String;

    .line 60
    .line 61
    invoke-direct/range {v2 .. v7}, Lzq0/a;-><init>(Lzq0/e;Ljava/lang/String;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 62
    .line 63
    .line 64
    iput-object p1, v2, Lzq0/a;->f:Ljava/lang/Object;

    .line 65
    .line 66
    return-object v2

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lzq0/a;->d:I

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
    invoke-virtual {p0, p1, p2}, Lzq0/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lzq0/a;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lzq0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lzq0/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lzq0/a;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lzq0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 11

    .line 1
    iget v0, p0, Lzq0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lzq0/a;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_2

    .line 14
    .line 15
    if-ne v1, v3, :cond_1

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    move-object v0, v2

    .line 21
    goto :goto_1

    .line 22
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iget-object p1, p0, Lzq0/a;->f:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p1, Ll2/t2;

    .line 36
    .line 37
    new-instance v1, Laa/a0;

    .line 38
    .line 39
    const/16 v4, 0x8

    .line 40
    .line 41
    invoke-direct {v1, p1, v4}, Laa/a0;-><init>(Ll2/t2;I)V

    .line 42
    .line 43
    .line 44
    invoke-static {v1}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-static {p1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    iget-object v1, p0, Lzq0/a;->g:Ljava/lang/Object;

    .line 53
    .line 54
    move-object v6, v1

    .line 55
    check-cast v6, Luu/g;

    .line 56
    .line 57
    iget-object v1, p0, Lzq0/a;->h:Ljava/lang/Object;

    .line 58
    .line 59
    move-object v7, v1

    .line 60
    check-cast v7, Lqu/c;

    .line 61
    .line 62
    iget-object v1, p0, Lzq0/a;->i:Ljava/lang/Object;

    .line 63
    .line 64
    move-object v8, v1

    .line 65
    check-cast v8, Ljava/util/List;

    .line 66
    .line 67
    new-instance v5, Li40/b0;

    .line 68
    .line 69
    iget-object v1, p0, Lzq0/a;->j:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v1, Lay0/k;

    .line 72
    .line 73
    const/4 v4, 0x7

    .line 74
    invoke-direct {v5, v4, v1}, Li40/b0;-><init>(ILay0/k;)V

    .line 75
    .line 76
    .line 77
    iput v3, p0, Lzq0/a;->e:I

    .line 78
    .line 79
    new-instance v4, Le1/b0;

    .line 80
    .line 81
    const/4 v9, 0x5

    .line 82
    invoke-direct/range {v4 .. v9}, Le1/b0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 83
    .line 84
    .line 85
    invoke-interface {p1, v4, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    if-ne p0, v0, :cond_3

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_3
    move-object p0, v2

    .line 93
    :goto_0
    if-ne p0, v0, :cond_0

    .line 94
    .line 95
    :goto_1
    return-object v0

    .line 96
    :pswitch_0
    iget-object v0, p0, Lzq0/a;->g:Ljava/lang/Object;

    .line 97
    .line 98
    move-object v3, v0

    .line 99
    check-cast v3, Lzq0/e;

    .line 100
    .line 101
    iget-object v0, p0, Lzq0/a;->f:Ljava/lang/Object;

    .line 102
    .line 103
    move-object v9, v0

    .line 104
    check-cast v9, Lvy0/b0;

    .line 105
    .line 106
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 107
    .line 108
    iget v1, p0, Lzq0/a;->e:I

    .line 109
    .line 110
    const/4 v2, 0x1

    .line 111
    if-eqz v1, :cond_5

    .line 112
    .line 113
    if-ne v1, v2, :cond_4

    .line 114
    .line 115
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 116
    .line 117
    .line 118
    goto :goto_3

    .line 119
    :catch_0
    move-exception v0

    .line 120
    :goto_2
    move-object p0, v0

    .line 121
    goto :goto_4

    .line 122
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 123
    .line 124
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 125
    .line 126
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    throw p0

    .line 130
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    :try_start_1
    iget-object p1, v3, Lzq0/e;->c:Lzq0/h;

    .line 134
    .line 135
    iget-object v1, p0, Lzq0/a;->h:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v1, Ljava/lang/String;

    .line 138
    .line 139
    iput-object v9, p0, Lzq0/a;->f:Ljava/lang/Object;

    .line 140
    .line 141
    iput v2, p0, Lzq0/a;->e:I

    .line 142
    .line 143
    invoke-virtual {p1, v1, p0}, Lzq0/h;->a(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    if-ne p1, v0, :cond_6

    .line 148
    .line 149
    goto :goto_6

    .line 150
    :cond_6
    :goto_3
    check-cast p1, Ljavax/crypto/Cipher;

    .line 151
    .line 152
    iget-object v0, p0, Lzq0/a;->j:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v0, Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 155
    .line 156
    iget-object p0, p0, Lzq0/a;->i:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast p0, Ljava/lang/String;

    .line 159
    .line 160
    new-instance v1, Lth/b;

    .line 161
    .line 162
    const-class v4, Lzq0/e;

    .line 163
    .line 164
    const-string v5, "decryptionAuthenticateError"

    .line 165
    .line 166
    const-string v6, "decryptionAuthenticateError(Ljava/lang/CharSequence;I)V"

    .line 167
    .line 168
    const/4 v7, 0x0

    .line 169
    const/16 v8, 0xf

    .line 170
    .line 171
    const/4 v2, 0x2

    .line 172
    invoke-direct/range {v1 .. v8}, Lth/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 173
    .line 174
    .line 175
    move-object v10, v1

    .line 176
    new-instance v1, Lth/b;

    .line 177
    .line 178
    const-class v4, Lzq0/e;

    .line 179
    .line 180
    const-string v5, "decryptionAuthenticateSuccess"

    .line 181
    .line 182
    const-string v6, "decryptionAuthenticateSuccess-KoeJU94(Ljava/lang/String;Ljavax/crypto/Cipher;)V"

    .line 183
    .line 184
    const/4 v7, 0x0

    .line 185
    const/16 v8, 0x10

    .line 186
    .line 187
    const/4 v2, 0x2

    .line 188
    invoke-direct/range {v1 .. v8}, Lth/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 189
    .line 190
    .line 191
    move-object v4, p1

    .line 192
    move-object v2, v0

    .line 193
    move-object v6, v1

    .line 194
    move-object v1, v3

    .line 195
    move-object v5, v10

    .line 196
    move-object v3, p0

    .line 197
    :try_start_2
    invoke-static/range {v1 .. v6}, Lzq0/e;->a(Lzq0/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Ljava/lang/String;Ljavax/crypto/Cipher;Lay0/n;Lay0/n;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    .line 198
    .line 199
    .line 200
    goto :goto_5

    .line 201
    :catch_1
    move-exception v0

    .line 202
    move-object v3, v1

    .line 203
    goto :goto_2

    .line 204
    :goto_4
    new-instance p1, Lac0/b;

    .line 205
    .line 206
    const/16 v0, 0xf

    .line 207
    .line 208
    invoke-direct {p1, v0, p0}, Lac0/b;-><init>(ILjava/lang/Exception;)V

    .line 209
    .line 210
    .line 211
    const/4 v0, 0x0

    .line 212
    invoke-static {v0, v9, p1}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 213
    .line 214
    .line 215
    iget-object p1, v3, Lzq0/e;->b:Luq0/a;

    .line 216
    .line 217
    new-instance v1, Lne0/c;

    .line 218
    .line 219
    new-instance v2, Lyq0/e;

    .line 220
    .line 221
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object p0

    .line 225
    if-nez p0, :cond_7

    .line 226
    .line 227
    const-string p0, ""

    .line 228
    .line 229
    :cond_7
    invoke-direct {v2, p0, v0}, Lyq0/e;-><init>(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 230
    .line 231
    .line 232
    const/4 v5, 0x0

    .line 233
    const/16 v6, 0x1e

    .line 234
    .line 235
    const/4 v3, 0x0

    .line 236
    const/4 v4, 0x0

    .line 237
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 238
    .line 239
    .line 240
    iget-object p0, p1, Luq0/a;->f:Lyy0/q1;

    .line 241
    .line 242
    invoke-virtual {p0, v1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 243
    .line 244
    .line 245
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 246
    .line 247
    :goto_6
    return-object v0

    .line 248
    nop

    .line 249
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
