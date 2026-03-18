.class public final Lic0/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lic0/p;


# direct methods
.method public synthetic constructor <init>(Lic0/p;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lic0/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lic0/g;->f:Lic0/p;

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
    iget p1, p0, Lic0/g;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lic0/g;

    .line 7
    .line 8
    iget-object p0, p0, Lic0/g;->f:Lic0/p;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lic0/g;-><init>(Lic0/p;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lic0/g;

    .line 16
    .line 17
    iget-object p0, p0, Lic0/g;->f:Lic0/p;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lic0/g;-><init>(Lic0/p;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lic0/g;

    .line 25
    .line 26
    iget-object p0, p0, Lic0/g;->f:Lic0/p;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lic0/g;-><init>(Lic0/p;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lic0/g;->d:I

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
    invoke-virtual {p0, p1, p2}, Lic0/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lic0/g;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lic0/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lic0/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lic0/g;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lic0/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lic0/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lic0/g;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lic0/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Lic0/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lic0/g;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Lic0/g;->f:Lic0/p;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v3, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, v2, Lic0/p;->b:Lti0/a;

    .line 33
    .line 34
    iput v3, p0, Lic0/g;->e:I

    .line 35
    .line 36
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    if-ne p1, v0, :cond_2

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_2
    :goto_0
    check-cast p1, Lic0/e;

    .line 44
    .line 45
    iget-object p0, v2, Lic0/p;->a:Llc0/l;

    .line 46
    .line 47
    iget-object p0, p0, Llc0/l;->d:Ljava/lang/String;

    .line 48
    .line 49
    iget-object p1, p1, Lic0/e;->a:Lla/u;

    .line 50
    .line 51
    const-string v0, "token"

    .line 52
    .line 53
    filled-new-array {v0}, [Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    new-instance v1, Lac0/r;

    .line 58
    .line 59
    const/16 v2, 0x1b

    .line 60
    .line 61
    invoke-direct {v1, p0, v2}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 62
    .line 63
    .line 64
    const/4 p0, 0x0

    .line 65
    invoke-static {p1, p0, v0, v1}, Ljp/ga;->a(Lla/u;Z[Ljava/lang/String;Lay0/k;)Lna/j;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    new-instance v0, Lic0/i;

    .line 70
    .line 71
    const/4 p1, 0x0

    .line 72
    invoke-direct {v0, p0, p1}, Lic0/i;-><init>(Lna/j;I)V

    .line 73
    .line 74
    .line 75
    :goto_1
    return-object v0

    .line 76
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 77
    .line 78
    iget v1, p0, Lic0/g;->e:I

    .line 79
    .line 80
    const/4 v2, 0x0

    .line 81
    iget-object v3, p0, Lic0/g;->f:Lic0/p;

    .line 82
    .line 83
    const/4 v4, 0x2

    .line 84
    const/4 v5, 0x1

    .line 85
    if-eqz v1, :cond_5

    .line 86
    .line 87
    if-eq v1, v5, :cond_4

    .line 88
    .line 89
    if-ne v1, v4, :cond_3

    .line 90
    .line 91
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 96
    .line 97
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 98
    .line 99
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw p0

    .line 103
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    iget-object p1, v3, Lic0/p;->b:Lti0/a;

    .line 111
    .line 112
    iput v5, p0, Lic0/g;->e:I

    .line 113
    .line 114
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    if-ne p1, v0, :cond_6

    .line 119
    .line 120
    goto :goto_5

    .line 121
    :cond_6
    :goto_2
    check-cast p1, Lic0/e;

    .line 122
    .line 123
    iget-object v1, v3, Lic0/p;->a:Llc0/l;

    .line 124
    .line 125
    iget-object v1, v1, Llc0/l;->d:Ljava/lang/String;

    .line 126
    .line 127
    iput v4, p0, Lic0/g;->e:I

    .line 128
    .line 129
    iget-object p1, p1, Lic0/e;->a:Lla/u;

    .line 130
    .line 131
    new-instance v3, Lac0/r;

    .line 132
    .line 133
    const/16 v4, 0x1c

    .line 134
    .line 135
    invoke-direct {v3, v1, v4}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 136
    .line 137
    .line 138
    invoke-static {p0, p1, v5, v2, v3}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    if-ne p1, v0, :cond_7

    .line 143
    .line 144
    goto :goto_5

    .line 145
    :cond_7
    :goto_3
    check-cast p1, Lic0/f;

    .line 146
    .line 147
    if-eqz p1, :cond_8

    .line 148
    .line 149
    iget-object p0, p1, Lic0/f;->b:Ljava/lang/String;

    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_8
    const/4 p0, 0x0

    .line 153
    :goto_4
    if-eqz p0, :cond_9

    .line 154
    .line 155
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 156
    .line 157
    .line 158
    move-result p0

    .line 159
    if-nez p0, :cond_a

    .line 160
    .line 161
    :cond_9
    move v2, v5

    .line 162
    :cond_a
    xor-int/lit8 p0, v2, 0x1

    .line 163
    .line 164
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    :goto_5
    return-object v0

    .line 169
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 170
    .line 171
    iget v1, p0, Lic0/g;->e:I

    .line 172
    .line 173
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 174
    .line 175
    iget-object v3, p0, Lic0/g;->f:Lic0/p;

    .line 176
    .line 177
    const/4 v4, 0x2

    .line 178
    const/4 v5, 0x1

    .line 179
    if-eqz v1, :cond_e

    .line 180
    .line 181
    if-eq v1, v5, :cond_d

    .line 182
    .line 183
    if-ne v1, v4, :cond_c

    .line 184
    .line 185
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    :cond_b
    move-object v0, v2

    .line 189
    goto :goto_8

    .line 190
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 191
    .line 192
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 193
    .line 194
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    throw p0

    .line 198
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    goto :goto_6

    .line 202
    :cond_e
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 203
    .line 204
    .line 205
    iget-object p1, v3, Lic0/p;->b:Lti0/a;

    .line 206
    .line 207
    iput v5, p0, Lic0/g;->e:I

    .line 208
    .line 209
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object p1

    .line 213
    if-ne p1, v0, :cond_f

    .line 214
    .line 215
    goto :goto_8

    .line 216
    :cond_f
    :goto_6
    check-cast p1, Lic0/e;

    .line 217
    .line 218
    iget-object v1, v3, Lic0/p;->a:Llc0/l;

    .line 219
    .line 220
    iget-object v1, v1, Llc0/l;->d:Ljava/lang/String;

    .line 221
    .line 222
    iput v4, p0, Lic0/g;->e:I

    .line 223
    .line 224
    iget-object p1, p1, Lic0/e;->a:Lla/u;

    .line 225
    .line 226
    new-instance v3, Lac0/r;

    .line 227
    .line 228
    const/16 v4, 0x1d

    .line 229
    .line 230
    invoke-direct {v3, v1, v4}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 231
    .line 232
    .line 233
    const/4 v1, 0x0

    .line 234
    invoke-static {p0, p1, v1, v5, v3}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object p0

    .line 238
    if-ne p0, v0, :cond_10

    .line 239
    .line 240
    goto :goto_7

    .line 241
    :cond_10
    move-object p0, v2

    .line 242
    :goto_7
    if-ne p0, v0, :cond_b

    .line 243
    .line 244
    :goto_8
    return-object v0

    .line 245
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
