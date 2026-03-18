.class public final Lge/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lhi/a;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lhi/a;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lge/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lge/b;->f:Lhi/a;

    .line 4
    .line 5
    iput-object p2, p0, Lge/b;->g:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lge/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lge/b;

    .line 7
    .line 8
    iget-object v1, p0, Lge/b;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v2, 0x3

    .line 11
    iget-object p0, p0, Lge/b;->f:Lhi/a;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p1, v2}, Lge/b;-><init>(Lhi/a;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lge/b;

    .line 18
    .line 19
    iget-object v1, p0, Lge/b;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v2, 0x2

    .line 22
    iget-object p0, p0, Lge/b;->f:Lhi/a;

    .line 23
    .line 24
    invoke-direct {v0, p0, v1, p1, v2}, Lge/b;-><init>(Lhi/a;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lge/b;

    .line 29
    .line 30
    iget-object v1, p0, Lge/b;->g:Ljava/lang/String;

    .line 31
    .line 32
    const/4 v2, 0x1

    .line 33
    iget-object p0, p0, Lge/b;->f:Lhi/a;

    .line 34
    .line 35
    invoke-direct {v0, p0, v1, p1, v2}, Lge/b;-><init>(Lhi/a;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_2
    new-instance v0, Lge/b;

    .line 40
    .line 41
    iget-object v1, p0, Lge/b;->g:Ljava/lang/String;

    .line 42
    .line 43
    const/4 v2, 0x0

    .line 44
    iget-object p0, p0, Lge/b;->f:Lhi/a;

    .line 45
    .line 46
    invoke-direct {v0, p0, v1, p1, v2}, Lge/b;-><init>(Lhi/a;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 47
    .line 48
    .line 49
    return-object v0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lge/b;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lge/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lge/b;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lge/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Lge/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lge/b;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lge/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Lge/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Lge/b;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Lge/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_2
    invoke-virtual {p0, p1}, Lge/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Lge/b;

    .line 52
    .line 53
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    invoke-virtual {p0, p1}, Lge/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lge/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lge/b;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    check-cast p1, Llx0/o;

    .line 19
    .line 20
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    const-class p1, Llg/h;

    .line 35
    .line 36
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 37
    .line 38
    invoke-virtual {v1, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    iget-object v1, p0, Lge/b;->f:Lhi/a;

    .line 43
    .line 44
    check-cast v1, Lii/a;

    .line 45
    .line 46
    invoke-virtual {v1, p1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    check-cast p1, Llg/h;

    .line 51
    .line 52
    iput v2, p0, Lge/b;->e:I

    .line 53
    .line 54
    iget-object v1, p0, Lge/b;->g:Ljava/lang/String;

    .line 55
    .line 56
    invoke-virtual {p1, v1, p0}, Llg/h;->e(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    if-ne p0, v0, :cond_2

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_2
    :goto_0
    new-instance v0, Llx0/o;

    .line 64
    .line 65
    invoke-direct {v0, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    :goto_1
    return-object v0

    .line 69
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 70
    .line 71
    iget v1, p0, Lge/b;->e:I

    .line 72
    .line 73
    const/4 v2, 0x1

    .line 74
    if-eqz v1, :cond_4

    .line 75
    .line 76
    if-ne v1, v2, :cond_3

    .line 77
    .line 78
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    check-cast p1, Llx0/o;

    .line 82
    .line 83
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 87
    .line 88
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 89
    .line 90
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw p0

    .line 94
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    const-class p1, Llg/h;

    .line 98
    .line 99
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 100
    .line 101
    invoke-virtual {v1, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    iget-object v1, p0, Lge/b;->f:Lhi/a;

    .line 106
    .line 107
    check-cast v1, Lii/a;

    .line 108
    .line 109
    invoke-virtual {v1, p1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    check-cast p1, Llg/h;

    .line 114
    .line 115
    iput v2, p0, Lge/b;->e:I

    .line 116
    .line 117
    iget-object v1, p0, Lge/b;->g:Ljava/lang/String;

    .line 118
    .line 119
    invoke-virtual {p1, v1, p0}, Llg/h;->e(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    if-ne p0, v0, :cond_5

    .line 124
    .line 125
    goto :goto_3

    .line 126
    :cond_5
    :goto_2
    new-instance v0, Llx0/o;

    .line 127
    .line 128
    invoke-direct {v0, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    :goto_3
    return-object v0

    .line 132
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 133
    .line 134
    iget v1, p0, Lge/b;->e:I

    .line 135
    .line 136
    const/4 v2, 0x1

    .line 137
    if-eqz v1, :cond_7

    .line 138
    .line 139
    if-ne v1, v2, :cond_6

    .line 140
    .line 141
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    check-cast p1, Llx0/o;

    .line 145
    .line 146
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 147
    .line 148
    goto :goto_4

    .line 149
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 150
    .line 151
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 152
    .line 153
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    throw p0

    .line 157
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    const-class p1, Llg/h;

    .line 161
    .line 162
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 163
    .line 164
    invoke-virtual {v1, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 165
    .line 166
    .line 167
    move-result-object p1

    .line 168
    iget-object v1, p0, Lge/b;->f:Lhi/a;

    .line 169
    .line 170
    check-cast v1, Lii/a;

    .line 171
    .line 172
    invoke-virtual {v1, p1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p1

    .line 176
    check-cast p1, Llg/h;

    .line 177
    .line 178
    iput v2, p0, Lge/b;->e:I

    .line 179
    .line 180
    iget-object v1, p0, Lge/b;->g:Ljava/lang/String;

    .line 181
    .line 182
    invoke-virtual {p1, v1, p0}, Llg/h;->e(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    if-ne p0, v0, :cond_8

    .line 187
    .line 188
    goto :goto_5

    .line 189
    :cond_8
    :goto_4
    new-instance v0, Llx0/o;

    .line 190
    .line 191
    invoke-direct {v0, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    :goto_5
    return-object v0

    .line 195
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 196
    .line 197
    iget v1, p0, Lge/b;->e:I

    .line 198
    .line 199
    const/4 v2, 0x1

    .line 200
    if-eqz v1, :cond_a

    .line 201
    .line 202
    if-ne v1, v2, :cond_9

    .line 203
    .line 204
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    check-cast p1, Llx0/o;

    .line 208
    .line 209
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 210
    .line 211
    goto :goto_6

    .line 212
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 213
    .line 214
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 215
    .line 216
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    throw p0

    .line 220
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    const-class p1, Lfe/c;

    .line 224
    .line 225
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 226
    .line 227
    invoke-virtual {v1, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 228
    .line 229
    .line 230
    move-result-object p1

    .line 231
    iget-object v1, p0, Lge/b;->f:Lhi/a;

    .line 232
    .line 233
    check-cast v1, Lii/a;

    .line 234
    .line 235
    invoke-virtual {v1, p1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object p1

    .line 239
    check-cast p1, Lfe/c;

    .line 240
    .line 241
    iput v2, p0, Lge/b;->e:I

    .line 242
    .line 243
    iget-object v1, p0, Lge/b;->g:Ljava/lang/String;

    .line 244
    .line 245
    invoke-virtual {p1, v1, p0}, Lfe/c;->a(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object p0

    .line 249
    if-ne p0, v0, :cond_b

    .line 250
    .line 251
    goto :goto_7

    .line 252
    :cond_b
    :goto_6
    new-instance v0, Llx0/o;

    .line 253
    .line 254
    invoke-direct {v0, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    :goto_7
    return-object v0

    .line 258
    nop

    .line 259
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
