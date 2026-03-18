.class public final Lm70/o0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lm70/r0;


# direct methods
.method public synthetic constructor <init>(Lm70/r0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lm70/o0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm70/o0;->g:Lm70/r0;

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
    .locals 2

    .line 1
    iget v0, p0, Lm70/o0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lm70/o0;

    .line 7
    .line 8
    iget-object p0, p0, Lm70/o0;->g:Lm70/r0;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lm70/o0;-><init>(Lm70/r0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lm70/o0;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lm70/o0;

    .line 18
    .line 19
    iget-object p0, p0, Lm70/o0;->g:Lm70/r0;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lm70/o0;-><init>(Lm70/r0;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lm70/o0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lm70/o0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Llf0/i;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lm70/o0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lm70/o0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lm70/o0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lm70/o0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lm70/o0;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lm70/o0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lm70/o0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lm70/o0;->f:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, v0

    .line 9
    check-cast v2, Llf0/i;

    .line 10
    .line 11
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 12
    .line 13
    iget v1, p0, Lm70/o0;->e:I

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    if-eqz v1, :cond_1

    .line 17
    .line 18
    if-ne v1, v3, :cond_0

    .line 19
    .line 20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    sget-object p1, Llf0/i;->j:Llf0/i;

    .line 36
    .line 37
    iget-object v11, p0, Lm70/o0;->g:Lm70/r0;

    .line 38
    .line 39
    if-ne v2, p1, :cond_2

    .line 40
    .line 41
    iget-object p1, v11, Lm70/r0;->i:Lk70/p0;

    .line 42
    .line 43
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Lyy0/i;

    .line 48
    .line 49
    new-instance v1, Lm70/o0;

    .line 50
    .line 51
    const/4 v2, 0x0

    .line 52
    const/4 v4, 0x0

    .line 53
    invoke-direct {v1, v11, v4, v2}, Lm70/o0;-><init>(Lm70/r0;Lkotlin/coroutines/Continuation;I)V

    .line 54
    .line 55
    .line 56
    iput-object v4, p0, Lm70/o0;->f:Ljava/lang/Object;

    .line 57
    .line 58
    iput v3, p0, Lm70/o0;->e:I

    .line 59
    .line 60
    invoke-static {v1, p0, p1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    if-ne p0, v0, :cond_3

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    invoke-virtual {v11}, Lql0/j;->a()Lql0/h;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    move-object v1, p0

    .line 72
    check-cast v1, Lm70/p0;

    .line 73
    .line 74
    const/4 v9, 0x0

    .line 75
    const/16 v10, 0xfc

    .line 76
    .line 77
    const/4 v3, 0x0

    .line 78
    const/4 v4, 0x0

    .line 79
    const/4 v5, 0x0

    .line 80
    const/4 v6, 0x0

    .line 81
    const/4 v7, 0x0

    .line 82
    const/4 v8, 0x0

    .line 83
    invoke-static/range {v1 .. v10}, Lm70/p0;->a(Lm70/p0;Llf0/i;ZZZLqr0/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lm70/p0;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    invoke-virtual {v11, p0}, Lql0/j;->g(Lql0/h;)V

    .line 88
    .line 89
    .line 90
    :cond_3
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    :goto_1
    return-object v0

    .line 93
    :pswitch_0
    iget-object v0, p0, Lm70/o0;->f:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Lne0/s;

    .line 96
    .line 97
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 98
    .line 99
    iget v2, p0, Lm70/o0;->e:I

    .line 100
    .line 101
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    const/4 v4, 0x1

    .line 104
    if-eqz v2, :cond_6

    .line 105
    .line 106
    if-ne v2, v4, :cond_5

    .line 107
    .line 108
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    :cond_4
    move-object v1, v3

    .line 112
    goto :goto_4

    .line 113
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 114
    .line 115
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 116
    .line 117
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    throw p0

    .line 121
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    const/4 p1, 0x0

    .line 125
    iput-object p1, p0, Lm70/o0;->f:Ljava/lang/Object;

    .line 126
    .line 127
    iput v4, p0, Lm70/o0;->e:I

    .line 128
    .line 129
    instance-of p1, v0, Lne0/c;

    .line 130
    .line 131
    iget-object v2, p0, Lm70/o0;->g:Lm70/r0;

    .line 132
    .line 133
    if-eqz p1, :cond_9

    .line 134
    .line 135
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    check-cast p0, Lm70/p0;

    .line 140
    .line 141
    iget-boolean p0, p0, Lm70/p0;->b:Z

    .line 142
    .line 143
    if-eqz p0, :cond_8

    .line 144
    .line 145
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    move-object v4, p0

    .line 150
    check-cast v4, Lm70/p0;

    .line 151
    .line 152
    sget-object v5, Llf0/i;->j:Llf0/i;

    .line 153
    .line 154
    const/4 v12, 0x0

    .line 155
    const/16 v13, 0xf8

    .line 156
    .line 157
    const/4 v6, 0x0

    .line 158
    const/4 v7, 0x1

    .line 159
    const/4 v8, 0x0

    .line 160
    const/4 v9, 0x0

    .line 161
    const/4 v10, 0x0

    .line 162
    const/4 v11, 0x0

    .line 163
    invoke-static/range {v4 .. v13}, Lm70/p0;->a(Lm70/p0;Llf0/i;ZZZLqr0/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lm70/p0;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 168
    .line 169
    .line 170
    :cond_7
    :goto_2
    move-object p0, v3

    .line 171
    goto :goto_3

    .line 172
    :cond_8
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 173
    .line 174
    .line 175
    goto :goto_2

    .line 176
    :cond_9
    instance-of p1, v0, Lne0/d;

    .line 177
    .line 178
    if-eqz p1, :cond_a

    .line 179
    .line 180
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    move-object v4, p0

    .line 185
    check-cast v4, Lm70/p0;

    .line 186
    .line 187
    const/4 v12, 0x0

    .line 188
    const/16 v13, 0xfd

    .line 189
    .line 190
    const/4 v5, 0x0

    .line 191
    const/4 v6, 0x1

    .line 192
    const/4 v7, 0x0

    .line 193
    const/4 v8, 0x0

    .line 194
    const/4 v9, 0x0

    .line 195
    const/4 v10, 0x0

    .line 196
    const/4 v11, 0x0

    .line 197
    invoke-static/range {v4 .. v13}, Lm70/p0;->a(Lm70/p0;Llf0/i;ZZZLqr0/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lm70/p0;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 202
    .line 203
    .line 204
    goto :goto_2

    .line 205
    :cond_a
    instance-of p1, v0, Lne0/e;

    .line 206
    .line 207
    if-eqz p1, :cond_b

    .line 208
    .line 209
    check-cast v0, Lne0/e;

    .line 210
    .line 211
    iget-object p1, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast p1, Ll70/z;

    .line 214
    .line 215
    invoke-virtual {v2, p1, p0}, Lm70/r0;->h(Ll70/z;Lrx0/c;)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    if-ne p0, v1, :cond_7

    .line 220
    .line 221
    :goto_3
    if-ne p0, v1, :cond_4

    .line 222
    .line 223
    :goto_4
    return-object v1

    .line 224
    :cond_b
    new-instance p0, La8/r0;

    .line 225
    .line 226
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 227
    .line 228
    .line 229
    throw p0

    .line 230
    nop

    .line 231
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
