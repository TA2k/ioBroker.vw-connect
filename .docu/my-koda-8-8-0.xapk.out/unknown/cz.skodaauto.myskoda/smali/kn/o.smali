.class public final Lkn/o;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;)V
    .locals 1

    .line 1
    const/4 v0, 0x3

    iput v0, p0, Lkn/o;->d:I

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p3, p0, Lkn/o;->d:I

    iput-object p1, p0, Lkn/o;->f:Ljava/lang/Object;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lkn/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lun0/b;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Boolean;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 11
    .line 12
    .line 13
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 14
    .line 15
    new-instance p1, Lkn/o;

    .line 16
    .line 17
    iget-object p0, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lyp0/b;

    .line 20
    .line 21
    const/4 p2, 0x6

    .line 22
    invoke-direct {p1, p0, p3, p2}, Lkn/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    invoke-virtual {p1, p0}, Lkn/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_0
    check-cast p1, Lyy0/j;

    .line 33
    .line 34
    check-cast p2, Ljava/lang/Throwable;

    .line 35
    .line 36
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    new-instance p1, Lkn/o;

    .line 39
    .line 40
    iget-object p0, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Luk0/r0;

    .line 43
    .line 44
    const/4 p2, 0x5

    .line 45
    invoke-direct {p1, p0, p3, p2}, Lkn/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 46
    .line 47
    .line 48
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    invoke-virtual {p1, p0}, Lkn/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    .line 55
    :pswitch_1
    check-cast p1, Lyy0/j;

    .line 56
    .line 57
    check-cast p2, Ljava/lang/Throwable;

    .line 58
    .line 59
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    new-instance p1, Lkn/o;

    .line 62
    .line 63
    iget-object p0, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast p0, Lsf0/a;

    .line 66
    .line 67
    const/4 p2, 0x4

    .line 68
    invoke-direct {p1, p0, p3, p2}, Lkn/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 69
    .line 70
    .line 71
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    invoke-virtual {p1, p0}, Lkn/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0

    .line 78
    :pswitch_2
    check-cast p1, Lm6/z;

    .line 79
    .line 80
    check-cast p2, Ljava/lang/Boolean;

    .line 81
    .line 82
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 86
    .line 87
    new-instance p0, Lkn/o;

    .line 88
    .line 89
    const/4 p2, 0x3

    .line 90
    invoke-direct {p0, p2, p3}, Lkn/o;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 91
    .line 92
    .line 93
    iput-object p1, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 94
    .line 95
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 96
    .line 97
    invoke-virtual {p0, p1}, Lkn/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    return-object p0

    .line 102
    :pswitch_3
    check-cast p1, Lyy0/j;

    .line 103
    .line 104
    check-cast p2, Ljava/lang/Throwable;

    .line 105
    .line 106
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 107
    .line 108
    new-instance p1, Lkn/o;

    .line 109
    .line 110
    iget-object p0, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast p0, Lm6/w;

    .line 113
    .line 114
    const/4 p2, 0x2

    .line 115
    invoke-direct {p1, p0, p3, p2}, Lkn/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 116
    .line 117
    .line 118
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    invoke-virtual {p1, p0}, Lkn/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    return-object p0

    .line 125
    :pswitch_4
    check-cast p1, Lyy0/j;

    .line 126
    .line 127
    check-cast p2, Ljava/lang/Throwable;

    .line 128
    .line 129
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 130
    .line 131
    new-instance p1, Lkn/o;

    .line 132
    .line 133
    iget-object p0, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast p0, Ll50/a0;

    .line 136
    .line 137
    const/4 p2, 0x1

    .line 138
    invoke-direct {p1, p0, p3, p2}, Lkn/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 139
    .line 140
    .line 141
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 142
    .line 143
    invoke-virtual {p1, p0}, Lkn/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    return-object p0

    .line 148
    :pswitch_5
    check-cast p1, Lvy0/b0;

    .line 149
    .line 150
    check-cast p2, Ljava/lang/Number;

    .line 151
    .line 152
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 153
    .line 154
    .line 155
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 156
    .line 157
    new-instance p1, Lkn/o;

    .line 158
    .line 159
    iget-object p0, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 160
    .line 161
    check-cast p0, Lkn/c0;

    .line 162
    .line 163
    const/4 p2, 0x0

    .line 164
    invoke-direct {p1, p0, p3, p2}, Lkn/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 165
    .line 166
    .line 167
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 168
    .line 169
    invoke-virtual {p1, p0}, Lkn/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    return-object p0

    .line 174
    nop

    .line 175
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lkn/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lkn/o;->e:I

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
    goto :goto_0

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
    iget-object p1, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p1, Lyp0/b;

    .line 36
    .line 37
    iget-object p1, p1, Lyp0/b;->d:Lwp0/d;

    .line 38
    .line 39
    iput v3, p0, Lkn/o;->e:I

    .line 40
    .line 41
    invoke-virtual {p1, p0}, Lwp0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    if-ne p0, v0, :cond_0

    .line 46
    .line 47
    :goto_0
    return-object v0

    .line 48
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 49
    .line 50
    iget v1, p0, Lkn/o;->e:I

    .line 51
    .line 52
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    const/4 v3, 0x1

    .line 55
    if-eqz v1, :cond_5

    .line 56
    .line 57
    if-ne v1, v3, :cond_4

    .line 58
    .line 59
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    :cond_3
    move-object v0, v2

    .line 63
    goto :goto_1

    .line 64
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 65
    .line 66
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 67
    .line 68
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw p0

    .line 72
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    iget-object p1, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p1, Luk0/r0;

    .line 78
    .line 79
    iget-object p1, p1, Luk0/r0;->b:Luk0/v;

    .line 80
    .line 81
    iput v3, p0, Lkn/o;->e:I

    .line 82
    .line 83
    check-cast p1, Lsk0/b;

    .line 84
    .line 85
    iget-object p0, p1, Lsk0/b;->c:Lyy0/c2;

    .line 86
    .line 87
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 88
    .line 89
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    const/4 v1, 0x0

    .line 93
    invoke-virtual {p0, v1, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    if-ne v2, v0, :cond_3

    .line 97
    .line 98
    :goto_1
    return-object v0

    .line 99
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 100
    .line 101
    iget v1, p0, Lkn/o;->e:I

    .line 102
    .line 103
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    const/4 v3, 0x1

    .line 106
    if-eqz v1, :cond_7

    .line 107
    .line 108
    if-ne v1, v3, :cond_6

    .line 109
    .line 110
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 115
    .line 116
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 117
    .line 118
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    throw p0

    .line 122
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    iget-object p1, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast p1, Lsf0/a;

    .line 128
    .line 129
    iput v3, p0, Lkn/o;->e:I

    .line 130
    .line 131
    iget-object p1, p1, Lsf0/a;->a:Lyy0/c2;

    .line 132
    .line 133
    new-instance v1, Lvf0/h;

    .line 134
    .line 135
    invoke-direct {v1}, Lvf0/h;-><init>()V

    .line 136
    .line 137
    .line 138
    invoke-virtual {p1, v1, p0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    if-ne v2, v0, :cond_8

    .line 142
    .line 143
    goto :goto_3

    .line 144
    :cond_8
    :goto_2
    move-object v0, v2

    .line 145
    :goto_3
    return-object v0

    .line 146
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 147
    .line 148
    iget v1, p0, Lkn/o;->e:I

    .line 149
    .line 150
    const/4 v2, 0x1

    .line 151
    if-eqz v1, :cond_a

    .line 152
    .line 153
    if-ne v1, v2, :cond_9

    .line 154
    .line 155
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 160
    .line 161
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 162
    .line 163
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    throw p0

    .line 167
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    iget-object p1, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast p1, Lm6/z;

    .line 173
    .line 174
    iput v2, p0, Lkn/o;->e:I

    .line 175
    .line 176
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 177
    .line 178
    .line 179
    invoke-static {p1, p0}, Lm6/z;->a(Lm6/z;Lrx0/c;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object p1

    .line 183
    if-ne p1, v0, :cond_b

    .line 184
    .line 185
    move-object p1, v0

    .line 186
    :cond_b
    :goto_4
    return-object p1

    .line 187
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 188
    .line 189
    iget v1, p0, Lkn/o;->e:I

    .line 190
    .line 191
    const/4 v2, 0x1

    .line 192
    if-eqz v1, :cond_d

    .line 193
    .line 194
    if-ne v1, v2, :cond_c

    .line 195
    .line 196
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    goto :goto_5

    .line 200
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 201
    .line 202
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 203
    .line 204
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    throw p0

    .line 208
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    iget-object p1, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast p1, Lm6/w;

    .line 214
    .line 215
    iput v2, p0, Lkn/o;->e:I

    .line 216
    .line 217
    invoke-static {p1, p0}, Lm6/w;->b(Lm6/w;Lrx0/c;)Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    if-ne p0, v0, :cond_e

    .line 222
    .line 223
    goto :goto_6

    .line 224
    :cond_e
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 225
    .line 226
    :goto_6
    return-object v0

    .line 227
    :pswitch_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 228
    .line 229
    iget v1, p0, Lkn/o;->e:I

    .line 230
    .line 231
    const/4 v2, 0x1

    .line 232
    if-eqz v1, :cond_10

    .line 233
    .line 234
    if-ne v1, v2, :cond_f

    .line 235
    .line 236
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    goto :goto_7

    .line 240
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 241
    .line 242
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 243
    .line 244
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    throw p0

    .line 248
    :cond_10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 249
    .line 250
    .line 251
    iget-object p1, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast p1, Ll50/a0;

    .line 254
    .line 255
    iget-object p1, p1, Ll50/a0;->b:Lal0/l1;

    .line 256
    .line 257
    iput v2, p0, Lkn/o;->e:I

    .line 258
    .line 259
    const/4 v1, 0x0

    .line 260
    invoke-virtual {p1, v1, p0}, Lal0/l1;->b(ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object p0

    .line 264
    if-ne p0, v0, :cond_11

    .line 265
    .line 266
    goto :goto_8

    .line 267
    :cond_11
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 268
    .line 269
    :goto_8
    return-object v0

    .line 270
    :pswitch_5
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 271
    .line 272
    iget v1, p0, Lkn/o;->e:I

    .line 273
    .line 274
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 275
    .line 276
    const/4 v3, 0x1

    .line 277
    if-eqz v1, :cond_13

    .line 278
    .line 279
    if-ne v1, v3, :cond_12

    .line 280
    .line 281
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 282
    .line 283
    .line 284
    goto :goto_a

    .line 285
    :cond_12
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 286
    .line 287
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 288
    .line 289
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    throw p0

    .line 293
    :cond_13
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 294
    .line 295
    .line 296
    iget-object p1, p0, Lkn/o;->f:Ljava/lang/Object;

    .line 297
    .line 298
    check-cast p1, Lkn/c0;

    .line 299
    .line 300
    iput v3, p0, Lkn/o;->e:I

    .line 301
    .line 302
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 303
    .line 304
    .line 305
    new-instance v1, Li50/p;

    .line 306
    .line 307
    const/4 v3, 0x0

    .line 308
    const/16 v4, 0x12

    .line 309
    .line 310
    invoke-direct {v1, p1, v3, v4}, Li50/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 311
    .line 312
    .line 313
    invoke-static {v1, p0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object p0

    .line 317
    if-ne p0, v0, :cond_14

    .line 318
    .line 319
    goto :goto_9

    .line 320
    :cond_14
    move-object p0, v2

    .line 321
    :goto_9
    if-ne p0, v0, :cond_15

    .line 322
    .line 323
    goto :goto_b

    .line 324
    :cond_15
    :goto_a
    move-object v0, v2

    .line 325
    :goto_b
    return-object v0

    .line 326
    nop

    .line 327
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
