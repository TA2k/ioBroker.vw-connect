.class public final Lm80/i;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public f:Z

.field public g:Z

.field public h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public j:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lm80/k;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lm80/i;->d:I

    .line 1
    iput-object p1, p0, Lm80/i;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lpx0/g;Lla/u;ZZLay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lm80/i;->d:I

    .line 2
    iput-object p1, p0, Lm80/i;->h:Ljava/lang/Object;

    iput-object p2, p0, Lm80/i;->i:Ljava/lang/Object;

    iput-boolean p3, p0, Lm80/i;->f:Z

    iput-boolean p4, p0, Lm80/i;->g:Z

    iput-object p5, p0, Lm80/i;->j:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    iget p1, p0, Lm80/i;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lm80/i;

    .line 7
    .line 8
    iget-object p1, p0, Lm80/i;->h:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lpx0/g;

    .line 12
    .line 13
    iget-object p1, p0, Lm80/i;->i:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v2, p1

    .line 16
    check-cast v2, Lla/u;

    .line 17
    .line 18
    iget-boolean v3, p0, Lm80/i;->f:Z

    .line 19
    .line 20
    iget-boolean v4, p0, Lm80/i;->g:Z

    .line 21
    .line 22
    iget-object p0, p0, Lm80/i;->j:Ljava/lang/Object;

    .line 23
    .line 24
    move-object v5, p0

    .line 25
    check-cast v5, Lay0/k;

    .line 26
    .line 27
    move-object v6, p2

    .line 28
    invoke-direct/range {v0 .. v6}, Lm80/i;-><init>(Lpx0/g;Lla/u;ZZLay0/k;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_0
    move-object v6, p2

    .line 33
    new-instance p1, Lm80/i;

    .line 34
    .line 35
    iget-object p0, p0, Lm80/i;->i:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Lm80/k;

    .line 38
    .line 39
    invoke-direct {p1, p0, v6}, Lm80/i;-><init>(Lm80/k;Lkotlin/coroutines/Continuation;)V

    .line 40
    .line 41
    .line 42
    return-object p1

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lm80/i;->d:I

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
    invoke-virtual {p0, p1, p2}, Lm80/i;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lm80/i;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lm80/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lm80/i;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lm80/i;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lm80/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 10

    .line 1
    iget v0, p0, Lm80/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lm80/i;->e:I

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
    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lm80/i;->h:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p1, Lpx0/g;

    .line 33
    .line 34
    new-instance v3, Lqa/c;

    .line 35
    .line 36
    iget-object v1, p0, Lm80/i;->i:Ljava/lang/Object;

    .line 37
    .line 38
    move-object v4, v1

    .line 39
    check-cast v4, Lla/u;

    .line 40
    .line 41
    iget-boolean v5, p0, Lm80/i;->f:Z

    .line 42
    .line 43
    iget-boolean v6, p0, Lm80/i;->g:Z

    .line 44
    .line 45
    iget-object v1, p0, Lm80/i;->j:Ljava/lang/Object;

    .line 46
    .line 47
    move-object v7, v1

    .line 48
    check-cast v7, Lay0/k;

    .line 49
    .line 50
    const/4 v8, 0x0

    .line 51
    invoke-direct/range {v3 .. v8}, Lqa/c;-><init>(Lla/u;ZZLay0/k;Lkotlin/coroutines/Continuation;)V

    .line 52
    .line 53
    .line 54
    iput v2, p0, Lm80/i;->e:I

    .line 55
    .line 56
    invoke-static {p1, v3, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    if-ne p1, v0, :cond_2

    .line 61
    .line 62
    move-object p1, v0

    .line 63
    :cond_2
    :goto_0
    return-object p1

    .line 64
    :pswitch_0
    iget-object v0, p0, Lm80/i;->i:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v0, Lm80/k;

    .line 67
    .line 68
    iget-object v1, v0, Lm80/k;->i:Lkf0/k;

    .line 69
    .line 70
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 71
    .line 72
    iget v3, p0, Lm80/i;->e:I

    .line 73
    .line 74
    const/4 v4, 0x3

    .line 75
    const/4 v5, 0x2

    .line 76
    const/4 v6, 0x1

    .line 77
    if-eqz v3, :cond_6

    .line 78
    .line 79
    if-eq v3, v6, :cond_5

    .line 80
    .line 81
    if-eq v3, v5, :cond_4

    .line 82
    .line 83
    if-ne v3, v4, :cond_3

    .line 84
    .line 85
    iget-boolean v0, p0, Lm80/i;->g:Z

    .line 86
    .line 87
    iget-object v1, p0, Lm80/i;->j:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v1, Lm80/j;

    .line 90
    .line 91
    iget-object p0, p0, Lm80/i;->h:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast p0, Lm80/k;

    .line 94
    .line 95
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    move v9, v0

    .line 99
    move-object v0, p0

    .line 100
    move p0, v9

    .line 101
    goto/16 :goto_3

    .line 102
    .line 103
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 104
    .line 105
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 106
    .line 107
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    throw p0

    .line 111
    :cond_4
    iget-boolean v1, p0, Lm80/i;->f:Z

    .line 112
    .line 113
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    iput v6, p0, Lm80/i;->e:I

    .line 125
    .line 126
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 127
    .line 128
    .line 129
    invoke-virtual {v1, p0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    if-ne p1, v2, :cond_7

    .line 134
    .line 135
    goto/16 :goto_5

    .line 136
    .line 137
    :cond_7
    :goto_1
    check-cast p1, Lss0/b;

    .line 138
    .line 139
    sget-object v3, Lss0/e;->y:Lss0/e;

    .line 140
    .line 141
    invoke-static {p1, v3}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 142
    .line 143
    .line 144
    move-result p1

    .line 145
    iput-boolean p1, p0, Lm80/i;->f:Z

    .line 146
    .line 147
    iput v5, p0, Lm80/i;->e:I

    .line 148
    .line 149
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 150
    .line 151
    .line 152
    invoke-virtual {v1, p0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    if-ne v1, v2, :cond_8

    .line 157
    .line 158
    goto :goto_5

    .line 159
    :cond_8
    move-object v9, v1

    .line 160
    move v1, p1

    .line 161
    move-object p1, v9

    .line 162
    :goto_2
    check-cast p1, Lss0/b;

    .line 163
    .line 164
    sget-object v3, Lss0/e;->x:Lss0/e;

    .line 165
    .line 166
    invoke-static {p1, v3}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 167
    .line 168
    .line 169
    move-result p1

    .line 170
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    check-cast v3, Lm80/j;

    .line 175
    .line 176
    if-eqz v1, :cond_b

    .line 177
    .line 178
    iget-object v5, v0, Lm80/k;->j:Lhh0/a;

    .line 179
    .line 180
    sget-object v7, Lih0/a;->p:Lih0/a;

    .line 181
    .line 182
    iput-object v0, p0, Lm80/i;->h:Ljava/lang/Object;

    .line 183
    .line 184
    iput-object v3, p0, Lm80/i;->j:Ljava/lang/Object;

    .line 185
    .line 186
    iput-boolean v1, p0, Lm80/i;->f:Z

    .line 187
    .line 188
    iput-boolean p1, p0, Lm80/i;->g:Z

    .line 189
    .line 190
    iput v4, p0, Lm80/i;->e:I

    .line 191
    .line 192
    invoke-virtual {v5, v7, p0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    if-ne p0, v2, :cond_9

    .line 197
    .line 198
    goto :goto_5

    .line 199
    :cond_9
    move v1, p1

    .line 200
    move-object p1, p0

    .line 201
    move p0, v1

    .line 202
    move-object v1, v3

    .line 203
    :goto_3
    check-cast p1, Ljava/lang/Boolean;

    .line 204
    .line 205
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 206
    .line 207
    .line 208
    move-result p1

    .line 209
    if-eqz p1, :cond_a

    .line 210
    .line 211
    move p1, v6

    .line 212
    goto :goto_4

    .line 213
    :cond_a
    move p1, p0

    .line 214
    move-object v3, v1

    .line 215
    :cond_b
    const/4 p0, 0x0

    .line 216
    move v1, p1

    .line 217
    move p1, p0

    .line 218
    move p0, v1

    .line 219
    move-object v1, v3

    .line 220
    :goto_4
    xor-int/2addr p0, v6

    .line 221
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 222
    .line 223
    .line 224
    new-instance v1, Lm80/j;

    .line 225
    .line 226
    invoke-direct {v1, p1, p0}, Lm80/j;-><init>(ZZ)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 230
    .line 231
    .line 232
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 233
    .line 234
    :goto_5
    return-object v2

    .line 235
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
