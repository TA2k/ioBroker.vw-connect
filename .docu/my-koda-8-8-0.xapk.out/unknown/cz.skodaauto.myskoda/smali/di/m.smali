.class public final Ldi/m;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ldi/o;


# direct methods
.method public synthetic constructor <init>(Ldi/o;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ldi/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ldi/m;->f:Ldi/o;

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
    iget p1, p0, Ldi/m;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ldi/m;

    .line 7
    .line 8
    iget-object p0, p0, Ldi/m;->f:Ldi/o;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ldi/m;-><init>(Ldi/o;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ldi/m;

    .line 16
    .line 17
    iget-object p0, p0, Ldi/m;->f:Ldi/o;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ldi/m;-><init>(Ldi/o;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ldi/m;

    .line 25
    .line 26
    iget-object p0, p0, Ldi/m;->f:Ldi/o;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ldi/m;-><init>(Ldi/o;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ldi/m;->d:I

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
    invoke-virtual {p0, p1, p2}, Ldi/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ldi/m;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ldi/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ldi/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ldi/m;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ldi/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ldi/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ldi/m;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ldi/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 5

    .line 1
    iget v0, p0, Ldi/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ldi/m;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object v3, p0, Ldi/m;->f:Ldi/o;

    .line 12
    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v2, :cond_0

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
    iget-object p1, v3, Ldi/o;->k:Lag/c;

    .line 33
    .line 34
    new-instance v1, Lzg/i0;

    .line 35
    .line 36
    iget-object v4, v3, Ldi/o;->d:Ljava/lang/String;

    .line 37
    .line 38
    invoke-direct {v1, v4}, Lzg/i0;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    iput v2, p0, Ldi/m;->e:I

    .line 42
    .line 43
    invoke-virtual {p1, v1, p0}, Lag/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    if-ne p1, v0, :cond_2

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    :goto_0
    check-cast p1, Llx0/o;

    .line 51
    .line 52
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 53
    .line 54
    instance-of p1, p0, Llx0/n;

    .line 55
    .line 56
    if-nez p1, :cond_3

    .line 57
    .line 58
    move-object p1, p0

    .line 59
    check-cast p1, Llx0/b0;

    .line 60
    .line 61
    iget-object p1, v3, Ldi/o;->g:Lyj/b;

    .line 62
    .line 63
    invoke-virtual {p1}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    :cond_3
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    if-eqz p0, :cond_4

    .line 71
    .line 72
    const/4 p1, 0x0

    .line 73
    invoke-virtual {v3, p1}, Ldi/o;->b(Z)V

    .line 74
    .line 75
    .line 76
    iget-object p1, v3, Ldi/o;->r:Lyy0/c2;

    .line 77
    .line 78
    invoke-virtual {p1, p0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    :cond_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    :goto_1
    return-object v0

    .line 84
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 85
    .line 86
    iget v1, p0, Ldi/m;->e:I

    .line 87
    .line 88
    const/4 v2, 0x1

    .line 89
    iget-object v3, p0, Ldi/m;->f:Ldi/o;

    .line 90
    .line 91
    if-eqz v1, :cond_6

    .line 92
    .line 93
    if-ne v1, v2, :cond_5

    .line 94
    .line 95
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 100
    .line 101
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 102
    .line 103
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    throw p0

    .line 107
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    iget-object p1, v3, Ldi/o;->j:Lag/c;

    .line 111
    .line 112
    new-instance v1, Lzg/c0;

    .line 113
    .line 114
    iget-object v4, v3, Ldi/o;->d:Ljava/lang/String;

    .line 115
    .line 116
    invoke-direct {v1, v4}, Lzg/c0;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    iput v2, p0, Ldi/m;->e:I

    .line 120
    .line 121
    invoke-virtual {p1, v1, p0}, Lag/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    if-ne p1, v0, :cond_7

    .line 126
    .line 127
    goto :goto_3

    .line 128
    :cond_7
    :goto_2
    check-cast p1, Llx0/o;

    .line 129
    .line 130
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 131
    .line 132
    instance-of p1, p0, Llx0/n;

    .line 133
    .line 134
    if-nez p1, :cond_8

    .line 135
    .line 136
    move-object p1, p0

    .line 137
    check-cast p1, Llx0/b0;

    .line 138
    .line 139
    iget-object p1, v3, Ldi/o;->g:Lyj/b;

    .line 140
    .line 141
    invoke-virtual {p1}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    :cond_8
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    if-eqz p0, :cond_9

    .line 149
    .line 150
    const/4 p1, 0x0

    .line 151
    invoke-virtual {v3, p1}, Ldi/o;->b(Z)V

    .line 152
    .line 153
    .line 154
    iget-object p1, v3, Ldi/o;->r:Lyy0/c2;

    .line 155
    .line 156
    invoke-virtual {p1, p0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    :cond_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 160
    .line 161
    :goto_3
    return-object v0

    .line 162
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 163
    .line 164
    iget v1, p0, Ldi/m;->e:I

    .line 165
    .line 166
    const/4 v2, 0x1

    .line 167
    if-eqz v1, :cond_b

    .line 168
    .line 169
    if-ne v1, v2, :cond_a

    .line 170
    .line 171
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    goto :goto_4

    .line 175
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 176
    .line 177
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 178
    .line 179
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    throw p0

    .line 183
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    iget-object p1, p0, Ldi/m;->f:Ldi/o;

    .line 187
    .line 188
    iget-object v1, p1, Ldi/o;->o:Lyy0/c2;

    .line 189
    .line 190
    new-instance v3, Ld2/g;

    .line 191
    .line 192
    const/4 v4, 0x3

    .line 193
    invoke-direct {v3, p1, v4}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 194
    .line 195
    .line 196
    iput v2, p0, Ldi/m;->e:I

    .line 197
    .line 198
    invoke-static {v1, v3, p0}, Lzb/b;->y(Lyy0/c2;Lay0/a;Lrx0/i;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    if-ne p0, v0, :cond_c

    .line 203
    .line 204
    goto :goto_5

    .line 205
    :cond_c
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 206
    .line 207
    :goto_5
    return-object v0

    .line 208
    nop

    .line 209
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
