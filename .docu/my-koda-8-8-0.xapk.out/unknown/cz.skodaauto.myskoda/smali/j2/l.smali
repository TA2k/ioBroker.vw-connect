.class public final Lj2/l;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lj2/o;


# direct methods
.method public synthetic constructor <init>(Lj2/o;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lj2/l;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lj2/l;->f:Lj2/o;

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
    iget p1, p0, Lj2/l;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lj2/l;

    .line 7
    .line 8
    iget-object p0, p0, Lj2/l;->f:Lj2/o;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lj2/l;-><init>(Lj2/o;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lj2/l;

    .line 16
    .line 17
    iget-object p0, p0, Lj2/l;->f:Lj2/o;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lj2/l;-><init>(Lj2/o;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lj2/l;

    .line 25
    .line 26
    iget-object p0, p0, Lj2/l;->f:Lj2/o;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lj2/l;-><init>(Lj2/o;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lj2/l;->d:I

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
    invoke-virtual {p0, p1, p2}, Lj2/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lj2/l;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lj2/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lj2/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lj2/l;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lj2/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lj2/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lj2/l;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lj2/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lj2/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lj2/l;->e:I

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    const/4 v3, 0x1

    .line 12
    if-eqz v1, :cond_2

    .line 13
    .line 14
    if-eq v1, v3, :cond_1

    .line 15
    .line 16
    if-ne v1, v2, :cond_0

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
    :goto_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iget-object p1, p0, Lj2/l;->f:Lj2/o;

    .line 35
    .line 36
    iget-boolean v1, p1, Lj2/o;->t:Z

    .line 37
    .line 38
    if-nez v1, :cond_3

    .line 39
    .line 40
    iput v3, p0, Lj2/l;->e:I

    .line 41
    .line 42
    invoke-virtual {p1, p0}, Lj2/o;->b1(Lrx0/c;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    if-ne p0, v0, :cond_4

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_3
    iput v2, p0, Lj2/l;->e:I

    .line 50
    .line 51
    invoke-static {p1, p0}, Lj2/o;->a1(Lj2/o;Lrx0/c;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    if-ne p0, v0, :cond_4

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_4
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    :goto_2
    return-object v0

    .line 61
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 62
    .line 63
    iget v1, p0, Lj2/l;->e:I

    .line 64
    .line 65
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    const/4 v3, 0x1

    .line 68
    if-eqz v1, :cond_6

    .line 69
    .line 70
    if-ne v1, v3, :cond_5

    .line 71
    .line 72
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_4

    .line 76
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 77
    .line 78
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 79
    .line 80
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p0

    .line 84
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    iget-object p1, p0, Lj2/l;->f:Lj2/o;

    .line 88
    .line 89
    iget-object v1, p1, Lj2/o;->w:Lj2/p;

    .line 90
    .line 91
    iget-object v1, v1, Lj2/p;->a:Lc1/c;

    .line 92
    .line 93
    invoke-virtual {v1}, Lc1/c;->e()Z

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    if-nez v1, :cond_8

    .line 98
    .line 99
    iget-object v1, p1, Lj2/o;->w:Lj2/p;

    .line 100
    .line 101
    iget-object v4, p1, Lj2/o;->z:Ll2/f1;

    .line 102
    .line 103
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 104
    .line 105
    .line 106
    move-result v4

    .line 107
    invoke-virtual {p1}, Lj2/o;->d1()I

    .line 108
    .line 109
    .line 110
    move-result p1

    .line 111
    int-to-float p1, p1

    .line 112
    div-float/2addr v4, p1

    .line 113
    iput v3, p0, Lj2/l;->e:I

    .line 114
    .line 115
    iget-object p1, v1, Lj2/p;->a:Lc1/c;

    .line 116
    .line 117
    new-instance v1, Ljava/lang/Float;

    .line 118
    .line 119
    invoke-direct {v1, v4}, Ljava/lang/Float;-><init>(F)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p1, v1, p0}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    if-ne p0, v0, :cond_7

    .line 127
    .line 128
    goto :goto_3

    .line 129
    :cond_7
    move-object p0, v2

    .line 130
    :goto_3
    if-ne p0, v0, :cond_8

    .line 131
    .line 132
    goto :goto_5

    .line 133
    :cond_8
    :goto_4
    move-object v0, v2

    .line 134
    :goto_5
    return-object v0

    .line 135
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 136
    .line 137
    iget v1, p0, Lj2/l;->e:I

    .line 138
    .line 139
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    const/4 v3, 0x1

    .line 142
    if-eqz v1, :cond_a

    .line 143
    .line 144
    if-ne v1, v3, :cond_9

    .line 145
    .line 146
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    goto :goto_8

    .line 150
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 151
    .line 152
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 153
    .line 154
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    throw p0

    .line 158
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    iget-object p1, p0, Lj2/l;->f:Lj2/o;

    .line 162
    .line 163
    iget-object v1, p1, Lj2/o;->w:Lj2/p;

    .line 164
    .line 165
    iget-boolean p1, p1, Lj2/o;->t:Z

    .line 166
    .line 167
    if-eqz p1, :cond_b

    .line 168
    .line 169
    const/high16 p1, 0x3f800000    # 1.0f

    .line 170
    .line 171
    goto :goto_6

    .line 172
    :cond_b
    const/4 p1, 0x0

    .line 173
    :goto_6
    iput v3, p0, Lj2/l;->e:I

    .line 174
    .line 175
    iget-object v1, v1, Lj2/p;->a:Lc1/c;

    .line 176
    .line 177
    new-instance v3, Ljava/lang/Float;

    .line 178
    .line 179
    invoke-direct {v3, p1}, Ljava/lang/Float;-><init>(F)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v1, v3, p0}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    if-ne p0, v0, :cond_c

    .line 187
    .line 188
    goto :goto_7

    .line 189
    :cond_c
    move-object p0, v2

    .line 190
    :goto_7
    if-ne p0, v0, :cond_d

    .line 191
    .line 192
    goto :goto_9

    .line 193
    :cond_d
    :goto_8
    move-object v0, v2

    .line 194
    :goto_9
    return-object v0

    .line 195
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
