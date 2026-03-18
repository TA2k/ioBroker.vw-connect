.class public final Lc1/w0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc1/c1;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lc1/w1;


# direct methods
.method public constructor <init>(Lc1/c1;Ljava/lang/Object;Lc1/w1;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lc1/w0;->d:I

    .line 1
    iput-object p1, p0, Lc1/w0;->f:Lc1/c1;

    iput-object p2, p0, Lc1/w0;->g:Ljava/lang/Object;

    iput-object p3, p0, Lc1/w0;->h:Lc1/w1;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lc1/w1;Lc1/c1;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lc1/w0;->d:I

    .line 2
    iput-object p1, p0, Lc1/w0;->h:Lc1/w1;

    iput-object p2, p0, Lc1/w0;->f:Lc1/c1;

    iput-object p3, p0, Lc1/w0;->g:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lc1/w0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lc1/w0;

    .line 7
    .line 8
    iget-object v1, p0, Lc1/w0;->g:Ljava/lang/Object;

    .line 9
    .line 10
    iget-object v2, p0, Lc1/w0;->h:Lc1/w1;

    .line 11
    .line 12
    iget-object p0, p0, Lc1/w0;->f:Lc1/c1;

    .line 13
    .line 14
    invoke-direct {v0, p0, v1, v2, p1}, Lc1/w0;-><init>(Lc1/c1;Ljava/lang/Object;Lc1/w1;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    return-object v0

    .line 18
    :pswitch_0
    new-instance v0, Lc1/w0;

    .line 19
    .line 20
    iget-object v1, p0, Lc1/w0;->f:Lc1/c1;

    .line 21
    .line 22
    iget-object v2, p0, Lc1/w0;->g:Ljava/lang/Object;

    .line 23
    .line 24
    iget-object p0, p0, Lc1/w0;->h:Lc1/w1;

    .line 25
    .line 26
    invoke-direct {v0, p0, v1, v2, p1}, Lc1/w0;-><init>(Lc1/w1;Lc1/c1;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    return-object v0

    .line 30
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lc1/w0;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lc1/w0;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lc1/w0;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lc1/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Lc1/w0;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lc1/w0;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lc1/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lc1/w0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lc1/w0;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object v3, p0, Lc1/w0;->h:Lc1/w1;

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
    goto :goto_1

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
    iget-object p1, p0, Lc1/w0;->f:Lc1/c1;

    .line 33
    .line 34
    invoke-virtual {p1}, Lc1/c1;->g0()V

    .line 35
    .line 36
    .line 37
    iget-object v1, p1, Lc1/c1;->f:Ll2/j1;

    .line 38
    .line 39
    const-wide/high16 v4, -0x8000000000000000L

    .line 40
    .line 41
    iput-wide v4, p1, Lc1/c1;->p:J

    .line 42
    .line 43
    const/4 v4, 0x0

    .line 44
    invoke-virtual {p1, v4}, Lc1/c1;->k0(F)V

    .line 45
    .line 46
    .line 47
    iget-object v5, p1, Lc1/c1;->g:Ll2/j1;

    .line 48
    .line 49
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    iget-object v6, p0, Lc1/w0;->g:Ljava/lang/Object;

    .line 54
    .line 55
    invoke-virtual {v6, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v5

    .line 59
    const/high16 v7, -0x3fc00000    # -3.0f

    .line 60
    .line 61
    if-eqz v5, :cond_2

    .line 62
    .line 63
    const/high16 v5, -0x3f800000    # -4.0f

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    invoke-virtual {v6, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v5

    .line 74
    if-eqz v5, :cond_3

    .line 75
    .line 76
    const/high16 v5, -0x3f600000    # -5.0f

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_3
    move v5, v7

    .line 80
    :goto_0
    invoke-virtual {v3, v6}, Lc1/w1;->p(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    const-wide/16 v8, 0x0

    .line 84
    .line 85
    invoke-virtual {v3, v8, v9}, Lc1/w1;->n(J)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v1, v6}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p1, v4}, Lc1/c1;->k0(F)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {p1, v6}, Lc1/c1;->T(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v3, v5}, Lc1/w1;->j(F)V

    .line 98
    .line 99
    .line 100
    cmpg-float v1, v5, v7

    .line 101
    .line 102
    if-nez v1, :cond_4

    .line 103
    .line 104
    iput v2, p0, Lc1/w0;->e:I

    .line 105
    .line 106
    invoke-static {p1, p0}, Lc1/c1;->e0(Lc1/c1;Lrx0/c;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    if-ne p0, v0, :cond_4

    .line 111
    .line 112
    goto :goto_2

    .line 113
    :cond_4
    :goto_1
    invoke-virtual {v3}, Lc1/w1;->i()V

    .line 114
    .line 115
    .line 116
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 117
    .line 118
    :goto_2
    return-object v0

    .line 119
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 120
    .line 121
    iget v1, p0, Lc1/w0;->e:I

    .line 122
    .line 123
    iget-object v2, p0, Lc1/w0;->h:Lc1/w1;

    .line 124
    .line 125
    const/4 v3, 0x1

    .line 126
    if-eqz v1, :cond_6

    .line 127
    .line 128
    if-ne v1, v3, :cond_5

    .line 129
    .line 130
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    goto :goto_3

    .line 134
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 135
    .line 136
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 137
    .line 138
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    throw p0

    .line 142
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    new-instance p1, Laa/i0;

    .line 146
    .line 147
    iget-object v1, p0, Lc1/w0;->g:Ljava/lang/Object;

    .line 148
    .line 149
    const/4 v4, 0x0

    .line 150
    iget-object v5, p0, Lc1/w0;->f:Lc1/c1;

    .line 151
    .line 152
    invoke-direct {p1, v5, v1, v2, v4}, Laa/i0;-><init>(Lc1/c1;Ljava/lang/Object;Lc1/w1;Lkotlin/coroutines/Continuation;)V

    .line 153
    .line 154
    .line 155
    iput v3, p0, Lc1/w0;->e:I

    .line 156
    .line 157
    invoke-static {p1, p0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    if-ne p0, v0, :cond_7

    .line 162
    .line 163
    goto :goto_4

    .line 164
    :cond_7
    :goto_3
    invoke-virtual {v2}, Lc1/w1;->i()V

    .line 165
    .line 166
    .line 167
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 168
    .line 169
    :goto_4
    return-object v0

    .line 170
    nop

    .line 171
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
