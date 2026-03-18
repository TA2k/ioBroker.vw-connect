.class public final Lic0/n;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lic0/p;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lic0/p;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lic0/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lic0/n;->f:Lic0/p;

    .line 4
    .line 5
    iput-object p2, p0, Lic0/n;->g:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Lic0/n;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lic0/n;

    .line 7
    .line 8
    iget-object v0, p0, Lic0/n;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lic0/n;->f:Lic0/p;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lic0/n;-><init>(Lic0/p;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lic0/n;

    .line 18
    .line 19
    iget-object v0, p0, Lic0/n;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lic0/n;->f:Lic0/p;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lic0/n;-><init>(Lic0/p;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

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
    iget v0, p0, Lic0/n;->d:I

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
    invoke-virtual {p0, p1, p2}, Lic0/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lic0/n;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lic0/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lic0/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lic0/n;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lic0/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 7

    .line 1
    iget v0, p0, Lic0/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lic0/n;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    iget-object v3, p0, Lic0/n;->f:Lic0/p;

    .line 13
    .line 14
    const/4 v4, 0x2

    .line 15
    const/4 v5, 0x1

    .line 16
    if-eqz v1, :cond_2

    .line 17
    .line 18
    if-eq v1, v5, :cond_1

    .line 19
    .line 20
    if-ne v1, v4, :cond_0

    .line 21
    .line 22
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    goto :goto_2

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object p1, v3, Lic0/p;->b:Lti0/a;

    .line 42
    .line 43
    iput v5, p0, Lic0/n;->e:I

    .line 44
    .line 45
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    if-ne p1, v0, :cond_3

    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_3
    :goto_0
    check-cast p1, Lic0/e;

    .line 53
    .line 54
    iget-object v1, v3, Lic0/p;->a:Llc0/l;

    .line 55
    .line 56
    iget-object v1, v1, Llc0/l;->d:Ljava/lang/String;

    .line 57
    .line 58
    const-string v3, "$v$c$cz-skodaauto-myskoda-library-authcomponent-model-RefreshToken$-$this$toEntity$0"

    .line 59
    .line 60
    iget-object v6, p0, Lic0/n;->g:Ljava/lang/String;

    .line 61
    .line 62
    invoke-static {v6, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    new-instance v3, Lic0/f;

    .line 66
    .line 67
    invoke-direct {v3, v1, v6}, Lic0/f;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    iput v4, p0, Lic0/n;->e:I

    .line 71
    .line 72
    iget-object v1, p1, Lic0/e;->a:Lla/u;

    .line 73
    .line 74
    new-instance v4, Li40/j0;

    .line 75
    .line 76
    const/4 v6, 0x7

    .line 77
    invoke-direct {v4, v6, p1, v3}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    const/4 p1, 0x0

    .line 81
    invoke-static {p0, v1, p1, v5, v4}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    if-ne p0, v0, :cond_4

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_4
    move-object p0, v2

    .line 89
    :goto_1
    if-ne p0, v0, :cond_5

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_5
    :goto_2
    move-object v0, v2

    .line 93
    :goto_3
    return-object v0

    .line 94
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 95
    .line 96
    iget v1, p0, Lic0/n;->e:I

    .line 97
    .line 98
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 99
    .line 100
    iget-object v3, p0, Lic0/n;->f:Lic0/p;

    .line 101
    .line 102
    const/4 v4, 0x2

    .line 103
    const/4 v5, 0x1

    .line 104
    if-eqz v1, :cond_8

    .line 105
    .line 106
    if-eq v1, v5, :cond_7

    .line 107
    .line 108
    if-ne v1, v4, :cond_6

    .line 109
    .line 110
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    goto :goto_6

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
    goto :goto_4

    .line 126
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    iget-object p1, v3, Lic0/p;->b:Lti0/a;

    .line 130
    .line 131
    iput v5, p0, Lic0/n;->e:I

    .line 132
    .line 133
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    if-ne p1, v0, :cond_9

    .line 138
    .line 139
    goto :goto_7

    .line 140
    :cond_9
    :goto_4
    check-cast p1, Lic0/e;

    .line 141
    .line 142
    iget-object v1, v3, Lic0/p;->a:Llc0/l;

    .line 143
    .line 144
    iget-object v1, v1, Llc0/l;->d:Ljava/lang/String;

    .line 145
    .line 146
    new-instance v3, Lic0/f;

    .line 147
    .line 148
    iget-object v6, p0, Lic0/n;->g:Ljava/lang/String;

    .line 149
    .line 150
    invoke-direct {v3, v1, v6}, Lic0/f;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    iput v4, p0, Lic0/n;->e:I

    .line 154
    .line 155
    iget-object v1, p1, Lic0/e;->a:Lla/u;

    .line 156
    .line 157
    new-instance v4, Li40/j0;

    .line 158
    .line 159
    const/4 v6, 0x7

    .line 160
    invoke-direct {v4, v6, p1, v3}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    const/4 p1, 0x0

    .line 164
    invoke-static {p0, v1, p1, v5, v4}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    if-ne p0, v0, :cond_a

    .line 169
    .line 170
    goto :goto_5

    .line 171
    :cond_a
    move-object p0, v2

    .line 172
    :goto_5
    if-ne p0, v0, :cond_b

    .line 173
    .line 174
    goto :goto_7

    .line 175
    :cond_b
    :goto_6
    move-object v0, v2

    .line 176
    :goto_7
    return-object v0

    .line 177
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
