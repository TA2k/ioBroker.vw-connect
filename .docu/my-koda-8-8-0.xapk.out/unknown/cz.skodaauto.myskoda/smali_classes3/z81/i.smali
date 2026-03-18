.class public final Lz81/i;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lz81/l;

.field public final synthetic g:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Lz81/l;Ljava/util/List;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lz81/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lz81/i;->f:Lz81/l;

    .line 4
    .line 5
    iput-object p2, p0, Lz81/i;->g:Ljava/util/List;

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
    iget p1, p0, Lz81/i;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lz81/i;

    .line 7
    .line 8
    iget-object v0, p0, Lz81/i;->g:Ljava/util/List;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lz81/i;->f:Lz81/l;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lz81/i;-><init>(Lz81/l;Ljava/util/List;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lz81/i;

    .line 18
    .line 19
    iget-object v0, p0, Lz81/i;->g:Ljava/util/List;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lz81/i;->f:Lz81/l;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lz81/i;-><init>(Lz81/l;Ljava/util/List;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lz81/i;->d:I

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
    invoke-virtual {p0, p1, p2}, Lz81/i;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lz81/i;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lz81/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lz81/i;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lz81/i;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lz81/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lz81/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lz81/i;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

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
    iget-object p1, p0, Lz81/i;->f:Lz81/l;

    .line 33
    .line 34
    iget-object p1, p1, Lz81/l;->d:Lb91/b;

    .line 35
    .line 36
    new-instance v1, Lc91/x;

    .line 37
    .line 38
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    invoke-virtual {v4}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    const-string v5, "toString(...)"

    .line 47
    .line 48
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    iget-object v5, p0, Lz81/i;->g:Ljava/util/List;

    .line 52
    .line 53
    invoke-direct {v1, v4, v5}, Lc91/x;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 54
    .line 55
    .line 56
    iput v3, p0, Lz81/i;->e:I

    .line 57
    .line 58
    iget-object v3, p1, Lb91/b;->b:Lm6/g;

    .line 59
    .line 60
    new-instance v4, La7/k;

    .line 61
    .line 62
    const/4 v5, 0x0

    .line 63
    const/4 v6, 0x7

    .line 64
    invoke-direct {v4, v6, p1, v1, v5}, La7/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 65
    .line 66
    .line 67
    invoke-static {v3, v4, p0}, Ljp/oe;->d(Lm6/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    if-ne p0, v0, :cond_2

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_2
    move-object p0, v2

    .line 75
    :goto_0
    if-ne p0, v0, :cond_3

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_3
    :goto_1
    move-object v0, v2

    .line 79
    :goto_2
    return-object v0

    .line 80
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 81
    .line 82
    iget v1, p0, Lz81/i;->e:I

    .line 83
    .line 84
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    const/4 v3, 0x1

    .line 87
    if-eqz v1, :cond_5

    .line 88
    .line 89
    if-ne v1, v3, :cond_4

    .line 90
    .line 91
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    goto :goto_4

    .line 95
    :cond_4
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
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    iget-object p1, p0, Lz81/i;->f:Lz81/l;

    .line 107
    .line 108
    iget-object p1, p1, Lz81/l;->d:Lb91/b;

    .line 109
    .line 110
    new-instance v1, Lc91/x;

    .line 111
    .line 112
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    invoke-virtual {v4}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    const-string v5, "toString(...)"

    .line 121
    .line 122
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    iget-object v5, p0, Lz81/i;->g:Ljava/util/List;

    .line 126
    .line 127
    invoke-direct {v1, v4, v5}, Lc91/x;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 128
    .line 129
    .line 130
    iput v3, p0, Lz81/i;->e:I

    .line 131
    .line 132
    iget-object v3, p1, Lb91/b;->b:Lm6/g;

    .line 133
    .line 134
    new-instance v4, La7/k;

    .line 135
    .line 136
    const/4 v5, 0x0

    .line 137
    const/4 v6, 0x7

    .line 138
    invoke-direct {v4, v6, p1, v1, v5}, La7/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 139
    .line 140
    .line 141
    invoke-static {v3, v4, p0}, Ljp/oe;->d(Lm6/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    if-ne p0, v0, :cond_6

    .line 146
    .line 147
    goto :goto_3

    .line 148
    :cond_6
    move-object p0, v2

    .line 149
    :goto_3
    if-ne p0, v0, :cond_7

    .line 150
    .line 151
    goto :goto_5

    .line 152
    :cond_7
    :goto_4
    move-object v0, v2

    .line 153
    :goto_5
    return-object v0

    .line 154
    nop

    .line 155
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
