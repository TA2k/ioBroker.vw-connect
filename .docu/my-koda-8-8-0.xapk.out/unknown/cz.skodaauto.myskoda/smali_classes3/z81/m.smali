.class public final Lz81/m;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lz81/o;

.field public final synthetic g:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Lz81/o;Ljava/util/List;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lz81/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lz81/m;->f:Lz81/o;

    .line 4
    .line 5
    iput-object p2, p0, Lz81/m;->g:Ljava/util/List;

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
    iget p1, p0, Lz81/m;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lz81/m;

    .line 7
    .line 8
    iget-object v0, p0, Lz81/m;->g:Ljava/util/List;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lz81/m;->f:Lz81/o;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lz81/m;-><init>(Lz81/o;Ljava/util/List;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lz81/m;

    .line 18
    .line 19
    iget-object v0, p0, Lz81/m;->g:Ljava/util/List;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lz81/m;->f:Lz81/o;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lz81/m;-><init>(Lz81/o;Ljava/util/List;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lz81/m;->d:I

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
    invoke-virtual {p0, p1, p2}, Lz81/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lz81/m;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lz81/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lz81/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lz81/m;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lz81/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lz81/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lz81/m;->e:I

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
    iget-object p1, p0, Lz81/m;->f:Lz81/o;

    .line 33
    .line 34
    iget-object p1, p1, Lz81/o;->d:Lb91/b;

    .line 35
    .line 36
    new-instance v1, Lc91/a0;

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
    iget-object v5, p0, Lz81/m;->g:Ljava/util/List;

    .line 52
    .line 53
    invoke-direct {v1, v4, v5}, Lc91/a0;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 54
    .line 55
    .line 56
    iput v3, p0, Lz81/m;->e:I

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
    const/16 v6, 0x8

    .line 64
    .line 65
    invoke-direct {v4, v6, p1, v1, v5}, La7/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 66
    .line 67
    .line 68
    invoke-static {v3, v4, p0}, Ljp/oe;->d(Lm6/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    if-ne p0, v0, :cond_2

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_2
    move-object p0, v2

    .line 76
    :goto_0
    if-ne p0, v0, :cond_3

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_3
    :goto_1
    move-object v0, v2

    .line 80
    :goto_2
    return-object v0

    .line 81
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 82
    .line 83
    iget v1, p0, Lz81/m;->e:I

    .line 84
    .line 85
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    const/4 v3, 0x1

    .line 88
    if-eqz v1, :cond_5

    .line 89
    .line 90
    if-ne v1, v3, :cond_4

    .line 91
    .line 92
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    goto :goto_4

    .line 96
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 97
    .line 98
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 99
    .line 100
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    throw p0

    .line 104
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    iget-object p1, p0, Lz81/m;->f:Lz81/o;

    .line 108
    .line 109
    iget-object p1, p1, Lz81/o;->d:Lb91/b;

    .line 110
    .line 111
    new-instance v1, Lc91/a0;

    .line 112
    .line 113
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    invoke-virtual {v4}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v4

    .line 121
    const-string v5, "toString(...)"

    .line 122
    .line 123
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    iget-object v5, p0, Lz81/m;->g:Ljava/util/List;

    .line 127
    .line 128
    invoke-direct {v1, v4, v5}, Lc91/a0;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 129
    .line 130
    .line 131
    iput v3, p0, Lz81/m;->e:I

    .line 132
    .line 133
    iget-object v3, p1, Lb91/b;->b:Lm6/g;

    .line 134
    .line 135
    new-instance v4, La7/k;

    .line 136
    .line 137
    const/4 v5, 0x0

    .line 138
    const/16 v6, 0x8

    .line 139
    .line 140
    invoke-direct {v4, v6, p1, v1, v5}, La7/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 141
    .line 142
    .line 143
    invoke-static {v3, v4, p0}, Ljp/oe;->d(Lm6/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    if-ne p0, v0, :cond_6

    .line 148
    .line 149
    goto :goto_3

    .line 150
    :cond_6
    move-object p0, v2

    .line 151
    :goto_3
    if-ne p0, v0, :cond_7

    .line 152
    .line 153
    goto :goto_5

    .line 154
    :cond_7
    :goto_4
    move-object v0, v2

    .line 155
    :goto_5
    return-object v0

    .line 156
    nop

    .line 157
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
