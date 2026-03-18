.class public final Li2/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:F

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;FLkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Li2/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li2/f;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput p2, p0, Li2/f;->f:F

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
    iget p1, p0, Li2/f;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Li2/f;

    .line 7
    .line 8
    iget-object v0, p0, Li2/f;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lkn/c0;

    .line 11
    .line 12
    iget p0, p0, Li2/f;->f:F

    .line 13
    .line 14
    const/4 v1, 0x2

    .line 15
    invoke-direct {p1, v0, p0, p2, v1}, Li2/f;-><init>(Ljava/lang/Object;FLkotlin/coroutines/Continuation;I)V

    .line 16
    .line 17
    .line 18
    return-object p1

    .line 19
    :pswitch_0
    new-instance p1, Li2/f;

    .line 20
    .line 21
    iget-object v0, p0, Li2/f;->g:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v0, Lc1/c;

    .line 24
    .line 25
    iget p0, p0, Li2/f;->f:F

    .line 26
    .line 27
    const/4 v1, 0x1

    .line 28
    invoke-direct {p1, v0, p0, p2, v1}, Li2/f;-><init>(Ljava/lang/Object;FLkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    return-object p1

    .line 32
    :pswitch_1
    new-instance p1, Li2/f;

    .line 33
    .line 34
    iget-object v0, p0, Li2/f;->g:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Li2/p;

    .line 37
    .line 38
    iget p0, p0, Li2/f;->f:F

    .line 39
    .line 40
    const/4 v1, 0x0

    .line 41
    invoke-direct {p1, v0, p0, p2, v1}, Li2/f;-><init>(Ljava/lang/Object;FLkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    return-object p1

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Li2/f;->d:I

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
    invoke-virtual {p0, p1, p2}, Li2/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Li2/f;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Li2/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Li2/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Li2/f;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Li2/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Li2/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Li2/f;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Li2/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 4

    .line 1
    iget v0, p0, Li2/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Li2/f;->e:I

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
    iget-object p1, p0, Li2/f;->g:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p1, Lkn/c0;

    .line 33
    .line 34
    iput v2, p0, Li2/f;->e:I

    .line 35
    .line 36
    iget v1, p0, Li2/f;->f:F

    .line 37
    .line 38
    invoke-virtual {p1, v1, p0}, Lkn/c0;->a(FLrx0/i;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    if-ne p0, v0, :cond_2

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    :goto_1
    return-object v0

    .line 48
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 49
    .line 50
    iget v1, p0, Li2/f;->e:I

    .line 51
    .line 52
    const/4 v2, 0x1

    .line 53
    if-eqz v1, :cond_4

    .line 54
    .line 55
    if-ne v1, v2, :cond_3

    .line 56
    .line 57
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    iget-object p1, p0, Li2/f;->g:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast p1, Lc1/c;

    .line 75
    .line 76
    invoke-virtual {p1}, Lc1/c;->d()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    check-cast v1, Ljava/lang/Number;

    .line 81
    .line 82
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    iget v3, p0, Li2/f;->f:F

    .line 87
    .line 88
    add-float/2addr v1, v3

    .line 89
    new-instance v3, Ljava/lang/Float;

    .line 90
    .line 91
    invoke-direct {v3, v1}, Ljava/lang/Float;-><init>(F)V

    .line 92
    .line 93
    .line 94
    iput v2, p0, Li2/f;->e:I

    .line 95
    .line 96
    invoke-virtual {p1, v3, p0}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    if-ne p0, v0, :cond_5

    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    :goto_3
    return-object v0

    .line 106
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 107
    .line 108
    iget v1, p0, Li2/f;->e:I

    .line 109
    .line 110
    const/4 v2, 0x1

    .line 111
    if-eqz v1, :cond_7

    .line 112
    .line 113
    if-ne v1, v2, :cond_6

    .line 114
    .line 115
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 120
    .line 121
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 122
    .line 123
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    throw p0

    .line 127
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    iget-object p1, p0, Li2/f;->g:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast p1, Li2/p;

    .line 133
    .line 134
    iput v2, p0, Li2/f;->e:I

    .line 135
    .line 136
    iget v1, p0, Li2/f;->f:F

    .line 137
    .line 138
    invoke-virtual {p1, v1, p0}, Li2/p;->i(FLrx0/i;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    if-ne p0, v0, :cond_8

    .line 143
    .line 144
    goto :goto_5

    .line 145
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 146
    .line 147
    :goto_5
    return-object v0

    .line 148
    nop

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
