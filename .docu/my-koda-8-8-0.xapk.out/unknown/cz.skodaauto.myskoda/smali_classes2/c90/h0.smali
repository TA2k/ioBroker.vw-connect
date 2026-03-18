.class public final Lc90/h0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc90/j0;


# direct methods
.method public synthetic constructor <init>(Lc90/j0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc90/h0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc90/h0;->f:Lc90/j0;

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
    iget p1, p0, Lc90/h0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lc90/h0;

    .line 7
    .line 8
    iget-object p0, p0, Lc90/h0;->f:Lc90/j0;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lc90/h0;-><init>(Lc90/j0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lc90/h0;

    .line 16
    .line 17
    iget-object p0, p0, Lc90/h0;->f:Lc90/j0;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lc90/h0;-><init>(Lc90/j0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lc90/h0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc90/h0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc90/h0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc90/h0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc90/h0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lc90/h0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lc90/h0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lc90/h0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lc90/h0;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Lc90/h0;->f:Lc90/j0;

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
    iget-object p1, v2, Lc90/j0;->k:Lfj0/i;

    .line 33
    .line 34
    iput v3, p0, Lc90/h0;->e:I

    .line 35
    .line 36
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1, p0}, Lfj0/i;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    if-ne p0, v0, :cond_2

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_2
    :goto_0
    iget-object p0, v2, Lc90/j0;->j:Lnr0/a;

    .line 47
    .line 48
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 52
    .line 53
    :goto_1
    return-object v0

    .line 54
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 55
    .line 56
    iget v1, p0, Lc90/h0;->e:I

    .line 57
    .line 58
    iget-object v2, p0, Lc90/h0;->f:Lc90/j0;

    .line 59
    .line 60
    const/4 v3, 0x1

    .line 61
    const/4 v4, 0x2

    .line 62
    if-eqz v1, :cond_5

    .line 63
    .line 64
    if-eq v1, v3, :cond_4

    .line 65
    .line 66
    if-ne v1, v4, :cond_3

    .line 67
    .line 68
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 73
    .line 74
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 75
    .line 76
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw p0

    .line 80
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    iget-object p1, v2, Lc90/j0;->h:Lfo0/b;

    .line 88
    .line 89
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    check-cast p1, Lyy0/i;

    .line 94
    .line 95
    new-instance v1, Lb40/a;

    .line 96
    .line 97
    const/4 v5, 0x3

    .line 98
    const/4 v6, 0x0

    .line 99
    invoke-direct {v1, v4, v6, v5}, Lb40/a;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 100
    .line 101
    .line 102
    iput v3, p0, Lc90/h0;->e:I

    .line 103
    .line 104
    invoke-static {p1, v1, p0}, Lyy0/u;->v(Lyy0/i;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    if-ne p1, v0, :cond_6

    .line 109
    .line 110
    goto :goto_4

    .line 111
    :cond_6
    :goto_2
    check-cast p1, Lgo0/c;

    .line 112
    .line 113
    if-eqz p1, :cond_7

    .line 114
    .line 115
    iget-object p1, v2, Lc90/j0;->i:Lfo0/c;

    .line 116
    .line 117
    new-instance v1, Lgo0/a;

    .line 118
    .line 119
    const v2, 0x7f110219

    .line 120
    .line 121
    .line 122
    invoke-direct {v1, v2}, Lgo0/a;-><init>(I)V

    .line 123
    .line 124
    .line 125
    iput v4, p0, Lc90/h0;->e:I

    .line 126
    .line 127
    invoke-virtual {p1, v1}, Lfo0/c;->b(Lgo0/a;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    if-ne p0, v0, :cond_7

    .line 132
    .line 133
    goto :goto_4

    .line 134
    :cond_7
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 135
    .line 136
    :goto_4
    return-object v0

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
