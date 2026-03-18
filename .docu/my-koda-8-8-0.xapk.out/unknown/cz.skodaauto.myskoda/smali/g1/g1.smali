.class public final Lg1/g1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lg1/h1;

.field public final synthetic h:J


# direct methods
.method public synthetic constructor <init>(Lg1/h1;JLkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Lg1/g1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg1/g1;->g:Lg1/h1;

    .line 4
    .line 5
    iput-wide p2, p0, Lg1/g1;->h:J

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget v0, p0, Lg1/g1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lg1/g1;

    .line 7
    .line 8
    iget-wide v3, p0, Lg1/g1;->h:J

    .line 9
    .line 10
    const/4 v6, 0x1

    .line 11
    iget-object v2, p0, Lg1/g1;->g:Lg1/h1;

    .line 12
    .line 13
    move-object v5, p2

    .line 14
    invoke-direct/range {v1 .. v6}, Lg1/g1;-><init>(Lg1/h1;JLkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, v1, Lg1/g1;->f:Ljava/lang/Object;

    .line 18
    .line 19
    return-object v1

    .line 20
    :pswitch_0
    move-object v5, p2

    .line 21
    new-instance v2, Lg1/g1;

    .line 22
    .line 23
    move-object v6, v5

    .line 24
    iget-wide v4, p0, Lg1/g1;->h:J

    .line 25
    .line 26
    const/4 v7, 0x0

    .line 27
    iget-object v3, p0, Lg1/g1;->g:Lg1/h1;

    .line 28
    .line 29
    invoke-direct/range {v2 .. v7}, Lg1/g1;-><init>(Lg1/h1;JLkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    iput-object p1, v2, Lg1/g1;->f:Ljava/lang/Object;

    .line 33
    .line 34
    return-object v2

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lg1/g1;->d:I

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
    invoke-virtual {p0, p1, p2}, Lg1/g1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg1/g1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg1/g1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lg1/g1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lg1/g1;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lg1/g1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 8

    .line 1
    iget v0, p0, Lg1/g1;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-wide v2, p0, Lg1/g1;->h:J

    .line 6
    .line 7
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 8
    .line 9
    const/4 v5, 0x1

    .line 10
    iget-object v6, p0, Lg1/g1;->g:Lg1/h1;

    .line 11
    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    iget v7, p0, Lg1/g1;->e:I

    .line 18
    .line 19
    if-eqz v7, :cond_1

    .line 20
    .line 21
    if-ne v7, v5, :cond_0

    .line 22
    .line 23
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    goto :goto_3

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, p0, Lg1/g1;->f:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p1, Lvy0/b0;

    .line 39
    .line 40
    iget-object v4, v6, Lg1/h1;->G:Lay0/o;

    .line 41
    .line 42
    iget-boolean v7, v6, Lg1/h1;->H:Z

    .line 43
    .line 44
    if-eqz v7, :cond_2

    .line 45
    .line 46
    const/high16 v7, -0x40800000    # -1.0f

    .line 47
    .line 48
    :goto_0
    invoke-static {v2, v3, v7}, Lt4/q;->f(JF)J

    .line 49
    .line 50
    .line 51
    move-result-wide v2

    .line 52
    goto :goto_1

    .line 53
    :cond_2
    const/high16 v7, 0x3f800000    # 1.0f

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :goto_1
    iget-object v6, v6, Lg1/h1;->D:Lg1/w1;

    .line 57
    .line 58
    sget-object v7, Lg1/f1;->a:Lg1/e1;

    .line 59
    .line 60
    sget-object v7, Lg1/w1;->d:Lg1/w1;

    .line 61
    .line 62
    if-ne v6, v7, :cond_3

    .line 63
    .line 64
    invoke-static {v2, v3}, Lt4/q;->c(J)F

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    goto :goto_2

    .line 69
    :cond_3
    invoke-static {v2, v3}, Lt4/q;->b(J)F

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    :goto_2
    new-instance v3, Ljava/lang/Float;

    .line 74
    .line 75
    invoke-direct {v3, v2}, Ljava/lang/Float;-><init>(F)V

    .line 76
    .line 77
    .line 78
    iput v5, p0, Lg1/g1;->e:I

    .line 79
    .line 80
    invoke-interface {v4, p1, v3, p0}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    if-ne p0, v0, :cond_4

    .line 85
    .line 86
    move-object v1, v0

    .line 87
    :cond_4
    :goto_3
    return-object v1

    .line 88
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 89
    .line 90
    iget v7, p0, Lg1/g1;->e:I

    .line 91
    .line 92
    if-eqz v7, :cond_6

    .line 93
    .line 94
    if-ne v7, v5, :cond_5

    .line 95
    .line 96
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    goto :goto_4

    .line 100
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 101
    .line 102
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    throw p0

    .line 106
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    iget-object p1, p0, Lg1/g1;->f:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast p1, Lvy0/b0;

    .line 112
    .line 113
    iget-object v4, v6, Lg1/h1;->F:Lay0/o;

    .line 114
    .line 115
    new-instance v6, Ld3/b;

    .line 116
    .line 117
    invoke-direct {v6, v2, v3}, Ld3/b;-><init>(J)V

    .line 118
    .line 119
    .line 120
    iput v5, p0, Lg1/g1;->e:I

    .line 121
    .line 122
    invoke-interface {v4, p1, v6, p0}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    if-ne p0, v0, :cond_7

    .line 127
    .line 128
    move-object v1, v0

    .line 129
    :cond_7
    :goto_4
    return-object v1

    .line 130
    nop

    .line 131
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
