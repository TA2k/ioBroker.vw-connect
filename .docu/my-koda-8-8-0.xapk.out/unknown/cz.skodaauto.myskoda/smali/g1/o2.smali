.class public final Lg1/o2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;FFLkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Lg1/o2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg1/o2;->h:Ljava/lang/Object;

    .line 4
    .line 5
    iput p2, p0, Lg1/o2;->f:F

    .line 6
    .line 7
    iput p3, p0, Lg1/o2;->g:F

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    iget p1, p0, Lg1/o2;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lg1/o2;

    .line 7
    .line 8
    iget-object p1, p0, Lg1/o2;->h:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lc1/c;

    .line 12
    .line 13
    iget v3, p0, Lg1/o2;->g:F

    .line 14
    .line 15
    const/4 v5, 0x1

    .line 16
    iget v2, p0, Lg1/o2;->f:F

    .line 17
    .line 18
    move-object v4, p2

    .line 19
    invoke-direct/range {v0 .. v5}, Lg1/o2;-><init>(Ljava/lang/Object;FFLkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    return-object v0

    .line 23
    :pswitch_0
    move-object v4, p2

    .line 24
    new-instance v1, Lg1/o2;

    .line 25
    .line 26
    iget-object p1, p0, Lg1/o2;->h:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v2, p1

    .line 29
    check-cast v2, Lg1/p2;

    .line 30
    .line 31
    move-object v5, v4

    .line 32
    iget v4, p0, Lg1/o2;->g:F

    .line 33
    .line 34
    const/4 v6, 0x0

    .line 35
    iget v3, p0, Lg1/o2;->f:F

    .line 36
    .line 37
    invoke-direct/range {v1 .. v6}, Lg1/o2;-><init>(Ljava/lang/Object;FFLkotlin/coroutines/Continuation;I)V

    .line 38
    .line 39
    .line 40
    return-object v1

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lg1/o2;->d:I

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
    invoke-virtual {p0, p1, p2}, Lg1/o2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg1/o2;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg1/o2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lg1/o2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lg1/o2;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lg1/o2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lg1/o2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lg1/o2;->e:I

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
    iget-object p1, p0, Lg1/o2;->h:Ljava/lang/Object;

    .line 31
    .line 32
    move-object v3, p1

    .line 33
    check-cast v3, Lc1/c;

    .line 34
    .line 35
    iget p1, p0, Lg1/o2;->f:F

    .line 36
    .line 37
    iget v1, p0, Lg1/o2;->g:F

    .line 38
    .line 39
    invoke-static {p1, v1}, Ljava/lang/Math;->max(FF)F

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    new-instance v4, Ljava/lang/Float;

    .line 44
    .line 45
    invoke-direct {v4, p1}, Ljava/lang/Float;-><init>(F)V

    .line 46
    .line 47
    .line 48
    const/4 p1, 0x7

    .line 49
    const/4 v1, 0x0

    .line 50
    const/4 v5, 0x0

    .line 51
    invoke-static {v1, v1, v5, p1}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 52
    .line 53
    .line 54
    move-result-object v5

    .line 55
    iput v2, p0, Lg1/o2;->e:I

    .line 56
    .line 57
    const/4 v6, 0x0

    .line 58
    const/4 v7, 0x0

    .line 59
    const/16 v9, 0xc

    .line 60
    .line 61
    move-object v8, p0

    .line 62
    invoke-static/range {v3 .. v9}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    if-ne p0, v0, :cond_2

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    :goto_1
    return-object v0

    .line 72
    :pswitch_0
    move-object v8, p0

    .line 73
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 74
    .line 75
    iget v0, v8, Lg1/o2;->e:I

    .line 76
    .line 77
    const/4 v1, 0x1

    .line 78
    if-eqz v0, :cond_4

    .line 79
    .line 80
    if-ne v0, v1, :cond_3

    .line 81
    .line 82
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 87
    .line 88
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 89
    .line 90
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw p0

    .line 94
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    iget-object p1, v8, Lg1/o2;->h:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p1, Lg1/p2;

    .line 100
    .line 101
    iget-object p1, p1, Lg1/p2;->H:Lg1/u2;

    .line 102
    .line 103
    iget v0, v8, Lg1/o2;->f:F

    .line 104
    .line 105
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    int-to-long v2, v0

    .line 110
    iget v0, v8, Lg1/o2;->g:F

    .line 111
    .line 112
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    int-to-long v4, v0

    .line 117
    const/16 v0, 0x20

    .line 118
    .line 119
    shl-long/2addr v2, v0

    .line 120
    const-wide v6, 0xffffffffL

    .line 121
    .line 122
    .line 123
    .line 124
    .line 125
    and-long/2addr v4, v6

    .line 126
    or-long/2addr v2, v4

    .line 127
    iput v1, v8, Lg1/o2;->e:I

    .line 128
    .line 129
    invoke-static {p1, v2, v3, v8}, Landroidx/compose/foundation/gestures/b;->a(Lg1/u2;JLrx0/c;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    if-ne p1, p0, :cond_5

    .line 134
    .line 135
    goto :goto_3

    .line 136
    :cond_5
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 137
    .line 138
    :goto_3
    return-object p0

    .line 139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
