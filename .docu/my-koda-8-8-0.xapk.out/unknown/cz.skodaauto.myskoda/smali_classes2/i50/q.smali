.class public final Li50/q;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc1/c;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(IILc1/c;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p2, p0, Li50/q;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Li50/q;->f:Lc1/c;

    .line 4
    .line 5
    iput p1, p0, Li50/q;->g:I

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
    .locals 2

    .line 1
    iget p1, p0, Li50/q;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Li50/q;

    .line 7
    .line 8
    iget v0, p0, Li50/q;->g:I

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Li50/q;->f:Lc1/c;

    .line 12
    .line 13
    invoke-direct {p1, v0, v1, p0, p2}, Li50/q;-><init>(IILc1/c;Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Li50/q;

    .line 18
    .line 19
    iget v0, p0, Li50/q;->g:I

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Li50/q;->f:Lc1/c;

    .line 23
    .line 24
    invoke-direct {p1, v0, v1, p0, p2}, Li50/q;-><init>(IILc1/c;Lkotlin/coroutines/Continuation;)V

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
    iget v0, p0, Li50/q;->d:I

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
    invoke-virtual {p0, p1, p2}, Li50/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Li50/q;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Li50/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Li50/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Li50/q;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Li50/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Li50/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Li50/q;->e:I

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
    move p1, v2

    .line 31
    new-instance v2, Ljava/lang/Float;

    .line 32
    .line 33
    const/high16 v1, 0x3f800000    # 1.0f

    .line 34
    .line 35
    invoke-direct {v2, v1}, Ljava/lang/Float;-><init>(F)V

    .line 36
    .line 37
    .line 38
    iget v1, p0, Li50/q;->g:I

    .line 39
    .line 40
    add-int/2addr v1, p1

    .line 41
    mul-int/lit16 v1, v1, 0x1f4

    .line 42
    .line 43
    sget-object v3, Lc1/x;->a:Lc1/s;

    .line 44
    .line 45
    move-object v4, v3

    .line 46
    new-instance v3, Lc1/a2;

    .line 47
    .line 48
    const/16 v5, 0x96

    .line 49
    .line 50
    invoke-direct {v3, v5, v1, v4}, Lc1/a2;-><init>(IILc1/w;)V

    .line 51
    .line 52
    .line 53
    iput p1, p0, Li50/q;->e:I

    .line 54
    .line 55
    iget-object v1, p0, Li50/q;->f:Lc1/c;

    .line 56
    .line 57
    const/4 v4, 0x0

    .line 58
    const/4 v5, 0x0

    .line 59
    const/16 v7, 0xc

    .line 60
    .line 61
    move-object v6, p0

    .line 62
    invoke-static/range {v1 .. v7}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

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
    move-object v6, p0

    .line 73
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 74
    .line 75
    iget v0, v6, Li50/q;->e:I

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
    new-instance v2, Ljava/lang/Float;

    .line 98
    .line 99
    const/high16 p1, 0x3f800000    # 1.0f

    .line 100
    .line 101
    invoke-direct {v2, p1}, Ljava/lang/Float;-><init>(F)V

    .line 102
    .line 103
    .line 104
    iget p1, v6, Li50/q;->g:I

    .line 105
    .line 106
    add-int/2addr p1, v1

    .line 107
    mul-int/lit16 p1, p1, 0xc8

    .line 108
    .line 109
    sget-object v0, Lc1/x;->a:Lc1/s;

    .line 110
    .line 111
    new-instance v3, Lc1/a2;

    .line 112
    .line 113
    const/16 v4, 0x15e

    .line 114
    .line 115
    invoke-direct {v3, v4, p1, v0}, Lc1/a2;-><init>(IILc1/w;)V

    .line 116
    .line 117
    .line 118
    iput v1, v6, Li50/q;->e:I

    .line 119
    .line 120
    iget-object v1, v6, Li50/q;->f:Lc1/c;

    .line 121
    .line 122
    const/4 v4, 0x0

    .line 123
    const/4 v5, 0x0

    .line 124
    const/16 v7, 0xc

    .line 125
    .line 126
    invoke-static/range {v1 .. v7}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    if-ne p1, p0, :cond_5

    .line 131
    .line 132
    goto :goto_3

    .line 133
    :cond_5
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 134
    .line 135
    :goto_3
    return-object p0

    .line 136
    nop

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
