.class public final Lh2/w2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lm1/t;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(IILkotlin/coroutines/Continuation;Lm1/t;)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/w2;->d:I

    .line 2
    .line 3
    iput-object p4, p0, Lh2/w2;->f:Lm1/t;

    .line 4
    .line 5
    iput p1, p0, Lh2/w2;->g:I

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
    iget p1, p0, Lh2/w2;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh2/w2;

    .line 7
    .line 8
    iget v0, p0, Lh2/w2;->g:I

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lh2/w2;->f:Lm1/t;

    .line 12
    .line 13
    invoke-direct {p1, v0, v1, p2, p0}, Lh2/w2;-><init>(IILkotlin/coroutines/Continuation;Lm1/t;)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lh2/w2;

    .line 18
    .line 19
    iget v0, p0, Lh2/w2;->g:I

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lh2/w2;->f:Lm1/t;

    .line 23
    .line 24
    invoke-direct {p1, v0, v1, p2, p0}, Lh2/w2;-><init>(IILkotlin/coroutines/Continuation;Lm1/t;)V

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
    iget v0, p0, Lh2/w2;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh2/w2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh2/w2;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh2/w2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh2/w2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh2/w2;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh2/w2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 4

    .line 1
    iget v0, p0, Lh2/w2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lh2/w2;->e:I

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
    iget-object p1, p0, Lh2/w2;->f:Lm1/t;

    .line 31
    .line 32
    iget-object v1, p1, Lm1/t;->e:Lm1/o;

    .line 33
    .line 34
    iget-object v1, v1, Lm1/o;->b:Ll2/g1;

    .line 35
    .line 36
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    iget v3, p0, Lh2/w2;->g:I

    .line 41
    .line 42
    if-eq v1, v3, :cond_2

    .line 43
    .line 44
    iput v2, p0, Lh2/w2;->e:I

    .line 45
    .line 46
    invoke-static {p1, v3, p0}, Lm1/t;->j(Lm1/t;ILrx0/i;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    if-ne p0, v0, :cond_2

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    :goto_1
    return-object v0

    .line 56
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 57
    .line 58
    iget v1, p0, Lh2/w2;->e:I

    .line 59
    .line 60
    const/4 v2, 0x1

    .line 61
    if-eqz v1, :cond_4

    .line 62
    .line 63
    if-ne v1, v2, :cond_3

    .line 64
    .line 65
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 72
    .line 73
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    iget-object p1, p0, Lh2/w2;->f:Lm1/t;

    .line 81
    .line 82
    iget-object v1, p1, Lm1/t;->i:Lg1/f0;

    .line 83
    .line 84
    invoke-virtual {v1}, Lg1/f0;->a()Z

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    if-nez v1, :cond_5

    .line 89
    .line 90
    iget-object v1, p1, Lm1/t;->e:Lm1/o;

    .line 91
    .line 92
    iget-object v1, v1, Lm1/o;->b:Ll2/g1;

    .line 93
    .line 94
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    iget v3, p0, Lh2/w2;->g:I

    .line 99
    .line 100
    if-eq v1, v3, :cond_5

    .line 101
    .line 102
    iput v2, p0, Lh2/w2;->e:I

    .line 103
    .line 104
    invoke-static {p1, v3, p0}, Lm1/t;->j(Lm1/t;ILrx0/i;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    if-ne p0, v0, :cond_5

    .line 109
    .line 110
    goto :goto_3

    .line 111
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 112
    .line 113
    :goto_3
    return-object v0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
