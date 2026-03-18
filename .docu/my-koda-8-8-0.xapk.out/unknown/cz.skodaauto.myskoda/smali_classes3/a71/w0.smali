.class public final La71/w0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh2/m0;

.field public final synthetic g:F

.field public final synthetic h:J

.field public final synthetic i:Ll2/b1;

.field public final synthetic j:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lh2/m0;FJLl2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p8, p0, La71/w0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La71/w0;->f:Lh2/m0;

    .line 4
    .line 5
    iput p2, p0, La71/w0;->g:F

    .line 6
    .line 7
    iput-wide p3, p0, La71/w0;->h:J

    .line 8
    .line 9
    iput-object p5, p0, La71/w0;->i:Ll2/b1;

    .line 10
    .line 11
    iput-object p6, p0, La71/w0;->j:Ll2/b1;

    .line 12
    .line 13
    const/4 p1, 0x2

    .line 14
    invoke-direct {p0, p1, p7}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 10

    .line 1
    iget p1, p0, La71/w0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, La71/w0;

    .line 7
    .line 8
    iget-object v6, p0, La71/w0;->j:Ll2/b1;

    .line 9
    .line 10
    const/4 v8, 0x1

    .line 11
    iget-object v1, p0, La71/w0;->f:Lh2/m0;

    .line 12
    .line 13
    iget v2, p0, La71/w0;->g:F

    .line 14
    .line 15
    iget-wide v3, p0, La71/w0;->h:J

    .line 16
    .line 17
    iget-object v5, p0, La71/w0;->i:Ll2/b1;

    .line 18
    .line 19
    move-object v7, p2

    .line 20
    invoke-direct/range {v0 .. v8}, La71/w0;-><init>(Lh2/m0;FJLl2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object v0

    .line 24
    :pswitch_0
    move-object v7, p2

    .line 25
    new-instance v1, La71/w0;

    .line 26
    .line 27
    move-object v8, v7

    .line 28
    iget-object v7, p0, La71/w0;->j:Ll2/b1;

    .line 29
    .line 30
    const/4 v9, 0x0

    .line 31
    iget-object v2, p0, La71/w0;->f:Lh2/m0;

    .line 32
    .line 33
    iget v3, p0, La71/w0;->g:F

    .line 34
    .line 35
    iget-wide v4, p0, La71/w0;->h:J

    .line 36
    .line 37
    iget-object v6, p0, La71/w0;->i:Ll2/b1;

    .line 38
    .line 39
    invoke-direct/range {v1 .. v9}, La71/w0;-><init>(Lh2/m0;FJLl2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    return-object v1

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, La71/w0;->d:I

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
    invoke-virtual {p0, p1, p2}, La71/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, La71/w0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, La71/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, La71/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, La71/w0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, La71/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 13

    .line 1
    iget v0, p0, La71/w0;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 12
    .line 13
    iget v4, p0, La71/w0;->e:I

    .line 14
    .line 15
    if-eqz v4, :cond_1

    .line 16
    .line 17
    if-ne v4, v3, :cond_0

    .line 18
    .line 19
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    sget-object p1, Lvy0/p0;->a:Lcz0/e;

    .line 33
    .line 34
    sget-object p1, Laz0/m;->a:Lwy0/c;

    .line 35
    .line 36
    new-instance v4, La71/w0;

    .line 37
    .line 38
    const/4 v11, 0x0

    .line 39
    const/4 v12, 0x0

    .line 40
    iget-object v5, p0, La71/w0;->f:Lh2/m0;

    .line 41
    .line 42
    iget v6, p0, La71/w0;->g:F

    .line 43
    .line 44
    iget-wide v7, p0, La71/w0;->h:J

    .line 45
    .line 46
    iget-object v9, p0, La71/w0;->i:Ll2/b1;

    .line 47
    .line 48
    iget-object v10, p0, La71/w0;->j:Ll2/b1;

    .line 49
    .line 50
    invoke-direct/range {v4 .. v12}, La71/w0;-><init>(Lh2/m0;FJLl2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 51
    .line 52
    .line 53
    iput v3, p0, La71/w0;->e:I

    .line 54
    .line 55
    invoke-static {p1, v4, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    if-ne p0, v0, :cond_2

    .line 60
    .line 61
    move-object v1, v0

    .line 62
    :cond_2
    :goto_0
    return-object v1

    .line 63
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 64
    .line 65
    iget v4, p0, La71/w0;->e:I

    .line 66
    .line 67
    if-eqz v4, :cond_4

    .line 68
    .line 69
    if-ne v4, v3, :cond_3

    .line 70
    .line 71
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 76
    .line 77
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iget-object p1, p0, La71/w0;->f:Lh2/m0;

    .line 85
    .line 86
    iget-object p1, p1, Lh2/m0;->a:Lh2/r8;

    .line 87
    .line 88
    iput v3, p0, La71/w0;->e:I

    .line 89
    .line 90
    invoke-virtual {p1, p0}, Lh2/r8;->d(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    if-ne p1, v0, :cond_5

    .line 95
    .line 96
    move-object v1, v0

    .line 97
    goto :goto_2

    .line 98
    :cond_5
    :goto_1
    new-instance p1, Lt4/f;

    .line 99
    .line 100
    iget v0, p0, La71/w0;->g:F

    .line 101
    .line 102
    invoke-direct {p1, v0}, Lt4/f;-><init>(F)V

    .line 103
    .line 104
    .line 105
    iget-object v0, p0, La71/w0;->i:Ll2/b1;

    .line 106
    .line 107
    invoke-interface {v0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    new-instance p1, Le3/s;

    .line 111
    .line 112
    iget-wide v2, p0, La71/w0;->h:J

    .line 113
    .line 114
    invoke-direct {p1, v2, v3}, Le3/s;-><init>(J)V

    .line 115
    .line 116
    .line 117
    iget-object p0, p0, La71/w0;->j:Ll2/b1;

    .line 118
    .line 119
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    :goto_2
    return-object v1

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
