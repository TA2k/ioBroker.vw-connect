.class public final Lb2/a;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic e:I

.field public f:I

.field public synthetic g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;

.field public i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lb2/a;->e:I

    iput-object p2, p0, Lb2/a;->h:Ljava/lang/Object;

    iput-object p3, p0, Lb2/a;->i:Ljava/lang/Object;

    iput-object p4, p0, Lb2/a;->j:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lay0/k;Lay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lb2/a;->e:I

    .line 2
    iput-object p1, p0, Lb2/a;->i:Ljava/lang/Object;

    iput-object p2, p0, Lb2/a;->j:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 3
    iput p3, p0, Lb2/a;->e:I

    iput-object p1, p0, Lb2/a;->j:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lvy0/b0;Lh2/yb;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lb2/a;->e:I

    .line 4
    iput-object p1, p0, Lb2/a;->h:Ljava/lang/Object;

    iput-object p2, p0, Lb2/a;->j:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget v0, p0, Lb2/a;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lb2/a;

    .line 7
    .line 8
    iget-object v0, p0, Lb2/a;->h:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v3, v0

    .line 11
    check-cast v3, Lg1/z1;

    .line 12
    .line 13
    iget-object v0, p0, Lb2/a;->i:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v4, v0

    .line 16
    check-cast v4, Lb1/e;

    .line 17
    .line 18
    iget-object p0, p0, Lb2/a;->j:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v5, p0

    .line 21
    check-cast v5, Lkotlin/jvm/internal/f0;

    .line 22
    .line 23
    const/4 v2, 0x6

    .line 24
    move-object v6, p2

    .line 25
    invoke-direct/range {v1 .. v6}, Lb2/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    iput-object p1, v1, Lb2/a;->g:Ljava/lang/Object;

    .line 29
    .line 30
    return-object v1

    .line 31
    :pswitch_0
    move-object v6, p2

    .line 32
    new-instance p2, Lb2/a;

    .line 33
    .line 34
    iget-object p0, p0, Lb2/a;->j:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Lvy0/p1;

    .line 37
    .line 38
    const/4 v0, 0x5

    .line 39
    invoke-direct {p2, p0, v6, v0}, Lb2/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    iput-object p1, p2, Lb2/a;->g:Ljava/lang/Object;

    .line 43
    .line 44
    return-object p2

    .line 45
    :pswitch_1
    move-object v6, p2

    .line 46
    new-instance p2, Lb2/a;

    .line 47
    .line 48
    iget-object p0, p0, Lb2/a;->j:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p0, Lp1/v;

    .line 51
    .line 52
    const/4 v0, 0x4

    .line 53
    invoke-direct {p2, p0, v6, v0}, Lb2/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 54
    .line 55
    .line 56
    iput-object p1, p2, Lb2/a;->g:Ljava/lang/Object;

    .line 57
    .line 58
    return-object p2

    .line 59
    :pswitch_2
    move-object v6, p2

    .line 60
    new-instance p2, Lb2/a;

    .line 61
    .line 62
    iget-object v0, p0, Lb2/a;->i:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v0, Lay0/k;

    .line 65
    .line 66
    iget-object p0, p0, Lb2/a;->j:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p0, Lay0/k;

    .line 69
    .line 70
    invoke-direct {p2, v0, p0, v6}, Lb2/a;-><init>(Lay0/k;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 71
    .line 72
    .line 73
    iput-object p1, p2, Lb2/a;->g:Ljava/lang/Object;

    .line 74
    .line 75
    return-object p2

    .line 76
    :pswitch_3
    move-object v6, p2

    .line 77
    new-instance p2, Lb2/a;

    .line 78
    .line 79
    iget-object v0, p0, Lb2/a;->h:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v0, Lvy0/b0;

    .line 82
    .line 83
    iget-object p0, p0, Lb2/a;->j:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast p0, Lh2/yb;

    .line 86
    .line 87
    invoke-direct {p2, v0, p0, v6}, Lb2/a;-><init>(Lvy0/b0;Lh2/yb;Lkotlin/coroutines/Continuation;)V

    .line 88
    .line 89
    .line 90
    iput-object p1, p2, Lb2/a;->g:Ljava/lang/Object;

    .line 91
    .line 92
    return-object p2

    .line 93
    :pswitch_4
    move-object v6, p2

    .line 94
    new-instance v2, Lb2/a;

    .line 95
    .line 96
    iget-object p2, p0, Lb2/a;->h:Ljava/lang/Object;

    .line 97
    .line 98
    move-object v4, p2

    .line 99
    check-cast v4, Lcom/google/android/gms/internal/measurement/i4;

    .line 100
    .line 101
    iget-object p2, p0, Lb2/a;->i:Ljava/lang/Object;

    .line 102
    .line 103
    move-object v5, p2

    .line 104
    check-cast v5, Lbb/g0;

    .line 105
    .line 106
    iget-object p0, p0, Lb2/a;->j:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast p0, Lt1/w0;

    .line 109
    .line 110
    const/4 v3, 0x1

    .line 111
    move-object v7, v6

    .line 112
    move-object v6, p0

    .line 113
    invoke-direct/range {v2 .. v7}, Lb2/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 114
    .line 115
    .line 116
    iput-object p1, v2, Lb2/a;->g:Ljava/lang/Object;

    .line 117
    .line 118
    return-object v2

    .line 119
    :pswitch_5
    move-object v6, p2

    .line 120
    new-instance p2, Lb2/a;

    .line 121
    .line 122
    iget-object p0, p0, Lb2/a;->j:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast p0, Lb2/c;

    .line 125
    .line 126
    const/4 v0, 0x0

    .line 127
    invoke-direct {p2, p0, v6, v0}, Lb2/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 128
    .line 129
    .line 130
    iput-object p1, p2, Lb2/a;->g:Ljava/lang/Object;

    .line 131
    .line 132
    return-object p2

    .line 133
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lb2/a;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lp3/i0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lb2/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lb2/a;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lb2/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lky0/k;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lb2/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lb2/a;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lb2/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lp3/i0;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lb2/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lb2/a;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lb2/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p1, Lp3/i0;

    .line 58
    .line 59
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2}, Lb2/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lb2/a;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lb2/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_3
    check-cast p1, Lp3/i0;

    .line 75
    .line 76
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 77
    .line 78
    invoke-virtual {p0, p1, p2}, Lb2/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Lb2/a;

    .line 83
    .line 84
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    invoke-virtual {p0, p1}, Lb2/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 90
    .line 91
    return-object p0

    .line 92
    :pswitch_4
    check-cast p1, Lp3/i0;

    .line 93
    .line 94
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 95
    .line 96
    invoke-virtual {p0, p1, p2}, Lb2/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    check-cast p0, Lb2/a;

    .line 101
    .line 102
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 103
    .line 104
    invoke-virtual {p0, p1}, Lb2/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    return-object p0

    .line 109
    :pswitch_5
    check-cast p1, Lp3/i0;

    .line 110
    .line 111
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 112
    .line 113
    invoke-virtual {p0, p1, p2}, Lb2/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    check-cast p0, Lb2/a;

    .line 118
    .line 119
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 120
    .line 121
    invoke-virtual {p0, p1}, Lb2/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    return-object p0

    .line 126
    nop

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lb2/a;->e:I

    .line 4
    .line 5
    const/4 v2, 0x4

    .line 6
    const/4 v3, 0x3

    .line 7
    const/4 v4, 0x0

    .line 8
    const/4 v5, 0x2

    .line 9
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    const/4 v7, 0x0

    .line 12
    iget-object v8, v0, Lb2/a;->j:Ljava/lang/Object;

    .line 13
    .line 14
    const-string v9, "call to \'resume\' before \'invoke\' with coroutine"

    .line 15
    .line 16
    const/4 v10, 0x1

    .line 17
    packed-switch v1, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    iget-object v1, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v1, Lg1/z1;

    .line 23
    .line 24
    iget-object v2, v1, Lg1/z1;->h:Lez0/c;

    .line 25
    .line 26
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 27
    .line 28
    iget v4, v0, Lb2/a;->f:I

    .line 29
    .line 30
    if-eqz v4, :cond_1

    .line 31
    .line 32
    if-ne v4, v10, :cond_0

    .line 33
    .line 34
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    move-object/from16 v4, p1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    invoke-direct {v0, v9}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw v0

    .line 46
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    iget-object v4, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v4, Lp3/i0;

    .line 52
    .line 53
    iput v10, v0, Lb2/a;->f:I

    .line 54
    .line 55
    invoke-static {v4, v0}, Lyv/e;->b(Lp3/i0;Lrx0/a;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    if-ne v4, v3, :cond_2

    .line 60
    .line 61
    move-object v6, v3

    .line 62
    goto :goto_1

    .line 63
    :cond_2
    :goto_0
    check-cast v4, Lp3/t;

    .line 64
    .line 65
    if-nez v4, :cond_4

    .line 66
    .line 67
    iput-boolean v10, v1, Lg1/z1;->g:Z

    .line 68
    .line 69
    invoke-virtual {v2, v7}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    iget-object v0, v0, Lb2/a;->i:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v0, Lb1/e;

    .line 75
    .line 76
    check-cast v8, Lkotlin/jvm/internal/f0;

    .line 77
    .line 78
    iget-object v1, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v1, Lp3/t;

    .line 81
    .line 82
    iget-wide v1, v1, Lp3/t;->c:J

    .line 83
    .line 84
    iget-object v3, v0, Lb1/e;->g:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast v3, Ll2/b1;

    .line 87
    .line 88
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    check-cast v3, Lg4/l0;

    .line 93
    .line 94
    if-eqz v3, :cond_3

    .line 95
    .line 96
    iget-object v0, v0, Lb1/e;->h:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, Lkotlin/jvm/internal/n;

    .line 99
    .line 100
    iget-object v3, v3, Lg4/l0;->b:Lg4/o;

    .line 101
    .line 102
    invoke-virtual {v3, v1, v2}, Lg4/o;->g(J)I

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    :cond_3
    :goto_1
    return-object v6

    .line 114
    :cond_4
    invoke-virtual {v4}, Lp3/t;->a()V

    .line 115
    .line 116
    .line 117
    iput-boolean v10, v1, Lg1/z1;->f:Z

    .line 118
    .line 119
    invoke-virtual {v2, v7}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    throw v7

    .line 123
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 124
    .line 125
    iget v2, v0, Lb2/a;->f:I

    .line 126
    .line 127
    if-eqz v2, :cond_7

    .line 128
    .line 129
    if-eq v2, v10, :cond_6

    .line 130
    .line 131
    if-ne v2, v5, :cond_5

    .line 132
    .line 133
    iget-object v2, v0, Lb2/a;->i:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v2, Lvy0/p;

    .line 136
    .line 137
    iget-object v3, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast v3, Lvy0/s1;

    .line 140
    .line 141
    iget-object v4, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast v4, Lky0/k;

    .line 144
    .line 145
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    goto :goto_4

    .line 149
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 150
    .line 151
    invoke-direct {v0, v9}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    throw v0

    .line 155
    :cond_6
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    goto :goto_5

    .line 159
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    iget-object v2, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast v2, Lky0/k;

    .line 165
    .line 166
    check-cast v8, Lvy0/p1;

    .line 167
    .line 168
    sget-object v3, Lvy0/p1;->d:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 169
    .line 170
    invoke-virtual {v3, v8}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    instance-of v4, v3, Lvy0/p;

    .line 175
    .line 176
    if-eqz v4, :cond_8

    .line 177
    .line 178
    check-cast v3, Lvy0/p;

    .line 179
    .line 180
    iget-object v3, v3, Lvy0/p;->h:Lvy0/p1;

    .line 181
    .line 182
    iput v10, v0, Lb2/a;->f:I

    .line 183
    .line 184
    invoke-virtual {v2, v3, v0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 185
    .line 186
    .line 187
    :goto_2
    move-object v6, v1

    .line 188
    goto :goto_5

    .line 189
    :cond_8
    instance-of v4, v3, Lvy0/e1;

    .line 190
    .line 191
    if-eqz v4, :cond_a

    .line 192
    .line 193
    check-cast v3, Lvy0/e1;

    .line 194
    .line 195
    invoke-interface {v3}, Lvy0/e1;->c()Lvy0/s1;

    .line 196
    .line 197
    .line 198
    move-result-object v3

    .line 199
    if-eqz v3, :cond_a

    .line 200
    .line 201
    sget-object v4, Laz0/i;->d:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 202
    .line 203
    invoke-virtual {v4, v3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v4

    .line 207
    const-string v7, "null cannot be cast to non-null type kotlinx.coroutines.internal.LockFreeLinkedListNode"

    .line 208
    .line 209
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    check-cast v4, Laz0/i;

    .line 213
    .line 214
    move-object/from16 v20, v4

    .line 215
    .line 216
    move-object v4, v2

    .line 217
    move-object/from16 v2, v20

    .line 218
    .line 219
    :goto_3
    invoke-virtual {v2, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    move-result v7

    .line 223
    if-nez v7, :cond_a

    .line 224
    .line 225
    instance-of v7, v2, Lvy0/p;

    .line 226
    .line 227
    if-eqz v7, :cond_9

    .line 228
    .line 229
    check-cast v2, Lvy0/p;

    .line 230
    .line 231
    iget-object v6, v2, Lvy0/p;->h:Lvy0/p1;

    .line 232
    .line 233
    iput-object v4, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 234
    .line 235
    iput-object v3, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 236
    .line 237
    iput-object v2, v0, Lb2/a;->i:Ljava/lang/Object;

    .line 238
    .line 239
    iput v5, v0, Lb2/a;->f:I

    .line 240
    .line 241
    invoke-virtual {v4, v6, v0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 242
    .line 243
    .line 244
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 245
    .line 246
    goto :goto_2

    .line 247
    :cond_9
    :goto_4
    invoke-virtual {v2}, Laz0/i;->g()Laz0/i;

    .line 248
    .line 249
    .line 250
    move-result-object v2

    .line 251
    goto :goto_3

    .line 252
    :cond_a
    :goto_5
    return-object v6

    .line 253
    :pswitch_1
    check-cast v8, Lp1/v;

    .line 254
    .line 255
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 256
    .line 257
    iget v2, v0, Lb2/a;->f:I

    .line 258
    .line 259
    if-eqz v2, :cond_d

    .line 260
    .line 261
    if-eq v2, v10, :cond_c

    .line 262
    .line 263
    if-ne v2, v5, :cond_b

    .line 264
    .line 265
    iget-object v2, v0, Lb2/a;->i:Ljava/lang/Object;

    .line 266
    .line 267
    check-cast v2, Lp3/t;

    .line 268
    .line 269
    iget-object v3, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 270
    .line 271
    check-cast v3, Lp3/t;

    .line 272
    .line 273
    iget-object v7, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 274
    .line 275
    check-cast v7, Lp3/i0;

    .line 276
    .line 277
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 278
    .line 279
    .line 280
    move-object v9, v7

    .line 281
    move-object v7, v2

    .line 282
    move-object v2, v9

    .line 283
    move-object/from16 v9, p1

    .line 284
    .line 285
    goto :goto_9

    .line 286
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 287
    .line 288
    invoke-direct {v0, v9}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    throw v0

    .line 292
    :cond_c
    iget-object v2, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 293
    .line 294
    check-cast v2, Lp3/i0;

    .line 295
    .line 296
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 297
    .line 298
    .line 299
    move-object/from16 v3, p1

    .line 300
    .line 301
    goto :goto_6

    .line 302
    :cond_d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 303
    .line 304
    .line 305
    iget-object v2, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 306
    .line 307
    check-cast v2, Lp3/i0;

    .line 308
    .line 309
    sget-object v3, Lp3/l;->d:Lp3/l;

    .line 310
    .line 311
    iput-object v2, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 312
    .line 313
    iput v10, v0, Lb2/a;->f:I

    .line 314
    .line 315
    invoke-static {v2, v4, v3, v0}, Lg1/g3;->b(Lp3/i0;ZLp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v3

    .line 319
    if-ne v3, v1, :cond_e

    .line 320
    .line 321
    goto :goto_8

    .line 322
    :cond_e
    :goto_6
    check-cast v3, Lp3/t;

    .line 323
    .line 324
    iget-object v9, v8, Lp1/v;->c:Ll2/j1;

    .line 325
    .line 326
    new-instance v10, Ld3/b;

    .line 327
    .line 328
    const-wide/16 v11, 0x0

    .line 329
    .line 330
    invoke-direct {v10, v11, v12}, Ld3/b;-><init>(J)V

    .line 331
    .line 332
    .line 333
    invoke-virtual {v9, v10}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 334
    .line 335
    .line 336
    :goto_7
    if-nez v7, :cond_12

    .line 337
    .line 338
    sget-object v9, Lp3/l;->d:Lp3/l;

    .line 339
    .line 340
    iput-object v2, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 341
    .line 342
    iput-object v3, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 343
    .line 344
    iput-object v7, v0, Lb2/a;->i:Ljava/lang/Object;

    .line 345
    .line 346
    iput v5, v0, Lb2/a;->f:I

    .line 347
    .line 348
    invoke-virtual {v2, v9, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v9

    .line 352
    if-ne v9, v1, :cond_f

    .line 353
    .line 354
    :goto_8
    move-object v6, v1

    .line 355
    goto :goto_b

    .line 356
    :cond_f
    :goto_9
    check-cast v9, Lp3/k;

    .line 357
    .line 358
    iget-object v10, v9, Lp3/k;->a:Ljava/lang/Object;

    .line 359
    .line 360
    move-object v11, v10

    .line 361
    check-cast v11, Ljava/util/Collection;

    .line 362
    .line 363
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    .line 364
    .line 365
    .line 366
    move-result v11

    .line 367
    move v12, v4

    .line 368
    :goto_a
    if-ge v12, v11, :cond_11

    .line 369
    .line 370
    invoke-interface {v10, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v13

    .line 374
    check-cast v13, Lp3/t;

    .line 375
    .line 376
    invoke-static {v13}, Lp3/s;->c(Lp3/t;)Z

    .line 377
    .line 378
    .line 379
    move-result v13

    .line 380
    if-nez v13, :cond_10

    .line 381
    .line 382
    goto :goto_7

    .line 383
    :cond_10
    add-int/lit8 v12, v12, 0x1

    .line 384
    .line 385
    goto :goto_a

    .line 386
    :cond_11
    iget-object v7, v9, Lp3/k;->a:Ljava/lang/Object;

    .line 387
    .line 388
    invoke-interface {v7, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v7

    .line 392
    check-cast v7, Lp3/t;

    .line 393
    .line 394
    goto :goto_7

    .line 395
    :cond_12
    iget-wide v0, v7, Lp3/t;->c:J

    .line 396
    .line 397
    iget-wide v2, v3, Lp3/t;->c:J

    .line 398
    .line 399
    invoke-static {v0, v1, v2, v3}, Ld3/b;->g(JJ)J

    .line 400
    .line 401
    .line 402
    move-result-wide v0

    .line 403
    iget-object v2, v8, Lp1/v;->c:Ll2/j1;

    .line 404
    .line 405
    new-instance v3, Ld3/b;

    .line 406
    .line 407
    invoke-direct {v3, v0, v1}, Ld3/b;-><init>(J)V

    .line 408
    .line 409
    .line 410
    invoke-virtual {v2, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 411
    .line 412
    .line 413
    :goto_b
    return-object v6

    .line 414
    :pswitch_2
    iget-object v1, v0, Lb2/a;->i:Ljava/lang/Object;

    .line 415
    .line 416
    check-cast v1, Lay0/k;

    .line 417
    .line 418
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 419
    .line 420
    iget v3, v0, Lb2/a;->f:I

    .line 421
    .line 422
    if-eqz v3, :cond_15

    .line 423
    .line 424
    if-eq v3, v10, :cond_14

    .line 425
    .line 426
    if-ne v3, v5, :cond_13

    .line 427
    .line 428
    iget-object v3, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 429
    .line 430
    check-cast v3, Lp3/t;

    .line 431
    .line 432
    iget-object v4, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 433
    .line 434
    check-cast v4, Lp3/i0;

    .line 435
    .line 436
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 437
    .line 438
    .line 439
    move-object/from16 v8, p1

    .line 440
    .line 441
    goto :goto_e

    .line 442
    :cond_13
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 443
    .line 444
    invoke-direct {v0, v9}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 445
    .line 446
    .line 447
    throw v0

    .line 448
    :cond_14
    iget-object v3, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 449
    .line 450
    check-cast v3, Lp3/i0;

    .line 451
    .line 452
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 453
    .line 454
    .line 455
    move-object/from16 v4, p1

    .line 456
    .line 457
    goto :goto_c

    .line 458
    :cond_15
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 459
    .line 460
    .line 461
    iget-object v3, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 462
    .line 463
    check-cast v3, Lp3/i0;

    .line 464
    .line 465
    iput-object v3, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 466
    .line 467
    iput v10, v0, Lb2/a;->f:I

    .line 468
    .line 469
    invoke-static {v3, v0, v5}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 470
    .line 471
    .line 472
    move-result-object v4

    .line 473
    if-ne v4, v2, :cond_16

    .line 474
    .line 475
    goto :goto_d

    .line 476
    :cond_16
    :goto_c
    check-cast v4, Lp3/t;

    .line 477
    .line 478
    iget-wide v9, v4, Lp3/t;->c:J

    .line 479
    .line 480
    new-instance v11, Ld3/b;

    .line 481
    .line 482
    invoke-direct {v11, v9, v10}, Ld3/b;-><init>(J)V

    .line 483
    .line 484
    .line 485
    invoke-interface {v1, v11}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    check-cast v8, Lay0/k;

    .line 489
    .line 490
    if-eqz v8, :cond_17

    .line 491
    .line 492
    iget-wide v9, v4, Lp3/t;->c:J

    .line 493
    .line 494
    new-instance v11, Ld3/b;

    .line 495
    .line 496
    invoke-direct {v11, v9, v10}, Ld3/b;-><init>(J)V

    .line 497
    .line 498
    .line 499
    invoke-interface {v8, v11}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 500
    .line 501
    .line 502
    :cond_17
    move-object/from16 v20, v4

    .line 503
    .line 504
    move-object v4, v3

    .line 505
    move-object/from16 v3, v20

    .line 506
    .line 507
    :cond_18
    sget-object v8, Lp3/l;->d:Lp3/l;

    .line 508
    .line 509
    iput-object v4, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 510
    .line 511
    iput-object v3, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 512
    .line 513
    iput v5, v0, Lb2/a;->f:I

    .line 514
    .line 515
    invoke-virtual {v4, v8, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 516
    .line 517
    .line 518
    move-result-object v8

    .line 519
    if-ne v8, v2, :cond_19

    .line 520
    .line 521
    :goto_d
    move-object v6, v2

    .line 522
    goto :goto_10

    .line 523
    :cond_19
    :goto_e
    check-cast v8, Lp3/k;

    .line 524
    .line 525
    iget-object v9, v8, Lp3/k;->a:Ljava/lang/Object;

    .line 526
    .line 527
    invoke-static {v9}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 528
    .line 529
    .line 530
    move-result-object v9

    .line 531
    check-cast v9, Lp3/t;

    .line 532
    .line 533
    iget-wide v9, v9, Lp3/t;->c:J

    .line 534
    .line 535
    new-instance v11, Ld3/b;

    .line 536
    .line 537
    invoke-direct {v11, v9, v10}, Ld3/b;-><init>(J)V

    .line 538
    .line 539
    .line 540
    invoke-interface {v1, v11}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 541
    .line 542
    .line 543
    iget-object v8, v8, Lp3/k;->a:Ljava/lang/Object;

    .line 544
    .line 545
    check-cast v8, Ljava/lang/Iterable;

    .line 546
    .line 547
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 548
    .line 549
    .line 550
    move-result-object v8

    .line 551
    :cond_1a
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 552
    .line 553
    .line 554
    move-result v9

    .line 555
    if-eqz v9, :cond_1b

    .line 556
    .line 557
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 558
    .line 559
    .line 560
    move-result-object v9

    .line 561
    move-object v10, v9

    .line 562
    check-cast v10, Lp3/t;

    .line 563
    .line 564
    iget-wide v10, v10, Lp3/t;->a:J

    .line 565
    .line 566
    iget-wide v12, v3, Lp3/t;->a:J

    .line 567
    .line 568
    invoke-static {v10, v11, v12, v13}, Lp3/s;->e(JJ)Z

    .line 569
    .line 570
    .line 571
    move-result v10

    .line 572
    if-eqz v10, :cond_1a

    .line 573
    .line 574
    goto :goto_f

    .line 575
    :cond_1b
    move-object v9, v7

    .line 576
    :goto_f
    check-cast v9, Lp3/t;

    .line 577
    .line 578
    if-eqz v9, :cond_1c

    .line 579
    .line 580
    invoke-static {v9}, Lp3/s;->d(Lp3/t;)Z

    .line 581
    .line 582
    .line 583
    move-result v8

    .line 584
    if-eqz v8, :cond_18

    .line 585
    .line 586
    :cond_1c
    :goto_10
    return-object v6

    .line 587
    :pswitch_3
    move-object v1, v8

    .line 588
    check-cast v1, Lh2/yb;

    .line 589
    .line 590
    sget-object v11, Lqx0/a;->d:Lqx0/a;

    .line 591
    .line 592
    iget v6, v0, Lb2/a;->f:I

    .line 593
    .line 594
    if-eqz v6, :cond_1e

    .line 595
    .line 596
    if-ne v6, v10, :cond_1d

    .line 597
    .line 598
    iget-object v6, v0, Lb2/a;->i:Ljava/lang/Object;

    .line 599
    .line 600
    check-cast v6, Lp3/l;

    .line 601
    .line 602
    iget-object v8, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 603
    .line 604
    check-cast v8, Lp3/i0;

    .line 605
    .line 606
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 607
    .line 608
    .line 609
    move-object/from16 v9, p1

    .line 610
    .line 611
    goto :goto_12

    .line 612
    :cond_1d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 613
    .line 614
    invoke-direct {v0, v9}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 615
    .line 616
    .line 617
    throw v0

    .line 618
    :cond_1e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 619
    .line 620
    .line 621
    iget-object v6, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 622
    .line 623
    check-cast v6, Lp3/i0;

    .line 624
    .line 625
    sget-object v8, Lp3/l;->e:Lp3/l;

    .line 626
    .line 627
    move-object/from16 v20, v8

    .line 628
    .line 629
    move-object v8, v6

    .line 630
    move-object/from16 v6, v20

    .line 631
    .line 632
    :cond_1f
    :goto_11
    iput-object v8, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 633
    .line 634
    iput-object v6, v0, Lb2/a;->i:Ljava/lang/Object;

    .line 635
    .line 636
    iput v10, v0, Lb2/a;->f:I

    .line 637
    .line 638
    invoke-virtual {v8, v6, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 639
    .line 640
    .line 641
    move-result-object v9

    .line 642
    if-ne v9, v11, :cond_20

    .line 643
    .line 644
    return-object v11

    .line 645
    :cond_20
    :goto_12
    check-cast v9, Lp3/k;

    .line 646
    .line 647
    iget-object v12, v9, Lp3/k;->a:Ljava/lang/Object;

    .line 648
    .line 649
    invoke-interface {v12, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 650
    .line 651
    .line 652
    move-result-object v12

    .line 653
    check-cast v12, Lp3/t;

    .line 654
    .line 655
    iget v12, v12, Lp3/t;->i:I

    .line 656
    .line 657
    if-ne v12, v5, :cond_1f

    .line 658
    .line 659
    iget v9, v9, Lp3/k;->e:I

    .line 660
    .line 661
    if-ne v9, v2, :cond_21

    .line 662
    .line 663
    iget-object v9, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 664
    .line 665
    check-cast v9, Lvy0/b0;

    .line 666
    .line 667
    new-instance v12, Li2/u;

    .line 668
    .line 669
    invoke-direct {v12, v1, v7, v10}, Li2/u;-><init>(Lh2/yb;Lkotlin/coroutines/Continuation;I)V

    .line 670
    .line 671
    .line 672
    invoke-static {v9, v7, v7, v12, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 673
    .line 674
    .line 675
    goto :goto_11

    .line 676
    :cond_21
    const/4 v12, 0x5

    .line 677
    if-ne v9, v12, :cond_1f

    .line 678
    .line 679
    invoke-virtual {v1}, Lh2/yb;->a()V

    .line 680
    .line 681
    .line 682
    goto :goto_11

    .line 683
    :pswitch_4
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 684
    .line 685
    iget v2, v0, Lb2/a;->f:I

    .line 686
    .line 687
    if-eqz v2, :cond_25

    .line 688
    .line 689
    if-eq v2, v10, :cond_24

    .line 690
    .line 691
    if-eq v2, v5, :cond_23

    .line 692
    .line 693
    if-ne v2, v3, :cond_22

    .line 694
    .line 695
    goto :goto_13

    .line 696
    :cond_22
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 697
    .line 698
    invoke-direct {v0, v9}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 699
    .line 700
    .line 701
    throw v0

    .line 702
    :cond_23
    :goto_13
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 703
    .line 704
    .line 705
    goto/16 :goto_18

    .line 706
    .line 707
    :cond_24
    iget-object v2, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 708
    .line 709
    check-cast v2, Lp3/i0;

    .line 710
    .line 711
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 712
    .line 713
    .line 714
    move-object/from16 v9, p1

    .line 715
    .line 716
    goto :goto_14

    .line 717
    :cond_25
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 718
    .line 719
    .line 720
    iget-object v2, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 721
    .line 722
    check-cast v2, Lp3/i0;

    .line 723
    .line 724
    iput-object v2, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 725
    .line 726
    iput v10, v0, Lb2/a;->f:I

    .line 727
    .line 728
    invoke-static {v2, v0}, Lkp/s;->a(Lp3/i0;Lrx0/a;)Ljava/lang/Object;

    .line 729
    .line 730
    .line 731
    move-result-object v9

    .line 732
    if-ne v9, v1, :cond_26

    .line 733
    .line 734
    goto :goto_17

    .line 735
    :cond_26
    :goto_14
    check-cast v9, Lp3/k;

    .line 736
    .line 737
    invoke-static {v9}, Lkp/s;->d(Lp3/k;)Z

    .line 738
    .line 739
    .line 740
    move-result v10

    .line 741
    if-eqz v10, :cond_29

    .line 742
    .line 743
    iget v10, v9, Lp3/k;->d:I

    .line 744
    .line 745
    and-int/lit8 v10, v10, 0x21

    .line 746
    .line 747
    if-eqz v10, :cond_29

    .line 748
    .line 749
    iget-object v10, v9, Lp3/k;->a:Ljava/lang/Object;

    .line 750
    .line 751
    move-object v11, v10

    .line 752
    check-cast v11, Ljava/util/Collection;

    .line 753
    .line 754
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    .line 755
    .line 756
    .line 757
    move-result v11

    .line 758
    :goto_15
    if-ge v4, v11, :cond_28

    .line 759
    .line 760
    invoke-interface {v10, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 761
    .line 762
    .line 763
    move-result-object v12

    .line 764
    check-cast v12, Lp3/t;

    .line 765
    .line 766
    invoke-virtual {v12}, Lp3/t;->b()Z

    .line 767
    .line 768
    .line 769
    move-result v12

    .line 770
    if-eqz v12, :cond_27

    .line 771
    .line 772
    goto :goto_16

    .line 773
    :cond_27
    add-int/lit8 v4, v4, 0x1

    .line 774
    .line 775
    goto :goto_15

    .line 776
    :cond_28
    iget-object v3, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 777
    .line 778
    check-cast v3, Lcom/google/android/gms/internal/measurement/i4;

    .line 779
    .line 780
    iget-object v4, v0, Lb2/a;->i:Ljava/lang/Object;

    .line 781
    .line 782
    check-cast v4, Lbb/g0;

    .line 783
    .line 784
    iput-object v7, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 785
    .line 786
    iput v5, v0, Lb2/a;->f:I

    .line 787
    .line 788
    invoke-static {v2, v3, v4, v9, v0}, Lkp/s;->b(Lp3/i0;Lcom/google/android/gms/internal/measurement/i4;Lbb/g0;Lp3/k;Lrx0/a;)Ljava/lang/Object;

    .line 789
    .line 790
    .line 791
    move-result-object v0

    .line 792
    if-ne v0, v1, :cond_2a

    .line 793
    .line 794
    goto :goto_17

    .line 795
    :cond_29
    :goto_16
    invoke-static {v9}, Lkp/s;->d(Lp3/k;)Z

    .line 796
    .line 797
    .line 798
    move-result v4

    .line 799
    if-nez v4, :cond_2a

    .line 800
    .line 801
    check-cast v8, Lt1/w0;

    .line 802
    .line 803
    iput-object v7, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 804
    .line 805
    iput v3, v0, Lb2/a;->f:I

    .line 806
    .line 807
    invoke-static {v2, v8, v9, v0}, Lkp/s;->c(Lp3/i0;Lt1/w0;Lp3/k;Lrx0/a;)Ljava/lang/Object;

    .line 808
    .line 809
    .line 810
    move-result-object v0

    .line 811
    if-ne v0, v1, :cond_2a

    .line 812
    .line 813
    :goto_17
    move-object v6, v1

    .line 814
    :cond_2a
    :goto_18
    return-object v6

    .line 815
    :pswitch_5
    check-cast v8, Lb2/c;

    .line 816
    .line 817
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 818
    .line 819
    iget v11, v0, Lb2/a;->f:I

    .line 820
    .line 821
    if-eqz v11, :cond_2e

    .line 822
    .line 823
    if-eq v11, v10, :cond_2d

    .line 824
    .line 825
    if-eq v11, v5, :cond_2c

    .line 826
    .line 827
    if-ne v11, v3, :cond_2b

    .line 828
    .line 829
    iget-object v2, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 830
    .line 831
    check-cast v2, Lp3/t;

    .line 832
    .line 833
    iget-object v5, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 834
    .line 835
    check-cast v5, Lp3/i0;

    .line 836
    .line 837
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 838
    .line 839
    .line 840
    move v14, v3

    .line 841
    move-object/from16 v3, p1

    .line 842
    .line 843
    goto/16 :goto_2f

    .line 844
    .line 845
    :cond_2b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 846
    .line 847
    invoke-direct {v0, v9}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 848
    .line 849
    .line 850
    throw v0

    .line 851
    :cond_2c
    iget-object v2, v0, Lb2/a;->i:Ljava/lang/Object;

    .line 852
    .line 853
    check-cast v2, Lp3/l;

    .line 854
    .line 855
    iget-object v9, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 856
    .line 857
    check-cast v9, Lp3/t;

    .line 858
    .line 859
    iget-object v11, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 860
    .line 861
    check-cast v11, Lp3/i0;

    .line 862
    .line 863
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 864
    .line 865
    .line 866
    move-object/from16 v3, p1

    .line 867
    .line 868
    goto/16 :goto_1f

    .line 869
    .line 870
    :cond_2d
    iget-object v9, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 871
    .line 872
    check-cast v9, Lp3/i0;

    .line 873
    .line 874
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 875
    .line 876
    .line 877
    move-object/from16 v11, p1

    .line 878
    .line 879
    goto :goto_19

    .line 880
    :cond_2e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 881
    .line 882
    .line 883
    iget-object v9, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 884
    .line 885
    check-cast v9, Lp3/i0;

    .line 886
    .line 887
    sget-object v11, Lp3/l;->d:Lp3/l;

    .line 888
    .line 889
    iput-object v9, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 890
    .line 891
    iput v10, v0, Lb2/a;->f:I

    .line 892
    .line 893
    invoke-static {v9, v10, v11, v0}, Lg1/g3;->b(Lp3/i0;ZLp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 894
    .line 895
    .line 896
    move-result-object v11

    .line 897
    if-ne v11, v1, :cond_2f

    .line 898
    .line 899
    goto/16 :goto_2e

    .line 900
    .line 901
    :cond_2f
    :goto_19
    check-cast v11, Lp3/t;

    .line 902
    .line 903
    iget v12, v11, Lp3/t;->i:I

    .line 904
    .line 905
    iget-wide v13, v11, Lp3/t;->c:J

    .line 906
    .line 907
    if-ne v12, v3, :cond_30

    .line 908
    .line 909
    goto :goto_1a

    .line 910
    :cond_30
    if-ne v12, v2, :cond_5a

    .line 911
    .line 912
    :goto_1a
    const/16 p1, 0x20

    .line 913
    .line 914
    shr-long v2, v13, p1

    .line 915
    .line 916
    long-to-int v2, v2

    .line 917
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 918
    .line 919
    .line 920
    move-result v3

    .line 921
    const/4 v15, 0x0

    .line 922
    cmpl-float v3, v3, v15

    .line 923
    .line 924
    if-ltz v3, :cond_31

    .line 925
    .line 926
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 927
    .line 928
    .line 929
    move-result v2

    .line 930
    iget-object v3, v9, Lp3/i0;->i:Lp3/j0;

    .line 931
    .line 932
    move-wide/from16 v16, v13

    .line 933
    .line 934
    iget-wide v12, v3, Lp3/j0;->B:J

    .line 935
    .line 936
    shr-long v12, v12, p1

    .line 937
    .line 938
    long-to-int v3, v12

    .line 939
    int-to-float v3, v3

    .line 940
    cmpg-float v2, v2, v3

    .line 941
    .line 942
    if-gez v2, :cond_31

    .line 943
    .line 944
    const-wide v2, 0xffffffffL

    .line 945
    .line 946
    .line 947
    .line 948
    .line 949
    and-long v12, v16, v2

    .line 950
    .line 951
    long-to-int v12, v12

    .line 952
    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 953
    .line 954
    .line 955
    move-result v13

    .line 956
    cmpl-float v13, v13, v15

    .line 957
    .line 958
    if-ltz v13, :cond_31

    .line 959
    .line 960
    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 961
    .line 962
    .line 963
    move-result v12

    .line 964
    iget-object v13, v9, Lp3/i0;->i:Lp3/j0;

    .line 965
    .line 966
    move-wide v15, v2

    .line 967
    iget-wide v2, v13, Lp3/j0;->B:J

    .line 968
    .line 969
    and-long/2addr v2, v15

    .line 970
    long-to-int v2, v2

    .line 971
    int-to-float v2, v2

    .line 972
    cmpg-float v2, v12, v2

    .line 973
    .line 974
    if-gez v2, :cond_31

    .line 975
    .line 976
    move v2, v10

    .line 977
    goto :goto_1b

    .line 978
    :cond_31
    move v2, v4

    .line 979
    :goto_1b
    iget-boolean v3, v8, Lb2/c;->u:Z

    .line 980
    .line 981
    if-nez v3, :cond_33

    .line 982
    .line 983
    if-eqz v2, :cond_32

    .line 984
    .line 985
    goto :goto_1c

    .line 986
    :cond_32
    sget-object v2, Lp3/l;->e:Lp3/l;

    .line 987
    .line 988
    goto :goto_1d

    .line 989
    :cond_33
    :goto_1c
    sget-object v2, Lp3/l;->d:Lp3/l;

    .line 990
    .line 991
    :goto_1d
    move-object/from16 v20, v11

    .line 992
    .line 993
    move-object v11, v9

    .line 994
    move-object/from16 v9, v20

    .line 995
    .line 996
    :goto_1e
    iput-object v11, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 997
    .line 998
    iput-object v9, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 999
    .line 1000
    iput-object v2, v0, Lb2/a;->i:Ljava/lang/Object;

    .line 1001
    .line 1002
    iput v5, v0, Lb2/a;->f:I

    .line 1003
    .line 1004
    invoke-virtual {v11, v2, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1005
    .line 1006
    .line 1007
    move-result-object v3

    .line 1008
    if-ne v3, v1, :cond_34

    .line 1009
    .line 1010
    goto/16 :goto_2e

    .line 1011
    .line 1012
    :cond_34
    :goto_1f
    check-cast v3, Lp3/k;

    .line 1013
    .line 1014
    iget-object v12, v3, Lp3/k;->a:Ljava/lang/Object;

    .line 1015
    .line 1016
    move-object v13, v12

    .line 1017
    check-cast v13, Ljava/util/Collection;

    .line 1018
    .line 1019
    invoke-interface {v13}, Ljava/util/Collection;->size()I

    .line 1020
    .line 1021
    .line 1022
    move-result v13

    .line 1023
    move v15, v4

    .line 1024
    :goto_20
    if-ge v15, v13, :cond_37

    .line 1025
    .line 1026
    invoke-interface {v12, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v16

    .line 1030
    move-object/from16 v4, v16

    .line 1031
    .line 1032
    check-cast v4, Lp3/t;

    .line 1033
    .line 1034
    invoke-virtual {v4}, Lp3/t;->b()Z

    .line 1035
    .line 1036
    .line 1037
    move-result v18

    .line 1038
    if-nez v18, :cond_35

    .line 1039
    .line 1040
    move/from16 v18, v15

    .line 1041
    .line 1042
    iget-wide v14, v4, Lp3/t;->a:J

    .line 1043
    .line 1044
    move-object/from16 v19, v11

    .line 1045
    .line 1046
    iget-wide v10, v9, Lp3/t;->a:J

    .line 1047
    .line 1048
    invoke-static {v14, v15, v10, v11}, Lp3/s;->e(JJ)Z

    .line 1049
    .line 1050
    .line 1051
    move-result v10

    .line 1052
    if-eqz v10, :cond_36

    .line 1053
    .line 1054
    iget-boolean v4, v4, Lp3/t;->d:Z

    .line 1055
    .line 1056
    if-eqz v4, :cond_36

    .line 1057
    .line 1058
    goto :goto_21

    .line 1059
    :cond_35
    move-object/from16 v19, v11

    .line 1060
    .line 1061
    move/from16 v18, v15

    .line 1062
    .line 1063
    :cond_36
    add-int/lit8 v15, v18, 0x1

    .line 1064
    .line 1065
    move-object/from16 v11, v19

    .line 1066
    .line 1067
    const/4 v4, 0x0

    .line 1068
    const/4 v10, 0x1

    .line 1069
    goto :goto_20

    .line 1070
    :cond_37
    move-object/from16 v19, v11

    .line 1071
    .line 1072
    move-object/from16 v16, v7

    .line 1073
    .line 1074
    :goto_21
    move-object/from16 v4, v16

    .line 1075
    .line 1076
    check-cast v4, Lp3/t;

    .line 1077
    .line 1078
    if-nez v4, :cond_38

    .line 1079
    .line 1080
    goto :goto_22

    .line 1081
    :cond_38
    iget-wide v10, v4, Lp3/t;->b:J

    .line 1082
    .line 1083
    iget-wide v12, v9, Lp3/t;->b:J

    .line 1084
    .line 1085
    sub-long/2addr v10, v12

    .line 1086
    invoke-virtual/range {v19 .. v19}, Lp3/i0;->f()Lw3/h2;

    .line 1087
    .line 1088
    .line 1089
    move-result-object v12

    .line 1090
    invoke-interface {v12}, Lw3/h2;->b()J

    .line 1091
    .line 1092
    .line 1093
    move-result-wide v12

    .line 1094
    cmp-long v10, v10, v12

    .line 1095
    .line 1096
    if-ltz v10, :cond_39

    .line 1097
    .line 1098
    goto :goto_22

    .line 1099
    :cond_39
    iget v3, v3, Lp3/k;->c:I

    .line 1100
    .line 1101
    if-ne v3, v5, :cond_3a

    .line 1102
    .line 1103
    :goto_22
    move-object v4, v7

    .line 1104
    goto :goto_23

    .line 1105
    :cond_3a
    iget-wide v10, v4, Lp3/t;->c:J

    .line 1106
    .line 1107
    iget-wide v12, v9, Lp3/t;->c:J

    .line 1108
    .line 1109
    invoke-static {v10, v11, v12, v13}, Ld3/b;->g(JJ)J

    .line 1110
    .line 1111
    .line 1112
    move-result-wide v10

    .line 1113
    invoke-static {v10, v11}, Ld3/b;->d(J)F

    .line 1114
    .line 1115
    .line 1116
    move-result v3

    .line 1117
    invoke-virtual/range {v19 .. v19}, Lp3/i0;->f()Lw3/h2;

    .line 1118
    .line 1119
    .line 1120
    move-result-object v10

    .line 1121
    invoke-interface {v10}, Lw3/h2;->c()F

    .line 1122
    .line 1123
    .line 1124
    move-result v10

    .line 1125
    cmpl-float v3, v3, v10

    .line 1126
    .line 1127
    if-lez v3, :cond_59

    .line 1128
    .line 1129
    :goto_23
    if-nez v4, :cond_3b

    .line 1130
    .line 1131
    goto/16 :goto_32

    .line 1132
    .line 1133
    :cond_3b
    iget-boolean v2, v8, Lb2/c;->u:Z

    .line 1134
    .line 1135
    if-nez v2, :cond_53

    .line 1136
    .line 1137
    sget-object v2, Lc3/n;->i:Lc3/n;

    .line 1138
    .line 1139
    iget-object v3, v8, Lx2/r;->d:Lx2/r;

    .line 1140
    .line 1141
    move-object v5, v7

    .line 1142
    :goto_24
    const/4 v10, 0x7

    .line 1143
    const/16 v11, 0x10

    .line 1144
    .line 1145
    if-eqz v3, :cond_44

    .line 1146
    .line 1147
    instance-of v12, v3, Lc3/v;

    .line 1148
    .line 1149
    if-eqz v12, :cond_3d

    .line 1150
    .line 1151
    check-cast v3, Lc3/v;

    .line 1152
    .line 1153
    invoke-virtual {v3}, Lc3/v;->Y0()Lc3/o;

    .line 1154
    .line 1155
    .line 1156
    move-result-object v5

    .line 1157
    iget-boolean v5, v5, Lc3/o;->a:Z

    .line 1158
    .line 1159
    if-eqz v5, :cond_3c

    .line 1160
    .line 1161
    invoke-static {v3}, Lc3/v;->c1(Lc3/v;)Z

    .line 1162
    .line 1163
    .line 1164
    goto/16 :goto_2c

    .line 1165
    .line 1166
    :cond_3c
    invoke-static {v3, v10, v2}, Lc3/f;->i(Lc3/v;ILay0/k;)Z

    .line 1167
    .line 1168
    .line 1169
    goto/16 :goto_2c

    .line 1170
    .line 1171
    :cond_3d
    iget v10, v3, Lx2/r;->f:I

    .line 1172
    .line 1173
    and-int/lit16 v10, v10, 0x400

    .line 1174
    .line 1175
    if-eqz v10, :cond_43

    .line 1176
    .line 1177
    instance-of v10, v3, Lv3/n;

    .line 1178
    .line 1179
    if-eqz v10, :cond_43

    .line 1180
    .line 1181
    move-object v10, v3

    .line 1182
    check-cast v10, Lv3/n;

    .line 1183
    .line 1184
    iget-object v10, v10, Lv3/n;->s:Lx2/r;

    .line 1185
    .line 1186
    const/4 v12, 0x0

    .line 1187
    :goto_25
    if-eqz v10, :cond_42

    .line 1188
    .line 1189
    iget v13, v10, Lx2/r;->f:I

    .line 1190
    .line 1191
    and-int/lit16 v13, v13, 0x400

    .line 1192
    .line 1193
    if-eqz v13, :cond_41

    .line 1194
    .line 1195
    add-int/lit8 v12, v12, 0x1

    .line 1196
    .line 1197
    const/4 v13, 0x1

    .line 1198
    if-ne v12, v13, :cond_3e

    .line 1199
    .line 1200
    move-object v3, v10

    .line 1201
    goto :goto_26

    .line 1202
    :cond_3e
    if-nez v5, :cond_3f

    .line 1203
    .line 1204
    new-instance v5, Ln2/b;

    .line 1205
    .line 1206
    new-array v13, v11, [Lx2/r;

    .line 1207
    .line 1208
    invoke-direct {v5, v13}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 1209
    .line 1210
    .line 1211
    :cond_3f
    if-eqz v3, :cond_40

    .line 1212
    .line 1213
    invoke-virtual {v5, v3}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 1214
    .line 1215
    .line 1216
    move-object v3, v7

    .line 1217
    :cond_40
    invoke-virtual {v5, v10}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 1218
    .line 1219
    .line 1220
    :cond_41
    :goto_26
    iget-object v10, v10, Lx2/r;->i:Lx2/r;

    .line 1221
    .line 1222
    goto :goto_25

    .line 1223
    :cond_42
    const/4 v13, 0x1

    .line 1224
    if-ne v12, v13, :cond_43

    .line 1225
    .line 1226
    goto :goto_24

    .line 1227
    :cond_43
    invoke-static {v5}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 1228
    .line 1229
    .line 1230
    move-result-object v3

    .line 1231
    goto :goto_24

    .line 1232
    :cond_44
    iget-object v3, v8, Lx2/r;->d:Lx2/r;

    .line 1233
    .line 1234
    iget-boolean v3, v3, Lx2/r;->q:Z

    .line 1235
    .line 1236
    if-nez v3, :cond_45

    .line 1237
    .line 1238
    const-string v3, "visitChildren called on an unattached node"

    .line 1239
    .line 1240
    invoke-static {v3}, Ls3/a;->b(Ljava/lang/String;)V

    .line 1241
    .line 1242
    .line 1243
    :cond_45
    new-instance v3, Ln2/b;

    .line 1244
    .line 1245
    new-array v5, v11, [Lx2/r;

    .line 1246
    .line 1247
    invoke-direct {v3, v5}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 1248
    .line 1249
    .line 1250
    iget-object v5, v8, Lx2/r;->d:Lx2/r;

    .line 1251
    .line 1252
    iget-object v12, v5, Lx2/r;->i:Lx2/r;

    .line 1253
    .line 1254
    if-nez v12, :cond_46

    .line 1255
    .line 1256
    invoke-static {v3, v5}, Lv3/f;->b(Ln2/b;Lx2/r;)V

    .line 1257
    .line 1258
    .line 1259
    goto :goto_27

    .line 1260
    :cond_46
    invoke-virtual {v3, v12}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 1261
    .line 1262
    .line 1263
    :cond_47
    :goto_27
    iget v5, v3, Ln2/b;->f:I

    .line 1264
    .line 1265
    if-eqz v5, :cond_53

    .line 1266
    .line 1267
    add-int/lit8 v5, v5, -0x1

    .line 1268
    .line 1269
    invoke-virtual {v3, v5}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 1270
    .line 1271
    .line 1272
    move-result-object v5

    .line 1273
    check-cast v5, Lx2/r;

    .line 1274
    .line 1275
    iget v12, v5, Lx2/r;->g:I

    .line 1276
    .line 1277
    and-int/lit16 v12, v12, 0x400

    .line 1278
    .line 1279
    if-nez v12, :cond_48

    .line 1280
    .line 1281
    invoke-static {v3, v5}, Lv3/f;->b(Ln2/b;Lx2/r;)V

    .line 1282
    .line 1283
    .line 1284
    goto :goto_27

    .line 1285
    :cond_48
    :goto_28
    if-eqz v5, :cond_47

    .line 1286
    .line 1287
    iget v12, v5, Lx2/r;->f:I

    .line 1288
    .line 1289
    and-int/lit16 v12, v12, 0x400

    .line 1290
    .line 1291
    if-eqz v12, :cond_52

    .line 1292
    .line 1293
    move-object v12, v7

    .line 1294
    :goto_29
    if-eqz v5, :cond_47

    .line 1295
    .line 1296
    instance-of v13, v5, Lc3/v;

    .line 1297
    .line 1298
    if-eqz v13, :cond_4a

    .line 1299
    .line 1300
    check-cast v5, Lc3/v;

    .line 1301
    .line 1302
    invoke-virtual {v5}, Lc3/v;->Y0()Lc3/o;

    .line 1303
    .line 1304
    .line 1305
    move-result-object v3

    .line 1306
    iget-boolean v3, v3, Lc3/o;->a:Z

    .line 1307
    .line 1308
    if-eqz v3, :cond_49

    .line 1309
    .line 1310
    invoke-static {v5}, Lc3/v;->c1(Lc3/v;)Z

    .line 1311
    .line 1312
    .line 1313
    goto :goto_2c

    .line 1314
    :cond_49
    invoke-static {v5, v10, v2}, Lc3/f;->i(Lc3/v;ILay0/k;)Z

    .line 1315
    .line 1316
    .line 1317
    goto :goto_2c

    .line 1318
    :cond_4a
    iget v13, v5, Lx2/r;->f:I

    .line 1319
    .line 1320
    and-int/lit16 v13, v13, 0x400

    .line 1321
    .line 1322
    if-eqz v13, :cond_50

    .line 1323
    .line 1324
    instance-of v13, v5, Lv3/n;

    .line 1325
    .line 1326
    if-eqz v13, :cond_50

    .line 1327
    .line 1328
    move-object v13, v5

    .line 1329
    check-cast v13, Lv3/n;

    .line 1330
    .line 1331
    iget-object v13, v13, Lv3/n;->s:Lx2/r;

    .line 1332
    .line 1333
    const/4 v14, 0x0

    .line 1334
    :goto_2a
    if-eqz v13, :cond_4f

    .line 1335
    .line 1336
    iget v15, v13, Lx2/r;->f:I

    .line 1337
    .line 1338
    and-int/lit16 v15, v15, 0x400

    .line 1339
    .line 1340
    if-eqz v15, :cond_4e

    .line 1341
    .line 1342
    add-int/lit8 v14, v14, 0x1

    .line 1343
    .line 1344
    const/4 v15, 0x1

    .line 1345
    if-ne v14, v15, :cond_4b

    .line 1346
    .line 1347
    move-object v5, v13

    .line 1348
    goto :goto_2b

    .line 1349
    :cond_4b
    if-nez v12, :cond_4c

    .line 1350
    .line 1351
    new-instance v12, Ln2/b;

    .line 1352
    .line 1353
    new-array v15, v11, [Lx2/r;

    .line 1354
    .line 1355
    invoke-direct {v12, v15}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 1356
    .line 1357
    .line 1358
    :cond_4c
    if-eqz v5, :cond_4d

    .line 1359
    .line 1360
    invoke-virtual {v12, v5}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 1361
    .line 1362
    .line 1363
    move-object v5, v7

    .line 1364
    :cond_4d
    invoke-virtual {v12, v13}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 1365
    .line 1366
    .line 1367
    :cond_4e
    :goto_2b
    iget-object v13, v13, Lx2/r;->i:Lx2/r;

    .line 1368
    .line 1369
    goto :goto_2a

    .line 1370
    :cond_4f
    const/4 v13, 0x1

    .line 1371
    if-ne v14, v13, :cond_51

    .line 1372
    .line 1373
    goto :goto_29

    .line 1374
    :cond_50
    const/4 v13, 0x1

    .line 1375
    :cond_51
    invoke-static {v12}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 1376
    .line 1377
    .line 1378
    move-result-object v5

    .line 1379
    goto :goto_29

    .line 1380
    :cond_52
    const/4 v13, 0x1

    .line 1381
    iget-object v5, v5, Lx2/r;->i:Lx2/r;

    .line 1382
    .line 1383
    goto :goto_28

    .line 1384
    :cond_53
    :goto_2c
    iget-object v2, v8, Lb2/c;->t:Lay0/a;

    .line 1385
    .line 1386
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 1387
    .line 1388
    .line 1389
    invoke-virtual {v4}, Lp3/t;->a()V

    .line 1390
    .line 1391
    .line 1392
    move-object v2, v9

    .line 1393
    move-object/from16 v5, v19

    .line 1394
    .line 1395
    :goto_2d
    sget-object v3, Lp3/l;->d:Lp3/l;

    .line 1396
    .line 1397
    iput-object v5, v0, Lb2/a;->g:Ljava/lang/Object;

    .line 1398
    .line 1399
    iput-object v2, v0, Lb2/a;->h:Ljava/lang/Object;

    .line 1400
    .line 1401
    iput-object v7, v0, Lb2/a;->i:Ljava/lang/Object;

    .line 1402
    .line 1403
    const/4 v14, 0x3

    .line 1404
    iput v14, v0, Lb2/a;->f:I

    .line 1405
    .line 1406
    invoke-virtual {v5, v3, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1407
    .line 1408
    .line 1409
    move-result-object v3

    .line 1410
    if-ne v3, v1, :cond_54

    .line 1411
    .line 1412
    :goto_2e
    move-object v6, v1

    .line 1413
    goto :goto_32

    .line 1414
    :cond_54
    :goto_2f
    check-cast v3, Lp3/k;

    .line 1415
    .line 1416
    iget-object v3, v3, Lp3/k;->a:Ljava/lang/Object;

    .line 1417
    .line 1418
    move-object v4, v3

    .line 1419
    check-cast v4, Ljava/util/Collection;

    .line 1420
    .line 1421
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 1422
    .line 1423
    .line 1424
    move-result v4

    .line 1425
    const/4 v8, 0x0

    .line 1426
    :goto_30
    if-ge v8, v4, :cond_57

    .line 1427
    .line 1428
    invoke-interface {v3, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1429
    .line 1430
    .line 1431
    move-result-object v9

    .line 1432
    move-object v10, v9

    .line 1433
    check-cast v10, Lp3/t;

    .line 1434
    .line 1435
    invoke-virtual {v10}, Lp3/t;->b()Z

    .line 1436
    .line 1437
    .line 1438
    move-result v11

    .line 1439
    if-nez v11, :cond_55

    .line 1440
    .line 1441
    iget-wide v11, v10, Lp3/t;->a:J

    .line 1442
    .line 1443
    move v13, v8

    .line 1444
    iget-wide v7, v2, Lp3/t;->a:J

    .line 1445
    .line 1446
    invoke-static {v11, v12, v7, v8}, Lp3/s;->e(JJ)Z

    .line 1447
    .line 1448
    .line 1449
    move-result v7

    .line 1450
    if-eqz v7, :cond_56

    .line 1451
    .line 1452
    iget-boolean v7, v10, Lp3/t;->d:Z

    .line 1453
    .line 1454
    if-eqz v7, :cond_56

    .line 1455
    .line 1456
    goto :goto_31

    .line 1457
    :cond_55
    move v13, v8

    .line 1458
    :cond_56
    add-int/lit8 v8, v13, 0x1

    .line 1459
    .line 1460
    const/4 v7, 0x0

    .line 1461
    goto :goto_30

    .line 1462
    :cond_57
    const/4 v9, 0x0

    .line 1463
    :goto_31
    check-cast v9, Lp3/t;

    .line 1464
    .line 1465
    if-nez v9, :cond_58

    .line 1466
    .line 1467
    goto :goto_32

    .line 1468
    :cond_58
    invoke-virtual {v9}, Lp3/t;->a()V

    .line 1469
    .line 1470
    .line 1471
    const/4 v7, 0x0

    .line 1472
    goto :goto_2d

    .line 1473
    :cond_59
    move-object/from16 v11, v19

    .line 1474
    .line 1475
    const/4 v4, 0x0

    .line 1476
    const/4 v10, 0x1

    .line 1477
    goto/16 :goto_1e

    .line 1478
    .line 1479
    :cond_5a
    :goto_32
    return-object v6

    .line 1480
    nop

    .line 1481
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
