.class public final Lnz/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lnz/z;


# direct methods
.method public synthetic constructor <init>(Lnz/z;I)V
    .locals 0

    .line 1
    iput p2, p0, Lnz/x;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lnz/x;->e:Lnz/z;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b(Lne0/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lnz/w;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lnz/w;

    .line 7
    .line 8
    iget v1, v0, Lnz/w;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lnz/w;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lnz/w;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lnz/w;-><init>(Lnz/x;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lnz/w;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lnz/w;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    instance-of p2, p1, Lne0/e;

    .line 52
    .line 53
    if-eqz p2, :cond_3

    .line 54
    .line 55
    check-cast p1, Lne0/e;

    .line 56
    .line 57
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p1, Ljava/util/List;

    .line 60
    .line 61
    iget-object p0, p0, Lnz/x;->e:Lnz/z;

    .line 62
    .line 63
    iget-object p0, p0, Lnz/z;->x:Llz/v;

    .line 64
    .line 65
    iput v3, v0, Lnz/w;->f:I

    .line 66
    .line 67
    invoke-virtual {p0, p1, v0}, Llz/v;->b(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    if-ne p0, v1, :cond_3

    .line 72
    .line 73
    return-object v1

    .line 74
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 75
    .line 76
    return-object p0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Lnz/x;->d:I

    .line 6
    .line 7
    iget-object v3, v0, Lnz/x;->e:Lnz/z;

    .line 8
    .line 9
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    packed-switch v2, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    move-object/from16 v0, p1

    .line 15
    .line 16
    check-cast v0, Lne0/t;

    .line 17
    .line 18
    instance-of v2, v0, Lne0/c;

    .line 19
    .line 20
    if-eqz v2, :cond_0

    .line 21
    .line 22
    iget-object v2, v3, Lnz/z;->m:Ljn0/c;

    .line 23
    .line 24
    check-cast v0, Lne0/c;

    .line 25
    .line 26
    invoke-virtual {v2, v0, v1}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    if-ne v0, v1, :cond_1

    .line 33
    .line 34
    move-object v4, v0

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    instance-of v0, v0, Lne0/e;

    .line 37
    .line 38
    if-eqz v0, :cond_2

    .line 39
    .line 40
    sget v0, Lnz/z;->B:I

    .line 41
    .line 42
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    check-cast v0, Lnz/s;

    .line 47
    .line 48
    iget-object v1, v3, Lnz/z;->i:Lij0/a;

    .line 49
    .line 50
    const/4 v2, 0x0

    .line 51
    invoke-static {v0, v1, v2}, Ljp/gb;->i(Lnz/s;Lij0/a;Z)Lnz/s;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 56
    .line 57
    .line 58
    :cond_1
    :goto_0
    return-object v4

    .line 59
    :cond_2
    new-instance v0, La8/r0;

    .line 60
    .line 61
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :pswitch_0
    move-object/from16 v0, p1

    .line 66
    .line 67
    check-cast v0, Lne0/s;

    .line 68
    .line 69
    sget v1, Lnz/z;->B:I

    .line 70
    .line 71
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    move-object v5, v1

    .line 76
    check-cast v5, Lnz/s;

    .line 77
    .line 78
    instance-of v8, v0, Lne0/d;

    .line 79
    .line 80
    const/16 v29, 0x0

    .line 81
    .line 82
    const v30, 0xffffffb

    .line 83
    .line 84
    .line 85
    const/4 v6, 0x0

    .line 86
    const/4 v7, 0x0

    .line 87
    const/4 v9, 0x0

    .line 88
    const/4 v10, 0x0

    .line 89
    const/4 v11, 0x0

    .line 90
    const/4 v12, 0x0

    .line 91
    const/4 v13, 0x0

    .line 92
    const/4 v14, 0x0

    .line 93
    const/4 v15, 0x0

    .line 94
    const/16 v16, 0x0

    .line 95
    .line 96
    const/16 v17, 0x0

    .line 97
    .line 98
    const/16 v18, 0x0

    .line 99
    .line 100
    const/16 v19, 0x0

    .line 101
    .line 102
    const/16 v20, 0x0

    .line 103
    .line 104
    const/16 v21, 0x0

    .line 105
    .line 106
    const/16 v22, 0x0

    .line 107
    .line 108
    const/16 v23, 0x0

    .line 109
    .line 110
    const/16 v24, 0x0

    .line 111
    .line 112
    const/16 v25, 0x0

    .line 113
    .line 114
    const/16 v26, 0x0

    .line 115
    .line 116
    const/16 v27, 0x0

    .line 117
    .line 118
    const/16 v28, 0x0

    .line 119
    .line 120
    invoke-static/range {v5 .. v30}, Lnz/s;->a(Lnz/s;Ler0/g;Llf0/i;ZZZZZZLjava/lang/String;Ljava/lang/String;Lnz/r;Lnz/q;Lbo0/l;Lnz/p;ZZLjava/lang/String;Lmz/a;Lqr0/q;Lqr0/q;Lmy0/c;ZLmb0/c;ZI)Lnz/s;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 125
    .line 126
    .line 127
    return-object v4

    .line 128
    :pswitch_1
    move-object/from16 v2, p1

    .line 129
    .line 130
    check-cast v2, Lne0/t;

    .line 131
    .line 132
    invoke-virtual {v0, v2, v1}, Lnz/x;->b(Lne0/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    return-object v0

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
