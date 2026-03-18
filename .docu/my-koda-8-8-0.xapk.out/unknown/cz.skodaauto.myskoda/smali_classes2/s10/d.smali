.class public final Ls10/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public d:I

.field public synthetic e:Lr10/a;

.field public synthetic f:Lcn0/c;

.field public synthetic g:Lcn0/c;

.field public final synthetic h:Ls10/e;


# direct methods
.method public constructor <init>(Ls10/e;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ls10/d;->h:Ls10/e;

    .line 2
    .line 3
    const/4 p1, 0x4

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lr10/a;

    .line 2
    .line 3
    check-cast p2, Lcn0/c;

    .line 4
    .line 5
    check-cast p3, Lcn0/c;

    .line 6
    .line 7
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    new-instance v0, Ls10/d;

    .line 10
    .line 11
    iget-object p0, p0, Ls10/d;->h:Ls10/e;

    .line 12
    .line 13
    invoke-direct {v0, p0, p4}, Ls10/d;-><init>(Ls10/e;Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Ls10/d;->e:Lr10/a;

    .line 17
    .line 18
    iput-object p2, v0, Ls10/d;->f:Lcn0/c;

    .line 19
    .line 20
    iput-object p3, v0, Ls10/d;->g:Lcn0/c;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Ls10/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Ls10/d;->h:Ls10/e;

    .line 4
    .line 5
    iget-object v2, v1, Ls10/e;->l:Lij0/a;

    .line 6
    .line 7
    iget-object v3, v0, Ls10/d;->e:Lr10/a;

    .line 8
    .line 9
    iget-object v4, v0, Ls10/d;->f:Lcn0/c;

    .line 10
    .line 11
    iget-object v5, v0, Ls10/d;->g:Lcn0/c;

    .line 12
    .line 13
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    iget v7, v0, Ls10/d;->d:I

    .line 16
    .line 17
    const/4 v8, 0x2

    .line 18
    const/4 v9, 0x1

    .line 19
    const/4 v10, 0x0

    .line 20
    if-eqz v7, :cond_2

    .line 21
    .line 22
    if-eq v7, v9, :cond_1

    .line 23
    .line 24
    if-ne v7, v8, :cond_0

    .line 25
    .line 26
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    goto/16 :goto_6

    .line 30
    .line 31
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 34
    .line 35
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw v0

    .line 39
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_4

    .line 43
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    if-eqz v3, :cond_6

    .line 47
    .line 48
    invoke-virtual {v1}, Lql0/j;->a()Lql0/h;

    .line 49
    .line 50
    .line 51
    move-result-object v7

    .line 52
    move-object v11, v7

    .line 53
    check-cast v11, Ls10/b;

    .line 54
    .line 55
    iget-object v7, v3, Lr10/a;->a:Lqr0/q;

    .line 56
    .line 57
    const v12, 0x7f1201aa

    .line 58
    .line 59
    .line 60
    const/4 v13, 0x0

    .line 61
    if-eqz v7, :cond_3

    .line 62
    .line 63
    invoke-static {v7, v2}, Lkp/p6;->b(Lqr0/q;Lij0/a;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v7

    .line 67
    goto :goto_0

    .line 68
    :cond_3
    new-array v7, v13, [Ljava/lang/Object;

    .line 69
    .line 70
    move-object v14, v2

    .line 71
    check-cast v14, Ljj0/f;

    .line 72
    .line 73
    invoke-virtual {v14, v12, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v7

    .line 77
    :goto_0
    iget-object v3, v3, Lr10/a;->b:Lqr0/l;

    .line 78
    .line 79
    if-eqz v3, :cond_4

    .line 80
    .line 81
    iget v14, v3, Lqr0/l;->d:I

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_4
    move v14, v13

    .line 85
    :goto_1
    if-eqz v3, :cond_5

    .line 86
    .line 87
    invoke-static {v3}, Lkp/l6;->a(Lqr0/l;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    :goto_2
    move-object v15, v2

    .line 92
    goto :goto_3

    .line 93
    :cond_5
    new-array v3, v13, [Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v2, Ljj0/f;

    .line 96
    .line 97
    invoke-virtual {v2, v12, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    goto :goto_2

    .line 102
    :goto_3
    const/16 v18, 0x0

    .line 103
    .line 104
    const/16 v19, 0xd1

    .line 105
    .line 106
    const/4 v12, 0x0

    .line 107
    const/16 v16, 0x0

    .line 108
    .line 109
    const/16 v17, 0x0

    .line 110
    .line 111
    move-object v13, v7

    .line 112
    invoke-static/range {v11 .. v19}, Ls10/b;->a(Ls10/b;Lql0/g;Ljava/lang/String;ILjava/lang/String;IZZI)Ls10/b;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    invoke-virtual {v1, v2}, Lql0/j;->g(Lql0/h;)V

    .line 117
    .line 118
    .line 119
    :cond_6
    iput-object v10, v0, Ls10/d;->e:Lr10/a;

    .line 120
    .line 121
    iput-object v10, v0, Ls10/d;->f:Lcn0/c;

    .line 122
    .line 123
    iput-object v5, v0, Ls10/d;->g:Lcn0/c;

    .line 124
    .line 125
    iput v9, v0, Ls10/d;->d:I

    .line 126
    .line 127
    invoke-static {v1, v4, v0}, Ls10/e;->j(Ls10/e;Lcn0/c;Ls10/d;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v2

    .line 131
    if-ne v2, v6, :cond_7

    .line 132
    .line 133
    goto :goto_5

    .line 134
    :cond_7
    :goto_4
    iput-object v10, v0, Ls10/d;->e:Lr10/a;

    .line 135
    .line 136
    iput-object v10, v0, Ls10/d;->f:Lcn0/c;

    .line 137
    .line 138
    iput-object v10, v0, Ls10/d;->g:Lcn0/c;

    .line 139
    .line 140
    iput v8, v0, Ls10/d;->d:I

    .line 141
    .line 142
    invoke-static {v1, v5, v0}, Ls10/e;->j(Ls10/e;Lcn0/c;Ls10/d;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    if-ne v0, v6, :cond_8

    .line 147
    .line 148
    :goto_5
    return-object v6

    .line 149
    :cond_8
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    return-object v0
.end method
