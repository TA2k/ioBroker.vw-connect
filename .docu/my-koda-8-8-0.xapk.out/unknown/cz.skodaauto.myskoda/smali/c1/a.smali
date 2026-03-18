.class public final Lc1/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:Lc1/k;

.field public e:Lkotlin/jvm/internal/b0;

.field public f:I

.field public final synthetic g:Lc1/c;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Lc1/f;

.field public final synthetic j:J

.field public final synthetic k:Lay0/k;


# direct methods
.method public constructor <init>(Lc1/c;Ljava/lang/Object;Lc1/f;JLay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lc1/a;->g:Lc1/c;

    .line 2
    .line 3
    iput-object p2, p0, Lc1/a;->h:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lc1/a;->i:Lc1/f;

    .line 6
    .line 7
    iput-wide p4, p0, Lc1/a;->j:J

    .line 8
    .line 9
    iput-object p6, p0, Lc1/a;->k:Lay0/k;

    .line 10
    .line 11
    const/4 p1, 0x1

    .line 12
    invoke-direct {p0, p1, p7}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    new-instance v0, Lc1/a;

    .line 2
    .line 3
    iget-wide v4, p0, Lc1/a;->j:J

    .line 4
    .line 5
    iget-object v6, p0, Lc1/a;->k:Lay0/k;

    .line 6
    .line 7
    iget-object v1, p0, Lc1/a;->g:Lc1/c;

    .line 8
    .line 9
    iget-object v2, p0, Lc1/a;->h:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v3, p0, Lc1/a;->i:Lc1/f;

    .line 12
    .line 13
    move-object v7, p1

    .line 14
    invoke-direct/range {v0 .. v7}, Lc1/a;-><init>(Lc1/c;Ljava/lang/Object;Lc1/f;JLay0/k;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lc1/a;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lc1/a;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lc1/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v5, p0

    .line 2
    .line 3
    iget-object v1, v5, Lc1/a;->i:Lc1/f;

    .line 4
    .line 5
    iget-object v7, v5, Lc1/a;->g:Lc1/c;

    .line 6
    .line 7
    iget-object v0, v7, Lc1/c;->c:Lc1/k;

    .line 8
    .line 9
    sget-object v12, Lqx0/a;->d:Lqx0/a;

    .line 10
    .line 11
    iget v2, v5, Lc1/a;->f:I

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    if-ne v2, v3, :cond_0

    .line 17
    .line 18
    iget-object v0, v5, Lc1/a;->e:Lkotlin/jvm/internal/b0;

    .line 19
    .line 20
    iget-object v1, v5, Lc1/a;->d:Lc1/k;

    .line 21
    .line 22
    :try_start_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catch_0
    move-exception v0

    .line 27
    goto/16 :goto_2

    .line 28
    .line 29
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 32
    .line 33
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw v0

    .line 37
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    :try_start_1
    iget-object v2, v7, Lc1/c;->a:Lc1/b2;

    .line 41
    .line 42
    iget-object v2, v2, Lc1/b2;->a:Lay0/k;

    .line 43
    .line 44
    iget-object v4, v5, Lc1/a;->h:Ljava/lang/Object;

    .line 45
    .line 46
    invoke-interface {v2, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    check-cast v2, Lc1/p;

    .line 51
    .line 52
    iput-object v2, v0, Lc1/k;->f:Lc1/p;

    .line 53
    .line 54
    invoke-interface {v1}, Lc1/f;->g()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    iget-object v4, v7, Lc1/c;->e:Ll2/j1;

    .line 59
    .line 60
    invoke-virtual {v4, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iget-object v2, v7, Lc1/c;->d:Ll2/j1;

    .line 64
    .line 65
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 66
    .line 67
    invoke-virtual {v2, v4}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iget-object v2, v0, Lc1/k;->e:Ll2/j1;

    .line 71
    .line 72
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v15

    .line 76
    iget-object v2, v0, Lc1/k;->f:Lc1/p;

    .line 77
    .line 78
    invoke-static {v2}, Lc1/d;->l(Lc1/p;)Lc1/p;

    .line 79
    .line 80
    .line 81
    move-result-object v16

    .line 82
    iget-wide v8, v0, Lc1/k;->g:J

    .line 83
    .line 84
    iget-boolean v2, v0, Lc1/k;->i:Z

    .line 85
    .line 86
    new-instance v13, Lc1/k;

    .line 87
    .line 88
    iget-object v14, v0, Lc1/k;->d:Lc1/b2;

    .line 89
    .line 90
    const-wide/high16 v19, -0x8000000000000000L

    .line 91
    .line 92
    move/from16 v21, v2

    .line 93
    .line 94
    move-wide/from16 v17, v8

    .line 95
    .line 96
    invoke-direct/range {v13 .. v21}, Lc1/k;-><init>(Lc1/b2;Ljava/lang/Object;Lc1/p;JJZ)V

    .line 97
    .line 98
    .line 99
    move-object v0, v13

    .line 100
    new-instance v10, Lkotlin/jvm/internal/b0;

    .line 101
    .line 102
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 103
    .line 104
    .line 105
    iget-wide v13, v5, Lc1/a;->j:J

    .line 106
    .line 107
    iget-object v9, v5, Lc1/a;->k:Lay0/k;

    .line 108
    .line 109
    new-instance v4, Lbg/a;

    .line 110
    .line 111
    const/4 v11, 0x1

    .line 112
    move-object v8, v0

    .line 113
    move-object v6, v4

    .line 114
    invoke-direct/range {v6 .. v11}, Lbg/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 115
    .line 116
    .line 117
    iput-object v0, v5, Lc1/a;->d:Lc1/k;

    .line 118
    .line 119
    iput-object v10, v5, Lc1/a;->e:Lkotlin/jvm/internal/b0;

    .line 120
    .line 121
    iput v3, v5, Lc1/a;->f:I

    .line 122
    .line 123
    move-wide v2, v13

    .line 124
    invoke-static/range {v0 .. v5}, Lc1/d;->d(Lc1/k;Lc1/f;JLay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    if-ne v1, v12, :cond_2

    .line 129
    .line 130
    return-object v12

    .line 131
    :cond_2
    move-object v1, v0

    .line 132
    move-object v0, v10

    .line 133
    :goto_0
    iget-boolean v0, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 134
    .line 135
    if-eqz v0, :cond_3

    .line 136
    .line 137
    sget-object v0, Lc1/g;->d:Lc1/g;

    .line 138
    .line 139
    goto :goto_1

    .line 140
    :cond_3
    sget-object v0, Lc1/g;->e:Lc1/g;

    .line 141
    .line 142
    :goto_1
    invoke-static {v7}, Lc1/c;->a(Lc1/c;)V

    .line 143
    .line 144
    .line 145
    new-instance v2, Lc1/h;

    .line 146
    .line 147
    invoke-direct {v2, v1, v0}, Lc1/h;-><init>(Lc1/k;Lc1/g;)V
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    .line 148
    .line 149
    .line 150
    return-object v2

    .line 151
    :goto_2
    invoke-static {v7}, Lc1/c;->a(Lc1/c;)V

    .line 152
    .line 153
    .line 154
    throw v0
.end method
