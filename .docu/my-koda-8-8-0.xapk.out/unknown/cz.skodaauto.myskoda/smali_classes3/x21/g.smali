.class public final Lx21/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Z

.field public final synthetic g:Lx21/c;

.field public final synthetic h:Lay0/n;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Ll2/b1;

.field public final synthetic k:Lvy0/b0;

.field public final synthetic l:Ll2/b1;

.field public final synthetic m:Lay0/a;


# direct methods
.method public constructor <init>(ZLx21/c;Lay0/n;Lay0/k;Ll2/b1;Lvy0/b0;Ll2/b1;Lay0/a;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lx21/g;->f:Z

    .line 2
    .line 3
    iput-object p2, p0, Lx21/g;->g:Lx21/c;

    .line 4
    .line 5
    iput-object p3, p0, Lx21/g;->h:Lay0/n;

    .line 6
    .line 7
    iput-object p4, p0, Lx21/g;->i:Lay0/k;

    .line 8
    .line 9
    iput-object p5, p0, Lx21/g;->j:Ll2/b1;

    .line 10
    .line 11
    iput-object p6, p0, Lx21/g;->k:Lvy0/b0;

    .line 12
    .line 13
    iput-object p7, p0, Lx21/g;->l:Ll2/b1;

    .line 14
    .line 15
    iput-object p8, p0, Lx21/g;->m:Lay0/a;

    .line 16
    .line 17
    const/4 p1, 0x2

    .line 18
    invoke-direct {p0, p1, p9}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 10

    .line 1
    new-instance v0, Lx21/g;

    .line 2
    .line 3
    iget-object v7, p0, Lx21/g;->l:Ll2/b1;

    .line 4
    .line 5
    iget-object v8, p0, Lx21/g;->m:Lay0/a;

    .line 6
    .line 7
    iget-boolean v1, p0, Lx21/g;->f:Z

    .line 8
    .line 9
    iget-object v2, p0, Lx21/g;->g:Lx21/c;

    .line 10
    .line 11
    iget-object v3, p0, Lx21/g;->h:Lay0/n;

    .line 12
    .line 13
    iget-object v4, p0, Lx21/g;->i:Lay0/k;

    .line 14
    .line 15
    iget-object v5, p0, Lx21/g;->j:Ll2/b1;

    .line 16
    .line 17
    iget-object v6, p0, Lx21/g;->k:Lvy0/b0;

    .line 18
    .line 19
    move-object v9, p2

    .line 20
    invoke-direct/range {v0 .. v9}, Lx21/g;-><init>(ZLx21/c;Lay0/n;Lay0/k;Ll2/b1;Lvy0/b0;Ll2/b1;Lay0/a;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    iput-object p1, v0, Lx21/g;->e:Ljava/lang/Object;

    .line 24
    .line 25
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lp3/x;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lx21/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lx21/g;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lx21/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Lx21/g;->d:I

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    if-eqz v2, :cond_1

    .line 11
    .line 12
    if-ne v2, v3, :cond_0

    .line 13
    .line 14
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-object v4

    .line 18
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 21
    .line 22
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw v0

    .line 26
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iget-object v2, v0, Lx21/g;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v2, Lp3/x;

    .line 32
    .line 33
    iget-boolean v5, v0, Lx21/g;->f:Z

    .line 34
    .line 35
    if-nez v5, :cond_2

    .line 36
    .line 37
    goto/16 :goto_3

    .line 38
    .line 39
    :cond_2
    new-instance v6, Lkn/k;

    .line 40
    .line 41
    const/4 v11, 0x2

    .line 42
    iget-object v7, v0, Lx21/g;->i:Lay0/k;

    .line 43
    .line 44
    iget-object v8, v0, Lx21/g;->j:Ll2/b1;

    .line 45
    .line 46
    iget-object v15, v0, Lx21/g;->k:Lvy0/b0;

    .line 47
    .line 48
    iget-object v14, v0, Lx21/g;->l:Ll2/b1;

    .line 49
    .line 50
    move-object v10, v14

    .line 51
    move-object v9, v15

    .line 52
    invoke-direct/range {v6 .. v11}, Lkn/k;-><init>(Llx0/e;Ll2/b1;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 53
    .line 54
    .line 55
    move-object/from16 v16, v8

    .line 56
    .line 57
    new-instance v12, Lx21/f;

    .line 58
    .line 59
    const/16 v17, 0x0

    .line 60
    .line 61
    iget-object v13, v0, Lx21/g;->m:Lay0/a;

    .line 62
    .line 63
    invoke-direct/range {v12 .. v17}, Lx21/f;-><init>(Lay0/a;Ll2/b1;Lvy0/b0;Ll2/b1;I)V

    .line 64
    .line 65
    .line 66
    move-object v5, v12

    .line 67
    new-instance v23, Lx21/f;

    .line 68
    .line 69
    const/16 v17, 0x1

    .line 70
    .line 71
    move-object/from16 v12, v23

    .line 72
    .line 73
    invoke-direct/range {v12 .. v17}, Lx21/f;-><init>(Lay0/a;Ll2/b1;Lvy0/b0;Ll2/b1;I)V

    .line 74
    .line 75
    .line 76
    iput v3, v0, Lx21/g;->d:I

    .line 77
    .line 78
    sget v3, Lg1/w0;->a:F

    .line 79
    .line 80
    new-instance v3, Lak/l;

    .line 81
    .line 82
    const/16 v7, 0xb

    .line 83
    .line 84
    invoke-direct {v3, v7, v6}, Lak/l;-><init>(ILay0/k;)V

    .line 85
    .line 86
    .line 87
    new-instance v6, Laj0/c;

    .line 88
    .line 89
    const/16 v7, 0x17

    .line 90
    .line 91
    invoke-direct {v6, v5, v7}, Laj0/c;-><init>(Lay0/a;I)V

    .line 92
    .line 93
    .line 94
    new-instance v5, Lf2/h0;

    .line 95
    .line 96
    const/16 v7, 0xf

    .line 97
    .line 98
    invoke-direct {v5, v7}, Lf2/h0;-><init>(I)V

    .line 99
    .line 100
    .line 101
    new-instance v19, Lkotlin/jvm/internal/e0;

    .line 102
    .line 103
    invoke-direct/range {v19 .. v19}, Ljava/lang/Object;-><init>()V

    .line 104
    .line 105
    .line 106
    new-instance v17, Lg1/q0;

    .line 107
    .line 108
    const/16 v25, 0x0

    .line 109
    .line 110
    const/16 v20, 0x0

    .line 111
    .line 112
    iget-object v7, v0, Lx21/g;->h:Lay0/n;

    .line 113
    .line 114
    move-object/from16 v21, v3

    .line 115
    .line 116
    move-object/from16 v18, v5

    .line 117
    .line 118
    move-object/from16 v24, v6

    .line 119
    .line 120
    move-object/from16 v22, v7

    .line 121
    .line 122
    invoke-direct/range {v17 .. v25}, Lg1/q0;-><init>(Lay0/a;Lkotlin/jvm/internal/e0;Lg1/w1;Lay0/o;Lay0/n;Lay0/a;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 123
    .line 124
    .line 125
    move-object/from16 v3, v17

    .line 126
    .line 127
    invoke-static {v2, v3, v0}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    if-ne v0, v1, :cond_3

    .line 132
    .line 133
    goto :goto_0

    .line 134
    :cond_3
    move-object v0, v4

    .line 135
    :goto_0
    if-ne v0, v1, :cond_4

    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_4
    move-object v0, v4

    .line 139
    :goto_1
    if-ne v0, v1, :cond_5

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_5
    move-object v0, v4

    .line 143
    :goto_2
    if-ne v0, v1, :cond_6

    .line 144
    .line 145
    return-object v1

    .line 146
    :cond_6
    :goto_3
    return-object v4
.end method
