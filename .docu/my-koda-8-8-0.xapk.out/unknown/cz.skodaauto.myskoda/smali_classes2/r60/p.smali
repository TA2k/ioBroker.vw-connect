.class public final Lr60/p;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/k;

.field public final i:Lp60/j;

.field public final j:Lp60/k;

.field public final k:Lnn0/e;

.field public final l:Lp60/e;

.field public final m:Lp60/a;

.field public final n:Lp60/f0;

.field public final o:Lbd0/c;

.field public final p:Lij0/a;

.field public final q:Lrq0/f;

.field public final r:Lnn0/g;

.field public final s:Lp60/s;

.field public final t:Lp60/d;


# direct methods
.method public constructor <init>(Lkf0/k;Lp60/j;Lp60/k;Lnn0/e;Lp60/e;Lp60/a;Lp60/f0;Lbd0/c;Ltr0/b;Lij0/a;Lrq0/f;Lnn0/g;Lp60/s;Lp60/d;)V
    .locals 7

    .line 1
    new-instance v0, Lr60/m;

    .line 2
    .line 3
    const/4 v3, 0x0

    .line 4
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    const-string v1, ""

    .line 7
    .line 8
    const/4 v5, 0x0

    .line 9
    move-object v2, v1

    .line 10
    move-object v6, v1

    .line 11
    invoke-direct/range {v0 .. v6}, Lr60/m;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/util/List;Lql0/g;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lr60/p;->h:Lkf0/k;

    .line 18
    .line 19
    iput-object p2, p0, Lr60/p;->i:Lp60/j;

    .line 20
    .line 21
    iput-object p3, p0, Lr60/p;->j:Lp60/k;

    .line 22
    .line 23
    iput-object p4, p0, Lr60/p;->k:Lnn0/e;

    .line 24
    .line 25
    iput-object p5, p0, Lr60/p;->l:Lp60/e;

    .line 26
    .line 27
    iput-object p6, p0, Lr60/p;->m:Lp60/a;

    .line 28
    .line 29
    iput-object p7, p0, Lr60/p;->n:Lp60/f0;

    .line 30
    .line 31
    iput-object p8, p0, Lr60/p;->o:Lbd0/c;

    .line 32
    .line 33
    move-object/from16 p1, p10

    .line 34
    .line 35
    iput-object p1, p0, Lr60/p;->p:Lij0/a;

    .line 36
    .line 37
    move-object/from16 p1, p11

    .line 38
    .line 39
    iput-object p1, p0, Lr60/p;->q:Lrq0/f;

    .line 40
    .line 41
    move-object/from16 p1, p12

    .line 42
    .line 43
    iput-object p1, p0, Lr60/p;->r:Lnn0/g;

    .line 44
    .line 45
    move-object/from16 p1, p13

    .line 46
    .line 47
    iput-object p1, p0, Lr60/p;->s:Lp60/s;

    .line 48
    .line 49
    move-object/from16 p1, p14

    .line 50
    .line 51
    iput-object p1, p0, Lr60/p;->t:Lp60/d;

    .line 52
    .line 53
    new-instance p1, La7/k0;

    .line 54
    .line 55
    const/4 p2, 0x0

    .line 56
    invoke-direct {p1, p0, p2}, La7/k0;-><init>(Lr60/p;Lkotlin/coroutines/Continuation;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 60
    .line 61
    .line 62
    return-void
.end method

.method public static final h(Lr60/p;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p1, Lr60/o;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Lr60/o;

    .line 10
    .line 11
    iget v1, v0, Lr60/o;->h:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    and-int v3, v1, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    sub-int/2addr v1, v2

    .line 20
    iput v1, v0, Lr60/o;->h:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Lr60/o;

    .line 24
    .line 25
    invoke-direct {v0, p0, p1}, Lr60/o;-><init>(Lr60/p;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p1, v0, Lr60/o;->f:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Lr60/o;->h:I

    .line 33
    .line 34
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    const/4 v4, 0x2

    .line 37
    const/4 v5, 0x1

    .line 38
    if-eqz v2, :cond_3

    .line 39
    .line 40
    if-eq v2, v5, :cond_2

    .line 41
    .line 42
    if-ne v2, v4, :cond_1

    .line 43
    .line 44
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object v3

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    iget-object p0, v0, Lr60/o;->e:Lij0/a;

    .line 57
    .line 58
    iget-object v2, v0, Lr60/o;->d:Lrq0/f;

    .line 59
    .line 60
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iget-object v2, p0, Lr60/p;->q:Lrq0/f;

    .line 68
    .line 69
    iget-object p1, p0, Lr60/p;->p:Lij0/a;

    .line 70
    .line 71
    iget-object p0, p0, Lr60/p;->h:Lkf0/k;

    .line 72
    .line 73
    iput-object v2, v0, Lr60/o;->d:Lrq0/f;

    .line 74
    .line 75
    iput-object p1, v0, Lr60/o;->e:Lij0/a;

    .line 76
    .line 77
    iput v5, v0, Lr60/o;->h:I

    .line 78
    .line 79
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    if-ne p0, v1, :cond_4

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_4
    move-object v7, p1

    .line 90
    move-object p1, p0

    .line 91
    move-object p0, v7

    .line 92
    :goto_1
    check-cast p1, Lss0/b;

    .line 93
    .line 94
    const v5, 0x7f120df2

    .line 95
    .line 96
    .line 97
    const v6, 0x7f120df1

    .line 98
    .line 99
    .line 100
    invoke-static {p0, p1, v5, v6}, Lkp/m;->d(Lij0/a;Lss0/b;II)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    new-instance p1, Lsq0/c;

    .line 105
    .line 106
    const/4 v5, 0x6

    .line 107
    const/4 v6, 0x0

    .line 108
    invoke-direct {p1, v5, p0, v6, v6}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    iput-object v6, v0, Lr60/o;->d:Lrq0/f;

    .line 112
    .line 113
    iput-object v6, v0, Lr60/o;->e:Lij0/a;

    .line 114
    .line 115
    iput v4, v0, Lr60/o;->h:I

    .line 116
    .line 117
    const/4 p0, 0x0

    .line 118
    invoke-virtual {v2, p1, p0, v0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    if-ne p0, v1, :cond_5

    .line 123
    .line 124
    :goto_2
    return-object v1

    .line 125
    :cond_5
    return-object v3
.end method
