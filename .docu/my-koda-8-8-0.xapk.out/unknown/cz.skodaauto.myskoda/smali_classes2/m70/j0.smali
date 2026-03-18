.class public final Lm70/j0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lk70/l0;

.field public final i:Lk70/m0;

.field public final j:Lk70/n0;

.field public final k:Lk70/m;

.field public final l:Lk70/c1;

.field public final m:Lk70/e1;

.field public final n:Lcs0/l;

.field public final o:Ltr0/b;

.field public final p:Lij0/a;

.field public final q:Lrq0/d;

.field public final r:Lkf0/v;

.field public final s:Lk70/t0;

.field public final t:Lk70/y0;

.field public u:Lvy0/x1;


# direct methods
.method public constructor <init>(Lk70/l0;Lk70/m0;Lk70/n0;Lk70/m;Lk70/c1;Lk70/e1;Lcs0/l;Ltr0/b;Lij0/a;Lrq0/d;Lkf0/v;Lk70/t0;Lk70/y0;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lm70/g0;

    .line 4
    .line 5
    sget-object v2, Ler0/g;->f:Ler0/g;

    .line 6
    .line 7
    const/16 v3, 0x1fff

    .line 8
    .line 9
    and-int/lit8 v4, v3, 0x1

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    sget-object v2, Ler0/g;->d:Ler0/g;

    .line 14
    .line 15
    :cond_0
    sget-object v4, Lqr0/s;->d:Lqr0/s;

    .line 16
    .line 17
    new-instance v9, Lm70/f0;

    .line 18
    .line 19
    sget-object v5, Lmx0/s;->d:Lmx0/s;

    .line 20
    .line 21
    invoke-direct {v9, v5}, Lm70/f0;-><init>(Ljava/util/List;)V

    .line 22
    .line 23
    .line 24
    and-int/lit16 v3, v3, 0x1000

    .line 25
    .line 26
    const/4 v15, 0x0

    .line 27
    if-eqz v3, :cond_1

    .line 28
    .line 29
    sget-object v3, Llf0/i;->j:Llf0/i;

    .line 30
    .line 31
    move-object v14, v3

    .line 32
    goto :goto_0

    .line 33
    :cond_1
    move-object v14, v15

    .line 34
    :goto_0
    sget-object v3, Lmx0/t;->d:Lmx0/t;

    .line 35
    .line 36
    const/4 v6, 0x0

    .line 37
    const/4 v7, 0x0

    .line 38
    const/4 v8, 0x0

    .line 39
    const/4 v10, 0x0

    .line 40
    const-string v11, ""

    .line 41
    .line 42
    const/4 v13, 0x1

    .line 43
    move-object v12, v5

    .line 44
    invoke-direct/range {v1 .. v14}, Lm70/g0;-><init>(Ler0/g;Ljava/util/Map;Lqr0/s;Ljava/util/List;ILjava/lang/Integer;ZLm70/f0;ZLjava/lang/String;Ljava/util/List;ZLlf0/i;)V

    .line 45
    .line 46
    .line 47
    invoke-direct {v0, v1}, Lql0/j;-><init>(Lql0/h;)V

    .line 48
    .line 49
    .line 50
    move-object/from16 v1, p1

    .line 51
    .line 52
    iput-object v1, v0, Lm70/j0;->h:Lk70/l0;

    .line 53
    .line 54
    move-object/from16 v1, p2

    .line 55
    .line 56
    iput-object v1, v0, Lm70/j0;->i:Lk70/m0;

    .line 57
    .line 58
    move-object/from16 v1, p3

    .line 59
    .line 60
    iput-object v1, v0, Lm70/j0;->j:Lk70/n0;

    .line 61
    .line 62
    move-object/from16 v1, p4

    .line 63
    .line 64
    iput-object v1, v0, Lm70/j0;->k:Lk70/m;

    .line 65
    .line 66
    move-object/from16 v1, p5

    .line 67
    .line 68
    iput-object v1, v0, Lm70/j0;->l:Lk70/c1;

    .line 69
    .line 70
    move-object/from16 v1, p6

    .line 71
    .line 72
    iput-object v1, v0, Lm70/j0;->m:Lk70/e1;

    .line 73
    .line 74
    move-object/from16 v1, p7

    .line 75
    .line 76
    iput-object v1, v0, Lm70/j0;->n:Lcs0/l;

    .line 77
    .line 78
    move-object/from16 v1, p8

    .line 79
    .line 80
    iput-object v1, v0, Lm70/j0;->o:Ltr0/b;

    .line 81
    .line 82
    move-object/from16 v1, p9

    .line 83
    .line 84
    iput-object v1, v0, Lm70/j0;->p:Lij0/a;

    .line 85
    .line 86
    move-object/from16 v1, p10

    .line 87
    .line 88
    iput-object v1, v0, Lm70/j0;->q:Lrq0/d;

    .line 89
    .line 90
    move-object/from16 v1, p11

    .line 91
    .line 92
    iput-object v1, v0, Lm70/j0;->r:Lkf0/v;

    .line 93
    .line 94
    move-object/from16 v1, p12

    .line 95
    .line 96
    iput-object v1, v0, Lm70/j0;->s:Lk70/t0;

    .line 97
    .line 98
    move-object/from16 v1, p13

    .line 99
    .line 100
    iput-object v1, v0, Lm70/j0;->t:Lk70/y0;

    .line 101
    .line 102
    new-instance v1, Lk31/t;

    .line 103
    .line 104
    const/16 v2, 0x1c

    .line 105
    .line 106
    invoke-direct {v1, v0, v15, v2}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v0, v1}, Lql0/j;->b(Lay0/n;)V

    .line 110
    .line 111
    .line 112
    return-void
.end method


# virtual methods
.method public final h(Ll70/s;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "filter"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    move-object v3, v2

    .line 15
    check-cast v3, Lm70/g0;

    .line 16
    .line 17
    const/16 v16, 0x0

    .line 18
    .line 19
    const/16 v17, 0x1fdf

    .line 20
    .line 21
    const/4 v4, 0x0

    .line 22
    const/4 v5, 0x0

    .line 23
    const/4 v6, 0x0

    .line 24
    const/4 v7, 0x0

    .line 25
    const/4 v8, 0x0

    .line 26
    const/4 v9, 0x0

    .line 27
    const/4 v10, 0x0

    .line 28
    const/4 v11, 0x0

    .line 29
    const/4 v12, 0x0

    .line 30
    const/4 v13, 0x0

    .line 31
    const/4 v14, 0x0

    .line 32
    const/4 v15, 0x0

    .line 33
    invoke-static/range {v3 .. v17}, Lm70/g0;->a(Lm70/g0;Ler0/g;Ljava/util/Map;Lqr0/s;Ljava/util/List;ILjava/lang/Integer;ZLm70/f0;ZLjava/lang/String;Ljava/util/ArrayList;ZLlf0/i;I)Lm70/g0;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 38
    .line 39
    .line 40
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    new-instance v3, Lk31/t;

    .line 45
    .line 46
    const/16 v4, 0x1d

    .line 47
    .line 48
    invoke-direct {v3, v4, v0, v1, v5}, Lk31/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 49
    .line 50
    .line 51
    const/4 v0, 0x3

    .line 52
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 53
    .line 54
    .line 55
    return-void
.end method
