.class public final Lr60/l;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/k;

.field public final i:Lwr0/e;

.field public final j:Lp60/h0;

.field public final k:Ltr0/b;

.field public final l:Lnn0/h;

.field public final m:Lp60/u;

.field public final n:Lp60/i;

.field public final o:Lij0/a;

.field public final p:Lp60/d;


# direct methods
.method public constructor <init>(Lnn0/e;Lkf0/k;Lwr0/e;Lp60/h0;Ltr0/b;Lnn0/h;Lp60/u;Lp60/i;Lij0/a;Lp60/d;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lr60/i;

    .line 4
    .line 5
    const/4 v15, 0x0

    .line 6
    const/16 v16, 0x0

    .line 7
    .line 8
    const-string v2, ""

    .line 9
    .line 10
    const/4 v10, 0x0

    .line 11
    const/4 v11, 0x0

    .line 12
    const/4 v12, 0x0

    .line 13
    sget-object v13, Lmx0/s;->d:Lmx0/s;

    .line 14
    .line 15
    const/4 v14, 0x0

    .line 16
    move-object v3, v2

    .line 17
    move-object v4, v2

    .line 18
    move-object v5, v2

    .line 19
    move-object v6, v2

    .line 20
    move-object v7, v2

    .line 21
    move-object v8, v2

    .line 22
    move-object v9, v2

    .line 23
    invoke-direct/range {v1 .. v16}, Lr60/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/List;Lql0/g;ZZ)V

    .line 24
    .line 25
    .line 26
    invoke-direct {v0, v1}, Lql0/j;-><init>(Lql0/h;)V

    .line 27
    .line 28
    .line 29
    move-object/from16 v1, p2

    .line 30
    .line 31
    iput-object v1, v0, Lr60/l;->h:Lkf0/k;

    .line 32
    .line 33
    move-object/from16 v1, p3

    .line 34
    .line 35
    iput-object v1, v0, Lr60/l;->i:Lwr0/e;

    .line 36
    .line 37
    move-object/from16 v1, p4

    .line 38
    .line 39
    iput-object v1, v0, Lr60/l;->j:Lp60/h0;

    .line 40
    .line 41
    move-object/from16 v1, p5

    .line 42
    .line 43
    iput-object v1, v0, Lr60/l;->k:Ltr0/b;

    .line 44
    .line 45
    move-object/from16 v1, p6

    .line 46
    .line 47
    iput-object v1, v0, Lr60/l;->l:Lnn0/h;

    .line 48
    .line 49
    move-object/from16 v1, p7

    .line 50
    .line 51
    iput-object v1, v0, Lr60/l;->m:Lp60/u;

    .line 52
    .line 53
    move-object/from16 v1, p8

    .line 54
    .line 55
    iput-object v1, v0, Lr60/l;->n:Lp60/i;

    .line 56
    .line 57
    move-object/from16 v1, p9

    .line 58
    .line 59
    iput-object v1, v0, Lr60/l;->o:Lij0/a;

    .line 60
    .line 61
    move-object/from16 v1, p10

    .line 62
    .line 63
    iput-object v1, v0, Lr60/l;->p:Lp60/d;

    .line 64
    .line 65
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    new-instance v2, Lk90/b;

    .line 70
    .line 71
    const/4 v3, 0x1

    .line 72
    const/4 v4, 0x0

    .line 73
    move-object/from16 v5, p1

    .line 74
    .line 75
    invoke-direct {v2, v3, v0, v5, v4}, Lk90/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 76
    .line 77
    .line 78
    const/4 v0, 0x3

    .line 79
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 80
    .line 81
    .line 82
    return-void
.end method


# virtual methods
.method public final h(Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lr60/i;

    .line 6
    .line 7
    iget-object p0, p0, Lr60/i;->l:Ljava/util/List;

    .line 8
    .line 9
    check-cast p0, Ljava/lang/Iterable;

    .line 10
    .line 11
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    move-object v1, v0

    .line 26
    check-cast v1, Lr60/j;

    .line 27
    .line 28
    iget-object v1, v1, Lr60/j;->a:Ljava/lang/String;

    .line 29
    .line 30
    const-string v2, "<this>"

    .line 31
    .line 32
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    const-string v2, "other"

    .line 36
    .line 37
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v1, p1}, Ljava/lang/String;->compareToIgnoreCase(Ljava/lang/String;)I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-nez v1, :cond_0

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    const/4 v0, 0x0

    .line 48
    :goto_0
    check-cast v0, Lr60/j;

    .line 49
    .line 50
    if-eqz v0, :cond_2

    .line 51
    .line 52
    iget-object p0, v0, Lr60/j;->b:Ljava/lang/String;

    .line 53
    .line 54
    if-eqz p0, :cond_2

    .line 55
    .line 56
    return-object p0

    .line 57
    :cond_2
    return-object p1
.end method

.method public final j(Lne0/c;)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    move-object v2, v1

    .line 8
    check-cast v2, Lr60/i;

    .line 9
    .line 10
    iget-object v1, v0, Lr60/l;->o:Lij0/a;

    .line 11
    .line 12
    move-object/from16 v3, p1

    .line 13
    .line 14
    invoke-static {v3, v1}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 15
    .line 16
    .line 17
    move-result-object v15

    .line 18
    const/16 v17, 0x0

    .line 19
    .line 20
    const/16 v18, 0x6dff

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    const/4 v4, 0x0

    .line 24
    const/4 v5, 0x0

    .line 25
    const/4 v6, 0x0

    .line 26
    const/4 v7, 0x0

    .line 27
    const/4 v8, 0x0

    .line 28
    const/4 v9, 0x0

    .line 29
    const/4 v10, 0x0

    .line 30
    const/4 v11, 0x0

    .line 31
    const/4 v12, 0x0

    .line 32
    const/4 v13, 0x0

    .line 33
    const/4 v14, 0x0

    .line 34
    const/16 v16, 0x0

    .line 35
    .line 36
    invoke-static/range {v2 .. v18}, Lr60/i;->a(Lr60/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/ArrayList;Lql0/g;ZZI)Lr60/i;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public final k()V
    .locals 19

    .line 1
    invoke-virtual/range {p0 .. p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lr60/i;

    .line 6
    .line 7
    invoke-virtual/range {p0 .. p0}, Lql0/j;->a()Lql0/h;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    move-object v2, v1

    .line 12
    check-cast v2, Lr60/i;

    .line 13
    .line 14
    iget-object v1, v0, Lr60/i;->c:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v3, v0, Lr60/i;->d:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v4, v0, Lr60/i;->e:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v5, v0, Lr60/i;->f:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v0, v0, Lr60/i;->g:Ljava/lang/String;

    .line 23
    .line 24
    filled-new-array {v1, v3, v4, v5, v0}, [Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    check-cast v0, Ljava/lang/Iterable;

    .line 33
    .line 34
    instance-of v1, v0, Ljava/util/Collection;

    .line 35
    .line 36
    const/4 v3, 0x1

    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    move-object v1, v0

    .line 40
    check-cast v1, Ljava/util/Collection;

    .line 41
    .line 42
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_1

    .line 47
    .line 48
    :cond_0
    :goto_0
    move v11, v3

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-eqz v1, :cond_0

    .line 59
    .line 60
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    check-cast v1, Ljava/lang/String;

    .line 65
    .line 66
    invoke-static {v1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-eqz v1, :cond_2

    .line 71
    .line 72
    const/4 v3, 0x0

    .line 73
    goto :goto_0

    .line 74
    :goto_1
    const/16 v17, 0x0

    .line 75
    .line 76
    const/16 v18, 0x7eff

    .line 77
    .line 78
    const/4 v3, 0x0

    .line 79
    const/4 v4, 0x0

    .line 80
    const/4 v5, 0x0

    .line 81
    const/4 v6, 0x0

    .line 82
    const/4 v7, 0x0

    .line 83
    const/4 v8, 0x0

    .line 84
    const/4 v9, 0x0

    .line 85
    const/4 v10, 0x0

    .line 86
    const/4 v12, 0x0

    .line 87
    const/4 v13, 0x0

    .line 88
    const/4 v14, 0x0

    .line 89
    const/4 v15, 0x0

    .line 90
    const/16 v16, 0x0

    .line 91
    .line 92
    invoke-static/range {v2 .. v18}, Lr60/i;->a(Lr60/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/ArrayList;Lql0/g;ZZI)Lr60/i;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    move-object/from16 v1, p0

    .line 97
    .line 98
    invoke-virtual {v1, v0}, Lql0/j;->g(Lql0/h;)V

    .line 99
    .line 100
    .line 101
    return-void
.end method
