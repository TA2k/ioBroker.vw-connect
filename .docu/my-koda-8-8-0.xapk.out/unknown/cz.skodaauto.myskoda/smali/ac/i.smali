.class public final Lac/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Z

.field public final b:Ljava/lang/Object;

.field public final c:Ljava/lang/Object;

.field public final d:Ljava/lang/Object;

.field public final e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;

.field public final g:Ljava/lang/Object;

.field public final h:Ljava/lang/Object;

.field public final i:Ljava/lang/Object;

.field public final j:Ljava/lang/Object;

.field public k:Ljava/lang/Object;

.field public l:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 30
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x4

    .line 31
    new-array v1, v0, [Lwq/u;

    iput-object v1, p0, Lac/i;->b:Ljava/lang/Object;

    .line 32
    new-array v1, v0, [Landroid/graphics/Matrix;

    iput-object v1, p0, Lac/i;->c:Ljava/lang/Object;

    .line 33
    new-array v1, v0, [Landroid/graphics/Matrix;

    iput-object v1, p0, Lac/i;->d:Ljava/lang/Object;

    .line 34
    new-instance v1, Landroid/graphics/PointF;

    invoke-direct {v1}, Landroid/graphics/PointF;-><init>()V

    iput-object v1, p0, Lac/i;->e:Ljava/lang/Object;

    .line 35
    new-instance v1, Landroid/graphics/Path;

    invoke-direct {v1}, Landroid/graphics/Path;-><init>()V

    iput-object v1, p0, Lac/i;->f:Ljava/lang/Object;

    .line 36
    new-instance v1, Landroid/graphics/Path;

    invoke-direct {v1}, Landroid/graphics/Path;-><init>()V

    iput-object v1, p0, Lac/i;->g:Ljava/lang/Object;

    .line 37
    new-instance v1, Lwq/u;

    invoke-direct {v1}, Lwq/u;-><init>()V

    iput-object v1, p0, Lac/i;->h:Ljava/lang/Object;

    const/4 v1, 0x2

    .line 38
    new-array v2, v1, [F

    iput-object v2, p0, Lac/i;->i:Ljava/lang/Object;

    .line 39
    new-array v1, v1, [F

    iput-object v1, p0, Lac/i;->j:Ljava/lang/Object;

    .line 40
    new-instance v1, Landroid/graphics/Path;

    invoke-direct {v1}, Landroid/graphics/Path;-><init>()V

    iput-object v1, p0, Lac/i;->k:Ljava/lang/Object;

    .line 41
    new-instance v1, Landroid/graphics/Path;

    invoke-direct {v1}, Landroid/graphics/Path;-><init>()V

    iput-object v1, p0, Lac/i;->l:Ljava/lang/Object;

    const/4 v1, 0x1

    .line 42
    iput-boolean v1, p0, Lac/i;->a:Z

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    .line 43
    iget-object v2, p0, Lac/i;->b:Ljava/lang/Object;

    check-cast v2, [Lwq/u;

    new-instance v3, Lwq/u;

    invoke-direct {v3}, Lwq/u;-><init>()V

    aput-object v3, v2, v1

    .line 44
    iget-object v2, p0, Lac/i;->c:Ljava/lang/Object;

    check-cast v2, [Landroid/graphics/Matrix;

    new-instance v3, Landroid/graphics/Matrix;

    invoke-direct {v3}, Landroid/graphics/Matrix;-><init>()V

    aput-object v3, v2, v1

    .line 45
    iget-object v2, p0, Lac/i;->d:Ljava/lang/Object;

    check-cast v2, [Landroid/graphics/Matrix;

    new-instance v3, Landroid/graphics/Matrix;

    invoke-direct {v3}, Landroid/graphics/Matrix;-><init>()V

    aput-object v3, v2, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public constructor <init>(La8/q0;Lb8/e;Lw7/t;Lb8/k;)V
    .locals 0

    .line 46
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 47
    iput-object p4, p0, Lac/i;->b:Ljava/lang/Object;

    .line 48
    iput-object p1, p0, Lac/i;->f:Ljava/lang/Object;

    .line 49
    new-instance p1, Lh8/a1;

    invoke-direct {p1}, Lh8/a1;-><init>()V

    iput-object p1, p0, Lac/i;->k:Ljava/lang/Object;

    .line 50
    new-instance p1, Ljava/util/IdentityHashMap;

    invoke-direct {p1}, Ljava/util/IdentityHashMap;-><init>()V

    iput-object p1, p0, Lac/i;->d:Ljava/lang/Object;

    .line 51
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lac/i;->e:Ljava/lang/Object;

    .line 52
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lac/i;->c:Ljava/lang/Object;

    .line 53
    iput-object p2, p0, Lac/i;->i:Ljava/lang/Object;

    .line 54
    iput-object p3, p0, Lac/i;->j:Ljava/lang/Object;

    .line 55
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lac/i;->g:Ljava/lang/Object;

    .line 56
    new-instance p1, Ljava/util/HashSet;

    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    iput-object p1, p0, Lac/i;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lr7/a;Lac/a0;ZLac/e;Ljava/util/List;)V
    .locals 26

    move-object/from16 v0, p0

    move-object/from16 v1, p4

    move-object/from16 v2, p5

    const-string v3, "userLegalCountry"

    move-object/from16 v4, p2

    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "initialCountries"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    move/from16 v14, p3

    .line 2
    iput-boolean v14, v0, Lac/i;->a:Z

    const/4 v3, 0x0

    if-eqz v1, :cond_0

    .line 3
    iget-object v5, v1, Lac/e;->d:Ljava/lang/String;

    goto :goto_0

    :cond_0
    move-object v5, v3

    .line 4
    :goto_0
    invoke-static {v5}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v5

    iput-object v5, v0, Lac/i;->b:Ljava/lang/Object;

    if-eqz v1, :cond_1

    .line 5
    iget-object v6, v1, Lac/e;->e:Ljava/lang/String;

    goto :goto_1

    :cond_1
    move-object v6, v3

    .line 6
    :goto_1
    invoke-static {v6}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v6

    iput-object v6, v0, Lac/i;->c:Ljava/lang/Object;

    if-eqz v1, :cond_2

    .line 7
    iget-object v7, v1, Lac/e;->f:Ljava/lang/String;

    goto :goto_2

    :cond_2
    move-object v7, v3

    .line 8
    :goto_2
    invoke-static {v7}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v7

    iput-object v7, v0, Lac/i;->d:Ljava/lang/Object;

    if-eqz v1, :cond_3

    .line 9
    iget-object v8, v1, Lac/e;->g:Ljava/lang/String;

    goto :goto_3

    :cond_3
    move-object v8, v3

    .line 10
    :goto_3
    invoke-static {v8}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v8

    iput-object v8, v0, Lac/i;->e:Ljava/lang/Object;

    if-eqz v1, :cond_4

    .line 11
    iget-object v9, v1, Lac/e;->h:Ljava/lang/String;

    goto :goto_4

    :cond_4
    move-object v9, v3

    .line 12
    :goto_4
    invoke-static {v9}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v9

    iput-object v9, v0, Lac/i;->f:Ljava/lang/Object;

    if-eqz v1, :cond_5

    .line 13
    iget-object v10, v1, Lac/e;->i:Ljava/lang/String;

    goto :goto_5

    :cond_5
    move-object v10, v3

    .line 14
    :goto_5
    invoke-static {v10}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v10

    iput-object v10, v0, Lac/i;->g:Ljava/lang/Object;

    if-eqz v1, :cond_6

    .line 15
    iget-object v11, v1, Lac/e;->j:Ljava/lang/String;

    goto :goto_6

    :cond_6
    move-object v11, v3

    .line 16
    :goto_6
    invoke-static {v11}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v11

    iput-object v11, v0, Lac/i;->h:Ljava/lang/Object;

    if-eqz v1, :cond_7

    .line 17
    iget-object v12, v1, Lac/e;->l:Ljava/lang/String;

    goto :goto_7

    :cond_7
    move-object v12, v3

    .line 18
    :goto_7
    invoke-static {v12}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v12

    iput-object v12, v0, Lac/i;->i:Ljava/lang/Object;

    if-eqz v1, :cond_8

    .line 19
    iget-object v1, v1, Lac/e;->k:Lac/a0;

    if-nez v1, :cond_9

    :cond_8
    move-object v1, v4

    .line 20
    :cond_9
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v1

    iput-object v1, v0, Lac/i;->j:Ljava/lang/Object;

    .line 21
    invoke-static {v2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v4

    iput-object v4, v0, Lac/i;->k:Ljava/lang/Object;

    .line 22
    new-instance v13, Lac/h;

    invoke-direct {v13, v0, v3}, Lac/h;-><init>(Lac/i;Lkotlin/coroutines/Continuation;)V

    const/16 v3, 0xa

    .line 23
    new-array v3, v3, [Lyy0/i;

    const/4 v15, 0x0

    aput-object v5, v3, v15

    const/4 v5, 0x1

    aput-object v6, v3, v5

    const/4 v6, 0x2

    aput-object v7, v3, v6

    const/4 v6, 0x3

    aput-object v8, v3, v6

    const/4 v6, 0x4

    aput-object v9, v3, v6

    const/4 v6, 0x5

    aput-object v10, v3, v6

    const/4 v6, 0x6

    aput-object v11, v3, v6

    const/4 v6, 0x7

    aput-object v1, v3, v6

    const/16 v1, 0x8

    aput-object v12, v3, v1

    const/16 v1, 0x9

    aput-object v4, v3, v1

    .line 24
    new-instance v1, Lac/l;

    invoke-direct {v1, v15, v3, v13}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 25
    sget-object v3, Lac/x;->v:Lac/x;

    .line 26
    check-cast v2, Ljava/util/Collection;

    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v2

    xor-int/lit8 v16, v2, 0x1

    .line 27
    iget-object v5, v3, Lac/x;->a:Ljava/lang/String;

    iget-object v6, v3, Lac/x;->b:Ljava/lang/String;

    iget-object v7, v3, Lac/x;->c:Ljava/lang/String;

    iget-object v8, v3, Lac/x;->d:Ljava/lang/String;

    iget-object v9, v3, Lac/x;->e:Ljava/lang/String;

    iget-object v10, v3, Lac/x;->f:Ljava/lang/String;

    iget-object v11, v3, Lac/x;->g:Ljava/lang/String;

    iget-object v12, v3, Lac/x;->h:Ljava/lang/String;

    iget-object v13, v3, Lac/x;->i:Ljava/lang/String;

    iget-object v15, v3, Lac/x;->k:Ljava/util/List;

    iget-object v2, v3, Lac/x;->m:Ljava/lang/String;

    iget-object v4, v3, Lac/x;->n:Ljava/lang/String;

    move-object/from16 v17, v2

    iget-object v2, v3, Lac/x;->o:Ljava/lang/String;

    move-object/from16 v19, v2

    iget-object v2, v3, Lac/x;->p:Ljava/lang/String;

    move-object/from16 v20, v2

    iget-object v2, v3, Lac/x;->q:Ljava/lang/String;

    move-object/from16 v21, v2

    iget-object v2, v3, Lac/x;->r:Ljava/lang/String;

    move-object/from16 v22, v2

    iget-object v2, v3, Lac/x;->s:Ljava/lang/String;

    move-object/from16 v23, v2

    iget-object v2, v3, Lac/x;->t:Ljava/lang/String;

    iget-boolean v3, v3, Lac/x;->u:Z

    move-object/from16 v24, v2

    .line 28
    const-string v2, "firstname"

    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "lastname"

    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "addressLine1"

    invoke-static {v7, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "addressLine2"

    invoke-static {v8, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "zip"

    invoke-static {v9, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "city"

    invoke-static {v10, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "state"

    invoke-static {v11, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "country"

    invoke-static {v12, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "taxNumber"

    invoke-static {v13, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "countries"

    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v18, v4

    new-instance v4, Lac/x;

    move/from16 v25, v3

    invoke-direct/range {v4 .. v25}, Lac/x;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/util/List;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 29
    sget-object v2, Lyy0/u1;->b:Lyy0/w1;

    move-object/from16 v3, p1

    invoke-static {v1, v3, v2, v4}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    move-result-object v1

    iput-object v1, v0, Lac/i;->l:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a(ILjava/util/ArrayList;Lh8/a1;)Lt7/p0;
    .locals 6

    .line 1
    iget-object v0, p0, Lac/i;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_4

    .line 10
    .line 11
    iput-object p3, p0, Lac/i;->k:Ljava/lang/Object;

    .line 12
    .line 13
    move p3, p1

    .line 14
    :goto_0
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    add-int/2addr v1, p1

    .line 19
    if-ge p3, v1, :cond_4

    .line 20
    .line 21
    sub-int v1, p3, p1

    .line 22
    .line 23
    invoke-virtual {p2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, La8/h1;

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    if-lez p3, :cond_0

    .line 31
    .line 32
    add-int/lit8 v3, p3, -0x1

    .line 33
    .line 34
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    check-cast v3, La8/h1;

    .line 39
    .line 40
    iget-object v4, v3, La8/h1;->a:Lh8/w;

    .line 41
    .line 42
    iget-object v4, v4, Lh8/w;->o:Lh8/u;

    .line 43
    .line 44
    iget v3, v3, La8/h1;->d:I

    .line 45
    .line 46
    iget-object v4, v4, Lh8/q;->b:Lt7/p0;

    .line 47
    .line 48
    invoke-virtual {v4}, Lt7/p0;->o()I

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    add-int/2addr v4, v3

    .line 53
    iput v4, v1, La8/h1;->d:I

    .line 54
    .line 55
    iput-boolean v2, v1, La8/h1;->e:Z

    .line 56
    .line 57
    iget-object v2, v1, La8/h1;->c:Ljava/util/ArrayList;

    .line 58
    .line 59
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_0
    iput v2, v1, La8/h1;->d:I

    .line 64
    .line 65
    iput-boolean v2, v1, La8/h1;->e:Z

    .line 66
    .line 67
    iget-object v2, v1, La8/h1;->c:Ljava/util/ArrayList;

    .line 68
    .line 69
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 70
    .line 71
    .line 72
    :goto_1
    iget-object v2, v1, La8/h1;->a:Lh8/w;

    .line 73
    .line 74
    iget-object v2, v2, Lh8/w;->o:Lh8/u;

    .line 75
    .line 76
    iget-object v2, v2, Lh8/q;->b:Lt7/p0;

    .line 77
    .line 78
    invoke-virtual {v2}, Lt7/p0;->o()I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    move v3, p3

    .line 83
    :goto_2
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 84
    .line 85
    .line 86
    move-result v4

    .line 87
    if-ge v3, v4, :cond_1

    .line 88
    .line 89
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    check-cast v4, La8/h1;

    .line 94
    .line 95
    iget v5, v4, La8/h1;->d:I

    .line 96
    .line 97
    add-int/2addr v5, v2

    .line 98
    iput v5, v4, La8/h1;->d:I

    .line 99
    .line 100
    add-int/lit8 v3, v3, 0x1

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_1
    invoke-virtual {v0, p3, v1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    iget-object v2, p0, Lac/i;->e:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v2, Ljava/util/HashMap;

    .line 109
    .line 110
    iget-object v3, v1, La8/h1;->b:Ljava/lang/Object;

    .line 111
    .line 112
    invoke-virtual {v2, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    iget-boolean v2, p0, Lac/i;->a:Z

    .line 116
    .line 117
    if-eqz v2, :cond_3

    .line 118
    .line 119
    invoke-virtual {p0, v1}, Lac/i;->i(La8/h1;)V

    .line 120
    .line 121
    .line 122
    iget-object v2, p0, Lac/i;->d:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v2, Ljava/util/IdentityHashMap;

    .line 125
    .line 126
    invoke-virtual {v2}, Ljava/util/IdentityHashMap;->isEmpty()Z

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    if-eqz v2, :cond_2

    .line 131
    .line 132
    iget-object v2, p0, Lac/i;->h:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast v2, Ljava/util/HashSet;

    .line 135
    .line 136
    invoke-virtual {v2, v1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    goto :goto_3

    .line 140
    :cond_2
    iget-object v2, p0, Lac/i;->g:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v2, Ljava/util/HashMap;

    .line 143
    .line 144
    invoke-virtual {v2, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    check-cast v1, La8/g1;

    .line 149
    .line 150
    if-eqz v1, :cond_3

    .line 151
    .line 152
    iget-object v2, v1, La8/g1;->a:Lh8/a;

    .line 153
    .line 154
    iget-object v1, v1, La8/g1;->b:La8/b1;

    .line 155
    .line 156
    invoke-virtual {v2, v1}, Lh8/a;->b(Lh8/c0;)V

    .line 157
    .line 158
    .line 159
    :cond_3
    :goto_3
    add-int/lit8 p3, p3, 0x1

    .line 160
    .line 161
    goto/16 :goto_0

    .line 162
    .line 163
    :cond_4
    invoke-virtual {p0}, Lac/i;->c()Lt7/p0;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    return-object p0
.end method

.method public b(Lwq/m;[FFLandroid/graphics/RectF;Lpv/g;Landroid/graphics/Path;)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    move-object/from16 v3, p5

    .line 8
    .line 9
    move-object/from16 v4, p6

    .line 10
    .line 11
    iget-object v5, v0, Lac/i;->d:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v5, [Landroid/graphics/Matrix;

    .line 14
    .line 15
    iget-object v6, v0, Lac/i;->i:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v6, [F

    .line 18
    .line 19
    iget-object v7, v0, Lac/i;->b:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v7, [Lwq/u;

    .line 22
    .line 23
    iget-object v8, v0, Lac/i;->c:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v8, [Landroid/graphics/Matrix;

    .line 26
    .line 27
    invoke-virtual {v4}, Landroid/graphics/Path;->rewind()V

    .line 28
    .line 29
    .line 30
    iget-object v9, v0, Lac/i;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v9, Landroid/graphics/Path;

    .line 33
    .line 34
    invoke-virtual {v9}, Landroid/graphics/Path;->rewind()V

    .line 35
    .line 36
    .line 37
    iget-object v10, v0, Lac/i;->g:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v10, Landroid/graphics/Path;

    .line 40
    .line 41
    invoke-virtual {v10}, Landroid/graphics/Path;->rewind()V

    .line 42
    .line 43
    .line 44
    sget-object v11, Landroid/graphics/Path$Direction;->CW:Landroid/graphics/Path$Direction;

    .line 45
    .line 46
    invoke-virtual {v10, v2, v11}, Landroid/graphics/Path;->addRect(Landroid/graphics/RectF;Landroid/graphics/Path$Direction;)V

    .line 47
    .line 48
    .line 49
    const/4 v12, 0x0

    .line 50
    :goto_0
    const/4 v13, 0x2

    .line 51
    const/4 v14, 0x3

    .line 52
    const/4 v15, 0x4

    .line 53
    const/16 v16, 0x0

    .line 54
    .line 55
    const/4 v11, 0x1

    .line 56
    if-ge v12, v15, :cond_a

    .line 57
    .line 58
    iget-object v15, v0, Lac/i;->e:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v15, Landroid/graphics/PointF;

    .line 61
    .line 62
    if-nez p2, :cond_3

    .line 63
    .line 64
    if-eq v12, v11, :cond_2

    .line 65
    .line 66
    if-eq v12, v13, :cond_1

    .line 67
    .line 68
    if-eq v12, v14, :cond_0

    .line 69
    .line 70
    iget-object v14, v1, Lwq/m;->f:Lwq/d;

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_0
    iget-object v14, v1, Lwq/m;->e:Lwq/d;

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    iget-object v14, v1, Lwq/m;->h:Lwq/d;

    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_2
    iget-object v14, v1, Lwq/m;->g:Lwq/d;

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    new-instance v14, Lwq/c;

    .line 83
    .line 84
    aget v13, p2, v12

    .line 85
    .line 86
    invoke-direct {v14, v13}, Lwq/c;-><init>(F)V

    .line 87
    .line 88
    .line 89
    :goto_1
    if-eq v12, v11, :cond_6

    .line 90
    .line 91
    const/4 v13, 0x2

    .line 92
    if-eq v12, v13, :cond_5

    .line 93
    .line 94
    const/4 v13, 0x3

    .line 95
    if-eq v12, v13, :cond_4

    .line 96
    .line 97
    iget-object v13, v1, Lwq/m;->b:Llp/nd;

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_4
    iget-object v13, v1, Lwq/m;->a:Llp/nd;

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_5
    iget-object v13, v1, Lwq/m;->d:Llp/nd;

    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_6
    iget-object v13, v1, Lwq/m;->c:Llp/nd;

    .line 107
    .line 108
    :goto_2
    aget-object v11, v7, v12

    .line 109
    .line 110
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 111
    .line 112
    .line 113
    invoke-interface {v14, v2}, Lwq/d;->a(Landroid/graphics/RectF;)F

    .line 114
    .line 115
    .line 116
    move-result v14

    .line 117
    move-object/from16 v18, v5

    .line 118
    .line 119
    move/from16 v5, p3

    .line 120
    .line 121
    invoke-virtual {v13, v11, v5, v14}, Llp/nd;->a(Lwq/u;FF)V

    .line 122
    .line 123
    .line 124
    add-int/lit8 v11, v12, 0x1

    .line 125
    .line 126
    rem-int/lit8 v13, v11, 0x4

    .line 127
    .line 128
    mul-int/lit8 v13, v13, 0x5a

    .line 129
    .line 130
    int-to-float v13, v13

    .line 131
    aget-object v14, v8, v12

    .line 132
    .line 133
    invoke-virtual {v14}, Landroid/graphics/Matrix;->reset()V

    .line 134
    .line 135
    .line 136
    const/4 v14, 0x1

    .line 137
    if-eq v12, v14, :cond_9

    .line 138
    .line 139
    const/4 v14, 0x2

    .line 140
    if-eq v12, v14, :cond_8

    .line 141
    .line 142
    const/4 v14, 0x3

    .line 143
    if-eq v12, v14, :cond_7

    .line 144
    .line 145
    iget v14, v2, Landroid/graphics/RectF;->right:F

    .line 146
    .line 147
    iget v5, v2, Landroid/graphics/RectF;->top:F

    .line 148
    .line 149
    invoke-virtual {v15, v14, v5}, Landroid/graphics/PointF;->set(FF)V

    .line 150
    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_7
    iget v5, v2, Landroid/graphics/RectF;->left:F

    .line 154
    .line 155
    iget v14, v2, Landroid/graphics/RectF;->top:F

    .line 156
    .line 157
    invoke-virtual {v15, v5, v14}, Landroid/graphics/PointF;->set(FF)V

    .line 158
    .line 159
    .line 160
    goto :goto_3

    .line 161
    :cond_8
    iget v5, v2, Landroid/graphics/RectF;->left:F

    .line 162
    .line 163
    iget v14, v2, Landroid/graphics/RectF;->bottom:F

    .line 164
    .line 165
    invoke-virtual {v15, v5, v14}, Landroid/graphics/PointF;->set(FF)V

    .line 166
    .line 167
    .line 168
    goto :goto_3

    .line 169
    :cond_9
    iget v5, v2, Landroid/graphics/RectF;->right:F

    .line 170
    .line 171
    iget v14, v2, Landroid/graphics/RectF;->bottom:F

    .line 172
    .line 173
    invoke-virtual {v15, v5, v14}, Landroid/graphics/PointF;->set(FF)V

    .line 174
    .line 175
    .line 176
    :goto_3
    aget-object v5, v8, v12

    .line 177
    .line 178
    iget v14, v15, Landroid/graphics/PointF;->x:F

    .line 179
    .line 180
    iget v15, v15, Landroid/graphics/PointF;->y:F

    .line 181
    .line 182
    invoke-virtual {v5, v14, v15}, Landroid/graphics/Matrix;->setTranslate(FF)V

    .line 183
    .line 184
    .line 185
    aget-object v5, v8, v12

    .line 186
    .line 187
    invoke-virtual {v5, v13}, Landroid/graphics/Matrix;->preRotate(F)Z

    .line 188
    .line 189
    .line 190
    aget-object v5, v7, v12

    .line 191
    .line 192
    iget v14, v5, Lwq/u;->b:F

    .line 193
    .line 194
    aput v14, v6, v16

    .line 195
    .line 196
    iget v5, v5, Lwq/u;->c:F

    .line 197
    .line 198
    const/16 v17, 0x1

    .line 199
    .line 200
    aput v5, v6, v17

    .line 201
    .line 202
    aget-object v5, v8, v12

    .line 203
    .line 204
    invoke-virtual {v5, v6}, Landroid/graphics/Matrix;->mapPoints([F)V

    .line 205
    .line 206
    .line 207
    aget-object v5, v18, v12

    .line 208
    .line 209
    invoke-virtual {v5}, Landroid/graphics/Matrix;->reset()V

    .line 210
    .line 211
    .line 212
    aget-object v5, v18, v12

    .line 213
    .line 214
    aget v14, v6, v16

    .line 215
    .line 216
    aget v15, v6, v17

    .line 217
    .line 218
    invoke-virtual {v5, v14, v15}, Landroid/graphics/Matrix;->setTranslate(FF)V

    .line 219
    .line 220
    .line 221
    aget-object v5, v18, v12

    .line 222
    .line 223
    invoke-virtual {v5, v13}, Landroid/graphics/Matrix;->preRotate(F)Z

    .line 224
    .line 225
    .line 226
    move v12, v11

    .line 227
    move-object/from16 v5, v18

    .line 228
    .line 229
    goto/16 :goto_0

    .line 230
    .line 231
    :cond_a
    move-object/from16 v18, v5

    .line 232
    .line 233
    move/from16 v5, v16

    .line 234
    .line 235
    :goto_4
    if-ge v5, v15, :cond_14

    .line 236
    .line 237
    aget-object v11, v7, v5

    .line 238
    .line 239
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 240
    .line 241
    .line 242
    const/4 v12, 0x0

    .line 243
    aput v12, v6, v16

    .line 244
    .line 245
    iget v11, v11, Lwq/u;->a:F

    .line 246
    .line 247
    const/16 v17, 0x1

    .line 248
    .line 249
    aput v11, v6, v17

    .line 250
    .line 251
    aget-object v11, v8, v5

    .line 252
    .line 253
    invoke-virtual {v11, v6}, Landroid/graphics/Matrix;->mapPoints([F)V

    .line 254
    .line 255
    .line 256
    if-nez v5, :cond_b

    .line 257
    .line 258
    aget v11, v6, v16

    .line 259
    .line 260
    aget v13, v6, v17

    .line 261
    .line 262
    invoke-virtual {v4, v11, v13}, Landroid/graphics/Path;->moveTo(FF)V

    .line 263
    .line 264
    .line 265
    goto :goto_5

    .line 266
    :cond_b
    aget v11, v6, v16

    .line 267
    .line 268
    aget v13, v6, v17

    .line 269
    .line 270
    invoke-virtual {v4, v11, v13}, Landroid/graphics/Path;->lineTo(FF)V

    .line 271
    .line 272
    .line 273
    :goto_5
    aget-object v11, v7, v5

    .line 274
    .line 275
    aget-object v13, v8, v5

    .line 276
    .line 277
    invoke-virtual {v11, v13, v4}, Lwq/u;->b(Landroid/graphics/Matrix;Landroid/graphics/Path;)V

    .line 278
    .line 279
    .line 280
    if-eqz v3, :cond_c

    .line 281
    .line 282
    aget-object v11, v7, v5

    .line 283
    .line 284
    aget-object v13, v8, v5

    .line 285
    .line 286
    iget-object v14, v3, Lpv/g;->e:Ljava/lang/Object;

    .line 287
    .line 288
    check-cast v14, Lwq/i;

    .line 289
    .line 290
    iget-object v15, v14, Lwq/i;->h:Ljava/util/BitSet;

    .line 291
    .line 292
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 293
    .line 294
    .line 295
    move/from16 p2, v12

    .line 296
    .line 297
    move/from16 v12, v16

    .line 298
    .line 299
    invoke-virtual {v15, v5, v12}, Ljava/util/BitSet;->set(IZ)V

    .line 300
    .line 301
    .line 302
    iget-object v12, v14, Lwq/i;->f:[Lwq/t;

    .line 303
    .line 304
    iget v14, v11, Lwq/u;->e:F

    .line 305
    .line 306
    invoke-virtual {v11, v14}, Lwq/u;->a(F)V

    .line 307
    .line 308
    .line 309
    new-instance v14, Landroid/graphics/Matrix;

    .line 310
    .line 311
    invoke-direct {v14, v13}, Landroid/graphics/Matrix;-><init>(Landroid/graphics/Matrix;)V

    .line 312
    .line 313
    .line 314
    new-instance v13, Ljava/util/ArrayList;

    .line 315
    .line 316
    iget-object v11, v11, Lwq/u;->g:Ljava/util/ArrayList;

    .line 317
    .line 318
    invoke-direct {v13, v11}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 319
    .line 320
    .line 321
    new-instance v11, Lwq/o;

    .line 322
    .line 323
    invoke-direct {v11, v13, v14}, Lwq/o;-><init>(Ljava/util/ArrayList;Landroid/graphics/Matrix;)V

    .line 324
    .line 325
    .line 326
    aput-object v11, v12, v5

    .line 327
    .line 328
    goto :goto_6

    .line 329
    :cond_c
    move/from16 p2, v12

    .line 330
    .line 331
    :goto_6
    iget-object v11, v0, Lac/i;->k:Ljava/lang/Object;

    .line 332
    .line 333
    check-cast v11, Landroid/graphics/Path;

    .line 334
    .line 335
    iget-object v12, v0, Lac/i;->h:Ljava/lang/Object;

    .line 336
    .line 337
    check-cast v12, Lwq/u;

    .line 338
    .line 339
    add-int/lit8 v13, v5, 0x1

    .line 340
    .line 341
    rem-int/lit8 v14, v13, 0x4

    .line 342
    .line 343
    aget-object v15, v7, v5

    .line 344
    .line 345
    iget v2, v15, Lwq/u;->b:F

    .line 346
    .line 347
    const/16 v16, 0x0

    .line 348
    .line 349
    aput v2, v6, v16

    .line 350
    .line 351
    iget v2, v15, Lwq/u;->c:F

    .line 352
    .line 353
    const/16 v17, 0x1

    .line 354
    .line 355
    aput v2, v6, v17

    .line 356
    .line 357
    aget-object v2, v8, v5

    .line 358
    .line 359
    invoke-virtual {v2, v6}, Landroid/graphics/Matrix;->mapPoints([F)V

    .line 360
    .line 361
    .line 362
    iget-object v2, v0, Lac/i;->j:Ljava/lang/Object;

    .line 363
    .line 364
    check-cast v2, [F

    .line 365
    .line 366
    aget-object v15, v7, v14

    .line 367
    .line 368
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 369
    .line 370
    .line 371
    aput p2, v2, v16

    .line 372
    .line 373
    iget v15, v15, Lwq/u;->a:F

    .line 374
    .line 375
    aput v15, v2, v17

    .line 376
    .line 377
    aget-object v15, v8, v14

    .line 378
    .line 379
    invoke-virtual {v15, v2}, Landroid/graphics/Matrix;->mapPoints([F)V

    .line 380
    .line 381
    .line 382
    aget v15, v6, v16

    .line 383
    .line 384
    aget v19, v2, v16

    .line 385
    .line 386
    sub-float v15, v15, v19

    .line 387
    .line 388
    move-object/from16 v19, v7

    .line 389
    .line 390
    move-object/from16 v20, v8

    .line 391
    .line 392
    float-to-double v7, v15

    .line 393
    aget v15, v6, v17

    .line 394
    .line 395
    aget v2, v2, v17

    .line 396
    .line 397
    sub-float/2addr v15, v2

    .line 398
    float-to-double v2, v15

    .line 399
    invoke-static {v7, v8, v2, v3}, Ljava/lang/Math;->hypot(DD)D

    .line 400
    .line 401
    .line 402
    move-result-wide v2

    .line 403
    double-to-float v2, v2

    .line 404
    const v3, 0x3a83126f    # 0.001f

    .line 405
    .line 406
    .line 407
    sub-float/2addr v2, v3

    .line 408
    move/from16 v3, p2

    .line 409
    .line 410
    invoke-static {v2, v3}, Ljava/lang/Math;->max(FF)F

    .line 411
    .line 412
    .line 413
    move-result v2

    .line 414
    aget-object v3, v19, v5

    .line 415
    .line 416
    iget v7, v3, Lwq/u;->b:F

    .line 417
    .line 418
    const/16 v16, 0x0

    .line 419
    .line 420
    aput v7, v6, v16

    .line 421
    .line 422
    iget v3, v3, Lwq/u;->c:F

    .line 423
    .line 424
    const/4 v7, 0x1

    .line 425
    aput v3, v6, v7

    .line 426
    .line 427
    aget-object v3, v20, v5

    .line 428
    .line 429
    invoke-virtual {v3, v6}, Landroid/graphics/Matrix;->mapPoints([F)V

    .line 430
    .line 431
    .line 432
    if-eq v5, v7, :cond_d

    .line 433
    .line 434
    const/4 v3, 0x3

    .line 435
    if-eq v5, v3, :cond_d

    .line 436
    .line 437
    invoke-virtual/range {p4 .. p4}, Landroid/graphics/RectF;->centerY()F

    .line 438
    .line 439
    .line 440
    move-result v3

    .line 441
    aget v8, v6, v7

    .line 442
    .line 443
    sub-float/2addr v3, v8

    .line 444
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 445
    .line 446
    .line 447
    goto :goto_7

    .line 448
    :cond_d
    invoke-virtual/range {p4 .. p4}, Landroid/graphics/RectF;->centerX()F

    .line 449
    .line 450
    .line 451
    move-result v3

    .line 452
    const/16 v16, 0x0

    .line 453
    .line 454
    aget v7, v6, v16

    .line 455
    .line 456
    sub-float/2addr v3, v7

    .line 457
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 458
    .line 459
    .line 460
    :goto_7
    const/high16 v3, 0x43870000    # 270.0f

    .line 461
    .line 462
    const/4 v7, 0x0

    .line 463
    invoke-virtual {v12, v7, v3, v7}, Lwq/u;->d(FFF)V

    .line 464
    .line 465
    .line 466
    const/4 v7, 0x1

    .line 467
    if-eq v5, v7, :cond_10

    .line 468
    .line 469
    const/4 v3, 0x2

    .line 470
    if-eq v5, v3, :cond_f

    .line 471
    .line 472
    const/4 v7, 0x3

    .line 473
    if-eq v5, v7, :cond_e

    .line 474
    .line 475
    iget-object v8, v1, Lwq/m;->j:Lwq/f;

    .line 476
    .line 477
    goto :goto_8

    .line 478
    :cond_e
    iget-object v8, v1, Lwq/m;->i:Lwq/f;

    .line 479
    .line 480
    goto :goto_8

    .line 481
    :cond_f
    const/4 v7, 0x3

    .line 482
    iget-object v8, v1, Lwq/m;->l:Lwq/f;

    .line 483
    .line 484
    goto :goto_8

    .line 485
    :cond_10
    const/4 v3, 0x2

    .line 486
    const/4 v7, 0x3

    .line 487
    iget-object v8, v1, Lwq/m;->k:Lwq/f;

    .line 488
    .line 489
    :goto_8
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 490
    .line 491
    .line 492
    const/4 v8, 0x0

    .line 493
    invoke-virtual {v12, v2, v8}, Lwq/u;->c(FF)V

    .line 494
    .line 495
    .line 496
    invoke-virtual {v11}, Landroid/graphics/Path;->reset()V

    .line 497
    .line 498
    .line 499
    aget-object v2, v18, v5

    .line 500
    .line 501
    invoke-virtual {v12, v2, v11}, Lwq/u;->b(Landroid/graphics/Matrix;Landroid/graphics/Path;)V

    .line 502
    .line 503
    .line 504
    iget-boolean v2, v0, Lac/i;->a:Z

    .line 505
    .line 506
    if-eqz v2, :cond_11

    .line 507
    .line 508
    invoke-virtual {v0, v11, v5}, Lac/i;->h(Landroid/graphics/Path;I)Z

    .line 509
    .line 510
    .line 511
    move-result v2

    .line 512
    if-nez v2, :cond_12

    .line 513
    .line 514
    invoke-virtual {v0, v11, v14}, Lac/i;->h(Landroid/graphics/Path;I)Z

    .line 515
    .line 516
    .line 517
    move-result v2

    .line 518
    if-eqz v2, :cond_11

    .line 519
    .line 520
    goto :goto_9

    .line 521
    :cond_11
    const/16 v17, 0x1

    .line 522
    .line 523
    goto :goto_a

    .line 524
    :cond_12
    :goto_9
    sget-object v2, Landroid/graphics/Path$Op;->DIFFERENCE:Landroid/graphics/Path$Op;

    .line 525
    .line 526
    invoke-virtual {v11, v11, v10, v2}, Landroid/graphics/Path;->op(Landroid/graphics/Path;Landroid/graphics/Path;Landroid/graphics/Path$Op;)Z

    .line 527
    .line 528
    .line 529
    const/4 v8, 0x0

    .line 530
    const/16 v16, 0x0

    .line 531
    .line 532
    aput v8, v6, v16

    .line 533
    .line 534
    iget v2, v12, Lwq/u;->a:F

    .line 535
    .line 536
    const/16 v17, 0x1

    .line 537
    .line 538
    aput v2, v6, v17

    .line 539
    .line 540
    aget-object v2, v18, v5

    .line 541
    .line 542
    invoke-virtual {v2, v6}, Landroid/graphics/Matrix;->mapPoints([F)V

    .line 543
    .line 544
    .line 545
    aget v2, v6, v16

    .line 546
    .line 547
    aget v8, v6, v17

    .line 548
    .line 549
    invoke-virtual {v9, v2, v8}, Landroid/graphics/Path;->moveTo(FF)V

    .line 550
    .line 551
    .line 552
    aget-object v2, v18, v5

    .line 553
    .line 554
    invoke-virtual {v12, v2, v9}, Lwq/u;->b(Landroid/graphics/Matrix;Landroid/graphics/Path;)V

    .line 555
    .line 556
    .line 557
    goto :goto_b

    .line 558
    :goto_a
    aget-object v2, v18, v5

    .line 559
    .line 560
    invoke-virtual {v12, v2, v4}, Lwq/u;->b(Landroid/graphics/Matrix;Landroid/graphics/Path;)V

    .line 561
    .line 562
    .line 563
    :goto_b
    if-eqz p5, :cond_13

    .line 564
    .line 565
    aget-object v2, v18, v5

    .line 566
    .line 567
    move-object/from16 v8, p5

    .line 568
    .line 569
    iget-object v11, v8, Lpv/g;->e:Ljava/lang/Object;

    .line 570
    .line 571
    check-cast v11, Lwq/i;

    .line 572
    .line 573
    iget-object v14, v11, Lwq/i;->h:Ljava/util/BitSet;

    .line 574
    .line 575
    add-int/lit8 v15, v5, 0x4

    .line 576
    .line 577
    const/4 v3, 0x0

    .line 578
    invoke-virtual {v14, v15, v3}, Ljava/util/BitSet;->set(IZ)V

    .line 579
    .line 580
    .line 581
    iget-object v11, v11, Lwq/i;->g:[Lwq/t;

    .line 582
    .line 583
    iget v14, v12, Lwq/u;->e:F

    .line 584
    .line 585
    invoke-virtual {v12, v14}, Lwq/u;->a(F)V

    .line 586
    .line 587
    .line 588
    new-instance v14, Landroid/graphics/Matrix;

    .line 589
    .line 590
    invoke-direct {v14, v2}, Landroid/graphics/Matrix;-><init>(Landroid/graphics/Matrix;)V

    .line 591
    .line 592
    .line 593
    new-instance v2, Ljava/util/ArrayList;

    .line 594
    .line 595
    iget-object v12, v12, Lwq/u;->g:Ljava/util/ArrayList;

    .line 596
    .line 597
    invoke-direct {v2, v12}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 598
    .line 599
    .line 600
    new-instance v12, Lwq/o;

    .line 601
    .line 602
    invoke-direct {v12, v2, v14}, Lwq/o;-><init>(Ljava/util/ArrayList;Landroid/graphics/Matrix;)V

    .line 603
    .line 604
    .line 605
    aput-object v12, v11, v5

    .line 606
    .line 607
    goto :goto_c

    .line 608
    :cond_13
    move-object/from16 v8, p5

    .line 609
    .line 610
    const/4 v3, 0x0

    .line 611
    :goto_c
    move-object/from16 v2, p4

    .line 612
    .line 613
    move/from16 v16, v3

    .line 614
    .line 615
    move-object v3, v8

    .line 616
    move v5, v13

    .line 617
    move-object/from16 v7, v19

    .line 618
    .line 619
    move-object/from16 v8, v20

    .line 620
    .line 621
    const/4 v15, 0x4

    .line 622
    goto/16 :goto_4

    .line 623
    .line 624
    :cond_14
    invoke-virtual {v4}, Landroid/graphics/Path;->close()V

    .line 625
    .line 626
    .line 627
    invoke-virtual {v9}, Landroid/graphics/Path;->close()V

    .line 628
    .line 629
    .line 630
    invoke-virtual {v9}, Landroid/graphics/Path;->isEmpty()Z

    .line 631
    .line 632
    .line 633
    move-result v0

    .line 634
    if-nez v0, :cond_15

    .line 635
    .line 636
    sget-object v0, Landroid/graphics/Path$Op;->UNION:Landroid/graphics/Path$Op;

    .line 637
    .line 638
    invoke-virtual {v4, v9, v0}, Landroid/graphics/Path;->op(Landroid/graphics/Path;Landroid/graphics/Path$Op;)Z

    .line 639
    .line 640
    .line 641
    :cond_15
    return-void
.end method

.method public c()Lt7/p0;
    .locals 4

    .line 1
    iget-object v0, p0, Lac/i;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    sget-object p0, Lt7/p0;->a:Lt7/m0;

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    const/4 v1, 0x0

    .line 15
    move v2, v1

    .line 16
    :goto_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    if-ge v1, v3, :cond_1

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    check-cast v3, La8/h1;

    .line 27
    .line 28
    iput v2, v3, La8/h1;->d:I

    .line 29
    .line 30
    iget-object v3, v3, La8/h1;->a:Lh8/w;

    .line 31
    .line 32
    iget-object v3, v3, Lh8/w;->o:Lh8/u;

    .line 33
    .line 34
    iget-object v3, v3, Lh8/q;->b:Lt7/p0;

    .line 35
    .line 36
    invoke-virtual {v3}, Lt7/p0;->o()I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    add-int/2addr v2, v3

    .line 41
    add-int/lit8 v1, v1, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    new-instance v1, La8/n1;

    .line 45
    .line 46
    iget-object p0, p0, Lac/i;->k:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast p0, Lh8/a1;

    .line 49
    .line 50
    invoke-direct {v1, v0, p0}, La8/n1;-><init>(Ljava/util/ArrayList;Lh8/a1;)V

    .line 51
    .line 52
    .line 53
    return-object v1
.end method

.method public d()V
    .locals 3

    .line 1
    iget-object v0, p0, Lac/i;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashSet;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_2

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, La8/h1;

    .line 20
    .line 21
    iget-object v2, v1, La8/h1;->c:Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    iget-object v2, p0, Lac/i;->g:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v2, Ljava/util/HashMap;

    .line 32
    .line 33
    invoke-virtual {v2, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    check-cast v1, La8/g1;

    .line 38
    .line 39
    if-eqz v1, :cond_1

    .line 40
    .line 41
    iget-object v2, v1, La8/g1;->a:Lh8/a;

    .line 42
    .line 43
    iget-object v1, v1, La8/g1;->b:La8/b1;

    .line 44
    .line 45
    invoke-virtual {v2, v1}, Lh8/a;->b(Lh8/c0;)V

    .line 46
    .line 47
    .line 48
    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->remove()V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    return-void
.end method

.method public e()Lac/e;
    .locals 10

    .line 1
    new-instance v0, Lac/e;

    .line 2
    .line 3
    iget-object v1, p0, Lac/i;->l:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lyy0/l1;

    .line 6
    .line 7
    iget-object v2, v1, Lyy0/l1;->d:Lyy0/a2;

    .line 8
    .line 9
    invoke-interface {v2}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    check-cast v2, Lac/x;

    .line 14
    .line 15
    iget-object v2, v2, Lac/x;->a:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v3, v1, Lyy0/l1;->d:Lyy0/a2;

    .line 18
    .line 19
    invoke-interface {v3}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    check-cast v3, Lac/x;

    .line 24
    .line 25
    iget-object v3, v3, Lac/x;->b:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v4, v1, Lyy0/l1;->d:Lyy0/a2;

    .line 28
    .line 29
    invoke-interface {v4}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    check-cast v4, Lac/x;

    .line 34
    .line 35
    iget-object v4, v4, Lac/x;->c:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v5, v1, Lyy0/l1;->d:Lyy0/a2;

    .line 38
    .line 39
    invoke-interface {v5}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    check-cast v5, Lac/x;

    .line 44
    .line 45
    iget-object v5, v5, Lac/x;->d:Ljava/lang/String;

    .line 46
    .line 47
    iget-object v6, v1, Lyy0/l1;->d:Lyy0/a2;

    .line 48
    .line 49
    invoke-interface {v6}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v6

    .line 53
    check-cast v6, Lac/x;

    .line 54
    .line 55
    iget-object v6, v6, Lac/x;->e:Ljava/lang/String;

    .line 56
    .line 57
    iget-object v7, v1, Lyy0/l1;->d:Lyy0/a2;

    .line 58
    .line 59
    invoke-interface {v7}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v7

    .line 63
    check-cast v7, Lac/x;

    .line 64
    .line 65
    iget-object v7, v7, Lac/x;->f:Ljava/lang/String;

    .line 66
    .line 67
    iget-object v8, v1, Lyy0/l1;->d:Lyy0/a2;

    .line 68
    .line 69
    invoke-interface {v8}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v8

    .line 73
    check-cast v8, Lac/x;

    .line 74
    .line 75
    iget-object v8, v8, Lac/x;->g:Ljava/lang/String;

    .line 76
    .line 77
    iget-object p0, p0, Lac/i;->j:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Lyy0/c2;

    .line 80
    .line 81
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Lac/a0;

    .line 86
    .line 87
    iget-object v1, v1, Lyy0/l1;->d:Lyy0/a2;

    .line 88
    .line 89
    invoke-interface {v1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    check-cast v1, Lac/x;

    .line 94
    .line 95
    iget-object v9, v1, Lac/x;->i:Ljava/lang/String;

    .line 96
    .line 97
    move-object v1, v2

    .line 98
    move-object v2, v3

    .line 99
    move-object v3, v4

    .line 100
    move-object v4, v5

    .line 101
    move-object v5, v6

    .line 102
    move-object v6, v7

    .line 103
    move-object v7, v8

    .line 104
    move-object v8, p0

    .line 105
    invoke-direct/range {v0 .. v9}, Lac/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lac/a0;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    return-object v0
.end method

.method public f(La8/h1;)V
    .locals 3

    .line 1
    iget-boolean v0, p1, La8/h1;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p1, La8/h1;->c:Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object v0, p0, Lac/i;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Ljava/util/HashMap;

    .line 16
    .line 17
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, La8/g1;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    iget-object v1, v0, La8/g1;->c:La8/f1;

    .line 27
    .line 28
    iget-object v2, v0, La8/g1;->a:Lh8/a;

    .line 29
    .line 30
    iget-object v0, v0, La8/g1;->b:La8/b1;

    .line 31
    .line 32
    invoke-virtual {v2, v0}, Lh8/a;->n(Lh8/c0;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v2, v1}, Lh8/a;->q(Lh8/h0;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v2, v1}, Lh8/a;->p(Ld8/g;)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lac/i;->h:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Ljava/util/HashSet;

    .line 44
    .line 45
    invoke-virtual {p0, p1}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    :cond_0
    return-void
.end method

.method public g(Lac/w;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lac/i;->j:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lyy0/c2;

    .line 4
    .line 5
    iget-object v1, p0, Lac/i;->k:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lyy0/c2;

    .line 8
    .line 9
    const-string v2, "event"

    .line 10
    .line 11
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    instance-of v2, p1, Lac/r;

    .line 15
    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    iget-object p0, p0, Lac/i;->b:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lyy0/c2;

    .line 21
    .line 22
    check-cast p1, Lac/r;

    .line 23
    .line 24
    iget-object p1, p1, Lac/r;->a:Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    instance-of v2, p1, Lac/s;

    .line 31
    .line 32
    if-eqz v2, :cond_1

    .line 33
    .line 34
    iget-object p0, p0, Lac/i;->c:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Lyy0/c2;

    .line 37
    .line 38
    check-cast p1, Lac/s;

    .line 39
    .line 40
    iget-object p1, p1, Lac/s;->a:Ljava/lang/String;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :cond_1
    instance-of v2, p1, Lac/m;

    .line 47
    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    iget-object p0, p0, Lac/i;->d:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p0, Lyy0/c2;

    .line 53
    .line 54
    check-cast p1, Lac/m;

    .line 55
    .line 56
    iget-object p1, p1, Lac/m;->a:Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    :cond_2
    instance-of v2, p1, Lac/n;

    .line 63
    .line 64
    if-eqz v2, :cond_3

    .line 65
    .line 66
    iget-object p0, p0, Lac/i;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p0, Lyy0/c2;

    .line 69
    .line 70
    check-cast p1, Lac/n;

    .line 71
    .line 72
    iget-object p1, p1, Lac/n;->a:Ljava/lang/String;

    .line 73
    .line 74
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    return-void

    .line 78
    :cond_3
    instance-of v2, p1, Lac/v;

    .line 79
    .line 80
    if-eqz v2, :cond_4

    .line 81
    .line 82
    iget-object p0, p0, Lac/i;->f:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast p0, Lyy0/c2;

    .line 85
    .line 86
    check-cast p1, Lac/v;

    .line 87
    .line 88
    iget-object p1, p1, Lac/v;->a:Ljava/lang/String;

    .line 89
    .line 90
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    return-void

    .line 94
    :cond_4
    instance-of v2, p1, Lac/t;

    .line 95
    .line 96
    if-eqz v2, :cond_5

    .line 97
    .line 98
    iget-object p0, p0, Lac/i;->h:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p0, Lyy0/c2;

    .line 101
    .line 102
    check-cast p1, Lac/t;

    .line 103
    .line 104
    iget-object p1, p1, Lac/t;->a:Ljava/lang/String;

    .line 105
    .line 106
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    return-void

    .line 110
    :cond_5
    instance-of v2, p1, Lac/o;

    .line 111
    .line 112
    if-eqz v2, :cond_6

    .line 113
    .line 114
    iget-object p0, p0, Lac/i;->g:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast p0, Lyy0/c2;

    .line 117
    .line 118
    check-cast p1, Lac/o;

    .line 119
    .line 120
    iget-object p1, p1, Lac/o;->a:Ljava/lang/String;

    .line 121
    .line 122
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    return-void

    .line 126
    :cond_6
    instance-of v2, p1, Lac/q;

    .line 127
    .line 128
    if-eqz v2, :cond_9

    .line 129
    .line 130
    check-cast p1, Lac/q;

    .line 131
    .line 132
    iget p0, p1, Lac/q;->a:I

    .line 133
    .line 134
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    check-cast p1, Ljava/util/List;

    .line 139
    .line 140
    invoke-static {p0, p1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    check-cast p1, Lac/a0;

    .line 145
    .line 146
    const/4 v1, 0x0

    .line 147
    if-nez p1, :cond_8

    .line 148
    .line 149
    sget-object p1, Lgi/b;->h:Lgi/b;

    .line 150
    .line 151
    new-instance v0, Lac/g;

    .line 152
    .line 153
    const/4 v2, 0x0

    .line 154
    invoke-direct {v0, p0, v2}, Lac/g;-><init>(II)V

    .line 155
    .line 156
    .line 157
    sget-object p0, Lgi/a;->e:Lgi/a;

    .line 158
    .line 159
    const-class v2, Lac/i;

    .line 160
    .line 161
    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v2

    .line 165
    const/16 v3, 0x24

    .line 166
    .line 167
    invoke-static {v2, v3}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v3

    .line 171
    const/16 v4, 0x2e

    .line 172
    .line 173
    invoke-static {v4, v3, v3}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object v3

    .line 177
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 178
    .line 179
    .line 180
    move-result v4

    .line 181
    if-nez v4, :cond_7

    .line 182
    .line 183
    goto :goto_0

    .line 184
    :cond_7
    const-string v2, "Kt"

    .line 185
    .line 186
    invoke-static {v3, v2}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v2

    .line 190
    :goto_0
    invoke-static {v2, p0, p1, v1, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 191
    .line 192
    .line 193
    return-void

    .line 194
    :cond_8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 195
    .line 196
    .line 197
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    return-void

    .line 201
    :cond_9
    instance-of v2, p1, Lac/u;

    .line 202
    .line 203
    if-eqz v2, :cond_a

    .line 204
    .line 205
    iget-object p0, p0, Lac/i;->i:Ljava/lang/Object;

    .line 206
    .line 207
    check-cast p0, Lyy0/c2;

    .line 208
    .line 209
    check-cast p1, Lac/u;

    .line 210
    .line 211
    iget-object p1, p1, Lac/u;->a:Ljava/lang/String;

    .line 212
    .line 213
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 214
    .line 215
    .line 216
    return-void

    .line 217
    :cond_a
    instance-of p0, p1, Lac/p;

    .line 218
    .line 219
    if-eqz p0, :cond_b

    .line 220
    .line 221
    check-cast p1, Lac/p;

    .line 222
    .line 223
    iget-object p0, p1, Lac/p;->a:Ljava/util/List;

    .line 224
    .line 225
    invoke-virtual {v1, p0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    iget-object p0, p1, Lac/p;->b:Lac/a0;

    .line 229
    .line 230
    invoke-virtual {v0, p0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    return-void

    .line 234
    :cond_b
    new-instance p0, La8/r0;

    .line 235
    .line 236
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 237
    .line 238
    .line 239
    throw p0
.end method

.method public h(Landroid/graphics/Path;I)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lac/i;->l:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/Path;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroid/graphics/Path;->reset()V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lac/i;->b:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, [Lwq/u;

    .line 11
    .line 12
    aget-object v1, v1, p2

    .line 13
    .line 14
    iget-object p0, p0, Lac/i;->c:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, [Landroid/graphics/Matrix;

    .line 17
    .line 18
    aget-object p0, p0, p2

    .line 19
    .line 20
    invoke-virtual {v1, p0, v0}, Lwq/u;->b(Landroid/graphics/Matrix;Landroid/graphics/Path;)V

    .line 21
    .line 22
    .line 23
    new-instance p0, Landroid/graphics/RectF;

    .line 24
    .line 25
    invoke-direct {p0}, Landroid/graphics/RectF;-><init>()V

    .line 26
    .line 27
    .line 28
    const/4 p2, 0x1

    .line 29
    invoke-virtual {p1, p0, p2}, Landroid/graphics/Path;->computeBounds(Landroid/graphics/RectF;Z)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, p0, p2}, Landroid/graphics/Path;->computeBounds(Landroid/graphics/RectF;Z)V

    .line 33
    .line 34
    .line 35
    sget-object v1, Landroid/graphics/Path$Op;->INTERSECT:Landroid/graphics/Path$Op;

    .line 36
    .line 37
    invoke-virtual {p1, v0, v1}, Landroid/graphics/Path;->op(Landroid/graphics/Path;Landroid/graphics/Path$Op;)Z

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1, p0, p2}, Landroid/graphics/Path;->computeBounds(Landroid/graphics/RectF;Z)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0}, Landroid/graphics/RectF;->isEmpty()Z

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    if-eqz p1, :cond_1

    .line 48
    .line 49
    invoke-virtual {p0}, Landroid/graphics/RectF;->width()F

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    const/high16 v0, 0x3f800000    # 1.0f

    .line 54
    .line 55
    cmpl-float p1, p1, v0

    .line 56
    .line 57
    if-lez p1, :cond_0

    .line 58
    .line 59
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    cmpl-float p0, p0, v0

    .line 64
    .line 65
    if-lez p0, :cond_0

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_0
    const/4 p0, 0x0

    .line 69
    return p0

    .line 70
    :cond_1
    :goto_0
    return p2
.end method

.method public i(La8/h1;)V
    .locals 6

    .line 1
    iget-object v0, p1, La8/h1;->a:Lh8/w;

    .line 2
    .line 3
    new-instance v1, La8/b1;

    .line 4
    .line 5
    invoke-direct {v1, p0}, La8/b1;-><init>(Lac/i;)V

    .line 6
    .line 7
    .line 8
    new-instance v2, La8/f1;

    .line 9
    .line 10
    invoke-direct {v2, p0, p1}, La8/f1;-><init>(Lac/i;La8/h1;)V

    .line 11
    .line 12
    .line 13
    iget-object v3, p0, Lac/i;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v3, Ljava/util/HashMap;

    .line 16
    .line 17
    new-instance v4, La8/g1;

    .line 18
    .line 19
    invoke-direct {v4, v0, v1, v2}, La8/g1;-><init>(Lh8/a;La8/b1;La8/f1;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v3, p1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    sget-object p1, Lw7/w;->a:Ljava/lang/String;

    .line 26
    .line 27
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    if-eqz p1, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    :goto_0
    new-instance v3, Landroid/os/Handler;

    .line 39
    .line 40
    const/4 v4, 0x0

    .line 41
    invoke-direct {v3, p1, v4}, Landroid/os/Handler;-><init>(Landroid/os/Looper;Landroid/os/Handler$Callback;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    iget-object p1, v0, Lh8/a;->c:Ld8/f;

    .line 48
    .line 49
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    iget-object p1, p1, Ld8/f;->c:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 53
    .line 54
    new-instance v5, Lh8/g0;

    .line 55
    .line 56
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 57
    .line 58
    .line 59
    iput-object v3, v5, Lh8/g0;->a:Landroid/os/Handler;

    .line 60
    .line 61
    iput-object v2, v5, Lh8/g0;->b:Ljava/lang/Object;

    .line 62
    .line 63
    invoke-virtual {p1, v5}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-eqz p1, :cond_1

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_1
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    :goto_1
    new-instance v3, Landroid/os/Handler;

    .line 78
    .line 79
    invoke-direct {v3, p1, v4}, Landroid/os/Handler;-><init>(Landroid/os/Looper;Landroid/os/Handler$Callback;)V

    .line 80
    .line 81
    .line 82
    iget-object p1, v0, Lh8/a;->d:Ld8/f;

    .line 83
    .line 84
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    iget-object p1, p1, Ld8/f;->c:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 88
    .line 89
    new-instance v3, Ld8/e;

    .line 90
    .line 91
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 92
    .line 93
    .line 94
    iput-object v2, v3, Ld8/e;->a:Ljava/lang/Object;

    .line 95
    .line 96
    invoke-virtual {p1, v3}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    iget-object p1, p0, Lac/i;->l:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast p1, Ly7/z;

    .line 102
    .line 103
    iget-object p0, p0, Lac/i;->b:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast p0, Lb8/k;

    .line 106
    .line 107
    invoke-virtual {v0, v1, p1, p0}, Lh8/a;->j(Lh8/c0;Ly7/z;Lb8/k;)V

    .line 108
    .line 109
    .line 110
    return-void
.end method

.method public j(Lh8/z;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lac/i;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/IdentityHashMap;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/util/IdentityHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, La8/h1;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget-object v2, v1, La8/h1;->a:Lh8/w;

    .line 15
    .line 16
    invoke-virtual {v2, p1}, Lh8/w;->m(Lh8/z;)V

    .line 17
    .line 18
    .line 19
    iget-object v2, v1, La8/h1;->c:Ljava/util/ArrayList;

    .line 20
    .line 21
    check-cast p1, Lh8/t;

    .line 22
    .line 23
    iget-object p1, p1, Lh8/t;->d:Lh8/b0;

    .line 24
    .line 25
    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/util/IdentityHashMap;->isEmpty()Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-nez p1, :cond_0

    .line 33
    .line 34
    invoke-virtual {p0}, Lac/i;->d()V

    .line 35
    .line 36
    .line 37
    :cond_0
    invoke-virtual {p0, v1}, Lac/i;->f(La8/h1;)V

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public k(II)V
    .locals 7

    .line 1
    iget-object v0, p0, Lac/i;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    sub-int/2addr p2, v1

    .line 7
    :goto_0
    if-lt p2, p1, :cond_2

    .line 8
    .line 9
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    check-cast v2, La8/h1;

    .line 14
    .line 15
    iget-object v3, p0, Lac/i;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v3, Ljava/util/HashMap;

    .line 18
    .line 19
    iget-object v4, v2, La8/h1;->b:Ljava/lang/Object;

    .line 20
    .line 21
    invoke-virtual {v3, v4}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    iget-object v3, v2, La8/h1;->a:Lh8/w;

    .line 25
    .line 26
    iget-object v3, v3, Lh8/w;->o:Lh8/u;

    .line 27
    .line 28
    iget-object v3, v3, Lh8/q;->b:Lt7/p0;

    .line 29
    .line 30
    invoke-virtual {v3}, Lt7/p0;->o()I

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    neg-int v3, v3

    .line 35
    move v4, p2

    .line 36
    :goto_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    if-ge v4, v5, :cond_0

    .line 41
    .line 42
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    check-cast v5, La8/h1;

    .line 47
    .line 48
    iget v6, v5, La8/h1;->d:I

    .line 49
    .line 50
    add-int/2addr v6, v3

    .line 51
    iput v6, v5, La8/h1;->d:I

    .line 52
    .line 53
    add-int/lit8 v4, v4, 0x1

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_0
    iput-boolean v1, v2, La8/h1;->e:Z

    .line 57
    .line 58
    iget-boolean v3, p0, Lac/i;->a:Z

    .line 59
    .line 60
    if-eqz v3, :cond_1

    .line 61
    .line 62
    invoke-virtual {p0, v2}, Lac/i;->f(La8/h1;)V

    .line 63
    .line 64
    .line 65
    :cond_1
    add-int/lit8 p2, p2, -0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    return-void
.end method
