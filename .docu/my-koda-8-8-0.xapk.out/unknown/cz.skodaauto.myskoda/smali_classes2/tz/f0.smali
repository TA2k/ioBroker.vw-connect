.class public final Ltz/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final A:Z

.field public final B:Ljava/lang/String;

.field public final C:Z

.field public final D:Z

.field public final E:Z

.field public final F:Z

.field public final a:Lql0/g;

.field public final b:Ler0/g;

.field public final c:Llf0/i;

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Ljava/lang/String;

.field public final k:Ljava/lang/String;

.field public final l:Ltz/e0;

.field public final m:Z

.field public final n:Ltz/z;

.field public final o:Ltz/x;

.field public final p:Ltz/y;

.field public final q:Llp/p0;

.field public final r:Ltz/a0;

.field public final s:Lne0/c;

.field public final t:Z

.field public final u:Z

.field public final v:Z

.field public final w:Z

.field public final x:Z

.field public final y:Ljava/lang/String;

.field public final z:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ler0/g;Llf0/i;Ljava/lang/String;Ltz/v;Ltz/c0;I)V
    .locals 31

    move/from16 v0, p6

    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_0

    .line 37
    sget-object v1, Ler0/g;->d:Ler0/g;

    move-object v4, v1

    goto :goto_0

    :cond_0
    move-object/from16 v4, p1

    :goto_0
    and-int/lit8 v1, v0, 0x4

    if-eqz v1, :cond_1

    .line 38
    sget-object v1, Llf0/i;->j:Llf0/i;

    move-object v5, v1

    goto :goto_1

    :cond_1
    move-object/from16 v5, p2

    :goto_1
    and-int/lit16 v1, v0, 0x80

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    move-object v10, v2

    goto :goto_2

    :cond_2
    move-object/from16 v10, p3

    :goto_2
    and-int/lit16 v1, v0, 0x2000

    if-eqz v1, :cond_3

    move-object/from16 v16, v2

    goto :goto_3

    :cond_3
    move-object/from16 v16, p4

    :goto_3
    const/high16 v1, 0x10000

    and-int/2addr v0, v1

    if-eqz v0, :cond_4

    .line 39
    new-instance v0, Ltz/b0;

    .line 40
    const-string v1, ""

    .line 41
    invoke-direct {v0, v1}, Ltz/b0;-><init>(Ljava/lang/String;)V

    move-object/from16 v19, v0

    goto :goto_4

    :cond_4
    move-object/from16 v19, p5

    :goto_4
    const/16 v26, 0x0

    const/16 v29, 0x0

    const/4 v3, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v30, 0x0

    move-object/from16 v2, p0

    .line 42
    invoke-direct/range {v2 .. v30}, Ltz/f0;-><init>(Lql0/g;Ler0/g;Llf0/i;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ltz/e0;ZLtz/z;Ltz/x;Ltz/y;Llp/p0;Ltz/a0;Lne0/c;ZZZZZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Lql0/g;Ler0/g;Llf0/i;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ltz/e0;ZLtz/z;Ltz/x;Ltz/y;Llp/p0;Ltz/a0;Lne0/c;ZZZZZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;)V
    .locals 6

    move-object v0, p9

    move-object/from16 v1, p11

    move-object/from16 v2, p14

    move-object/from16 v3, p17

    move/from16 v4, p24

    const-string v5, "subscriptionLicenseState"

    invoke-static {p2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "viewMode"

    invoke-static {p3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "gaugeState"

    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ltz/f0;->a:Lql0/g;

    .line 3
    iput-object p2, p0, Ltz/f0;->b:Ler0/g;

    .line 4
    iput-object p3, p0, Ltz/f0;->c:Llf0/i;

    .line 5
    iput-boolean p4, p0, Ltz/f0;->d:Z

    .line 6
    iput-boolean p5, p0, Ltz/f0;->e:Z

    .line 7
    iput-boolean p6, p0, Ltz/f0;->f:Z

    .line 8
    iput-object p7, p0, Ltz/f0;->g:Ljava/lang/String;

    .line 9
    iput-object p8, p0, Ltz/f0;->h:Ljava/lang/String;

    .line 10
    iput-object v0, p0, Ltz/f0;->i:Ljava/lang/String;

    move-object/from16 p1, p10

    .line 11
    iput-object p1, p0, Ltz/f0;->j:Ljava/lang/String;

    .line 12
    iput-object v1, p0, Ltz/f0;->k:Ljava/lang/String;

    move-object/from16 p1, p12

    .line 13
    iput-object p1, p0, Ltz/f0;->l:Ltz/e0;

    move/from16 p1, p13

    .line 14
    iput-boolean p1, p0, Ltz/f0;->m:Z

    .line 15
    iput-object v2, p0, Ltz/f0;->n:Ltz/z;

    move-object/from16 p1, p15

    .line 16
    iput-object p1, p0, Ltz/f0;->o:Ltz/x;

    move-object/from16 p1, p16

    .line 17
    iput-object p1, p0, Ltz/f0;->p:Ltz/y;

    .line 18
    iput-object v3, p0, Ltz/f0;->q:Llp/p0;

    move-object/from16 p1, p18

    .line 19
    iput-object p1, p0, Ltz/f0;->r:Ltz/a0;

    move-object/from16 p1, p19

    .line 20
    iput-object p1, p0, Ltz/f0;->s:Lne0/c;

    move/from16 p1, p20

    .line 21
    iput-boolean p1, p0, Ltz/f0;->t:Z

    move/from16 p1, p21

    .line 22
    iput-boolean p1, p0, Ltz/f0;->u:Z

    move/from16 p1, p22

    .line 23
    iput-boolean p1, p0, Ltz/f0;->v:Z

    move/from16 p1, p23

    .line 24
    iput-boolean p1, p0, Ltz/f0;->w:Z

    .line 25
    iput-boolean v4, p0, Ltz/f0;->x:Z

    move-object/from16 p1, p25

    .line 26
    iput-object p1, p0, Ltz/f0;->y:Ljava/lang/String;

    move-object/from16 p1, p26

    .line 27
    iput-object p1, p0, Ltz/f0;->z:Ljava/lang/String;

    move/from16 p1, p27

    .line 28
    iput-boolean p1, p0, Ltz/f0;->A:Z

    move-object/from16 p1, p28

    .line 29
    iput-object p1, p0, Ltz/f0;->B:Ljava/lang/String;

    .line 30
    sget-object p1, Llf0/i;->h:Llf0/i;

    const/4 p2, 0x0

    const/4 p4, 0x1

    if-ne p3, p1, :cond_0

    move p1, p4

    goto :goto_0

    :cond_0
    move p1, p2

    :goto_0
    iput-boolean p1, p0, Ltz/f0;->C:Z

    .line 31
    invoke-static {p3}, Llp/tf;->d(Llf0/i;)Z

    move-result p1

    iput-boolean p1, p0, Ltz/f0;->D:Z

    if-nez v4, :cond_2

    if-nez v2, :cond_1

    goto :goto_1

    :cond_1
    move p1, p2

    goto :goto_2

    :cond_2
    :goto_1
    move p1, p4

    .line 32
    :goto_2
    iput-boolean p1, p0, Ltz/f0;->E:Z

    .line 33
    filled-new-array {v1, p8, p9}, [Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    .line 34
    instance-of p3, p1, Ljava/util/Collection;

    if-eqz p3, :cond_3

    move-object p3, p1

    check-cast p3, Ljava/util/Collection;

    invoke-interface {p3}, Ljava/util/Collection;->isEmpty()Z

    move-result p3

    if-eqz p3, :cond_3

    goto :goto_4

    .line 35
    :cond_3
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p3

    if-eqz p3, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Ljava/lang/String;

    if-nez p3, :cond_5

    goto :goto_3

    .line 36
    :cond_4
    :goto_4
    iget-boolean p1, p0, Ltz/f0;->E:Z

    if-eqz p1, :cond_5

    move p2, p4

    :cond_5
    iput-boolean p2, p0, Ltz/f0;->F:Z

    return-void
.end method

.method public static a(Ltz/f0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ltz/e0;ZLtz/z;Ltz/x;Ltz/y;Llp/p0;Ltz/a0;Lne0/c;ZZZZZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;I)Ltz/f0;
    .locals 33

    move-object/from16 v0, p0

    move/from16 v1, p27

    sget-object v2, Ler0/g;->d:Ler0/g;

    and-int/lit8 v3, v1, 0x1

    if-eqz v3, :cond_0

    iget-object v3, v0, Ltz/f0;->a:Lql0/g;

    move-object v5, v3

    goto :goto_0

    :cond_0
    move-object/from16 v5, p1

    :goto_0
    and-int/lit8 v3, v1, 0x2

    if-eqz v3, :cond_1

    iget-object v2, v0, Ltz/f0;->b:Ler0/g;

    :cond_1
    move-object v6, v2

    iget-object v7, v0, Ltz/f0;->c:Llf0/i;

    and-int/lit8 v2, v1, 0x8

    if-eqz v2, :cond_2

    iget-boolean v2, v0, Ltz/f0;->d:Z

    move v8, v2

    goto :goto_1

    :cond_2
    move/from16 v8, p2

    :goto_1
    and-int/lit8 v2, v1, 0x10

    if-eqz v2, :cond_3

    iget-boolean v2, v0, Ltz/f0;->e:Z

    move v9, v2

    goto :goto_2

    :cond_3
    move/from16 v9, p3

    :goto_2
    and-int/lit8 v2, v1, 0x20

    if-eqz v2, :cond_4

    iget-boolean v2, v0, Ltz/f0;->f:Z

    move v10, v2

    goto :goto_3

    :cond_4
    move/from16 v10, p4

    :goto_3
    and-int/lit8 v2, v1, 0x40

    if-eqz v2, :cond_5

    iget-object v2, v0, Ltz/f0;->g:Ljava/lang/String;

    move-object v11, v2

    goto :goto_4

    :cond_5
    move-object/from16 v11, p5

    :goto_4
    and-int/lit16 v2, v1, 0x80

    if-eqz v2, :cond_6

    iget-object v2, v0, Ltz/f0;->h:Ljava/lang/String;

    move-object v12, v2

    goto :goto_5

    :cond_6
    move-object/from16 v12, p6

    :goto_5
    and-int/lit16 v2, v1, 0x100

    if-eqz v2, :cond_7

    iget-object v2, v0, Ltz/f0;->i:Ljava/lang/String;

    move-object v13, v2

    goto :goto_6

    :cond_7
    move-object/from16 v13, p7

    :goto_6
    and-int/lit16 v2, v1, 0x200

    if-eqz v2, :cond_8

    iget-object v2, v0, Ltz/f0;->j:Ljava/lang/String;

    move-object v14, v2

    goto :goto_7

    :cond_8
    move-object/from16 v14, p8

    :goto_7
    and-int/lit16 v2, v1, 0x400

    if-eqz v2, :cond_9

    iget-object v2, v0, Ltz/f0;->k:Ljava/lang/String;

    move-object v15, v2

    goto :goto_8

    :cond_9
    move-object/from16 v15, p9

    :goto_8
    and-int/lit16 v2, v1, 0x800

    if-eqz v2, :cond_a

    iget-object v2, v0, Ltz/f0;->l:Ltz/e0;

    move-object/from16 v16, v2

    goto :goto_9

    :cond_a
    move-object/from16 v16, p10

    :goto_9
    and-int/lit16 v2, v1, 0x1000

    if-eqz v2, :cond_b

    iget-boolean v2, v0, Ltz/f0;->m:Z

    move/from16 v17, v2

    goto :goto_a

    :cond_b
    move/from16 v17, p11

    :goto_a
    and-int/lit16 v2, v1, 0x2000

    if-eqz v2, :cond_c

    iget-object v2, v0, Ltz/f0;->n:Ltz/z;

    move-object/from16 v18, v2

    goto :goto_b

    :cond_c
    move-object/from16 v18, p12

    :goto_b
    and-int/lit16 v2, v1, 0x4000

    if-eqz v2, :cond_d

    iget-object v2, v0, Ltz/f0;->o:Ltz/x;

    move-object/from16 v19, v2

    goto :goto_c

    :cond_d
    move-object/from16 v19, p13

    :goto_c
    const v2, 0x8000

    and-int/2addr v2, v1

    if-eqz v2, :cond_e

    iget-object v2, v0, Ltz/f0;->p:Ltz/y;

    move-object/from16 v20, v2

    goto :goto_d

    :cond_e
    move-object/from16 v20, p14

    :goto_d
    const/high16 v2, 0x10000

    and-int/2addr v2, v1

    if-eqz v2, :cond_f

    iget-object v2, v0, Ltz/f0;->q:Llp/p0;

    goto :goto_e

    :cond_f
    move-object/from16 v2, p15

    :goto_e
    const/high16 v3, 0x20000

    and-int/2addr v3, v1

    if-eqz v3, :cond_10

    iget-object v3, v0, Ltz/f0;->r:Ltz/a0;

    move-object/from16 v22, v3

    goto :goto_f

    :cond_10
    move-object/from16 v22, p16

    :goto_f
    const/high16 v3, 0x40000

    and-int/2addr v3, v1

    if-eqz v3, :cond_11

    iget-object v3, v0, Ltz/f0;->s:Lne0/c;

    move-object/from16 v23, v3

    goto :goto_10

    :cond_11
    move-object/from16 v23, p17

    :goto_10
    const/high16 v3, 0x80000

    and-int/2addr v3, v1

    if-eqz v3, :cond_12

    iget-boolean v3, v0, Ltz/f0;->t:Z

    move/from16 v24, v3

    goto :goto_11

    :cond_12
    move/from16 v24, p18

    :goto_11
    const/high16 v3, 0x100000

    and-int/2addr v3, v1

    if-eqz v3, :cond_13

    iget-boolean v3, v0, Ltz/f0;->u:Z

    move/from16 v25, v3

    goto :goto_12

    :cond_13
    move/from16 v25, p19

    :goto_12
    const/high16 v3, 0x200000

    and-int/2addr v3, v1

    if-eqz v3, :cond_14

    iget-boolean v3, v0, Ltz/f0;->v:Z

    move/from16 v26, v3

    goto :goto_13

    :cond_14
    move/from16 v26, p20

    :goto_13
    const/high16 v3, 0x400000

    and-int/2addr v3, v1

    if-eqz v3, :cond_15

    iget-boolean v3, v0, Ltz/f0;->w:Z

    move/from16 v27, v3

    goto :goto_14

    :cond_15
    move/from16 v27, p21

    :goto_14
    const/high16 v3, 0x800000

    and-int/2addr v3, v1

    if-eqz v3, :cond_16

    iget-boolean v3, v0, Ltz/f0;->x:Z

    move/from16 v28, v3

    goto :goto_15

    :cond_16
    move/from16 v28, p22

    :goto_15
    const/high16 v3, 0x1000000

    and-int/2addr v3, v1

    if-eqz v3, :cond_17

    iget-object v3, v0, Ltz/f0;->y:Ljava/lang/String;

    move-object/from16 v29, v3

    goto :goto_16

    :cond_17
    move-object/from16 v29, p23

    :goto_16
    const/high16 v3, 0x2000000

    and-int/2addr v3, v1

    if-eqz v3, :cond_18

    iget-object v3, v0, Ltz/f0;->z:Ljava/lang/String;

    move-object/from16 v30, v3

    goto :goto_17

    :cond_18
    move-object/from16 v30, p24

    :goto_17
    const/high16 v3, 0x4000000

    and-int/2addr v3, v1

    if-eqz v3, :cond_19

    iget-boolean v3, v0, Ltz/f0;->A:Z

    move/from16 v31, v3

    goto :goto_18

    :cond_19
    move/from16 v31, p25

    :goto_18
    const/high16 v3, 0x8000000

    and-int/2addr v1, v3

    if-eqz v1, :cond_1a

    iget-object v1, v0, Ltz/f0;->B:Ljava/lang/String;

    move-object/from16 v32, v1

    goto :goto_19

    :cond_1a
    move-object/from16 v32, p26

    :goto_19
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1
    const-string v0, "subscriptionLicenseState"

    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "viewMode"

    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "gaugeState"

    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v4, Ltz/f0;

    move-object/from16 v21, v2

    invoke-direct/range {v4 .. v32}, Ltz/f0;-><init>(Lql0/g;Ler0/g;Llf0/i;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ltz/e0;ZLtz/z;Ltz/x;Ltz/y;Llp/p0;Ltz/a0;Lne0/c;ZZZZZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;)V

    return-object v4
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltz/f0;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Ltz/f0;

    .line 12
    .line 13
    iget-object v1, p0, Ltz/f0;->a:Lql0/g;

    .line 14
    .line 15
    iget-object v3, p1, Ltz/f0;->a:Lql0/g;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Ltz/f0;->b:Ler0/g;

    .line 25
    .line 26
    iget-object v3, p1, Ltz/f0;->b:Ler0/g;

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Ltz/f0;->c:Llf0/i;

    .line 32
    .line 33
    iget-object v3, p1, Ltz/f0;->c:Llf0/i;

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-boolean v1, p0, Ltz/f0;->d:Z

    .line 39
    .line 40
    iget-boolean v3, p1, Ltz/f0;->d:Z

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-boolean v1, p0, Ltz/f0;->e:Z

    .line 46
    .line 47
    iget-boolean v3, p1, Ltz/f0;->e:Z

    .line 48
    .line 49
    if-eq v1, v3, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-boolean v1, p0, Ltz/f0;->f:Z

    .line 53
    .line 54
    iget-boolean v3, p1, Ltz/f0;->f:Z

    .line 55
    .line 56
    if-eq v1, v3, :cond_7

    .line 57
    .line 58
    return v2

    .line 59
    :cond_7
    iget-object v1, p0, Ltz/f0;->g:Ljava/lang/String;

    .line 60
    .line 61
    iget-object v3, p1, Ltz/f0;->g:Ljava/lang/String;

    .line 62
    .line 63
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    if-nez v1, :cond_8

    .line 68
    .line 69
    return v2

    .line 70
    :cond_8
    iget-object v1, p0, Ltz/f0;->h:Ljava/lang/String;

    .line 71
    .line 72
    iget-object v3, p1, Ltz/f0;->h:Ljava/lang/String;

    .line 73
    .line 74
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    if-nez v1, :cond_9

    .line 79
    .line 80
    return v2

    .line 81
    :cond_9
    iget-object v1, p0, Ltz/f0;->i:Ljava/lang/String;

    .line 82
    .line 83
    iget-object v3, p1, Ltz/f0;->i:Ljava/lang/String;

    .line 84
    .line 85
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    if-nez v1, :cond_a

    .line 90
    .line 91
    return v2

    .line 92
    :cond_a
    iget-object v1, p0, Ltz/f0;->j:Ljava/lang/String;

    .line 93
    .line 94
    iget-object v3, p1, Ltz/f0;->j:Ljava/lang/String;

    .line 95
    .line 96
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-nez v1, :cond_b

    .line 101
    .line 102
    return v2

    .line 103
    :cond_b
    iget-object v1, p0, Ltz/f0;->k:Ljava/lang/String;

    .line 104
    .line 105
    iget-object v3, p1, Ltz/f0;->k:Ljava/lang/String;

    .line 106
    .line 107
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-nez v1, :cond_c

    .line 112
    .line 113
    return v2

    .line 114
    :cond_c
    iget-object v1, p0, Ltz/f0;->l:Ltz/e0;

    .line 115
    .line 116
    iget-object v3, p1, Ltz/f0;->l:Ltz/e0;

    .line 117
    .line 118
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    if-nez v1, :cond_d

    .line 123
    .line 124
    return v2

    .line 125
    :cond_d
    iget-boolean v1, p0, Ltz/f0;->m:Z

    .line 126
    .line 127
    iget-boolean v3, p1, Ltz/f0;->m:Z

    .line 128
    .line 129
    if-eq v1, v3, :cond_e

    .line 130
    .line 131
    return v2

    .line 132
    :cond_e
    iget-object v1, p0, Ltz/f0;->n:Ltz/z;

    .line 133
    .line 134
    iget-object v3, p1, Ltz/f0;->n:Ltz/z;

    .line 135
    .line 136
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v1

    .line 140
    if-nez v1, :cond_f

    .line 141
    .line 142
    return v2

    .line 143
    :cond_f
    iget-object v1, p0, Ltz/f0;->o:Ltz/x;

    .line 144
    .line 145
    iget-object v3, p1, Ltz/f0;->o:Ltz/x;

    .line 146
    .line 147
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    if-nez v1, :cond_10

    .line 152
    .line 153
    return v2

    .line 154
    :cond_10
    iget-object v1, p0, Ltz/f0;->p:Ltz/y;

    .line 155
    .line 156
    iget-object v3, p1, Ltz/f0;->p:Ltz/y;

    .line 157
    .line 158
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result v1

    .line 162
    if-nez v1, :cond_11

    .line 163
    .line 164
    return v2

    .line 165
    :cond_11
    iget-object v1, p0, Ltz/f0;->q:Llp/p0;

    .line 166
    .line 167
    iget-object v3, p1, Ltz/f0;->q:Llp/p0;

    .line 168
    .line 169
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v1

    .line 173
    if-nez v1, :cond_12

    .line 174
    .line 175
    return v2

    .line 176
    :cond_12
    iget-object v1, p0, Ltz/f0;->r:Ltz/a0;

    .line 177
    .line 178
    iget-object v3, p1, Ltz/f0;->r:Ltz/a0;

    .line 179
    .line 180
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v1

    .line 184
    if-nez v1, :cond_13

    .line 185
    .line 186
    return v2

    .line 187
    :cond_13
    iget-object v1, p0, Ltz/f0;->s:Lne0/c;

    .line 188
    .line 189
    iget-object v3, p1, Ltz/f0;->s:Lne0/c;

    .line 190
    .line 191
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 192
    .line 193
    .line 194
    move-result v1

    .line 195
    if-nez v1, :cond_14

    .line 196
    .line 197
    return v2

    .line 198
    :cond_14
    iget-boolean v1, p0, Ltz/f0;->t:Z

    .line 199
    .line 200
    iget-boolean v3, p1, Ltz/f0;->t:Z

    .line 201
    .line 202
    if-eq v1, v3, :cond_15

    .line 203
    .line 204
    return v2

    .line 205
    :cond_15
    iget-boolean v1, p0, Ltz/f0;->u:Z

    .line 206
    .line 207
    iget-boolean v3, p1, Ltz/f0;->u:Z

    .line 208
    .line 209
    if-eq v1, v3, :cond_16

    .line 210
    .line 211
    return v2

    .line 212
    :cond_16
    iget-boolean v1, p0, Ltz/f0;->v:Z

    .line 213
    .line 214
    iget-boolean v3, p1, Ltz/f0;->v:Z

    .line 215
    .line 216
    if-eq v1, v3, :cond_17

    .line 217
    .line 218
    return v2

    .line 219
    :cond_17
    iget-boolean v1, p0, Ltz/f0;->w:Z

    .line 220
    .line 221
    iget-boolean v3, p1, Ltz/f0;->w:Z

    .line 222
    .line 223
    if-eq v1, v3, :cond_18

    .line 224
    .line 225
    return v2

    .line 226
    :cond_18
    iget-boolean v1, p0, Ltz/f0;->x:Z

    .line 227
    .line 228
    iget-boolean v3, p1, Ltz/f0;->x:Z

    .line 229
    .line 230
    if-eq v1, v3, :cond_19

    .line 231
    .line 232
    return v2

    .line 233
    :cond_19
    iget-object v1, p0, Ltz/f0;->y:Ljava/lang/String;

    .line 234
    .line 235
    iget-object v3, p1, Ltz/f0;->y:Ljava/lang/String;

    .line 236
    .line 237
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    move-result v1

    .line 241
    if-nez v1, :cond_1a

    .line 242
    .line 243
    return v2

    .line 244
    :cond_1a
    iget-object v1, p0, Ltz/f0;->z:Ljava/lang/String;

    .line 245
    .line 246
    iget-object v3, p1, Ltz/f0;->z:Ljava/lang/String;

    .line 247
    .line 248
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 249
    .line 250
    .line 251
    move-result v1

    .line 252
    if-nez v1, :cond_1b

    .line 253
    .line 254
    return v2

    .line 255
    :cond_1b
    iget-boolean v1, p0, Ltz/f0;->A:Z

    .line 256
    .line 257
    iget-boolean v3, p1, Ltz/f0;->A:Z

    .line 258
    .line 259
    if-eq v1, v3, :cond_1c

    .line 260
    .line 261
    return v2

    .line 262
    :cond_1c
    iget-object p0, p0, Ltz/f0;->B:Ljava/lang/String;

    .line 263
    .line 264
    iget-object p1, p1, Ltz/f0;->B:Ljava/lang/String;

    .line 265
    .line 266
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    move-result p0

    .line 270
    if-nez p0, :cond_1d

    .line 271
    .line 272
    return v2

    .line 273
    :cond_1d
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Ltz/f0;->a:Lql0/g;

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    move v1, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v1}, Lql0/g;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    :goto_0
    const/16 v2, 0x1f

    .line 13
    .line 14
    mul-int/2addr v1, v2

    .line 15
    iget-object v3, p0, Ltz/f0;->b:Ler0/g;

    .line 16
    .line 17
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    add-int/2addr v3, v1

    .line 22
    mul-int/2addr v3, v2

    .line 23
    iget-object v1, p0, Ltz/f0;->c:Llf0/i;

    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    add-int/2addr v1, v3

    .line 30
    mul-int/2addr v1, v2

    .line 31
    iget-boolean v3, p0, Ltz/f0;->d:Z

    .line 32
    .line 33
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    iget-boolean v3, p0, Ltz/f0;->e:Z

    .line 38
    .line 39
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    iget-boolean v3, p0, Ltz/f0;->f:Z

    .line 44
    .line 45
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    iget-object v3, p0, Ltz/f0;->g:Ljava/lang/String;

    .line 50
    .line 51
    if-nez v3, :cond_1

    .line 52
    .line 53
    move v3, v0

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    :goto_1
    add-int/2addr v1, v3

    .line 60
    mul-int/2addr v1, v2

    .line 61
    iget-object v3, p0, Ltz/f0;->h:Ljava/lang/String;

    .line 62
    .line 63
    if-nez v3, :cond_2

    .line 64
    .line 65
    move v3, v0

    .line 66
    goto :goto_2

    .line 67
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    :goto_2
    add-int/2addr v1, v3

    .line 72
    mul-int/2addr v1, v2

    .line 73
    iget-object v3, p0, Ltz/f0;->i:Ljava/lang/String;

    .line 74
    .line 75
    if-nez v3, :cond_3

    .line 76
    .line 77
    move v3, v0

    .line 78
    goto :goto_3

    .line 79
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    :goto_3
    add-int/2addr v1, v3

    .line 84
    mul-int/2addr v1, v2

    .line 85
    iget-object v3, p0, Ltz/f0;->j:Ljava/lang/String;

    .line 86
    .line 87
    if-nez v3, :cond_4

    .line 88
    .line 89
    move v3, v0

    .line 90
    goto :goto_4

    .line 91
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    :goto_4
    add-int/2addr v1, v3

    .line 96
    mul-int/2addr v1, v2

    .line 97
    iget-object v3, p0, Ltz/f0;->k:Ljava/lang/String;

    .line 98
    .line 99
    if-nez v3, :cond_5

    .line 100
    .line 101
    move v3, v0

    .line 102
    goto :goto_5

    .line 103
    :cond_5
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    :goto_5
    add-int/2addr v1, v3

    .line 108
    mul-int/2addr v1, v2

    .line 109
    iget-object v3, p0, Ltz/f0;->l:Ltz/e0;

    .line 110
    .line 111
    if-nez v3, :cond_6

    .line 112
    .line 113
    move v3, v0

    .line 114
    goto :goto_6

    .line 115
    :cond_6
    invoke-virtual {v3}, Ltz/e0;->hashCode()I

    .line 116
    .line 117
    .line 118
    move-result v3

    .line 119
    :goto_6
    add-int/2addr v1, v3

    .line 120
    mul-int/2addr v1, v2

    .line 121
    iget-boolean v3, p0, Ltz/f0;->m:Z

    .line 122
    .line 123
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 124
    .line 125
    .line 126
    move-result v1

    .line 127
    iget-object v3, p0, Ltz/f0;->n:Ltz/z;

    .line 128
    .line 129
    if-nez v3, :cond_7

    .line 130
    .line 131
    move v3, v0

    .line 132
    goto :goto_7

    .line 133
    :cond_7
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 134
    .line 135
    .line 136
    move-result v3

    .line 137
    :goto_7
    add-int/2addr v1, v3

    .line 138
    mul-int/2addr v1, v2

    .line 139
    iget-object v3, p0, Ltz/f0;->o:Ltz/x;

    .line 140
    .line 141
    if-nez v3, :cond_8

    .line 142
    .line 143
    move v3, v0

    .line 144
    goto :goto_8

    .line 145
    :cond_8
    iget-boolean v3, v3, Ltz/x;->b:Z

    .line 146
    .line 147
    invoke-static {v3}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 148
    .line 149
    .line 150
    move-result v3

    .line 151
    :goto_8
    add-int/2addr v1, v3

    .line 152
    mul-int/2addr v1, v2

    .line 153
    iget-object v3, p0, Ltz/f0;->p:Ltz/y;

    .line 154
    .line 155
    if-nez v3, :cond_9

    .line 156
    .line 157
    move v3, v0

    .line 158
    goto :goto_9

    .line 159
    :cond_9
    iget-boolean v3, v3, Ltz/y;->b:Z

    .line 160
    .line 161
    invoke-static {v3}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 162
    .line 163
    .line 164
    move-result v3

    .line 165
    :goto_9
    add-int/2addr v1, v3

    .line 166
    mul-int/2addr v1, v2

    .line 167
    iget-object v3, p0, Ltz/f0;->q:Llp/p0;

    .line 168
    .line 169
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 170
    .line 171
    .line 172
    move-result v3

    .line 173
    add-int/2addr v3, v1

    .line 174
    mul-int/2addr v3, v2

    .line 175
    iget-object v1, p0, Ltz/f0;->r:Ltz/a0;

    .line 176
    .line 177
    if-nez v1, :cond_a

    .line 178
    .line 179
    move v1, v0

    .line 180
    goto :goto_a

    .line 181
    :cond_a
    invoke-virtual {v1}, Ltz/a0;->hashCode()I

    .line 182
    .line 183
    .line 184
    move-result v1

    .line 185
    :goto_a
    add-int/2addr v3, v1

    .line 186
    mul-int/2addr v3, v2

    .line 187
    iget-object v1, p0, Ltz/f0;->s:Lne0/c;

    .line 188
    .line 189
    if-nez v1, :cond_b

    .line 190
    .line 191
    move v1, v0

    .line 192
    goto :goto_b

    .line 193
    :cond_b
    invoke-virtual {v1}, Lne0/c;->hashCode()I

    .line 194
    .line 195
    .line 196
    move-result v1

    .line 197
    :goto_b
    add-int/2addr v3, v1

    .line 198
    mul-int/2addr v3, v2

    .line 199
    iget-boolean v1, p0, Ltz/f0;->t:Z

    .line 200
    .line 201
    invoke-static {v3, v2, v1}, La7/g0;->e(IIZ)I

    .line 202
    .line 203
    .line 204
    move-result v1

    .line 205
    iget-boolean v3, p0, Ltz/f0;->u:Z

    .line 206
    .line 207
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 208
    .line 209
    .line 210
    move-result v1

    .line 211
    iget-boolean v3, p0, Ltz/f0;->v:Z

    .line 212
    .line 213
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 214
    .line 215
    .line 216
    move-result v1

    .line 217
    iget-boolean v3, p0, Ltz/f0;->w:Z

    .line 218
    .line 219
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 220
    .line 221
    .line 222
    move-result v1

    .line 223
    iget-boolean v3, p0, Ltz/f0;->x:Z

    .line 224
    .line 225
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 226
    .line 227
    .line 228
    move-result v1

    .line 229
    iget-object v3, p0, Ltz/f0;->y:Ljava/lang/String;

    .line 230
    .line 231
    if-nez v3, :cond_c

    .line 232
    .line 233
    move v3, v0

    .line 234
    goto :goto_c

    .line 235
    :cond_c
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 236
    .line 237
    .line 238
    move-result v3

    .line 239
    :goto_c
    add-int/2addr v1, v3

    .line 240
    mul-int/2addr v1, v2

    .line 241
    iget-object v3, p0, Ltz/f0;->z:Ljava/lang/String;

    .line 242
    .line 243
    if-nez v3, :cond_d

    .line 244
    .line 245
    move v3, v0

    .line 246
    goto :goto_d

    .line 247
    :cond_d
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 248
    .line 249
    .line 250
    move-result v3

    .line 251
    :goto_d
    add-int/2addr v1, v3

    .line 252
    mul-int/2addr v1, v2

    .line 253
    iget-boolean v3, p0, Ltz/f0;->A:Z

    .line 254
    .line 255
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 256
    .line 257
    .line 258
    move-result v1

    .line 259
    iget-object p0, p0, Ltz/f0;->B:Ljava/lang/String;

    .line 260
    .line 261
    if-nez p0, :cond_e

    .line 262
    .line 263
    goto :goto_e

    .line 264
    :cond_e
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 265
    .line 266
    .line 267
    move-result v0

    .line 268
    :goto_e
    add-int/2addr v1, v0

    .line 269
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(error="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ltz/f0;->a:Lql0/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", subscriptionLicenseState="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Ltz/f0;->b:Ler0/g;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", viewMode="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Ltz/f0;->c:Llf0/i;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", isRefreshing="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-boolean v1, p0, Ltz/f0;->d:Z

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", isChargingLoading="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v1, ", isChargingSettingsEnabled="

    .line 49
    .line 50
    const-string v2, ", chargingTypeTitle="

    .line 51
    .line 52
    iget-boolean v3, p0, Ltz/f0;->e:Z

    .line 53
    .line 54
    iget-boolean v4, p0, Ltz/f0;->f:Z

    .line 55
    .line 56
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const-string v1, ", chargingTitle="

    .line 60
    .line 61
    const-string v2, ", chargingText="

    .line 62
    .line 63
    iget-object v3, p0, Ltz/f0;->g:Ljava/lang/String;

    .line 64
    .line 65
    iget-object v4, p0, Ltz/f0;->h:Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const-string v1, ", chargeModeTitle="

    .line 71
    .line 72
    const-string v2, ", chargeModeText="

    .line 73
    .line 74
    iget-object v3, p0, Ltz/f0;->i:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v4, p0, Ltz/f0;->j:Ljava/lang/String;

    .line 77
    .line 78
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    iget-object v1, p0, Ltz/f0;->k:Ljava/lang/String;

    .line 82
    .line 83
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string v1, ", chargingProfile="

    .line 87
    .line 88
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    iget-object v1, p0, Ltz/f0;->l:Ltz/e0;

    .line 92
    .line 93
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    const-string v1, ", isWarning="

    .line 97
    .line 98
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    iget-boolean v1, p0, Ltz/f0;->m:Z

    .line 102
    .line 103
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    const-string v1, ", changeChargeLimitButton="

    .line 107
    .line 108
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    iget-object v1, p0, Ltz/f0;->n:Ltz/z;

    .line 112
    .line 113
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    const-string v1, ", startChargingButton="

    .line 117
    .line 118
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    iget-object v1, p0, Ltz/f0;->o:Ltz/x;

    .line 122
    .line 123
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    const-string v1, ", stopChargingButton="

    .line 127
    .line 128
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    iget-object v1, p0, Ltz/f0;->p:Ltz/y;

    .line 132
    .line 133
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    const-string v1, ", gaugeState="

    .line 137
    .line 138
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    iget-object v1, p0, Ltz/f0;->q:Llp/p0;

    .line 142
    .line 143
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 144
    .line 145
    .line 146
    const-string v1, ", chargingDetails="

    .line 147
    .line 148
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    iget-object v1, p0, Ltz/f0;->r:Ltz/a0;

    .line 152
    .line 153
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    const-string v1, ", lastShownError="

    .line 157
    .line 158
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    iget-object v1, p0, Ltz/f0;->s:Lne0/c;

    .line 162
    .line 163
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    const-string v1, ", isChargingHistoryVisible="

    .line 167
    .line 168
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    iget-boolean v1, p0, Ltz/f0;->t:Z

    .line 172
    .line 173
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 174
    .line 175
    .line 176
    const-string v1, ", isChargingStatisticsVisible="

    .line 177
    .line 178
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    const-string v1, ", isChargingStatisticsReadyToChargeVisible="

    .line 182
    .line 183
    const-string v2, ", isChargingProfilesVisible="

    .line 184
    .line 185
    iget-boolean v3, p0, Ltz/f0;->u:Z

    .line 186
    .line 187
    iget-boolean v4, p0, Ltz/f0;->v:Z

    .line 188
    .line 189
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 190
    .line 191
    .line 192
    const-string v1, ", useNewRadial="

    .line 193
    .line 194
    const-string v2, ", biDiWarningText="

    .line 195
    .line 196
    iget-boolean v3, p0, Ltz/f0;->w:Z

    .line 197
    .line 198
    iget-boolean v4, p0, Ltz/f0;->x:Z

    .line 199
    .line 200
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 201
    .line 202
    .line 203
    const-string v1, ", biDiLimitText="

    .line 204
    .line 205
    const-string v2, ", isBiDiChargingFeatureEnabled="

    .line 206
    .line 207
    iget-object v3, p0, Ltz/f0;->y:Ljava/lang/String;

    .line 208
    .line 209
    iget-object v4, p0, Ltz/f0;->z:Ljava/lang/String;

    .line 210
    .line 211
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    iget-boolean v1, p0, Ltz/f0;->A:Z

    .line 215
    .line 216
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 217
    .line 218
    .line 219
    const-string v1, ", profileLimitRange="

    .line 220
    .line 221
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 222
    .line 223
    .line 224
    iget-object p0, p0, Ltz/f0;->B:Ljava/lang/String;

    .line 225
    .line 226
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 227
    .line 228
    .line 229
    const-string p0, ")"

    .line 230
    .line 231
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 232
    .line 233
    .line 234
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object p0

    .line 238
    return-object p0
.end method
