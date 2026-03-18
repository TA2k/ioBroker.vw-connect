.class public final Lh50/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final A:Z

.field public final B:Ljava/lang/String;

.field public final C:Z

.field public final D:I

.field public final E:Z

.field public final F:Z

.field public final G:Z

.field public final H:Z

.field public final I:Z

.field public final J:Z

.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:I

.field public final h:Z

.field public final i:Z

.field public final j:Ljava/lang/String;

.field public final k:Z

.field public final l:Z

.field public final m:Z

.field public final n:Z

.field public final o:Ljava/lang/String;

.field public final p:Ljava/lang/String;

.field public final q:Ljava/lang/String;

.field public final r:Ljava/lang/String;

.field public final s:Ljava/util/List;

.field public final t:Ljava/util/List;

.field public final u:Ljava/lang/String;

.field public final v:Ler0/g;

.field public final w:Ljava/lang/String;

.field public final x:Lql0/g;

.field public final y:Lqp0/b0;

.field public final z:Z


# direct methods
.method public synthetic constructor <init>(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;I)V
    .locals 36

    move/from16 v0, p8

    and-int/lit8 v1, v0, 0x1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    move v4, v2

    goto :goto_0

    :cond_0
    move/from16 v4, p1

    :goto_0
    and-int/lit16 v1, v0, 0x4000

    if-eqz v1, :cond_1

    .line 42
    const-string v1, ""

    move-object/from16 v18, v1

    goto :goto_1

    :cond_1
    move-object/from16 v18, p2

    :goto_1
    const v1, 0x8000

    and-int/2addr v1, v0

    const/4 v3, 0x0

    if-eqz v1, :cond_2

    move-object/from16 v19, v3

    goto :goto_2

    :cond_2
    move-object/from16 v19, p3

    :goto_2
    const/high16 v1, 0x10000

    and-int/2addr v1, v0

    if-eqz v1, :cond_3

    move-object/from16 v20, v3

    goto :goto_3

    :cond_3
    move-object/from16 v20, p4

    :goto_3
    const/high16 v1, 0x20000

    and-int/2addr v1, v0

    if-eqz v1, :cond_4

    move-object/from16 v21, v3

    goto :goto_4

    :cond_4
    move-object/from16 v21, p5

    :goto_4
    const/high16 v1, 0x40000

    and-int/2addr v1, v0

    .line 43
    sget-object v23, Lmx0/s;->d:Lmx0/s;

    if-eqz v1, :cond_5

    move-object/from16 v22, v23

    goto :goto_5

    :cond_5
    move-object/from16 v22, p6

    :goto_5
    const/high16 v1, 0x100000

    and-int/2addr v1, v0

    if-eqz v1, :cond_6

    move-object/from16 v24, v3

    goto :goto_6

    :cond_6
    move-object/from16 v24, p7

    .line 44
    :goto_6
    sget-object v25, Ler0/g;->d:Ler0/g;

    const/high16 v1, 0x2000000

    and-int/2addr v1, v0

    const/4 v3, 0x1

    if-eqz v1, :cond_7

    move/from16 v29, v2

    goto :goto_7

    :cond_7
    move/from16 v29, v3

    :goto_7
    const/high16 v1, 0x4000000

    and-int/2addr v0, v1

    if-eqz v0, :cond_8

    move/from16 v30, v2

    goto :goto_8

    :cond_8
    move/from16 v30, v3

    :goto_8
    const/16 v34, 0x0

    const/16 v35, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v31, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x5

    move-object/from16 v3, p0

    .line 45
    invoke-direct/range {v3 .. v35}, Lh50/v;-><init>(ZZZZZZIZZLjava/lang/String;ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ler0/g;Ljava/lang/String;Lql0/g;Lqp0/b0;ZZLjava/lang/String;ZIZZ)V

    return-void
.end method

.method public constructor <init>(ZZZZZZIZZLjava/lang/String;ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ler0/g;Ljava/lang/String;Lql0/g;Lqp0/b0;ZZLjava/lang/String;ZIZZ)V
    .locals 4

    move-object/from16 v0, p15

    move-object/from16 v1, p19

    move-object/from16 v2, p20

    const-string v3, "tripDuration"

    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "stops"

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-boolean p1, p0, Lh50/v;->a:Z

    .line 3
    iput-boolean p2, p0, Lh50/v;->b:Z

    .line 4
    iput-boolean p3, p0, Lh50/v;->c:Z

    .line 5
    iput-boolean p4, p0, Lh50/v;->d:Z

    .line 6
    iput-boolean p5, p0, Lh50/v;->e:Z

    .line 7
    iput-boolean p6, p0, Lh50/v;->f:Z

    .line 8
    iput p7, p0, Lh50/v;->g:I

    .line 9
    iput-boolean p8, p0, Lh50/v;->h:Z

    .line 10
    iput-boolean p9, p0, Lh50/v;->i:Z

    .line 11
    iput-object p10, p0, Lh50/v;->j:Ljava/lang/String;

    .line 12
    iput-boolean p11, p0, Lh50/v;->k:Z

    move/from16 p1, p12

    .line 13
    iput-boolean p1, p0, Lh50/v;->l:Z

    move/from16 p1, p13

    .line 14
    iput-boolean p1, p0, Lh50/v;->m:Z

    move/from16 p1, p14

    .line 15
    iput-boolean p1, p0, Lh50/v;->n:Z

    .line 16
    iput-object v0, p0, Lh50/v;->o:Ljava/lang/String;

    move-object/from16 p1, p16

    .line 17
    iput-object p1, p0, Lh50/v;->p:Ljava/lang/String;

    move-object/from16 p1, p17

    .line 18
    iput-object p1, p0, Lh50/v;->q:Ljava/lang/String;

    move-object/from16 p1, p18

    .line 19
    iput-object p1, p0, Lh50/v;->r:Ljava/lang/String;

    .line 20
    iput-object v1, p0, Lh50/v;->s:Ljava/util/List;

    .line 21
    iput-object v2, p0, Lh50/v;->t:Ljava/util/List;

    move-object/from16 p1, p21

    .line 22
    iput-object p1, p0, Lh50/v;->u:Ljava/lang/String;

    move-object/from16 p1, p22

    .line 23
    iput-object p1, p0, Lh50/v;->v:Ler0/g;

    move-object/from16 p1, p23

    .line 24
    iput-object p1, p0, Lh50/v;->w:Ljava/lang/String;

    move-object/from16 p1, p24

    .line 25
    iput-object p1, p0, Lh50/v;->x:Lql0/g;

    move-object/from16 p1, p25

    .line 26
    iput-object p1, p0, Lh50/v;->y:Lqp0/b0;

    move/from16 p1, p26

    .line 27
    iput-boolean p1, p0, Lh50/v;->z:Z

    move/from16 p1, p27

    .line 28
    iput-boolean p1, p0, Lh50/v;->A:Z

    move-object/from16 p1, p28

    .line 29
    iput-object p1, p0, Lh50/v;->B:Ljava/lang/String;

    move/from16 p1, p29

    .line 30
    iput-boolean p1, p0, Lh50/v;->C:Z

    move/from16 p1, p30

    .line 31
    iput p1, p0, Lh50/v;->D:I

    move/from16 p1, p31

    .line 32
    iput-boolean p1, p0, Lh50/v;->E:Z

    move/from16 p1, p32

    .line 33
    iput-boolean p1, p0, Lh50/v;->F:Z

    .line 34
    move-object p1, v2

    check-cast p1, Ljava/lang/Iterable;

    .line 35
    instance-of p2, p1, Ljava/util/Collection;

    const/4 p3, 0x0

    const/4 p4, 0x1

    if-eqz p2, :cond_1

    move-object p2, p1

    check-cast p2, Ljava/util/Collection;

    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result p2

    if-eqz p2, :cond_1

    :cond_0
    move p1, p4

    goto :goto_0

    .line 36
    :cond_1
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Lh50/t;

    .line 37
    iget-boolean p2, p2, Lh50/t;->b:Z

    if-eqz p2, :cond_2

    move p1, p3

    .line 38
    :goto_0
    iput-boolean p1, p0, Lh50/v;->G:Z

    .line 39
    iget-boolean p1, p0, Lh50/v;->m:Z

    xor-int/lit8 p2, p1, 0x1

    iput-boolean p2, p0, Lh50/v;->H:Z

    .line 40
    iput-boolean p1, p0, Lh50/v;->I:Z

    .line 41
    iget-boolean p1, p0, Lh50/v;->z:Z

    if-eqz p1, :cond_3

    iget-boolean p1, p0, Lh50/v;->E:Z

    if-nez p1, :cond_3

    move p3, p4

    :cond_3
    iput-boolean p3, p0, Lh50/v;->J:Z

    return-void
.end method

.method public static a(Lh50/v;ZZZZZZIZZLjava/lang/String;ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;Ler0/g;Ljava/lang/String;Lql0/g;Lqp0/b0;ZZLjava/lang/String;ZZZI)Lh50/v;
    .locals 36

    move-object/from16 v0, p0

    move/from16 v1, p31

    and-int/lit8 v2, v1, 0x1

    if-eqz v2, :cond_0

    iget-boolean v2, v0, Lh50/v;->a:Z

    move v4, v2

    goto :goto_0

    :cond_0
    move/from16 v4, p1

    :goto_0
    and-int/lit8 v2, v1, 0x2

    if-eqz v2, :cond_1

    iget-boolean v2, v0, Lh50/v;->b:Z

    move v5, v2

    goto :goto_1

    :cond_1
    move/from16 v5, p2

    :goto_1
    and-int/lit8 v2, v1, 0x4

    if-eqz v2, :cond_2

    iget-boolean v2, v0, Lh50/v;->c:Z

    move v6, v2

    goto :goto_2

    :cond_2
    move/from16 v6, p3

    :goto_2
    and-int/lit8 v2, v1, 0x8

    if-eqz v2, :cond_3

    iget-boolean v2, v0, Lh50/v;->d:Z

    move v7, v2

    goto :goto_3

    :cond_3
    move/from16 v7, p4

    :goto_3
    and-int/lit8 v2, v1, 0x10

    if-eqz v2, :cond_4

    iget-boolean v2, v0, Lh50/v;->e:Z

    move v8, v2

    goto :goto_4

    :cond_4
    move/from16 v8, p5

    :goto_4
    and-int/lit8 v2, v1, 0x20

    if-eqz v2, :cond_5

    iget-boolean v2, v0, Lh50/v;->f:Z

    move v9, v2

    goto :goto_5

    :cond_5
    move/from16 v9, p6

    :goto_5
    and-int/lit8 v2, v1, 0x40

    if-eqz v2, :cond_6

    iget v2, v0, Lh50/v;->g:I

    move v10, v2

    goto :goto_6

    :cond_6
    move/from16 v10, p7

    :goto_6
    and-int/lit16 v2, v1, 0x80

    if-eqz v2, :cond_7

    iget-boolean v2, v0, Lh50/v;->h:Z

    move v11, v2

    goto :goto_7

    :cond_7
    move/from16 v11, p8

    :goto_7
    and-int/lit16 v2, v1, 0x100

    if-eqz v2, :cond_8

    iget-boolean v2, v0, Lh50/v;->i:Z

    move v12, v2

    goto :goto_8

    :cond_8
    move/from16 v12, p9

    :goto_8
    and-int/lit16 v2, v1, 0x200

    if-eqz v2, :cond_9

    iget-object v2, v0, Lh50/v;->j:Ljava/lang/String;

    move-object v13, v2

    goto :goto_9

    :cond_9
    move-object/from16 v13, p10

    :goto_9
    and-int/lit16 v2, v1, 0x400

    if-eqz v2, :cond_a

    iget-boolean v2, v0, Lh50/v;->k:Z

    move v14, v2

    goto :goto_a

    :cond_a
    move/from16 v14, p11

    :goto_a
    and-int/lit16 v2, v1, 0x800

    if-eqz v2, :cond_b

    iget-boolean v2, v0, Lh50/v;->l:Z

    move v15, v2

    goto :goto_b

    :cond_b
    move/from16 v15, p12

    :goto_b
    and-int/lit16 v2, v1, 0x1000

    if-eqz v2, :cond_c

    iget-boolean v2, v0, Lh50/v;->m:Z

    move/from16 v16, v2

    goto :goto_c

    :cond_c
    move/from16 v16, p13

    :goto_c
    and-int/lit16 v2, v1, 0x2000

    if-eqz v2, :cond_d

    iget-boolean v2, v0, Lh50/v;->n:Z

    move/from16 v17, v2

    goto :goto_d

    :cond_d
    move/from16 v17, p14

    :goto_d
    and-int/lit16 v2, v1, 0x4000

    if-eqz v2, :cond_e

    iget-object v2, v0, Lh50/v;->o:Ljava/lang/String;

    goto :goto_e

    :cond_e
    move-object/from16 v2, p15

    :goto_e
    const v3, 0x8000

    and-int/2addr v3, v1

    if-eqz v3, :cond_f

    iget-object v3, v0, Lh50/v;->p:Ljava/lang/String;

    move-object/from16 v19, v3

    goto :goto_f

    :cond_f
    move-object/from16 v19, p16

    :goto_f
    const/high16 v3, 0x10000

    and-int/2addr v3, v1

    if-eqz v3, :cond_10

    iget-object v3, v0, Lh50/v;->q:Ljava/lang/String;

    move-object/from16 v20, v3

    goto :goto_10

    :cond_10
    move-object/from16 v20, p17

    :goto_10
    const/high16 v3, 0x20000

    and-int/2addr v3, v1

    if-eqz v3, :cond_11

    iget-object v3, v0, Lh50/v;->r:Ljava/lang/String;

    move-object/from16 v21, v3

    goto :goto_11

    :cond_11
    move-object/from16 v21, p18

    :goto_11
    const/high16 v3, 0x40000

    and-int/2addr v3, v1

    if-eqz v3, :cond_12

    iget-object v3, v0, Lh50/v;->s:Ljava/util/List;

    goto :goto_12

    :cond_12
    move-object/from16 v3, p19

    :goto_12
    const/high16 v18, 0x80000

    and-int v18, v1, v18

    if-eqz v18, :cond_13

    iget-object v1, v0, Lh50/v;->t:Ljava/util/List;

    goto :goto_13

    :cond_13
    move-object/from16 v1, p20

    :goto_13
    const/high16 v18, 0x100000

    and-int v18, p31, v18

    move/from16 p1, v4

    if-eqz v18, :cond_14

    iget-object v4, v0, Lh50/v;->u:Ljava/lang/String;

    :goto_14
    move-object/from16 v24, v4

    goto :goto_15

    :cond_14
    const/4 v4, 0x0

    goto :goto_14

    :goto_15
    const/high16 v4, 0x200000

    and-int v4, p31, v4

    if-eqz v4, :cond_15

    iget-object v4, v0, Lh50/v;->v:Ler0/g;

    goto :goto_16

    :cond_15
    move-object/from16 v4, p21

    :goto_16
    const/high16 v18, 0x400000

    and-int v18, p31, v18

    move/from16 p2, v5

    if-eqz v18, :cond_16

    iget-object v5, v0, Lh50/v;->w:Ljava/lang/String;

    move-object/from16 v26, v5

    goto :goto_17

    :cond_16
    move-object/from16 v26, p22

    :goto_17
    const/high16 v5, 0x800000

    and-int v5, p31, v5

    if-eqz v5, :cond_17

    iget-object v5, v0, Lh50/v;->x:Lql0/g;

    move-object/from16 v27, v5

    goto :goto_18

    :cond_17
    move-object/from16 v27, p23

    :goto_18
    const/high16 v5, 0x1000000

    and-int v5, p31, v5

    if-eqz v5, :cond_18

    iget-object v5, v0, Lh50/v;->y:Lqp0/b0;

    move-object/from16 v28, v5

    goto :goto_19

    :cond_18
    move-object/from16 v28, p24

    :goto_19
    const/high16 v5, 0x2000000

    and-int v5, p31, v5

    if-eqz v5, :cond_19

    iget-boolean v5, v0, Lh50/v;->z:Z

    move/from16 v29, v5

    goto :goto_1a

    :cond_19
    move/from16 v29, p25

    :goto_1a
    const/high16 v5, 0x4000000

    and-int v5, p31, v5

    if-eqz v5, :cond_1a

    iget-boolean v5, v0, Lh50/v;->A:Z

    move/from16 v30, v5

    goto :goto_1b

    :cond_1a
    move/from16 v30, p26

    :goto_1b
    const/high16 v5, 0x8000000

    and-int v5, p31, v5

    if-eqz v5, :cond_1b

    iget-object v5, v0, Lh50/v;->B:Ljava/lang/String;

    move-object/from16 v31, v5

    goto :goto_1c

    :cond_1b
    move-object/from16 v31, p27

    :goto_1c
    const/high16 v5, 0x10000000

    and-int v5, p31, v5

    if-eqz v5, :cond_1c

    iget-boolean v5, v0, Lh50/v;->C:Z

    move/from16 v32, v5

    goto :goto_1d

    :cond_1c
    move/from16 v32, p28

    :goto_1d
    iget v5, v0, Lh50/v;->D:I

    const/high16 v18, 0x40000000    # 2.0f

    and-int v18, p31, v18

    move/from16 v33, v5

    if-eqz v18, :cond_1d

    iget-boolean v5, v0, Lh50/v;->E:Z

    move/from16 v34, v5

    goto :goto_1e

    :cond_1d
    move/from16 v34, p29

    :goto_1e
    const/high16 v5, -0x80000000

    and-int v5, p31, v5

    if-eqz v5, :cond_1e

    iget-boolean v5, v0, Lh50/v;->F:Z

    move/from16 v35, v5

    goto :goto_1f

    :cond_1e
    move/from16 v35, p30

    :goto_1f
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1
    const-string v0, "tripDuration"

    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "stops"

    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "shareRows"

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "subscriptionLicenseState"

    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v22, v3

    new-instance v3, Lh50/v;

    move/from16 v5, p2

    move-object/from16 v23, v1

    move-object/from16 v18, v2

    move-object/from16 v25, v4

    move/from16 v4, p1

    invoke-direct/range {v3 .. v35}, Lh50/v;-><init>(ZZZZZZIZZLjava/lang/String;ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ler0/g;Ljava/lang/String;Lql0/g;Lqp0/b0;ZZLjava/lang/String;ZIZZ)V

    return-object v3
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_1

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Lh50/v;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Lh50/v;

    .line 12
    .line 13
    iget-boolean v0, p0, Lh50/v;->a:Z

    .line 14
    .line 15
    iget-boolean v1, p1, Lh50/v;->a:Z

    .line 16
    .line 17
    if-eq v0, v1, :cond_2

    .line 18
    .line 19
    goto/16 :goto_0

    .line 20
    .line 21
    :cond_2
    iget-boolean v0, p0, Lh50/v;->b:Z

    .line 22
    .line 23
    iget-boolean v1, p1, Lh50/v;->b:Z

    .line 24
    .line 25
    if-eq v0, v1, :cond_3

    .line 26
    .line 27
    goto/16 :goto_0

    .line 28
    .line 29
    :cond_3
    iget-boolean v0, p0, Lh50/v;->c:Z

    .line 30
    .line 31
    iget-boolean v1, p1, Lh50/v;->c:Z

    .line 32
    .line 33
    if-eq v0, v1, :cond_4

    .line 34
    .line 35
    goto/16 :goto_0

    .line 36
    .line 37
    :cond_4
    iget-boolean v0, p0, Lh50/v;->d:Z

    .line 38
    .line 39
    iget-boolean v1, p1, Lh50/v;->d:Z

    .line 40
    .line 41
    if-eq v0, v1, :cond_5

    .line 42
    .line 43
    goto/16 :goto_0

    .line 44
    .line 45
    :cond_5
    iget-boolean v0, p0, Lh50/v;->e:Z

    .line 46
    .line 47
    iget-boolean v1, p1, Lh50/v;->e:Z

    .line 48
    .line 49
    if-eq v0, v1, :cond_6

    .line 50
    .line 51
    goto/16 :goto_0

    .line 52
    .line 53
    :cond_6
    iget-boolean v0, p0, Lh50/v;->f:Z

    .line 54
    .line 55
    iget-boolean v1, p1, Lh50/v;->f:Z

    .line 56
    .line 57
    if-eq v0, v1, :cond_7

    .line 58
    .line 59
    goto/16 :goto_0

    .line 60
    .line 61
    :cond_7
    iget v0, p0, Lh50/v;->g:I

    .line 62
    .line 63
    iget v1, p1, Lh50/v;->g:I

    .line 64
    .line 65
    if-eq v0, v1, :cond_8

    .line 66
    .line 67
    goto/16 :goto_0

    .line 68
    .line 69
    :cond_8
    iget-boolean v0, p0, Lh50/v;->h:Z

    .line 70
    .line 71
    iget-boolean v1, p1, Lh50/v;->h:Z

    .line 72
    .line 73
    if-eq v0, v1, :cond_9

    .line 74
    .line 75
    goto/16 :goto_0

    .line 76
    .line 77
    :cond_9
    iget-boolean v0, p0, Lh50/v;->i:Z

    .line 78
    .line 79
    iget-boolean v1, p1, Lh50/v;->i:Z

    .line 80
    .line 81
    if-eq v0, v1, :cond_a

    .line 82
    .line 83
    goto/16 :goto_0

    .line 84
    .line 85
    :cond_a
    iget-object v0, p0, Lh50/v;->j:Ljava/lang/String;

    .line 86
    .line 87
    iget-object v1, p1, Lh50/v;->j:Ljava/lang/String;

    .line 88
    .line 89
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    if-nez v0, :cond_b

    .line 94
    .line 95
    goto/16 :goto_0

    .line 96
    .line 97
    :cond_b
    iget-boolean v0, p0, Lh50/v;->k:Z

    .line 98
    .line 99
    iget-boolean v1, p1, Lh50/v;->k:Z

    .line 100
    .line 101
    if-eq v0, v1, :cond_c

    .line 102
    .line 103
    goto/16 :goto_0

    .line 104
    .line 105
    :cond_c
    iget-boolean v0, p0, Lh50/v;->l:Z

    .line 106
    .line 107
    iget-boolean v1, p1, Lh50/v;->l:Z

    .line 108
    .line 109
    if-eq v0, v1, :cond_d

    .line 110
    .line 111
    goto/16 :goto_0

    .line 112
    .line 113
    :cond_d
    iget-boolean v0, p0, Lh50/v;->m:Z

    .line 114
    .line 115
    iget-boolean v1, p1, Lh50/v;->m:Z

    .line 116
    .line 117
    if-eq v0, v1, :cond_e

    .line 118
    .line 119
    goto/16 :goto_0

    .line 120
    .line 121
    :cond_e
    iget-boolean v0, p0, Lh50/v;->n:Z

    .line 122
    .line 123
    iget-boolean v1, p1, Lh50/v;->n:Z

    .line 124
    .line 125
    if-eq v0, v1, :cond_f

    .line 126
    .line 127
    goto/16 :goto_0

    .line 128
    .line 129
    :cond_f
    iget-object v0, p0, Lh50/v;->o:Ljava/lang/String;

    .line 130
    .line 131
    iget-object v1, p1, Lh50/v;->o:Ljava/lang/String;

    .line 132
    .line 133
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v0

    .line 137
    if-nez v0, :cond_10

    .line 138
    .line 139
    goto/16 :goto_0

    .line 140
    .line 141
    :cond_10
    iget-object v0, p0, Lh50/v;->p:Ljava/lang/String;

    .line 142
    .line 143
    iget-object v1, p1, Lh50/v;->p:Ljava/lang/String;

    .line 144
    .line 145
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v0

    .line 149
    if-nez v0, :cond_11

    .line 150
    .line 151
    goto/16 :goto_0

    .line 152
    .line 153
    :cond_11
    iget-object v0, p0, Lh50/v;->q:Ljava/lang/String;

    .line 154
    .line 155
    iget-object v1, p1, Lh50/v;->q:Ljava/lang/String;

    .line 156
    .line 157
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v0

    .line 161
    if-nez v0, :cond_12

    .line 162
    .line 163
    goto/16 :goto_0

    .line 164
    .line 165
    :cond_12
    iget-object v0, p0, Lh50/v;->r:Ljava/lang/String;

    .line 166
    .line 167
    iget-object v1, p1, Lh50/v;->r:Ljava/lang/String;

    .line 168
    .line 169
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v0

    .line 173
    if-nez v0, :cond_13

    .line 174
    .line 175
    goto/16 :goto_0

    .line 176
    .line 177
    :cond_13
    iget-object v0, p0, Lh50/v;->s:Ljava/util/List;

    .line 178
    .line 179
    iget-object v1, p1, Lh50/v;->s:Ljava/util/List;

    .line 180
    .line 181
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v0

    .line 185
    if-nez v0, :cond_14

    .line 186
    .line 187
    goto/16 :goto_0

    .line 188
    .line 189
    :cond_14
    iget-object v0, p0, Lh50/v;->t:Ljava/util/List;

    .line 190
    .line 191
    iget-object v1, p1, Lh50/v;->t:Ljava/util/List;

    .line 192
    .line 193
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v0

    .line 197
    if-nez v0, :cond_15

    .line 198
    .line 199
    goto/16 :goto_0

    .line 200
    .line 201
    :cond_15
    iget-object v0, p0, Lh50/v;->u:Ljava/lang/String;

    .line 202
    .line 203
    iget-object v1, p1, Lh50/v;->u:Ljava/lang/String;

    .line 204
    .line 205
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v0

    .line 209
    if-nez v0, :cond_16

    .line 210
    .line 211
    goto :goto_0

    .line 212
    :cond_16
    iget-object v0, p0, Lh50/v;->v:Ler0/g;

    .line 213
    .line 214
    iget-object v1, p1, Lh50/v;->v:Ler0/g;

    .line 215
    .line 216
    if-eq v0, v1, :cond_17

    .line 217
    .line 218
    goto :goto_0

    .line 219
    :cond_17
    iget-object v0, p0, Lh50/v;->w:Ljava/lang/String;

    .line 220
    .line 221
    iget-object v1, p1, Lh50/v;->w:Ljava/lang/String;

    .line 222
    .line 223
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    move-result v0

    .line 227
    if-nez v0, :cond_18

    .line 228
    .line 229
    goto :goto_0

    .line 230
    :cond_18
    iget-object v0, p0, Lh50/v;->x:Lql0/g;

    .line 231
    .line 232
    iget-object v1, p1, Lh50/v;->x:Lql0/g;

    .line 233
    .line 234
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 235
    .line 236
    .line 237
    move-result v0

    .line 238
    if-nez v0, :cond_19

    .line 239
    .line 240
    goto :goto_0

    .line 241
    :cond_19
    iget-object v0, p0, Lh50/v;->y:Lqp0/b0;

    .line 242
    .line 243
    iget-object v1, p1, Lh50/v;->y:Lqp0/b0;

    .line 244
    .line 245
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    move-result v0

    .line 249
    if-nez v0, :cond_1a

    .line 250
    .line 251
    goto :goto_0

    .line 252
    :cond_1a
    iget-boolean v0, p0, Lh50/v;->z:Z

    .line 253
    .line 254
    iget-boolean v1, p1, Lh50/v;->z:Z

    .line 255
    .line 256
    if-eq v0, v1, :cond_1b

    .line 257
    .line 258
    goto :goto_0

    .line 259
    :cond_1b
    iget-boolean v0, p0, Lh50/v;->A:Z

    .line 260
    .line 261
    iget-boolean v1, p1, Lh50/v;->A:Z

    .line 262
    .line 263
    if-eq v0, v1, :cond_1c

    .line 264
    .line 265
    goto :goto_0

    .line 266
    :cond_1c
    iget-object v0, p0, Lh50/v;->B:Ljava/lang/String;

    .line 267
    .line 268
    iget-object v1, p1, Lh50/v;->B:Ljava/lang/String;

    .line 269
    .line 270
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 271
    .line 272
    .line 273
    move-result v0

    .line 274
    if-nez v0, :cond_1d

    .line 275
    .line 276
    goto :goto_0

    .line 277
    :cond_1d
    iget-boolean v0, p0, Lh50/v;->C:Z

    .line 278
    .line 279
    iget-boolean v1, p1, Lh50/v;->C:Z

    .line 280
    .line 281
    if-eq v0, v1, :cond_1e

    .line 282
    .line 283
    goto :goto_0

    .line 284
    :cond_1e
    iget v0, p0, Lh50/v;->D:I

    .line 285
    .line 286
    iget v1, p1, Lh50/v;->D:I

    .line 287
    .line 288
    if-eq v0, v1, :cond_1f

    .line 289
    .line 290
    goto :goto_0

    .line 291
    :cond_1f
    iget-boolean v0, p0, Lh50/v;->E:Z

    .line 292
    .line 293
    iget-boolean v1, p1, Lh50/v;->E:Z

    .line 294
    .line 295
    if-eq v0, v1, :cond_20

    .line 296
    .line 297
    goto :goto_0

    .line 298
    :cond_20
    iget-boolean p0, p0, Lh50/v;->F:Z

    .line 299
    .line 300
    iget-boolean p1, p1, Lh50/v;->F:Z

    .line 301
    .line 302
    if-eq p0, p1, :cond_21

    .line 303
    .line 304
    :goto_0
    const/4 p0, 0x0

    .line 305
    return p0

    .line 306
    :cond_21
    :goto_1
    const/4 p0, 0x1

    .line 307
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lh50/v;->a:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-boolean v2, p0, Lh50/v;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lh50/v;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lh50/v;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean v2, p0, Lh50/v;->e:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean v2, p0, Lh50/v;->f:Z

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget v2, p0, Lh50/v;->g:I

    .line 41
    .line 42
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-boolean v2, p0, Lh50/v;->h:Z

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-boolean v2, p0, Lh50/v;->i:Z

    .line 53
    .line 54
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    const/4 v2, 0x0

    .line 59
    iget-object v3, p0, Lh50/v;->j:Ljava/lang/String;

    .line 60
    .line 61
    if-nez v3, :cond_0

    .line 62
    .line 63
    move v3, v2

    .line 64
    goto :goto_0

    .line 65
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    :goto_0
    add-int/2addr v0, v3

    .line 70
    mul-int/2addr v0, v1

    .line 71
    iget-boolean v3, p0, Lh50/v;->k:Z

    .line 72
    .line 73
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    iget-boolean v3, p0, Lh50/v;->l:Z

    .line 78
    .line 79
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    iget-boolean v3, p0, Lh50/v;->m:Z

    .line 84
    .line 85
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    iget-boolean v3, p0, Lh50/v;->n:Z

    .line 90
    .line 91
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    iget-object v3, p0, Lh50/v;->o:Ljava/lang/String;

    .line 96
    .line 97
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    iget-object v3, p0, Lh50/v;->p:Ljava/lang/String;

    .line 102
    .line 103
    if-nez v3, :cond_1

    .line 104
    .line 105
    move v3, v2

    .line 106
    goto :goto_1

    .line 107
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    :goto_1
    add-int/2addr v0, v3

    .line 112
    mul-int/2addr v0, v1

    .line 113
    iget-object v3, p0, Lh50/v;->q:Ljava/lang/String;

    .line 114
    .line 115
    if-nez v3, :cond_2

    .line 116
    .line 117
    move v3, v2

    .line 118
    goto :goto_2

    .line 119
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    :goto_2
    add-int/2addr v0, v3

    .line 124
    mul-int/2addr v0, v1

    .line 125
    iget-object v3, p0, Lh50/v;->r:Ljava/lang/String;

    .line 126
    .line 127
    if-nez v3, :cond_3

    .line 128
    .line 129
    move v3, v2

    .line 130
    goto :goto_3

    .line 131
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 132
    .line 133
    .line 134
    move-result v3

    .line 135
    :goto_3
    add-int/2addr v0, v3

    .line 136
    mul-int/2addr v0, v1

    .line 137
    iget-object v3, p0, Lh50/v;->s:Ljava/util/List;

    .line 138
    .line 139
    invoke-static {v0, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 140
    .line 141
    .line 142
    move-result v0

    .line 143
    iget-object v3, p0, Lh50/v;->t:Ljava/util/List;

    .line 144
    .line 145
    invoke-static {v0, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 146
    .line 147
    .line 148
    move-result v0

    .line 149
    iget-object v3, p0, Lh50/v;->u:Ljava/lang/String;

    .line 150
    .line 151
    if-nez v3, :cond_4

    .line 152
    .line 153
    move v3, v2

    .line 154
    goto :goto_4

    .line 155
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 156
    .line 157
    .line 158
    move-result v3

    .line 159
    :goto_4
    add-int/2addr v0, v3

    .line 160
    mul-int/2addr v0, v1

    .line 161
    iget-object v3, p0, Lh50/v;->v:Ler0/g;

    .line 162
    .line 163
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 164
    .line 165
    .line 166
    move-result v3

    .line 167
    add-int/2addr v3, v0

    .line 168
    mul-int/2addr v3, v1

    .line 169
    iget-object v0, p0, Lh50/v;->w:Ljava/lang/String;

    .line 170
    .line 171
    if-nez v0, :cond_5

    .line 172
    .line 173
    move v0, v2

    .line 174
    goto :goto_5

    .line 175
    :cond_5
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 176
    .line 177
    .line 178
    move-result v0

    .line 179
    :goto_5
    add-int/2addr v3, v0

    .line 180
    mul-int/2addr v3, v1

    .line 181
    iget-object v0, p0, Lh50/v;->x:Lql0/g;

    .line 182
    .line 183
    if-nez v0, :cond_6

    .line 184
    .line 185
    move v0, v2

    .line 186
    goto :goto_6

    .line 187
    :cond_6
    invoke-virtual {v0}, Lql0/g;->hashCode()I

    .line 188
    .line 189
    .line 190
    move-result v0

    .line 191
    :goto_6
    add-int/2addr v3, v0

    .line 192
    mul-int/2addr v3, v1

    .line 193
    iget-object v0, p0, Lh50/v;->y:Lqp0/b0;

    .line 194
    .line 195
    if-nez v0, :cond_7

    .line 196
    .line 197
    move v0, v2

    .line 198
    goto :goto_7

    .line 199
    :cond_7
    invoke-virtual {v0}, Lqp0/b0;->hashCode()I

    .line 200
    .line 201
    .line 202
    move-result v0

    .line 203
    :goto_7
    add-int/2addr v3, v0

    .line 204
    mul-int/2addr v3, v1

    .line 205
    iget-boolean v0, p0, Lh50/v;->z:Z

    .line 206
    .line 207
    invoke-static {v3, v1, v0}, La7/g0;->e(IIZ)I

    .line 208
    .line 209
    .line 210
    move-result v0

    .line 211
    iget-boolean v3, p0, Lh50/v;->A:Z

    .line 212
    .line 213
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 214
    .line 215
    .line 216
    move-result v0

    .line 217
    iget-object v3, p0, Lh50/v;->B:Ljava/lang/String;

    .line 218
    .line 219
    if-nez v3, :cond_8

    .line 220
    .line 221
    goto :goto_8

    .line 222
    :cond_8
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 223
    .line 224
    .line 225
    move-result v2

    .line 226
    :goto_8
    add-int/2addr v0, v2

    .line 227
    mul-int/2addr v0, v1

    .line 228
    iget-boolean v2, p0, Lh50/v;->C:Z

    .line 229
    .line 230
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 231
    .line 232
    .line 233
    move-result v0

    .line 234
    iget v2, p0, Lh50/v;->D:I

    .line 235
    .line 236
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 237
    .line 238
    .line 239
    move-result v0

    .line 240
    iget-boolean v2, p0, Lh50/v;->E:Z

    .line 241
    .line 242
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 243
    .line 244
    .line 245
    move-result v0

    .line 246
    iget-boolean p0, p0, Lh50/v;->F:Z

    .line 247
    .line 248
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 249
    .line 250
    .line 251
    move-result p0

    .line 252
    add-int/2addr p0, v0

    .line 253
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isDeleteStopoverDialogVisible="

    .line 2
    .line 3
    const-string v1, ", isDiscardRouteDialogVisible="

    .line 4
    .line 5
    const-string v2, "State(isLoading="

    .line 6
    .line 7
    iget-boolean v3, p0, Lh50/v;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lh50/v;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isEditTripDialogVisible="

    .line 16
    .line 17
    const-string v2, ", isMaxChargersDialogVisible="

    .line 18
    .line 19
    iget-boolean v3, p0, Lh50/v;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Lh50/v;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", isPrivacyDialogVisible="

    .line 27
    .line 28
    const-string v2, ", chargersLimit="

    .line 29
    .line 30
    iget-boolean v3, p0, Lh50/v;->e:Z

    .line 31
    .line 32
    iget-boolean v4, p0, Lh50/v;->f:Z

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget v1, p0, Lh50/v;->g:I

    .line 38
    .line 39
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v1, ", isRouteAdjustmentDialogVisible="

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    iget-boolean v1, p0, Lh50/v;->h:Z

    .line 48
    .line 49
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string v1, ", isShareRouteDialogVisible="

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string v1, ", routeImportDialogWarning="

    .line 58
    .line 59
    const-string v2, ", isBottomButtonsVisible="

    .line 60
    .line 61
    iget-object v3, p0, Lh50/v;->j:Ljava/lang/String;

    .line 62
    .line 63
    iget-boolean v4, p0, Lh50/v;->i:Z

    .line 64
    .line 65
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 66
    .line 67
    .line 68
    const-string v1, ", isSendVisible="

    .line 69
    .line 70
    const-string v2, ", isAITrip="

    .line 71
    .line 72
    iget-boolean v3, p0, Lh50/v;->k:Z

    .line 73
    .line 74
    iget-boolean v4, p0, Lh50/v;->l:Z

    .line 75
    .line 76
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 77
    .line 78
    .line 79
    const-string v1, ", isSendEnabled="

    .line 80
    .line 81
    const-string v2, ", tripDuration="

    .line 82
    .line 83
    iget-boolean v3, p0, Lh50/v;->m:Z

    .line 84
    .line 85
    iget-boolean v4, p0, Lh50/v;->n:Z

    .line 86
    .line 87
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 88
    .line 89
    .line 90
    const-string v1, ", destination="

    .line 91
    .line 92
    const-string v2, ", drivingDuration="

    .line 93
    .line 94
    iget-object v3, p0, Lh50/v;->o:Ljava/lang/String;

    .line 95
    .line 96
    iget-object v4, p0, Lh50/v;->p:Ljava/lang/String;

    .line 97
    .line 98
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const-string v1, ", chargingDuration="

    .line 102
    .line 103
    const-string v2, ", stops="

    .line 104
    .line 105
    iget-object v3, p0, Lh50/v;->q:Ljava/lang/String;

    .line 106
    .line 107
    iget-object v4, p0, Lh50/v;->r:Ljava/lang/String;

    .line 108
    .line 109
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const-string v1, ", shareRows="

    .line 113
    .line 114
    const-string v2, ", errorTitle="

    .line 115
    .line 116
    iget-object v3, p0, Lh50/v;->s:Ljava/util/List;

    .line 117
    .line 118
    iget-object v4, p0, Lh50/v;->t:Ljava/util/List;

    .line 119
    .line 120
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    iget-object v1, p0, Lh50/v;->u:Ljava/lang/String;

    .line 124
    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string v1, ", subscriptionLicenseState="

    .line 129
    .line 130
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    iget-object v1, p0, Lh50/v;->v:Ler0/g;

    .line 134
    .line 135
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    const-string v1, ", sendToCarWarning="

    .line 139
    .line 140
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    iget-object v1, p0, Lh50/v;->w:Ljava/lang/String;

    .line 144
    .line 145
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    const-string v1, ", error="

    .line 149
    .line 150
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    iget-object v1, p0, Lh50/v;->x:Lql0/g;

    .line 154
    .line 155
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    const-string v1, ", selectedWaypoint="

    .line 159
    .line 160
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    iget-object v1, p0, Lh50/v;->y:Lqp0/b0;

    .line 164
    .line 165
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    const-string v1, ", isAIAssistant="

    .line 169
    .line 170
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    iget-boolean v1, p0, Lh50/v;->z:Z

    .line 174
    .line 175
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    const-string v1, ", isAnyWaypointInWalkingDistance="

    .line 179
    .line 180
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    const-string v1, ", aiSummary="

    .line 184
    .line 185
    const-string v2, ", isMaxStopsDialogVisible="

    .line 186
    .line 187
    iget-object v3, p0, Lh50/v;->B:Ljava/lang/String;

    .line 188
    .line 189
    iget-boolean v4, p0, Lh50/v;->A:Z

    .line 190
    .line 191
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 192
    .line 193
    .line 194
    iget-boolean v1, p0, Lh50/v;->C:Z

    .line 195
    .line 196
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    const-string v1, ", totalStopsLimit="

    .line 200
    .line 201
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    iget v1, p0, Lh50/v;->D:I

    .line 205
    .line 206
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 207
    .line 208
    .line 209
    const-string v1, ", isRouteRecalculated="

    .line 210
    .line 211
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    const-string v1, ", isCatNavAvailable="

    .line 215
    .line 216
    const-string v2, ")"

    .line 217
    .line 218
    iget-boolean v3, p0, Lh50/v;->E:Z

    .line 219
    .line 220
    iget-boolean p0, p0, Lh50/v;->F:Z

    .line 221
    .line 222
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    return-object p0
.end method
