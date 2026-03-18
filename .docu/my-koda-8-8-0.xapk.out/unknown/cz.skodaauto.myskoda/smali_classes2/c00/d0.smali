.class public final Lc00/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final A:Z

.field public final a:Lc00/z;

.field public final b:Z

.field public final c:Z

.field public final d:Lc00/a0;

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Lc00/y;

.field public final i:Lc00/c0;

.field public final j:Lc00/b0;

.field public final k:Ljava/lang/String;

.field public final l:Ljava/lang/String;

.field public final m:Z

.field public final n:Ljava/lang/String;

.field public final o:Ler0/g;

.field public final p:Llf0/i;

.field public final q:Z

.field public final r:Z

.field public final s:Z

.field public final t:Z

.field public final u:Z

.field public final v:Z

.field public final w:Z

.field public final x:Z

.field public final y:Z

.field public final z:Z


# direct methods
.method public synthetic constructor <init>(Lc00/z;Ler0/g;Llf0/i;I)V
    .locals 23

    move/from16 v0, p4

    .line 1
    sget-object v8, Lc00/y;->e:Lc00/y;

    .line 2
    sget-object v1, Lc00/c0;->f:Lc00/c0;

    and-int/lit8 v2, v0, 0x1

    if-eqz v2, :cond_0

    .line 3
    new-instance v9, Lc00/z;

    const/4 v13, 0x0

    const/16 v14, 0x3f

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    invoke-direct/range {v9 .. v14}, Lc00/z;-><init>(Ljava/lang/String;Ljava/lang/String;FZI)V

    goto :goto_0

    :cond_0
    move-object/from16 v9, p1

    .line 4
    :goto_0
    sget-object v4, Lc00/a0;->e:Lc00/a0;

    and-int/lit8 v2, v0, 0x20

    const/4 v3, 0x0

    const/4 v5, 0x1

    if-eqz v2, :cond_1

    move v6, v5

    goto :goto_1

    :cond_1
    move v6, v3

    :goto_1
    and-int/lit8 v2, v0, 0x40

    if-eqz v2, :cond_2

    move v7, v5

    goto :goto_2

    :cond_2
    move v7, v3

    :goto_2
    and-int/lit16 v2, v0, 0x100

    if-eqz v2, :cond_3

    .line 5
    sget-object v1, Lc00/c0;->d:Lc00/c0;

    :cond_3
    and-int/lit16 v2, v0, 0x1000

    if-eqz v2, :cond_4

    move v13, v3

    goto :goto_3

    :cond_4
    move v13, v5

    :goto_3
    and-int/lit16 v2, v0, 0x4000

    if-eqz v2, :cond_5

    .line 6
    sget-object v2, Ler0/g;->d:Ler0/g;

    move-object v15, v2

    goto :goto_4

    :cond_5
    move-object/from16 v15, p2

    :goto_4
    const v2, 0x8000

    and-int/2addr v2, v0

    if-eqz v2, :cond_6

    .line 7
    sget-object v2, Llf0/i;->j:Llf0/i;

    move-object/from16 v16, v2

    goto :goto_5

    :cond_6
    move-object/from16 v16, p3

    :goto_5
    const/high16 v2, 0x80000

    and-int/2addr v0, v2

    if-eqz v0, :cond_7

    move/from16 v20, v3

    goto :goto_6

    :cond_7
    move/from16 v20, v5

    :goto_6
    const/16 v21, 0x1

    const/16 v22, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v14, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    move-object v0, v9

    move-object v9, v1

    move-object v1, v0

    move-object/from16 v0, p0

    .line 8
    invoke-direct/range {v0 .. v22}, Lc00/d0;-><init>(Lc00/z;ZZLc00/a0;ZZZLc00/y;Lc00/c0;Lc00/b0;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ler0/g;Llf0/i;ZZZZZZ)V

    return-void
.end method

.method public constructor <init>(Lc00/z;ZZLc00/a0;ZZZLc00/y;Lc00/c0;Lc00/b0;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ler0/g;Llf0/i;ZZZZZZ)V
    .locals 4

    move-object/from16 v0, p15

    move-object/from16 v1, p16

    move/from16 v2, p18

    const-string v3, "gauge"

    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "climateState"

    invoke-static {p8, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "windowHeatingState"

    invoke-static {p9, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "subscriptionLicenseState"

    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "viewMode"

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    iput-object p1, p0, Lc00/d0;->a:Lc00/z;

    .line 11
    iput-boolean p2, p0, Lc00/d0;->b:Z

    .line 12
    iput-boolean p3, p0, Lc00/d0;->c:Z

    .line 13
    iput-object p4, p0, Lc00/d0;->d:Lc00/a0;

    .line 14
    iput-boolean p5, p0, Lc00/d0;->e:Z

    .line 15
    iput-boolean p6, p0, Lc00/d0;->f:Z

    .line 16
    iput-boolean p7, p0, Lc00/d0;->g:Z

    .line 17
    iput-object p8, p0, Lc00/d0;->h:Lc00/y;

    .line 18
    iput-object p9, p0, Lc00/d0;->i:Lc00/c0;

    move-object p1, p10

    .line 19
    iput-object p1, p0, Lc00/d0;->j:Lc00/b0;

    move-object p1, p11

    .line 20
    iput-object p1, p0, Lc00/d0;->k:Ljava/lang/String;

    move-object/from16 p1, p12

    .line 21
    iput-object p1, p0, Lc00/d0;->l:Ljava/lang/String;

    move/from16 p1, p13

    .line 22
    iput-boolean p1, p0, Lc00/d0;->m:Z

    move-object/from16 p1, p14

    .line 23
    iput-object p1, p0, Lc00/d0;->n:Ljava/lang/String;

    .line 24
    iput-object v0, p0, Lc00/d0;->o:Ler0/g;

    .line 25
    iput-object v1, p0, Lc00/d0;->p:Llf0/i;

    move/from16 p1, p17

    .line 26
    iput-boolean p1, p0, Lc00/d0;->q:Z

    .line 27
    iput-boolean v2, p0, Lc00/d0;->r:Z

    move/from16 p1, p19

    .line 28
    iput-boolean p1, p0, Lc00/d0;->s:Z

    move/from16 p1, p20

    .line 29
    iput-boolean p1, p0, Lc00/d0;->t:Z

    move/from16 p1, p21

    .line 30
    iput-boolean p1, p0, Lc00/d0;->u:Z

    move/from16 p1, p22

    .line 31
    iput-boolean p1, p0, Lc00/d0;->v:Z

    .line 32
    invoke-virtual {p8}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    const/4 p2, 0x0

    const/4 p3, 0x1

    if-eqz p1, :cond_2

    if-eq p1, p3, :cond_2

    const/4 p4, 0x2

    if-eq p1, p4, :cond_1

    const/4 p4, 0x3

    if-ne p1, p4, :cond_0

    goto :goto_0

    :cond_0
    new-instance p0, La8/r0;

    .line 33
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 34
    throw p0

    :cond_1
    :goto_0
    move p1, p3

    goto :goto_1

    :cond_2
    move p1, p2

    :goto_1
    iput-boolean p1, p0, Lc00/d0;->w:Z

    .line 35
    sget-object p1, Llf0/i;->h:Llf0/i;

    if-ne v1, p1, :cond_3

    move p1, p3

    goto :goto_2

    :cond_3
    move p1, p2

    :goto_2
    iput-boolean p1, p0, Lc00/d0;->x:Z

    .line 36
    invoke-static {v1}, Llp/tf;->d(Llf0/i;)Z

    move-result p4

    iput-boolean p4, p0, Lc00/d0;->y:Z

    if-nez p1, :cond_4

    if-eqz p4, :cond_5

    :cond_4
    move p2, p3

    .line 37
    :cond_5
    iput-boolean p2, p0, Lc00/d0;->z:Z

    xor-int/lit8 p1, v2, 0x1

    .line 38
    iput-boolean p1, p0, Lc00/d0;->A:Z

    return-void
.end method

.method public static a(Lc00/d0;Lc00/z;ZZLc00/a0;ZZZLc00/y;Lc00/c0;Lc00/b0;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Llf0/i;ZZZZZZI)Lc00/d0;
    .locals 17

    move-object/from16 v0, p0

    move/from16 v1, p22

    sget-object v2, Ler0/g;->d:Ler0/g;

    and-int/lit8 v3, v1, 0x1

    if-eqz v3, :cond_0

    iget-object v3, v0, Lc00/d0;->a:Lc00/z;

    goto :goto_0

    :cond_0
    move-object/from16 v3, p1

    :goto_0
    and-int/lit8 v4, v1, 0x2

    if-eqz v4, :cond_1

    iget-boolean v4, v0, Lc00/d0;->b:Z

    goto :goto_1

    :cond_1
    move/from16 v4, p2

    :goto_1
    and-int/lit8 v5, v1, 0x4

    if-eqz v5, :cond_2

    iget-boolean v5, v0, Lc00/d0;->c:Z

    goto :goto_2

    :cond_2
    move/from16 v5, p3

    :goto_2
    and-int/lit8 v6, v1, 0x8

    if-eqz v6, :cond_3

    iget-object v6, v0, Lc00/d0;->d:Lc00/a0;

    goto :goto_3

    :cond_3
    move-object/from16 v6, p4

    :goto_3
    and-int/lit8 v7, v1, 0x10

    if-eqz v7, :cond_4

    iget-boolean v7, v0, Lc00/d0;->e:Z

    goto :goto_4

    :cond_4
    move/from16 v7, p5

    :goto_4
    and-int/lit8 v8, v1, 0x20

    if-eqz v8, :cond_5

    iget-boolean v8, v0, Lc00/d0;->f:Z

    goto :goto_5

    :cond_5
    move/from16 v8, p6

    :goto_5
    and-int/lit8 v9, v1, 0x40

    if-eqz v9, :cond_6

    iget-boolean v9, v0, Lc00/d0;->g:Z

    goto :goto_6

    :cond_6
    move/from16 v9, p7

    :goto_6
    and-int/lit16 v10, v1, 0x80

    if-eqz v10, :cond_7

    iget-object v10, v0, Lc00/d0;->h:Lc00/y;

    goto :goto_7

    :cond_7
    move-object/from16 v10, p8

    :goto_7
    and-int/lit16 v11, v1, 0x100

    if-eqz v11, :cond_8

    iget-object v11, v0, Lc00/d0;->i:Lc00/c0;

    goto :goto_8

    :cond_8
    move-object/from16 v11, p9

    :goto_8
    and-int/lit16 v12, v1, 0x200

    if-eqz v12, :cond_9

    iget-object v12, v0, Lc00/d0;->j:Lc00/b0;

    goto :goto_9

    :cond_9
    move-object/from16 v12, p10

    :goto_9
    and-int/lit16 v13, v1, 0x400

    if-eqz v13, :cond_a

    iget-object v13, v0, Lc00/d0;->k:Ljava/lang/String;

    goto :goto_a

    :cond_a
    move-object/from16 v13, p11

    :goto_a
    and-int/lit16 v14, v1, 0x800

    if-eqz v14, :cond_b

    iget-object v14, v0, Lc00/d0;->l:Ljava/lang/String;

    goto :goto_b

    :cond_b
    move-object/from16 v14, p12

    :goto_b
    and-int/lit16 v15, v1, 0x1000

    if-eqz v15, :cond_c

    iget-boolean v15, v0, Lc00/d0;->m:Z

    goto :goto_c

    :cond_c
    move/from16 v15, p13

    :goto_c
    move-object/from16 v16, v2

    and-int/lit16 v2, v1, 0x2000

    if-eqz v2, :cond_d

    iget-object v2, v0, Lc00/d0;->n:Ljava/lang/String;

    goto :goto_d

    :cond_d
    move-object/from16 v2, p14

    :goto_d
    move-object/from16 p14, v2

    and-int/lit16 v2, v1, 0x4000

    if-eqz v2, :cond_e

    iget-object v2, v0, Lc00/d0;->o:Ler0/g;

    goto :goto_e

    :cond_e
    move-object/from16 v2, v16

    :goto_e
    const v16, 0x8000

    and-int v16, v1, v16

    if-eqz v16, :cond_f

    iget-object v1, v0, Lc00/d0;->p:Llf0/i;

    goto :goto_f

    :cond_f
    move-object/from16 v1, p15

    :goto_f
    const/high16 v16, 0x10000

    and-int v16, p22, v16

    move/from16 p2, v4

    if-eqz v16, :cond_10

    iget-boolean v4, v0, Lc00/d0;->q:Z

    goto :goto_10

    :cond_10
    move/from16 v4, p16

    :goto_10
    const/high16 v16, 0x20000

    and-int v16, p22, v16

    move/from16 p1, v4

    if-eqz v16, :cond_11

    iget-boolean v4, v0, Lc00/d0;->r:Z

    goto :goto_11

    :cond_11
    move/from16 v4, p17

    :goto_11
    const/high16 v16, 0x40000

    and-int v16, p22, v16

    move/from16 p3, v4

    if-eqz v16, :cond_12

    iget-boolean v4, v0, Lc00/d0;->s:Z

    goto :goto_12

    :cond_12
    move/from16 v4, p18

    :goto_12
    const/high16 v16, 0x80000

    and-int v16, p22, v16

    move/from16 p4, v4

    if-eqz v16, :cond_13

    iget-boolean v4, v0, Lc00/d0;->t:Z

    goto :goto_13

    :cond_13
    move/from16 v4, p19

    :goto_13
    const/high16 v16, 0x100000

    and-int v16, p22, v16

    move/from16 p5, v4

    if-eqz v16, :cond_14

    iget-boolean v4, v0, Lc00/d0;->u:Z

    goto :goto_14

    :cond_14
    move/from16 v4, p20

    :goto_14
    const/high16 v16, 0x200000

    and-int v16, p22, v16

    move/from16 p6, v4

    if-eqz v16, :cond_15

    iget-boolean v4, v0, Lc00/d0;->v:Z

    goto :goto_15

    :cond_15
    move/from16 v4, p21

    :goto_15
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1
    const-string v0, "gauge"

    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "heaterSource"

    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "climateState"

    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowHeatingState"

    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "subscriptionLicenseState"

    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "viewMode"

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Lc00/d0;

    move/from16 p17, p1

    move/from16 p18, p3

    move/from16 p19, p4

    move/from16 p20, p5

    move/from16 p21, p6

    move-object/from16 p0, v0

    move-object/from16 p16, v1

    move-object/from16 p15, v2

    move-object/from16 p1, v3

    move/from16 p22, v4

    move/from16 p3, v5

    move-object/from16 p4, v6

    move/from16 p5, v7

    move/from16 p6, v8

    move/from16 p7, v9

    move-object/from16 p8, v10

    move-object/from16 p9, v11

    move-object/from16 p10, v12

    move-object/from16 p11, v13

    move-object/from16 p12, v14

    move/from16 p13, v15

    invoke-direct/range {p0 .. p22}, Lc00/d0;-><init>(Lc00/z;ZZLc00/a0;ZZZLc00/y;Lc00/c0;Lc00/b0;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ler0/g;Llf0/i;ZZZZZZ)V

    return-object v0
.end method


# virtual methods
.method public final b()I
    .locals 2

    .line 1
    sget-object v0, Lc00/y;->e:Lc00/y;

    .line 2
    .line 3
    iget-object v1, p0, Lc00/d0;->h:Lc00/y;

    .line 4
    .line 5
    if-eq v1, v0, :cond_0

    .line 6
    .line 7
    sget-object v0, Lc00/y;->d:Lc00/y;

    .line 8
    .line 9
    if-ne v1, v0, :cond_2

    .line 10
    .line 11
    :cond_0
    iget-object v0, p0, Lc00/d0;->j:Lc00/b0;

    .line 12
    .line 13
    sget-object v1, Lc00/b0;->e:Lc00/b0;

    .line 14
    .line 15
    if-eq v0, v1, :cond_2

    .line 16
    .line 17
    iget-boolean v0, p0, Lc00/d0;->u:Z

    .line 18
    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    iget-boolean p0, p0, Lc00/d0;->m:Z

    .line 22
    .line 23
    if-eqz p0, :cond_1

    .line 24
    .line 25
    const p0, 0x7f120077

    .line 26
    .line 27
    .line 28
    return p0

    .line 29
    :cond_1
    const p0, 0x7f120079

    .line 30
    .line 31
    .line 32
    return p0

    .line 33
    :cond_2
    const p0, 0x7f12007a

    .line 34
    .line 35
    .line 36
    return p0
.end method

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
    instance-of v1, p1, Lc00/d0;

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
    check-cast p1, Lc00/d0;

    .line 12
    .line 13
    iget-object v1, p0, Lc00/d0;->a:Lc00/z;

    .line 14
    .line 15
    iget-object v3, p1, Lc00/d0;->a:Lc00/z;

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
    iget-boolean v1, p0, Lc00/d0;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lc00/d0;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Lc00/d0;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Lc00/d0;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object v1, p0, Lc00/d0;->d:Lc00/a0;

    .line 39
    .line 40
    iget-object v3, p1, Lc00/d0;->d:Lc00/a0;

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-boolean v1, p0, Lc00/d0;->e:Z

    .line 46
    .line 47
    iget-boolean v3, p1, Lc00/d0;->e:Z

    .line 48
    .line 49
    if-eq v1, v3, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-boolean v1, p0, Lc00/d0;->f:Z

    .line 53
    .line 54
    iget-boolean v3, p1, Lc00/d0;->f:Z

    .line 55
    .line 56
    if-eq v1, v3, :cond_7

    .line 57
    .line 58
    return v2

    .line 59
    :cond_7
    iget-boolean v1, p0, Lc00/d0;->g:Z

    .line 60
    .line 61
    iget-boolean v3, p1, Lc00/d0;->g:Z

    .line 62
    .line 63
    if-eq v1, v3, :cond_8

    .line 64
    .line 65
    return v2

    .line 66
    :cond_8
    iget-object v1, p0, Lc00/d0;->h:Lc00/y;

    .line 67
    .line 68
    iget-object v3, p1, Lc00/d0;->h:Lc00/y;

    .line 69
    .line 70
    if-eq v1, v3, :cond_9

    .line 71
    .line 72
    return v2

    .line 73
    :cond_9
    iget-object v1, p0, Lc00/d0;->i:Lc00/c0;

    .line 74
    .line 75
    iget-object v3, p1, Lc00/d0;->i:Lc00/c0;

    .line 76
    .line 77
    if-eq v1, v3, :cond_a

    .line 78
    .line 79
    return v2

    .line 80
    :cond_a
    iget-object v1, p0, Lc00/d0;->j:Lc00/b0;

    .line 81
    .line 82
    iget-object v3, p1, Lc00/d0;->j:Lc00/b0;

    .line 83
    .line 84
    if-eq v1, v3, :cond_b

    .line 85
    .line 86
    return v2

    .line 87
    :cond_b
    iget-object v1, p0, Lc00/d0;->k:Ljava/lang/String;

    .line 88
    .line 89
    iget-object v3, p1, Lc00/d0;->k:Ljava/lang/String;

    .line 90
    .line 91
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    if-nez v1, :cond_c

    .line 96
    .line 97
    return v2

    .line 98
    :cond_c
    iget-object v1, p0, Lc00/d0;->l:Ljava/lang/String;

    .line 99
    .line 100
    iget-object v3, p1, Lc00/d0;->l:Ljava/lang/String;

    .line 101
    .line 102
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    if-nez v1, :cond_d

    .line 107
    .line 108
    return v2

    .line 109
    :cond_d
    iget-boolean v1, p0, Lc00/d0;->m:Z

    .line 110
    .line 111
    iget-boolean v3, p1, Lc00/d0;->m:Z

    .line 112
    .line 113
    if-eq v1, v3, :cond_e

    .line 114
    .line 115
    return v2

    .line 116
    :cond_e
    iget-object v1, p0, Lc00/d0;->n:Ljava/lang/String;

    .line 117
    .line 118
    iget-object v3, p1, Lc00/d0;->n:Ljava/lang/String;

    .line 119
    .line 120
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    if-nez v1, :cond_f

    .line 125
    .line 126
    return v2

    .line 127
    :cond_f
    iget-object v1, p0, Lc00/d0;->o:Ler0/g;

    .line 128
    .line 129
    iget-object v3, p1, Lc00/d0;->o:Ler0/g;

    .line 130
    .line 131
    if-eq v1, v3, :cond_10

    .line 132
    .line 133
    return v2

    .line 134
    :cond_10
    iget-object v1, p0, Lc00/d0;->p:Llf0/i;

    .line 135
    .line 136
    iget-object v3, p1, Lc00/d0;->p:Llf0/i;

    .line 137
    .line 138
    if-eq v1, v3, :cond_11

    .line 139
    .line 140
    return v2

    .line 141
    :cond_11
    iget-boolean v1, p0, Lc00/d0;->q:Z

    .line 142
    .line 143
    iget-boolean v3, p1, Lc00/d0;->q:Z

    .line 144
    .line 145
    if-eq v1, v3, :cond_12

    .line 146
    .line 147
    return v2

    .line 148
    :cond_12
    iget-boolean v1, p0, Lc00/d0;->r:Z

    .line 149
    .line 150
    iget-boolean v3, p1, Lc00/d0;->r:Z

    .line 151
    .line 152
    if-eq v1, v3, :cond_13

    .line 153
    .line 154
    return v2

    .line 155
    :cond_13
    iget-boolean v1, p0, Lc00/d0;->s:Z

    .line 156
    .line 157
    iget-boolean v3, p1, Lc00/d0;->s:Z

    .line 158
    .line 159
    if-eq v1, v3, :cond_14

    .line 160
    .line 161
    return v2

    .line 162
    :cond_14
    iget-boolean v1, p0, Lc00/d0;->t:Z

    .line 163
    .line 164
    iget-boolean v3, p1, Lc00/d0;->t:Z

    .line 165
    .line 166
    if-eq v1, v3, :cond_15

    .line 167
    .line 168
    return v2

    .line 169
    :cond_15
    iget-boolean v1, p0, Lc00/d0;->u:Z

    .line 170
    .line 171
    iget-boolean v3, p1, Lc00/d0;->u:Z

    .line 172
    .line 173
    if-eq v1, v3, :cond_16

    .line 174
    .line 175
    return v2

    .line 176
    :cond_16
    iget-boolean p0, p0, Lc00/d0;->v:Z

    .line 177
    .line 178
    iget-boolean p1, p1, Lc00/d0;->v:Z

    .line 179
    .line 180
    if-eq p0, p1, :cond_17

    .line 181
    .line 182
    return v2

    .line 183
    :cond_17
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lc00/d0;->a:Lc00/z;

    .line 2
    .line 3
    invoke-virtual {v0}, Lc00/z;->hashCode()I

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
    iget-boolean v2, p0, Lc00/d0;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lc00/d0;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lc00/d0;->d:Lc00/a0;

    .line 23
    .line 24
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    add-int/2addr v2, v0

    .line 29
    mul-int/2addr v2, v1

    .line 30
    iget-boolean v0, p0, Lc00/d0;->e:Z

    .line 31
    .line 32
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-boolean v2, p0, Lc00/d0;->f:Z

    .line 37
    .line 38
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-boolean v2, p0, Lc00/d0;->g:Z

    .line 43
    .line 44
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-object v2, p0, Lc00/d0;->h:Lc00/y;

    .line 49
    .line 50
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    add-int/2addr v2, v0

    .line 55
    mul-int/2addr v2, v1

    .line 56
    iget-object v0, p0, Lc00/d0;->i:Lc00/c0;

    .line 57
    .line 58
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    add-int/2addr v0, v2

    .line 63
    mul-int/2addr v0, v1

    .line 64
    const/4 v2, 0x0

    .line 65
    iget-object v3, p0, Lc00/d0;->j:Lc00/b0;

    .line 66
    .line 67
    if-nez v3, :cond_0

    .line 68
    .line 69
    move v3, v2

    .line 70
    goto :goto_0

    .line 71
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    :goto_0
    add-int/2addr v0, v3

    .line 76
    mul-int/2addr v0, v1

    .line 77
    iget-object v3, p0, Lc00/d0;->k:Ljava/lang/String;

    .line 78
    .line 79
    if-nez v3, :cond_1

    .line 80
    .line 81
    move v3, v2

    .line 82
    goto :goto_1

    .line 83
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    :goto_1
    add-int/2addr v0, v3

    .line 88
    mul-int/2addr v0, v1

    .line 89
    iget-object v3, p0, Lc00/d0;->l:Ljava/lang/String;

    .line 90
    .line 91
    if-nez v3, :cond_2

    .line 92
    .line 93
    move v3, v2

    .line 94
    goto :goto_2

    .line 95
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    :goto_2
    add-int/2addr v0, v3

    .line 100
    mul-int/2addr v0, v1

    .line 101
    iget-boolean v3, p0, Lc00/d0;->m:Z

    .line 102
    .line 103
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 104
    .line 105
    .line 106
    move-result v0

    .line 107
    iget-object v3, p0, Lc00/d0;->n:Ljava/lang/String;

    .line 108
    .line 109
    if-nez v3, :cond_3

    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 113
    .line 114
    .line 115
    move-result v2

    .line 116
    :goto_3
    add-int/2addr v0, v2

    .line 117
    mul-int/2addr v0, v1

    .line 118
    iget-object v2, p0, Lc00/d0;->o:Ler0/g;

    .line 119
    .line 120
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 121
    .line 122
    .line 123
    move-result v2

    .line 124
    add-int/2addr v2, v0

    .line 125
    mul-int/2addr v2, v1

    .line 126
    iget-object v0, p0, Lc00/d0;->p:Llf0/i;

    .line 127
    .line 128
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    add-int/2addr v0, v2

    .line 133
    mul-int/2addr v0, v1

    .line 134
    iget-boolean v2, p0, Lc00/d0;->q:Z

    .line 135
    .line 136
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 137
    .line 138
    .line 139
    move-result v0

    .line 140
    iget-boolean v2, p0, Lc00/d0;->r:Z

    .line 141
    .line 142
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 143
    .line 144
    .line 145
    move-result v0

    .line 146
    iget-boolean v2, p0, Lc00/d0;->s:Z

    .line 147
    .line 148
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 149
    .line 150
    .line 151
    move-result v0

    .line 152
    iget-boolean v2, p0, Lc00/d0;->t:Z

    .line 153
    .line 154
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 155
    .line 156
    .line 157
    move-result v0

    .line 158
    iget-boolean v2, p0, Lc00/d0;->u:Z

    .line 159
    .line 160
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 161
    .line 162
    .line 163
    move-result v0

    .line 164
    iget-boolean p0, p0, Lc00/d0;->v:Z

    .line 165
    .line 166
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 167
    .line 168
    .line 169
    move-result p0

    .line 170
    add-int/2addr p0, v0

    .line 171
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(gauge="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lc00/d0;->a:Lc00/z;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", isSettingActionEnabled="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lc00/d0;->b:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", isRefreshing="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-boolean v1, p0, Lc00/d0;->c:Z

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", heaterSource="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lc00/d0;->d:Lc00/a0;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", heaterSourceSelectionAvailable="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v1, ", isStatusLoading="

    .line 49
    .line 50
    const-string v2, ", isStatusMissing="

    .line 51
    .line 52
    iget-boolean v3, p0, Lc00/d0;->e:Z

    .line 53
    .line 54
    iget-boolean v4, p0, Lc00/d0;->f:Z

    .line 55
    .line 56
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iget-boolean v1, p0, Lc00/d0;->g:Z

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v1, ", climateState="

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    iget-object v1, p0, Lc00/d0;->h:Lc00/y;

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v1, ", windowHeatingState="

    .line 75
    .line 76
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    iget-object v1, p0, Lc00/d0;->i:Lc00/c0;

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v1, ", climateOperationRequestStatus="

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    iget-object v1, p0, Lc00/d0;->j:Lc00/b0;

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v1, ", statusTitle="

    .line 95
    .line 96
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    const-string v1, ", statusSubtitle="

    .line 100
    .line 101
    const-string v2, ", isTemperatureUpdated="

    .line 102
    .line 103
    iget-object v3, p0, Lc00/d0;->k:Ljava/lang/String;

    .line 104
    .line 105
    iget-object v4, p0, Lc00/d0;->l:Ljava/lang/String;

    .line 106
    .line 107
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    const-string v1, ", windowHeatingStatusSubtitle="

    .line 111
    .line 112
    const-string v2, ", subscriptionLicenseState="

    .line 113
    .line 114
    iget-object v3, p0, Lc00/d0;->n:Ljava/lang/String;

    .line 115
    .line 116
    iget-boolean v4, p0, Lc00/d0;->m:Z

    .line 117
    .line 118
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 119
    .line 120
    .line 121
    iget-object v1, p0, Lc00/d0;->o:Ler0/g;

    .line 122
    .line 123
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    const-string v1, ", viewMode="

    .line 127
    .line 128
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    iget-object v1, p0, Lc00/d0;->p:Llf0/i;

    .line 132
    .line 133
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    const-string v1, ", showExternalPowerWarningDialog="

    .line 137
    .line 138
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    const-string v1, ", isBatteryUseDisabled="

    .line 142
    .line 143
    const-string v2, ", startClimaForElectric="

    .line 144
    .line 145
    iget-boolean v3, p0, Lc00/d0;->q:Z

    .line 146
    .line 147
    iget-boolean v4, p0, Lc00/d0;->r:Z

    .line 148
    .line 149
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 150
    .line 151
    .line 152
    const-string v1, ", isWindowHeatingSupported="

    .line 153
    .line 154
    const-string v2, ", isSaveAndActivateEnabled="

    .line 155
    .line 156
    iget-boolean v3, p0, Lc00/d0;->s:Z

    .line 157
    .line 158
    iget-boolean v4, p0, Lc00/d0;->t:Z

    .line 159
    .line 160
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 161
    .line 162
    .line 163
    const-string v1, ", hasOutsideTemperatureCapability="

    .line 164
    .line 165
    const-string v2, ")"

    .line 166
    .line 167
    iget-boolean v3, p0, Lc00/d0;->u:Z

    .line 168
    .line 169
    iget-boolean p0, p0, Lc00/d0;->v:Z

    .line 170
    .line 171
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    return-object p0
.end method
