.class public final Lh40/s3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Ljava/util/List;

.field public final h:Ljava/util/List;

.field public final i:Z

.field public final j:Lh40/u;

.field public final k:I

.field public final l:Z

.field public final m:Ljava/lang/String;

.field public final n:Lh40/g0;

.field public final o:Lql0/g;

.field public final p:Z

.field public final q:Z

.field public final r:Z

.field public final s:Z

.field public final t:Z

.field public final u:Z

.field public final v:Z

.field public final w:Z

.field public final x:Z

.field public final y:Lh40/r3;

.field public final z:Z


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Ljava/util/List;I)V
    .locals 30

    move/from16 v0, p3

    and-int/lit8 v1, v0, 0x1

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eqz v1, :cond_0

    move v5, v3

    goto :goto_0

    :cond_0
    move v5, v2

    :goto_0
    and-int/lit8 v1, v0, 0x8

    if-eqz v1, :cond_1

    move v8, v3

    goto :goto_1

    :cond_1
    move v8, v2

    :goto_1
    and-int/lit8 v1, v0, 0x40

    .line 1
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    if-eqz v1, :cond_2

    move-object v11, v4

    goto :goto_2

    :cond_2
    move-object/from16 v11, p1

    :goto_2
    and-int/lit16 v1, v0, 0x80

    if-eqz v1, :cond_3

    move-object v12, v4

    goto :goto_3

    :cond_3
    move-object/from16 v12, p2

    :goto_3
    and-int/lit16 v1, v0, 0x400

    if-eqz v1, :cond_4

    move v15, v3

    goto :goto_4

    :cond_4
    const/16 v1, 0x384

    move v15, v1

    :goto_4
    and-int/lit16 v1, v0, 0x1000

    if-eqz v1, :cond_5

    .line 2
    const-string v1, ""

    :goto_5
    move-object/from16 v17, v1

    goto :goto_6

    .line 3
    :cond_5
    const-string v1, "My\u0160koda Club"

    goto :goto_5

    .line 4
    :goto_6
    new-instance v18, Lh40/g0;

    invoke-direct/range {v18 .. v18}, Lh40/g0;-><init>()V

    const/high16 v1, 0x10000

    and-int/2addr v0, v1

    if-eqz v0, :cond_6

    move/from16 v21, v3

    goto :goto_7

    :cond_6
    move/from16 v21, v2

    :goto_7
    const/16 v28, 0x0

    .line 5
    sget-object v29, Lh40/r3;->d:Lh40/r3;

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/16 v16, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    move-object/from16 v4, p0

    .line 6
    invoke-direct/range {v4 .. v29}, Lh40/s3;-><init>(ZZZZZZLjava/util/List;Ljava/util/List;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZZLh40/r3;)V

    return-void
.end method

.method public constructor <init>(ZZZZZZLjava/util/List;Ljava/util/List;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZZLh40/r3;)V
    .locals 3

    move-object/from16 v0, p13

    move/from16 v1, p19

    const-string v2, "inProgressChallenges"

    invoke-static {p7, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "activeRewards"

    invoke-static {p8, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "loyaltyProgramTitle"

    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-boolean p1, p0, Lh40/s3;->a:Z

    .line 9
    iput-boolean p2, p0, Lh40/s3;->b:Z

    .line 10
    iput-boolean p3, p0, Lh40/s3;->c:Z

    .line 11
    iput-boolean p4, p0, Lh40/s3;->d:Z

    .line 12
    iput-boolean p5, p0, Lh40/s3;->e:Z

    .line 13
    iput-boolean p6, p0, Lh40/s3;->f:Z

    .line 14
    iput-object p7, p0, Lh40/s3;->g:Ljava/util/List;

    .line 15
    iput-object p8, p0, Lh40/s3;->h:Ljava/util/List;

    .line 16
    iput-boolean p9, p0, Lh40/s3;->i:Z

    .line 17
    iput-object p10, p0, Lh40/s3;->j:Lh40/u;

    .line 18
    iput p11, p0, Lh40/s3;->k:I

    .line 19
    iput-boolean p12, p0, Lh40/s3;->l:Z

    .line 20
    iput-object v0, p0, Lh40/s3;->m:Ljava/lang/String;

    move-object/from16 p1, p14

    .line 21
    iput-object p1, p0, Lh40/s3;->n:Lh40/g0;

    move-object/from16 p1, p15

    .line 22
    iput-object p1, p0, Lh40/s3;->o:Lql0/g;

    move/from16 p1, p16

    .line 23
    iput-boolean p1, p0, Lh40/s3;->p:Z

    move/from16 p1, p17

    .line 24
    iput-boolean p1, p0, Lh40/s3;->q:Z

    move/from16 p1, p18

    .line 25
    iput-boolean p1, p0, Lh40/s3;->r:Z

    .line 26
    iput-boolean v1, p0, Lh40/s3;->s:Z

    move/from16 p1, p20

    .line 27
    iput-boolean p1, p0, Lh40/s3;->t:Z

    move/from16 p1, p21

    .line 28
    iput-boolean p1, p0, Lh40/s3;->u:Z

    move/from16 p1, p22

    .line 29
    iput-boolean p1, p0, Lh40/s3;->v:Z

    move/from16 p1, p23

    .line 30
    iput-boolean p1, p0, Lh40/s3;->w:Z

    move/from16 p1, p24

    .line 31
    iput-boolean p1, p0, Lh40/s3;->x:Z

    move-object/from16 p1, p25

    .line 32
    iput-object p1, p0, Lh40/s3;->y:Lh40/r3;

    .line 33
    invoke-interface {p7}, Ljava/util/List;->size()I

    move-result p1

    const/4 p2, 0x1

    if-le p1, p2, :cond_0

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    iput-boolean p2, p0, Lh40/s3;->z:Z

    return-void
.end method

.method public static a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;
    .locals 17

    move-object/from16 v0, p0

    move/from16 v1, p25

    and-int/lit8 v2, v1, 0x1

    if-eqz v2, :cond_0

    iget-boolean v2, v0, Lh40/s3;->a:Z

    goto :goto_0

    :cond_0
    move/from16 v2, p1

    :goto_0
    and-int/lit8 v3, v1, 0x2

    if-eqz v3, :cond_1

    iget-boolean v3, v0, Lh40/s3;->b:Z

    goto :goto_1

    :cond_1
    move/from16 v3, p2

    :goto_1
    and-int/lit8 v4, v1, 0x4

    if-eqz v4, :cond_2

    iget-boolean v4, v0, Lh40/s3;->c:Z

    goto :goto_2

    :cond_2
    move/from16 v4, p3

    :goto_2
    and-int/lit8 v5, v1, 0x8

    if-eqz v5, :cond_3

    iget-boolean v5, v0, Lh40/s3;->d:Z

    goto :goto_3

    :cond_3
    move/from16 v5, p4

    :goto_3
    and-int/lit8 v6, v1, 0x10

    if-eqz v6, :cond_4

    iget-boolean v6, v0, Lh40/s3;->e:Z

    goto :goto_4

    :cond_4
    move/from16 v6, p5

    :goto_4
    and-int/lit8 v7, v1, 0x20

    if-eqz v7, :cond_5

    iget-boolean v7, v0, Lh40/s3;->f:Z

    goto :goto_5

    :cond_5
    move/from16 v7, p6

    :goto_5
    and-int/lit8 v8, v1, 0x40

    if-eqz v8, :cond_6

    iget-object v8, v0, Lh40/s3;->g:Ljava/util/List;

    goto :goto_6

    :cond_6
    move-object/from16 v8, p7

    :goto_6
    and-int/lit16 v9, v1, 0x80

    if-eqz v9, :cond_7

    iget-object v9, v0, Lh40/s3;->h:Ljava/util/List;

    goto :goto_7

    :cond_7
    move-object/from16 v9, p8

    :goto_7
    and-int/lit16 v10, v1, 0x100

    if-eqz v10, :cond_8

    iget-boolean v10, v0, Lh40/s3;->i:Z

    goto :goto_8

    :cond_8
    move/from16 v10, p9

    :goto_8
    and-int/lit16 v11, v1, 0x200

    if-eqz v11, :cond_9

    iget-object v11, v0, Lh40/s3;->j:Lh40/u;

    goto :goto_9

    :cond_9
    move-object/from16 v11, p10

    :goto_9
    and-int/lit16 v12, v1, 0x400

    if-eqz v12, :cond_a

    iget v12, v0, Lh40/s3;->k:I

    goto :goto_a

    :cond_a
    move/from16 v12, p11

    :goto_a
    and-int/lit16 v13, v1, 0x800

    if-eqz v13, :cond_b

    iget-boolean v13, v0, Lh40/s3;->l:Z

    goto :goto_b

    :cond_b
    move/from16 v13, p12

    :goto_b
    and-int/lit16 v14, v1, 0x1000

    if-eqz v14, :cond_c

    iget-object v14, v0, Lh40/s3;->m:Ljava/lang/String;

    goto :goto_c

    :cond_c
    move-object/from16 v14, p13

    :goto_c
    and-int/lit16 v15, v1, 0x2000

    if-eqz v15, :cond_d

    iget-object v15, v0, Lh40/s3;->n:Lh40/g0;

    goto :goto_d

    :cond_d
    move-object/from16 v15, p14

    :goto_d
    move/from16 p1, v2

    and-int/lit16 v2, v1, 0x4000

    if-eqz v2, :cond_e

    iget-object v2, v0, Lh40/s3;->o:Lql0/g;

    goto :goto_e

    :cond_e
    move-object/from16 v2, p15

    :goto_e
    const v16, 0x8000

    and-int v16, v1, v16

    if-eqz v16, :cond_f

    iget-boolean v1, v0, Lh40/s3;->p:Z

    goto :goto_f

    :cond_f
    move/from16 v1, p16

    :goto_f
    const/high16 v16, 0x10000

    and-int v16, p25, v16

    move/from16 p16, v1

    if-eqz v16, :cond_10

    iget-boolean v1, v0, Lh40/s3;->q:Z

    goto :goto_10

    :cond_10
    move/from16 v1, p17

    :goto_10
    const/high16 v16, 0x20000

    and-int v16, p25, v16

    move/from16 p17, v1

    if-eqz v16, :cond_11

    iget-boolean v1, v0, Lh40/s3;->r:Z

    goto :goto_11

    :cond_11
    move/from16 v1, p18

    :goto_11
    const/high16 v16, 0x40000

    and-int v16, p25, v16

    move/from16 p18, v1

    if-eqz v16, :cond_12

    iget-boolean v1, v0, Lh40/s3;->s:Z

    goto :goto_12

    :cond_12
    const/4 v1, 0x1

    :goto_12
    const/high16 v16, 0x80000

    and-int v16, p25, v16

    move/from16 p2, v1

    if-eqz v16, :cond_13

    iget-boolean v1, v0, Lh40/s3;->t:Z

    goto :goto_13

    :cond_13
    move/from16 v1, p19

    :goto_13
    const/high16 v16, 0x100000

    and-int v16, p25, v16

    move/from16 p3, v1

    if-eqz v16, :cond_14

    iget-boolean v1, v0, Lh40/s3;->u:Z

    goto :goto_14

    :cond_14
    move/from16 v1, p20

    :goto_14
    const/high16 v16, 0x200000

    and-int v16, p25, v16

    move/from16 p4, v1

    if-eqz v16, :cond_15

    iget-boolean v1, v0, Lh40/s3;->v:Z

    goto :goto_15

    :cond_15
    move/from16 v1, p21

    :goto_15
    const/high16 v16, 0x400000

    and-int v16, p25, v16

    move/from16 p5, v1

    if-eqz v16, :cond_16

    iget-boolean v1, v0, Lh40/s3;->w:Z

    goto :goto_16

    :cond_16
    move/from16 v1, p22

    :goto_16
    const/high16 v16, 0x800000

    and-int v16, p25, v16

    move/from16 p6, v1

    if-eqz v16, :cond_17

    iget-boolean v1, v0, Lh40/s3;->x:Z

    goto :goto_17

    :cond_17
    move/from16 v1, p23

    :goto_17
    const/high16 v16, 0x1000000

    and-int v16, p25, v16

    move/from16 p7, v1

    if-eqz v16, :cond_18

    iget-object v1, v0, Lh40/s3;->y:Lh40/r3;

    goto :goto_18

    :cond_18
    move-object/from16 v1, p24

    :goto_18
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1
    const-string v0, "inProgressChallenges"

    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "activeRewards"

    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "loyaltyProgramTitle"

    invoke-static {v14, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "loyaltyConsent"

    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "bottomSheetContent"

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Lh40/s3;

    move/from16 p19, p2

    move/from16 p20, p3

    move/from16 p21, p4

    move/from16 p22, p5

    move/from16 p23, p6

    move/from16 p24, p7

    move-object/from16 p0, v0

    move-object/from16 p25, v1

    move-object/from16 p15, v2

    move/from16 p2, v3

    move/from16 p3, v4

    move/from16 p4, v5

    move/from16 p5, v6

    move/from16 p6, v7

    move-object/from16 p7, v8

    move-object/from16 p8, v9

    move/from16 p9, v10

    move-object/from16 p10, v11

    move/from16 p11, v12

    move/from16 p12, v13

    move-object/from16 p13, v14

    move-object/from16 p14, v15

    invoke-direct/range {p0 .. p25}, Lh40/s3;-><init>(ZZZZZZLjava/util/List;Ljava/util/List;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZZLh40/r3;)V

    return-object v0
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
    instance-of v1, p1, Lh40/s3;

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
    check-cast p1, Lh40/s3;

    .line 12
    .line 13
    iget-boolean v1, p0, Lh40/s3;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lh40/s3;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lh40/s3;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lh40/s3;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lh40/s3;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lh40/s3;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lh40/s3;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lh40/s3;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-boolean v1, p0, Lh40/s3;->e:Z

    .line 42
    .line 43
    iget-boolean v3, p1, Lh40/s3;->e:Z

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-boolean v1, p0, Lh40/s3;->f:Z

    .line 49
    .line 50
    iget-boolean v3, p1, Lh40/s3;->f:Z

    .line 51
    .line 52
    if-eq v1, v3, :cond_7

    .line 53
    .line 54
    return v2

    .line 55
    :cond_7
    iget-object v1, p0, Lh40/s3;->g:Ljava/util/List;

    .line 56
    .line 57
    iget-object v3, p1, Lh40/s3;->g:Ljava/util/List;

    .line 58
    .line 59
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-nez v1, :cond_8

    .line 64
    .line 65
    return v2

    .line 66
    :cond_8
    iget-object v1, p0, Lh40/s3;->h:Ljava/util/List;

    .line 67
    .line 68
    iget-object v3, p1, Lh40/s3;->h:Ljava/util/List;

    .line 69
    .line 70
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    if-nez v1, :cond_9

    .line 75
    .line 76
    return v2

    .line 77
    :cond_9
    iget-boolean v1, p0, Lh40/s3;->i:Z

    .line 78
    .line 79
    iget-boolean v3, p1, Lh40/s3;->i:Z

    .line 80
    .line 81
    if-eq v1, v3, :cond_a

    .line 82
    .line 83
    return v2

    .line 84
    :cond_a
    iget-object v1, p0, Lh40/s3;->j:Lh40/u;

    .line 85
    .line 86
    iget-object v3, p1, Lh40/s3;->j:Lh40/u;

    .line 87
    .line 88
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-nez v1, :cond_b

    .line 93
    .line 94
    return v2

    .line 95
    :cond_b
    iget v1, p0, Lh40/s3;->k:I

    .line 96
    .line 97
    iget v3, p1, Lh40/s3;->k:I

    .line 98
    .line 99
    if-eq v1, v3, :cond_c

    .line 100
    .line 101
    return v2

    .line 102
    :cond_c
    iget-boolean v1, p0, Lh40/s3;->l:Z

    .line 103
    .line 104
    iget-boolean v3, p1, Lh40/s3;->l:Z

    .line 105
    .line 106
    if-eq v1, v3, :cond_d

    .line 107
    .line 108
    return v2

    .line 109
    :cond_d
    iget-object v1, p0, Lh40/s3;->m:Ljava/lang/String;

    .line 110
    .line 111
    iget-object v3, p1, Lh40/s3;->m:Ljava/lang/String;

    .line 112
    .line 113
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v1

    .line 117
    if-nez v1, :cond_e

    .line 118
    .line 119
    return v2

    .line 120
    :cond_e
    iget-object v1, p0, Lh40/s3;->n:Lh40/g0;

    .line 121
    .line 122
    iget-object v3, p1, Lh40/s3;->n:Lh40/g0;

    .line 123
    .line 124
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    if-nez v1, :cond_f

    .line 129
    .line 130
    return v2

    .line 131
    :cond_f
    iget-object v1, p0, Lh40/s3;->o:Lql0/g;

    .line 132
    .line 133
    iget-object v3, p1, Lh40/s3;->o:Lql0/g;

    .line 134
    .line 135
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v1

    .line 139
    if-nez v1, :cond_10

    .line 140
    .line 141
    return v2

    .line 142
    :cond_10
    iget-boolean v1, p0, Lh40/s3;->p:Z

    .line 143
    .line 144
    iget-boolean v3, p1, Lh40/s3;->p:Z

    .line 145
    .line 146
    if-eq v1, v3, :cond_11

    .line 147
    .line 148
    return v2

    .line 149
    :cond_11
    iget-boolean v1, p0, Lh40/s3;->q:Z

    .line 150
    .line 151
    iget-boolean v3, p1, Lh40/s3;->q:Z

    .line 152
    .line 153
    if-eq v1, v3, :cond_12

    .line 154
    .line 155
    return v2

    .line 156
    :cond_12
    iget-boolean v1, p0, Lh40/s3;->r:Z

    .line 157
    .line 158
    iget-boolean v3, p1, Lh40/s3;->r:Z

    .line 159
    .line 160
    if-eq v1, v3, :cond_13

    .line 161
    .line 162
    return v2

    .line 163
    :cond_13
    iget-boolean v1, p0, Lh40/s3;->s:Z

    .line 164
    .line 165
    iget-boolean v3, p1, Lh40/s3;->s:Z

    .line 166
    .line 167
    if-eq v1, v3, :cond_14

    .line 168
    .line 169
    return v2

    .line 170
    :cond_14
    iget-boolean v1, p0, Lh40/s3;->t:Z

    .line 171
    .line 172
    iget-boolean v3, p1, Lh40/s3;->t:Z

    .line 173
    .line 174
    if-eq v1, v3, :cond_15

    .line 175
    .line 176
    return v2

    .line 177
    :cond_15
    iget-boolean v1, p0, Lh40/s3;->u:Z

    .line 178
    .line 179
    iget-boolean v3, p1, Lh40/s3;->u:Z

    .line 180
    .line 181
    if-eq v1, v3, :cond_16

    .line 182
    .line 183
    return v2

    .line 184
    :cond_16
    iget-boolean v1, p0, Lh40/s3;->v:Z

    .line 185
    .line 186
    iget-boolean v3, p1, Lh40/s3;->v:Z

    .line 187
    .line 188
    if-eq v1, v3, :cond_17

    .line 189
    .line 190
    return v2

    .line 191
    :cond_17
    iget-boolean v1, p0, Lh40/s3;->w:Z

    .line 192
    .line 193
    iget-boolean v3, p1, Lh40/s3;->w:Z

    .line 194
    .line 195
    if-eq v1, v3, :cond_18

    .line 196
    .line 197
    return v2

    .line 198
    :cond_18
    iget-boolean v1, p0, Lh40/s3;->x:Z

    .line 199
    .line 200
    iget-boolean v3, p1, Lh40/s3;->x:Z

    .line 201
    .line 202
    if-eq v1, v3, :cond_19

    .line 203
    .line 204
    return v2

    .line 205
    :cond_19
    iget-object p0, p0, Lh40/s3;->y:Lh40/r3;

    .line 206
    .line 207
    iget-object p1, p1, Lh40/s3;->y:Lh40/r3;

    .line 208
    .line 209
    if-eq p0, p1, :cond_1a

    .line 210
    .line 211
    return v2

    .line 212
    :cond_1a
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lh40/s3;->a:Z

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
    iget-boolean v2, p0, Lh40/s3;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lh40/s3;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lh40/s3;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean v2, p0, Lh40/s3;->e:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean v2, p0, Lh40/s3;->f:Z

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-object v2, p0, Lh40/s3;->g:Ljava/util/List;

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object v2, p0, Lh40/s3;->h:Ljava/util/List;

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-boolean v2, p0, Lh40/s3;->i:Z

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
    iget-object v3, p0, Lh40/s3;->j:Lh40/u;

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
    invoke-virtual {v3}, Lh40/u;->hashCode()I

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
    iget v3, p0, Lh40/s3;->k:I

    .line 72
    .line 73
    invoke-static {v3, v0, v1}, Lc1/j0;->g(III)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    iget-boolean v3, p0, Lh40/s3;->l:Z

    .line 78
    .line 79
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    iget-object v3, p0, Lh40/s3;->m:Ljava/lang/String;

    .line 84
    .line 85
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    iget-object v3, p0, Lh40/s3;->n:Lh40/g0;

    .line 90
    .line 91
    invoke-virtual {v3}, Lh40/g0;->hashCode()I

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    add-int/2addr v3, v0

    .line 96
    mul-int/2addr v3, v1

    .line 97
    iget-object v0, p0, Lh40/s3;->o:Lql0/g;

    .line 98
    .line 99
    if-nez v0, :cond_1

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_1
    invoke-virtual {v0}, Lql0/g;->hashCode()I

    .line 103
    .line 104
    .line 105
    move-result v2

    .line 106
    :goto_1
    add-int/2addr v3, v2

    .line 107
    mul-int/2addr v3, v1

    .line 108
    iget-boolean v0, p0, Lh40/s3;->p:Z

    .line 109
    .line 110
    invoke-static {v3, v1, v0}, La7/g0;->e(IIZ)I

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    iget-boolean v2, p0, Lh40/s3;->q:Z

    .line 115
    .line 116
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    iget-boolean v2, p0, Lh40/s3;->r:Z

    .line 121
    .line 122
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    iget-boolean v2, p0, Lh40/s3;->s:Z

    .line 127
    .line 128
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    iget-boolean v2, p0, Lh40/s3;->t:Z

    .line 133
    .line 134
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    iget-boolean v2, p0, Lh40/s3;->u:Z

    .line 139
    .line 140
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 141
    .line 142
    .line 143
    move-result v0

    .line 144
    iget-boolean v2, p0, Lh40/s3;->v:Z

    .line 145
    .line 146
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 147
    .line 148
    .line 149
    move-result v0

    .line 150
    iget-boolean v2, p0, Lh40/s3;->w:Z

    .line 151
    .line 152
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 153
    .line 154
    .line 155
    move-result v0

    .line 156
    iget-boolean v2, p0, Lh40/s3;->x:Z

    .line 157
    .line 158
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 159
    .line 160
    .line 161
    move-result v0

    .line 162
    iget-object p0, p0, Lh40/s3;->y:Lh40/r3;

    .line 163
    .line 164
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 165
    .line 166
    .line 167
    move-result p0

    .line 168
    add-int/2addr p0, v0

    .line 169
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isConsentLoading="

    .line 2
    .line 3
    const-string v1, ", isRefreshing="

    .line 4
    .line 5
    const-string v2, "State(isLoading="

    .line 6
    .line 7
    iget-boolean v3, p0, Lh40/s3;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lh40/s3;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isDataUnavailable="

    .line 16
    .line 17
    const-string v2, ", isDailyCheckInCollected="

    .line 18
    .line 19
    iget-boolean v3, p0, Lh40/s3;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Lh40/s3;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", dailyCheckInLoading="

    .line 27
    .line 28
    const-string v2, ", inProgressChallenges="

    .line 29
    .line 30
    iget-boolean v3, p0, Lh40/s3;->e:Z

    .line 31
    .line 32
    iget-boolean v4, p0, Lh40/s3;->f:Z

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v1, ", activeRewards="

    .line 38
    .line 39
    const-string v2, ", isShowDeleteAccountConfirmDialogVisible="

    .line 40
    .line 41
    iget-object v3, p0, Lh40/s3;->g:Ljava/util/List;

    .line 42
    .line 43
    iget-object v4, p0, Lh40/s3;->h:Ljava/util/List;

    .line 44
    .line 45
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-boolean v1, p0, Lh40/s3;->i:Z

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", dailyChallengeProgress="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lh40/s3;->j:Lh40/u;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", pointBalance="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget v1, p0, Lh40/s3;->k:I

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", accountDeleteLoading="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-boolean v1, p0, Lh40/s3;->l:Z

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", loyaltyProgramTitle="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lh40/s3;->m:Ljava/lang/String;

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", loyaltyConsent="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v1, p0, Lh40/s3;->n:Lh40/g0;

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v1, ", error="

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-object v1, p0, Lh40/s3;->o:Lql0/g;

    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v1, ", shouldShowBadgesOnboarding="

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    iget-boolean v1, p0, Lh40/s3;->p:Z

    .line 119
    .line 120
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string v1, ", shouldShowInviteFriends="

    .line 124
    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string v1, ", isPreferredServicePartnerLoading="

    .line 129
    .line 130
    const-string v2, ", shouldShowAllActiveChallenges="

    .line 131
    .line 132
    iget-boolean v3, p0, Lh40/s3;->q:Z

    .line 133
    .line 134
    iget-boolean v4, p0, Lh40/s3;->r:Z

    .line 135
    .line 136
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 137
    .line 138
    .line 139
    const-string v1, ", isShowAllBadgesButtonVisible="

    .line 140
    .line 141
    const-string v2, ", isLuckyDrawEnabled="

    .line 142
    .line 143
    iget-boolean v3, p0, Lh40/s3;->s:Z

    .line 144
    .line 145
    iget-boolean v4, p0, Lh40/s3;->t:Z

    .line 146
    .line 147
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 148
    .line 149
    .line 150
    const-string v1, ", isShowAllLuckyDrawButtonVisible="

    .line 151
    .line 152
    const-string v2, ", showBottomSheet="

    .line 153
    .line 154
    iget-boolean v3, p0, Lh40/s3;->u:Z

    .line 155
    .line 156
    iget-boolean v4, p0, Lh40/s3;->v:Z

    .line 157
    .line 158
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 159
    .line 160
    .line 161
    const-string v1, ", hideBottomSheet="

    .line 162
    .line 163
    const-string v2, ", bottomSheetContent="

    .line 164
    .line 165
    iget-boolean v3, p0, Lh40/s3;->w:Z

    .line 166
    .line 167
    iget-boolean v4, p0, Lh40/s3;->x:Z

    .line 168
    .line 169
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 170
    .line 171
    .line 172
    iget-object p0, p0, Lh40/s3;->y:Lh40/r3;

    .line 173
    .line 174
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    const-string p0, ")"

    .line 178
    .line 179
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 180
    .line 181
    .line 182
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    return-object p0
.end method
