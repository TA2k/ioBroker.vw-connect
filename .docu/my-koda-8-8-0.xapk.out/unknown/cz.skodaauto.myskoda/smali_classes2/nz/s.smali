.class public final Lnz/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final A:Lmb0/c;

.field public final B:Z

.field public final C:Z

.field public final D:Z

.field public final E:Z

.field public final F:Z

.field public final a:Ler0/g;

.field public final b:Llf0/i;

.field public final c:Z

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Z

.field public final j:Z

.field public final k:Z

.field public final l:Ljava/lang/String;

.field public final m:Ljava/lang/String;

.field public final n:Lnz/r;

.field public final o:Lnz/q;

.field public final p:Lbo0/l;

.field public final q:Lnz/p;

.field public final r:Z

.field public final s:Z

.field public final t:Ljava/lang/String;

.field public final u:Z

.field public final v:Lmz/a;

.field public final w:Lqr0/q;

.field public final x:Lqr0/q;

.field public final y:Lmy0/c;

.field public final z:Z


# direct methods
.method public constructor <init>(Ler0/g;Llf0/i;ZZZZLjava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;Ljava/lang/String;Lnz/r;Lnz/q;Lbo0/l;Lnz/p;ZZLjava/lang/String;ZLmz/a;Lqr0/q;Lqr0/q;Lmy0/c;ZLmb0/c;Z)V
    .locals 3

    move-object/from16 v0, p14

    move-object/from16 v1, p16

    .line 1
    const-string v2, "viewMode"

    invoke-static {p2, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "gauge"

    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "plan"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lnz/s;->a:Ler0/g;

    .line 4
    iput-object p2, p0, Lnz/s;->b:Llf0/i;

    .line 5
    iput-boolean p3, p0, Lnz/s;->c:Z

    .line 6
    iput-boolean p4, p0, Lnz/s;->d:Z

    .line 7
    iput-boolean p5, p0, Lnz/s;->e:Z

    .line 8
    iput-boolean p6, p0, Lnz/s;->f:Z

    .line 9
    iput-object p7, p0, Lnz/s;->g:Ljava/lang/String;

    .line 10
    iput-object p8, p0, Lnz/s;->h:Ljava/lang/String;

    .line 11
    iput-boolean p9, p0, Lnz/s;->i:Z

    .line 12
    iput-boolean p10, p0, Lnz/s;->j:Z

    .line 13
    iput-boolean p11, p0, Lnz/s;->k:Z

    .line 14
    iput-object p12, p0, Lnz/s;->l:Ljava/lang/String;

    move-object/from16 p1, p13

    .line 15
    iput-object p1, p0, Lnz/s;->m:Ljava/lang/String;

    .line 16
    iput-object v0, p0, Lnz/s;->n:Lnz/r;

    move-object/from16 p1, p15

    .line 17
    iput-object p1, p0, Lnz/s;->o:Lnz/q;

    .line 18
    iput-object v1, p0, Lnz/s;->p:Lbo0/l;

    move-object/from16 p1, p17

    .line 19
    iput-object p1, p0, Lnz/s;->q:Lnz/p;

    move/from16 p1, p18

    .line 20
    iput-boolean p1, p0, Lnz/s;->r:Z

    move/from16 p1, p19

    .line 21
    iput-boolean p1, p0, Lnz/s;->s:Z

    move-object/from16 p1, p20

    .line 22
    iput-object p1, p0, Lnz/s;->t:Ljava/lang/String;

    move/from16 p1, p21

    .line 23
    iput-boolean p1, p0, Lnz/s;->u:Z

    move-object/from16 p1, p22

    .line 24
    iput-object p1, p0, Lnz/s;->v:Lmz/a;

    move-object/from16 p1, p23

    .line 25
    iput-object p1, p0, Lnz/s;->w:Lqr0/q;

    move-object/from16 p3, p24

    .line 26
    iput-object p3, p0, Lnz/s;->x:Lqr0/q;

    move-object/from16 p4, p25

    .line 27
    iput-object p4, p0, Lnz/s;->y:Lmy0/c;

    move/from16 p4, p26

    .line 28
    iput-boolean p4, p0, Lnz/s;->z:Z

    move-object/from16 p4, p27

    .line 29
    iput-object p4, p0, Lnz/s;->A:Lmb0/c;

    move/from16 p4, p28

    .line 30
    iput-boolean p4, p0, Lnz/s;->B:Z

    .line 31
    invoke-static/range {p23 .. p24}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    const/4 p3, 0x1

    xor-int/2addr p1, p3

    iput-boolean p1, p0, Lnz/s;->C:Z

    .line 32
    sget-object p1, Llf0/i;->h:Llf0/i;

    const/4 p4, 0x0

    if-ne p2, p1, :cond_0

    move p1, p3

    goto :goto_0

    :cond_0
    move p1, p4

    :goto_0
    iput-boolean p1, p0, Lnz/s;->D:Z

    .line 33
    invoke-static {p2}, Llp/tf;->d(Llf0/i;)Z

    move-result p2

    iput-boolean p2, p0, Lnz/s;->E:Z

    if-nez p1, :cond_2

    if-eqz p2, :cond_1

    goto :goto_1

    :cond_1
    move p3, p4

    .line 34
    :cond_2
    :goto_1
    iput-boolean p3, p0, Lnz/s;->F:Z

    return-void
.end method

.method public synthetic constructor <init>(ZLnz/r;Lnz/q;Lbo0/l;Lqr0/q;Lqr0/q;I)V
    .locals 29

    move/from16 v0, p7

    .line 35
    sget-object v1, Ler0/g;->d:Ler0/g;

    .line 36
    sget-object v2, Llf0/i;->j:Llf0/i;

    and-int/lit8 v3, v0, 0x8

    const/4 v4, 0x0

    if-eqz v3, :cond_0

    move v3, v4

    goto :goto_0

    :cond_0
    move/from16 v3, p1

    :goto_0
    and-int/lit8 v5, v0, 0x20

    const/4 v6, 0x1

    if-eqz v5, :cond_1

    move v5, v6

    goto :goto_1

    :cond_1
    move v5, v6

    move v6, v4

    :goto_1
    and-int/lit16 v7, v0, 0x400

    if-eqz v7, :cond_2

    move v11, v4

    goto :goto_2

    :cond_2
    move v11, v5

    :goto_2
    and-int/lit16 v4, v0, 0x800

    const/4 v5, 0x0

    if-eqz v4, :cond_3

    move-object v12, v5

    goto :goto_3

    .line 37
    :cond_3
    const-string v4, "Target temperature same as previously set in car"

    move-object v12, v4

    :goto_3
    and-int/lit16 v4, v0, 0x2000

    if-eqz v4, :cond_4

    .line 38
    new-instance v13, Lnz/r;

    const/16 v20, 0x0

    const/16 v21, 0xff

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    invoke-direct/range {v13 .. v21}, Lnz/r;-><init>(Ljava/lang/String;Ljava/lang/String;FIZZLvf0/g;I)V

    move-object v14, v13

    goto :goto_4

    :cond_4
    move-object/from16 v14, p2

    :goto_4
    and-int/lit16 v4, v0, 0x4000

    if-eqz v4, :cond_5

    move-object v15, v5

    goto :goto_5

    :cond_5
    move-object/from16 v15, p3

    :goto_5
    const v4, 0x8000

    and-int/2addr v4, v0

    if-eqz v4, :cond_6

    .line 39
    new-instance v4, Lbo0/l;

    invoke-direct {v4}, Lbo0/l;-><init>()V

    move-object/from16 v16, v4

    goto :goto_6

    :cond_6
    move-object/from16 v16, p4

    .line 40
    :goto_6
    sget-object v17, Lnz/p;->d:Lnz/p;

    .line 41
    sget-object v22, Lmz/a;->e:Lmz/a;

    const/high16 v4, 0x400000

    and-int/2addr v4, v0

    if-eqz v4, :cond_7

    move-object/from16 v23, v5

    goto :goto_7

    :cond_7
    move-object/from16 v23, p5

    :goto_7
    const/high16 v4, 0x800000

    and-int/2addr v0, v4

    if-eqz v0, :cond_8

    move-object/from16 v24, v5

    goto :goto_8

    :cond_8
    move-object/from16 v24, p6

    :goto_8
    const/16 v26, 0x0

    const/16 v28, 0x0

    move v4, v3

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v13, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x1

    const/16 v25, 0x0

    const/16 v27, 0x0

    move-object/from16 v0, p0

    .line 42
    invoke-direct/range {v0 .. v28}, Lnz/s;-><init>(Ler0/g;Llf0/i;ZZZZLjava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;Ljava/lang/String;Lnz/r;Lnz/q;Lbo0/l;Lnz/p;ZZLjava/lang/String;ZLmz/a;Lqr0/q;Lqr0/q;Lmy0/c;ZLmb0/c;Z)V

    return-void
.end method

.method public static a(Lnz/s;Ler0/g;Llf0/i;ZZZZZZLjava/lang/String;Ljava/lang/String;Lnz/r;Lnz/q;Lbo0/l;Lnz/p;ZZLjava/lang/String;Lmz/a;Lqr0/q;Lqr0/q;Lmy0/c;ZLmb0/c;ZI)Lnz/s;
    .locals 32

    move-object/from16 v0, p0

    move/from16 v1, p25

    and-int/lit8 v2, v1, 0x1

    if-eqz v2, :cond_0

    iget-object v2, v0, Lnz/s;->a:Ler0/g;

    move-object v4, v2

    goto :goto_0

    :cond_0
    move-object/from16 v4, p1

    :goto_0
    and-int/lit8 v2, v1, 0x2

    if-eqz v2, :cond_1

    iget-object v2, v0, Lnz/s;->b:Llf0/i;

    move-object v5, v2

    goto :goto_1

    :cond_1
    move-object/from16 v5, p2

    :goto_1
    and-int/lit8 v2, v1, 0x4

    if-eqz v2, :cond_2

    iget-boolean v2, v0, Lnz/s;->c:Z

    move v6, v2

    goto :goto_2

    :cond_2
    move/from16 v6, p3

    :goto_2
    and-int/lit8 v2, v1, 0x8

    if-eqz v2, :cond_3

    iget-boolean v2, v0, Lnz/s;->d:Z

    move v7, v2

    goto :goto_3

    :cond_3
    move/from16 v7, p4

    :goto_3
    and-int/lit8 v2, v1, 0x10

    if-eqz v2, :cond_4

    iget-boolean v2, v0, Lnz/s;->e:Z

    :goto_4
    move v8, v2

    goto :goto_5

    :cond_4
    const/4 v2, 0x1

    goto :goto_4

    :goto_5
    and-int/lit8 v2, v1, 0x20

    if-eqz v2, :cond_5

    iget-boolean v2, v0, Lnz/s;->f:Z

    move v9, v2

    goto :goto_6

    :cond_5
    move/from16 v9, p5

    :goto_6
    iget-object v10, v0, Lnz/s;->g:Ljava/lang/String;

    iget-object v11, v0, Lnz/s;->h:Ljava/lang/String;

    and-int/lit16 v2, v1, 0x100

    if-eqz v2, :cond_6

    iget-boolean v2, v0, Lnz/s;->i:Z

    move v12, v2

    goto :goto_7

    :cond_6
    move/from16 v12, p6

    :goto_7
    and-int/lit16 v2, v1, 0x200

    if-eqz v2, :cond_7

    iget-boolean v2, v0, Lnz/s;->j:Z

    move v13, v2

    goto :goto_8

    :cond_7
    move/from16 v13, p7

    :goto_8
    and-int/lit16 v2, v1, 0x400

    if-eqz v2, :cond_8

    iget-boolean v2, v0, Lnz/s;->k:Z

    move v14, v2

    goto :goto_9

    :cond_8
    move/from16 v14, p8

    :goto_9
    and-int/lit16 v2, v1, 0x800

    if-eqz v2, :cond_9

    iget-object v2, v0, Lnz/s;->l:Ljava/lang/String;

    move-object v15, v2

    goto :goto_a

    :cond_9
    move-object/from16 v15, p9

    :goto_a
    and-int/lit16 v2, v1, 0x1000

    if-eqz v2, :cond_a

    iget-object v2, v0, Lnz/s;->m:Ljava/lang/String;

    move-object/from16 v16, v2

    goto :goto_b

    :cond_a
    move-object/from16 v16, p10

    :goto_b
    and-int/lit16 v2, v1, 0x2000

    if-eqz v2, :cond_b

    iget-object v2, v0, Lnz/s;->n:Lnz/r;

    goto :goto_c

    :cond_b
    move-object/from16 v2, p11

    :goto_c
    and-int/lit16 v3, v1, 0x4000

    if-eqz v3, :cond_c

    iget-object v3, v0, Lnz/s;->o:Lnz/q;

    move-object/from16 v18, v3

    goto :goto_d

    :cond_c
    move-object/from16 v18, p12

    :goto_d
    const v3, 0x8000

    and-int/2addr v3, v1

    if-eqz v3, :cond_d

    iget-object v3, v0, Lnz/s;->p:Lbo0/l;

    goto :goto_e

    :cond_d
    move-object/from16 v3, p13

    :goto_e
    const/high16 v17, 0x10000

    and-int v17, v1, v17

    if-eqz v17, :cond_e

    iget-object v1, v0, Lnz/s;->q:Lnz/p;

    goto :goto_f

    :cond_e
    move-object/from16 v1, p14

    :goto_f
    const/high16 v17, 0x20000

    and-int v17, p25, v17

    move/from16 p1, v6

    if-eqz v17, :cond_f

    iget-boolean v6, v0, Lnz/s;->r:Z

    move/from16 v21, v6

    goto :goto_10

    :cond_f
    move/from16 v21, p15

    :goto_10
    const/high16 v6, 0x40000

    and-int v6, p25, v6

    if-eqz v6, :cond_10

    iget-boolean v6, v0, Lnz/s;->s:Z

    move/from16 v22, v6

    goto :goto_11

    :cond_10
    move/from16 v22, p16

    :goto_11
    const/high16 v6, 0x80000

    and-int v6, p25, v6

    if-eqz v6, :cond_11

    iget-object v6, v0, Lnz/s;->t:Ljava/lang/String;

    move-object/from16 v23, v6

    goto :goto_12

    :cond_11
    move-object/from16 v23, p17

    :goto_12
    const/high16 v6, 0x100000

    and-int v6, p25, v6

    if-eqz v6, :cond_12

    iget-boolean v6, v0, Lnz/s;->u:Z

    :goto_13
    move/from16 v24, v6

    goto :goto_14

    :cond_12
    const/4 v6, 0x0

    goto :goto_13

    :goto_14
    const/high16 v6, 0x200000

    and-int v6, p25, v6

    if-eqz v6, :cond_13

    iget-object v6, v0, Lnz/s;->v:Lmz/a;

    goto :goto_15

    :cond_13
    move-object/from16 v6, p18

    :goto_15
    const/high16 v17, 0x400000

    and-int v17, p25, v17

    move/from16 p2, v7

    if-eqz v17, :cond_14

    iget-object v7, v0, Lnz/s;->w:Lqr0/q;

    move-object/from16 v26, v7

    goto :goto_16

    :cond_14
    move-object/from16 v26, p19

    :goto_16
    const/high16 v7, 0x800000

    and-int v7, p25, v7

    if-eqz v7, :cond_15

    iget-object v7, v0, Lnz/s;->x:Lqr0/q;

    move-object/from16 v27, v7

    goto :goto_17

    :cond_15
    move-object/from16 v27, p20

    :goto_17
    const/high16 v7, 0x1000000

    and-int v7, p25, v7

    if-eqz v7, :cond_16

    iget-object v7, v0, Lnz/s;->y:Lmy0/c;

    move-object/from16 v28, v7

    goto :goto_18

    :cond_16
    move-object/from16 v28, p21

    :goto_18
    const/high16 v7, 0x2000000

    and-int v7, p25, v7

    if-eqz v7, :cond_17

    iget-boolean v7, v0, Lnz/s;->z:Z

    move/from16 v29, v7

    goto :goto_19

    :cond_17
    move/from16 v29, p22

    :goto_19
    const/high16 v7, 0x4000000

    and-int v7, p25, v7

    if-eqz v7, :cond_18

    iget-object v7, v0, Lnz/s;->A:Lmb0/c;

    move-object/from16 v30, v7

    goto :goto_1a

    :cond_18
    move-object/from16 v30, p23

    :goto_1a
    const/high16 v7, 0x8000000

    and-int v7, p25, v7

    if-eqz v7, :cond_19

    iget-boolean v7, v0, Lnz/s;->B:Z

    move/from16 v31, v7

    goto :goto_1b

    :cond_19
    move/from16 v31, p24

    :goto_1b
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1
    const-string v0, "subscriptionLicenseState"

    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "viewMode"

    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "gauge"

    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "plan"

    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "auxiliaryState"

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "generation"

    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v19, v3

    new-instance v3, Lnz/s;

    move/from16 v7, p2

    move-object/from16 v20, v1

    move-object/from16 v17, v2

    move-object/from16 v25, v6

    move/from16 v6, p1

    invoke-direct/range {v3 .. v31}, Lnz/s;-><init>(Ler0/g;Llf0/i;ZZZZLjava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;Ljava/lang/String;Lnz/r;Lnz/q;Lbo0/l;Lnz/p;ZZLjava/lang/String;ZLmz/a;Lqr0/q;Lqr0/q;Lmy0/c;ZLmb0/c;Z)V

    return-object v3
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
    instance-of v1, p1, Lnz/s;

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
    check-cast p1, Lnz/s;

    .line 12
    .line 13
    iget-object v1, p0, Lnz/s;->a:Ler0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lnz/s;->a:Ler0/g;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lnz/s;->b:Llf0/i;

    .line 21
    .line 22
    iget-object v3, p1, Lnz/s;->b:Llf0/i;

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lnz/s;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lnz/s;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lnz/s;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lnz/s;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-boolean v1, p0, Lnz/s;->e:Z

    .line 42
    .line 43
    iget-boolean v3, p1, Lnz/s;->e:Z

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-boolean v1, p0, Lnz/s;->f:Z

    .line 49
    .line 50
    iget-boolean v3, p1, Lnz/s;->f:Z

    .line 51
    .line 52
    if-eq v1, v3, :cond_7

    .line 53
    .line 54
    return v2

    .line 55
    :cond_7
    iget-object v1, p0, Lnz/s;->g:Ljava/lang/String;

    .line 56
    .line 57
    iget-object v3, p1, Lnz/s;->g:Ljava/lang/String;

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
    iget-object v1, p0, Lnz/s;->h:Ljava/lang/String;

    .line 67
    .line 68
    iget-object v3, p1, Lnz/s;->h:Ljava/lang/String;

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
    iget-boolean v1, p0, Lnz/s;->i:Z

    .line 78
    .line 79
    iget-boolean v3, p1, Lnz/s;->i:Z

    .line 80
    .line 81
    if-eq v1, v3, :cond_a

    .line 82
    .line 83
    return v2

    .line 84
    :cond_a
    iget-boolean v1, p0, Lnz/s;->j:Z

    .line 85
    .line 86
    iget-boolean v3, p1, Lnz/s;->j:Z

    .line 87
    .line 88
    if-eq v1, v3, :cond_b

    .line 89
    .line 90
    return v2

    .line 91
    :cond_b
    iget-boolean v1, p0, Lnz/s;->k:Z

    .line 92
    .line 93
    iget-boolean v3, p1, Lnz/s;->k:Z

    .line 94
    .line 95
    if-eq v1, v3, :cond_c

    .line 96
    .line 97
    return v2

    .line 98
    :cond_c
    iget-object v1, p0, Lnz/s;->l:Ljava/lang/String;

    .line 99
    .line 100
    iget-object v3, p1, Lnz/s;->l:Ljava/lang/String;

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
    iget-object v1, p0, Lnz/s;->m:Ljava/lang/String;

    .line 110
    .line 111
    iget-object v3, p1, Lnz/s;->m:Ljava/lang/String;

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
    iget-object v1, p0, Lnz/s;->n:Lnz/r;

    .line 121
    .line 122
    iget-object v3, p1, Lnz/s;->n:Lnz/r;

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
    iget-object v1, p0, Lnz/s;->o:Lnz/q;

    .line 132
    .line 133
    iget-object v3, p1, Lnz/s;->o:Lnz/q;

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
    iget-object v1, p0, Lnz/s;->p:Lbo0/l;

    .line 143
    .line 144
    iget-object v3, p1, Lnz/s;->p:Lbo0/l;

    .line 145
    .line 146
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result v1

    .line 150
    if-nez v1, :cond_11

    .line 151
    .line 152
    return v2

    .line 153
    :cond_11
    iget-object v1, p0, Lnz/s;->q:Lnz/p;

    .line 154
    .line 155
    iget-object v3, p1, Lnz/s;->q:Lnz/p;

    .line 156
    .line 157
    if-eq v1, v3, :cond_12

    .line 158
    .line 159
    return v2

    .line 160
    :cond_12
    iget-boolean v1, p0, Lnz/s;->r:Z

    .line 161
    .line 162
    iget-boolean v3, p1, Lnz/s;->r:Z

    .line 163
    .line 164
    if-eq v1, v3, :cond_13

    .line 165
    .line 166
    return v2

    .line 167
    :cond_13
    iget-boolean v1, p0, Lnz/s;->s:Z

    .line 168
    .line 169
    iget-boolean v3, p1, Lnz/s;->s:Z

    .line 170
    .line 171
    if-eq v1, v3, :cond_14

    .line 172
    .line 173
    return v2

    .line 174
    :cond_14
    iget-object v1, p0, Lnz/s;->t:Ljava/lang/String;

    .line 175
    .line 176
    iget-object v3, p1, Lnz/s;->t:Ljava/lang/String;

    .line 177
    .line 178
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v1

    .line 182
    if-nez v1, :cond_15

    .line 183
    .line 184
    return v2

    .line 185
    :cond_15
    iget-boolean v1, p0, Lnz/s;->u:Z

    .line 186
    .line 187
    iget-boolean v3, p1, Lnz/s;->u:Z

    .line 188
    .line 189
    if-eq v1, v3, :cond_16

    .line 190
    .line 191
    return v2

    .line 192
    :cond_16
    iget-object v1, p0, Lnz/s;->v:Lmz/a;

    .line 193
    .line 194
    iget-object v3, p1, Lnz/s;->v:Lmz/a;

    .line 195
    .line 196
    if-eq v1, v3, :cond_17

    .line 197
    .line 198
    return v2

    .line 199
    :cond_17
    iget-object v1, p0, Lnz/s;->w:Lqr0/q;

    .line 200
    .line 201
    iget-object v3, p1, Lnz/s;->w:Lqr0/q;

    .line 202
    .line 203
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    move-result v1

    .line 207
    if-nez v1, :cond_18

    .line 208
    .line 209
    return v2

    .line 210
    :cond_18
    iget-object v1, p0, Lnz/s;->x:Lqr0/q;

    .line 211
    .line 212
    iget-object v3, p1, Lnz/s;->x:Lqr0/q;

    .line 213
    .line 214
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-result v1

    .line 218
    if-nez v1, :cond_19

    .line 219
    .line 220
    return v2

    .line 221
    :cond_19
    iget-object v1, p0, Lnz/s;->y:Lmy0/c;

    .line 222
    .line 223
    iget-object v3, p1, Lnz/s;->y:Lmy0/c;

    .line 224
    .line 225
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 226
    .line 227
    .line 228
    move-result v1

    .line 229
    if-nez v1, :cond_1a

    .line 230
    .line 231
    return v2

    .line 232
    :cond_1a
    iget-boolean v1, p0, Lnz/s;->z:Z

    .line 233
    .line 234
    iget-boolean v3, p1, Lnz/s;->z:Z

    .line 235
    .line 236
    if-eq v1, v3, :cond_1b

    .line 237
    .line 238
    return v2

    .line 239
    :cond_1b
    iget-object v1, p0, Lnz/s;->A:Lmb0/c;

    .line 240
    .line 241
    iget-object v3, p1, Lnz/s;->A:Lmb0/c;

    .line 242
    .line 243
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result v1

    .line 247
    if-nez v1, :cond_1c

    .line 248
    .line 249
    return v2

    .line 250
    :cond_1c
    iget-boolean p0, p0, Lnz/s;->B:Z

    .line 251
    .line 252
    iget-boolean p1, p1, Lnz/s;->B:Z

    .line 253
    .line 254
    if-eq p0, p1, :cond_1d

    .line 255
    .line 256
    return v2

    .line 257
    :cond_1d
    return v0
.end method

.method public final hashCode()I
    .locals 6

    .line 1
    iget-object v0, p0, Lnz/s;->a:Ler0/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

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
    iget-object v2, p0, Lnz/s;->b:Llf0/i;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-boolean v0, p0, Lnz/s;->c:Z

    .line 19
    .line 20
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-boolean v2, p0, Lnz/s;->d:Z

    .line 25
    .line 26
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget-boolean v2, p0, Lnz/s;->e:Z

    .line 31
    .line 32
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-boolean v2, p0, Lnz/s;->f:Z

    .line 37
    .line 38
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    const/4 v2, 0x0

    .line 43
    iget-object v3, p0, Lnz/s;->g:Ljava/lang/String;

    .line 44
    .line 45
    if-nez v3, :cond_0

    .line 46
    .line 47
    move v3, v2

    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    :goto_0
    add-int/2addr v0, v3

    .line 54
    mul-int/2addr v0, v1

    .line 55
    iget-object v3, p0, Lnz/s;->h:Ljava/lang/String;

    .line 56
    .line 57
    if-nez v3, :cond_1

    .line 58
    .line 59
    move v3, v2

    .line 60
    goto :goto_1

    .line 61
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    :goto_1
    add-int/2addr v0, v3

    .line 66
    mul-int/2addr v0, v1

    .line 67
    iget-boolean v3, p0, Lnz/s;->i:Z

    .line 68
    .line 69
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    iget-boolean v3, p0, Lnz/s;->j:Z

    .line 74
    .line 75
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    iget-boolean v3, p0, Lnz/s;->k:Z

    .line 80
    .line 81
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    iget-object v3, p0, Lnz/s;->l:Ljava/lang/String;

    .line 86
    .line 87
    if-nez v3, :cond_2

    .line 88
    .line 89
    move v3, v2

    .line 90
    goto :goto_2

    .line 91
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    :goto_2
    add-int/2addr v0, v3

    .line 96
    mul-int/2addr v0, v1

    .line 97
    iget-object v3, p0, Lnz/s;->m:Ljava/lang/String;

    .line 98
    .line 99
    if-nez v3, :cond_3

    .line 100
    .line 101
    move v3, v2

    .line 102
    goto :goto_3

    .line 103
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    :goto_3
    add-int/2addr v0, v3

    .line 108
    mul-int/2addr v0, v1

    .line 109
    iget-object v3, p0, Lnz/s;->n:Lnz/r;

    .line 110
    .line 111
    invoke-virtual {v3}, Lnz/r;->hashCode()I

    .line 112
    .line 113
    .line 114
    move-result v3

    .line 115
    add-int/2addr v3, v0

    .line 116
    mul-int/2addr v3, v1

    .line 117
    iget-object v0, p0, Lnz/s;->o:Lnz/q;

    .line 118
    .line 119
    if-nez v0, :cond_4

    .line 120
    .line 121
    move v0, v2

    .line 122
    goto :goto_4

    .line 123
    :cond_4
    invoke-virtual {v0}, Lnz/q;->hashCode()I

    .line 124
    .line 125
    .line 126
    move-result v0

    .line 127
    :goto_4
    add-int/2addr v3, v0

    .line 128
    mul-int/2addr v3, v1

    .line 129
    iget-object v0, p0, Lnz/s;->p:Lbo0/l;

    .line 130
    .line 131
    invoke-virtual {v0}, Lbo0/l;->hashCode()I

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    add-int/2addr v0, v3

    .line 136
    mul-int/2addr v0, v1

    .line 137
    iget-object v3, p0, Lnz/s;->q:Lnz/p;

    .line 138
    .line 139
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 140
    .line 141
    .line 142
    move-result v3

    .line 143
    add-int/2addr v3, v0

    .line 144
    mul-int/2addr v3, v1

    .line 145
    iget-boolean v0, p0, Lnz/s;->r:Z

    .line 146
    .line 147
    invoke-static {v3, v1, v0}, La7/g0;->e(IIZ)I

    .line 148
    .line 149
    .line 150
    move-result v0

    .line 151
    iget-boolean v3, p0, Lnz/s;->s:Z

    .line 152
    .line 153
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 154
    .line 155
    .line 156
    move-result v0

    .line 157
    iget-object v3, p0, Lnz/s;->t:Ljava/lang/String;

    .line 158
    .line 159
    if-nez v3, :cond_5

    .line 160
    .line 161
    move v3, v2

    .line 162
    goto :goto_5

    .line 163
    :cond_5
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 164
    .line 165
    .line 166
    move-result v3

    .line 167
    :goto_5
    add-int/2addr v0, v3

    .line 168
    mul-int/2addr v0, v1

    .line 169
    iget-boolean v3, p0, Lnz/s;->u:Z

    .line 170
    .line 171
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 172
    .line 173
    .line 174
    move-result v0

    .line 175
    iget-object v3, p0, Lnz/s;->v:Lmz/a;

    .line 176
    .line 177
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 178
    .line 179
    .line 180
    move-result v3

    .line 181
    add-int/2addr v3, v0

    .line 182
    mul-int/2addr v3, v1

    .line 183
    iget-object v0, p0, Lnz/s;->w:Lqr0/q;

    .line 184
    .line 185
    if-nez v0, :cond_6

    .line 186
    .line 187
    move v0, v2

    .line 188
    goto :goto_6

    .line 189
    :cond_6
    invoke-virtual {v0}, Lqr0/q;->hashCode()I

    .line 190
    .line 191
    .line 192
    move-result v0

    .line 193
    :goto_6
    add-int/2addr v3, v0

    .line 194
    mul-int/2addr v3, v1

    .line 195
    iget-object v0, p0, Lnz/s;->x:Lqr0/q;

    .line 196
    .line 197
    if-nez v0, :cond_7

    .line 198
    .line 199
    move v0, v2

    .line 200
    goto :goto_7

    .line 201
    :cond_7
    invoke-virtual {v0}, Lqr0/q;->hashCode()I

    .line 202
    .line 203
    .line 204
    move-result v0

    .line 205
    :goto_7
    add-int/2addr v3, v0

    .line 206
    mul-int/2addr v3, v1

    .line 207
    iget-object v0, p0, Lnz/s;->y:Lmy0/c;

    .line 208
    .line 209
    if-nez v0, :cond_8

    .line 210
    .line 211
    move v0, v2

    .line 212
    goto :goto_8

    .line 213
    :cond_8
    iget-wide v4, v0, Lmy0/c;->d:J

    .line 214
    .line 215
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 216
    .line 217
    .line 218
    move-result v0

    .line 219
    :goto_8
    add-int/2addr v3, v0

    .line 220
    mul-int/2addr v3, v1

    .line 221
    iget-boolean v0, p0, Lnz/s;->z:Z

    .line 222
    .line 223
    invoke-static {v3, v1, v0}, La7/g0;->e(IIZ)I

    .line 224
    .line 225
    .line 226
    move-result v0

    .line 227
    iget-object v3, p0, Lnz/s;->A:Lmb0/c;

    .line 228
    .line 229
    if-nez v3, :cond_9

    .line 230
    .line 231
    goto :goto_9

    .line 232
    :cond_9
    invoke-virtual {v3}, Lmb0/c;->hashCode()I

    .line 233
    .line 234
    .line 235
    move-result v2

    .line 236
    :goto_9
    add-int/2addr v0, v2

    .line 237
    mul-int/2addr v0, v1

    .line 238
    iget-boolean p0, p0, Lnz/s;->B:Z

    .line 239
    .line 240
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 241
    .line 242
    .line 243
    move-result p0

    .line 244
    add-int/2addr p0, v0

    .line 245
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(subscriptionLicenseState="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lnz/s;->a:Ler0/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", viewMode="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lnz/s;->b:Llf0/i;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

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
    const-string v1, ", isStartStopEnabled="

    .line 29
    .line 30
    const-string v2, ", isRefreshEnabled="

    .line 31
    .line 32
    iget-boolean v3, p0, Lnz/s;->c:Z

    .line 33
    .line 34
    iget-boolean v4, p0, Lnz/s;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string v1, ", isStatusLoading="

    .line 40
    .line 41
    const-string v2, ", statusTitle="

    .line 42
    .line 43
    iget-boolean v3, p0, Lnz/s;->e:Z

    .line 44
    .line 45
    iget-boolean v4, p0, Lnz/s;->f:Z

    .line 46
    .line 47
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const-string v1, ", statusSubtitle="

    .line 51
    .line 52
    const-string v2, ", isRunning="

    .line 53
    .line 54
    iget-object v3, p0, Lnz/s;->g:Ljava/lang/String;

    .line 55
    .line 56
    iget-object v4, p0, Lnz/s;->h:Ljava/lang/String;

    .line 57
    .line 58
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    const-string v1, ", isHeatingSelected="

    .line 62
    .line 63
    const-string v2, ", isSourceSelectionVisible="

    .line 64
    .line 65
    iget-boolean v3, p0, Lnz/s;->i:Z

    .line 66
    .line 67
    iget-boolean v4, p0, Lnz/s;->j:Z

    .line 68
    .line 69
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 70
    .line 71
    .line 72
    const-string v1, ", informationTextHeader="

    .line 73
    .line 74
    const-string v2, ", informationText="

    .line 75
    .line 76
    iget-object v3, p0, Lnz/s;->l:Ljava/lang/String;

    .line 77
    .line 78
    iget-boolean v4, p0, Lnz/s;->k:Z

    .line 79
    .line 80
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 81
    .line 82
    .line 83
    iget-object v1, p0, Lnz/s;->m:Ljava/lang/String;

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    const-string v1, ", gauge="

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    iget-object v1, p0, Lnz/s;->n:Lnz/r;

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    const-string v1, ", baseLine="

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    iget-object v1, p0, Lnz/s;->o:Lnz/q;

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    const-string v1, ", plan="

    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    iget-object v1, p0, Lnz/s;->p:Lbo0/l;

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    const-string v1, ", auxiliaryState="

    .line 119
    .line 120
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    iget-object v1, p0, Lnz/s;->q:Lnz/p;

    .line 124
    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string v1, ", isSendingRequest="

    .line 129
    .line 130
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    iget-boolean v1, p0, Lnz/s;->r:Z

    .line 134
    .line 135
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    const-string v1, ", isSendingStopRequest="

    .line 139
    .line 140
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    const-string v1, ", sendingRequestTitle="

    .line 144
    .line 145
    const-string v2, ", isFirstError="

    .line 146
    .line 147
    iget-object v3, p0, Lnz/s;->t:Ljava/lang/String;

    .line 148
    .line 149
    iget-boolean v4, p0, Lnz/s;->s:Z

    .line 150
    .line 151
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 152
    .line 153
    .line 154
    iget-boolean v1, p0, Lnz/s;->u:Z

    .line 155
    .line 156
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    const-string v1, ", generation="

    .line 160
    .line 161
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 162
    .line 163
    .line 164
    iget-object v1, p0, Lnz/s;->v:Lmz/a;

    .line 165
    .line 166
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 167
    .line 168
    .line 169
    const-string v1, ", currentTemperature="

    .line 170
    .line 171
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 172
    .line 173
    .line 174
    iget-object v1, p0, Lnz/s;->w:Lqr0/q;

    .line 175
    .line 176
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 177
    .line 178
    .line 179
    const-string v1, ", targetTemperature="

    .line 180
    .line 181
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    iget-object v1, p0, Lnz/s;->x:Lqr0/q;

    .line 185
    .line 186
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    const-string v1, ", currentTime="

    .line 190
    .line 191
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 192
    .line 193
    .line 194
    iget-object v1, p0, Lnz/s;->y:Lmy0/c;

    .line 195
    .line 196
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    const-string v1, ", hasOutsideTemperatureCapability="

    .line 200
    .line 201
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    iget-boolean v1, p0, Lnz/s;->z:Z

    .line 205
    .line 206
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 207
    .line 208
    .line 209
    const-string v1, ", outsideTemperature="

    .line 210
    .line 211
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    iget-object v1, p0, Lnz/s;->A:Lmb0/c;

    .line 215
    .line 216
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 217
    .line 218
    .line 219
    const-string v1, ", waitingForServerUpdate="

    .line 220
    .line 221
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 222
    .line 223
    .line 224
    iget-boolean p0, p0, Lnz/s;->B:Z

    .line 225
    .line 226
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

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
