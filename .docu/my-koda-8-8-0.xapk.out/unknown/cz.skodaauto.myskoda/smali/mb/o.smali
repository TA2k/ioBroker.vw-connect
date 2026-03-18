.class public final Lmb/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final A:Lj9/d;

.field public static final z:Ljava/lang/String;


# instance fields
.field public final a:Ljava/lang/String;

.field public b:Leb/h0;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public e:Leb/h;

.field public final f:Leb/h;

.field public g:J

.field public h:J

.field public i:J

.field public j:Leb/e;

.field public final k:I

.field public final l:Leb/a;

.field public final m:J

.field public n:J

.field public o:J

.field public final p:J

.field public q:Z

.field public final r:Leb/e0;

.field public final s:I

.field public final t:I

.field public final u:J

.field public final v:I

.field public final w:I

.field public x:Ljava/lang/String;

.field public final y:Ljava/lang/Boolean;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "WorkSpec"

    .line 2
    .line 3
    invoke-static {v0}, Leb/w;->f(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "tagWithPrefix(...)"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lmb/o;->z:Ljava/lang/String;

    .line 13
    .line 14
    new-instance v0, Lj9/d;

    .line 15
    .line 16
    const/16 v1, 0x9

    .line 17
    .line 18
    invoke-direct {v0, v1}, Lj9/d;-><init>(I)V

    .line 19
    .line 20
    .line 21
    sput-object v0, Lmb/o;->A:Lj9/d;

    .line 22
    .line 23
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IIJIILjava/lang/String;Ljava/lang/Boolean;)V
    .locals 4

    move-object/from16 v0, p13

    move-object/from16 v1, p15

    move-object/from16 v2, p25

    const-string v3, "id"

    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "state"

    invoke-static {p2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "workerClassName"

    invoke-static {p3, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "inputMergerClassName"

    invoke-static {p4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "input"

    invoke-static {p5, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "output"

    invoke-static {p6, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "constraints"

    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "backoffPolicy"

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "outOfQuotaPolicy"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lmb/o;->a:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lmb/o;->b:Leb/h0;

    .line 4
    iput-object p3, p0, Lmb/o;->c:Ljava/lang/String;

    .line 5
    iput-object p4, p0, Lmb/o;->d:Ljava/lang/String;

    .line 6
    iput-object p5, p0, Lmb/o;->e:Leb/h;

    .line 7
    iput-object p6, p0, Lmb/o;->f:Leb/h;

    .line 8
    iput-wide p7, p0, Lmb/o;->g:J

    .line 9
    iput-wide p9, p0, Lmb/o;->h:J

    move-wide p1, p11

    .line 10
    iput-wide p1, p0, Lmb/o;->i:J

    .line 11
    iput-object v0, p0, Lmb/o;->j:Leb/e;

    move/from16 p1, p14

    .line 12
    iput p1, p0, Lmb/o;->k:I

    .line 13
    iput-object v1, p0, Lmb/o;->l:Leb/a;

    move-wide/from16 p1, p16

    .line 14
    iput-wide p1, p0, Lmb/o;->m:J

    move-wide/from16 p1, p18

    .line 15
    iput-wide p1, p0, Lmb/o;->n:J

    move-wide/from16 p1, p20

    .line 16
    iput-wide p1, p0, Lmb/o;->o:J

    move-wide/from16 p1, p22

    .line 17
    iput-wide p1, p0, Lmb/o;->p:J

    move/from16 p1, p24

    .line 18
    iput-boolean p1, p0, Lmb/o;->q:Z

    .line 19
    iput-object v2, p0, Lmb/o;->r:Leb/e0;

    move/from16 p1, p26

    .line 20
    iput p1, p0, Lmb/o;->s:I

    move/from16 p1, p27

    .line 21
    iput p1, p0, Lmb/o;->t:I

    move-wide/from16 p1, p28

    .line 22
    iput-wide p1, p0, Lmb/o;->u:J

    move/from16 p1, p30

    .line 23
    iput p1, p0, Lmb/o;->v:I

    move/from16 p1, p31

    .line 24
    iput p1, p0, Lmb/o;->w:I

    move-object/from16 p1, p32

    .line 25
    iput-object p1, p0, Lmb/o;->x:Ljava/lang/String;

    move-object/from16 p1, p33

    .line 26
    iput-object p1, p0, Lmb/o;->y:Ljava/lang/Boolean;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IJIILjava/lang/String;Ljava/lang/Boolean;I)V
    .locals 36

    move/from16 v0, p33

    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_0

    .line 27
    sget-object v1, Leb/h0;->d:Leb/h0;

    move-object v4, v1

    goto :goto_0

    :cond_0
    move-object/from16 v4, p2

    :goto_0
    and-int/lit8 v1, v0, 0x8

    if-eqz v1, :cond_1

    .line 28
    const-class v1, Landroidx/work/OverwritingInputMerger;

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    move-object v6, v1

    goto :goto_1

    :cond_1
    move-object/from16 v6, p4

    :goto_1
    and-int/lit8 v1, v0, 0x10

    if-eqz v1, :cond_2

    .line 29
    sget-object v1, Leb/h;->b:Leb/h;

    move-object v7, v1

    goto :goto_2

    :cond_2
    move-object/from16 v7, p5

    :goto_2
    and-int/lit8 v1, v0, 0x20

    if-eqz v1, :cond_3

    .line 30
    sget-object v1, Leb/h;->b:Leb/h;

    move-object v8, v1

    goto :goto_3

    :cond_3
    move-object/from16 v8, p6

    :goto_3
    and-int/lit8 v1, v0, 0x40

    const-wide/16 v2, 0x0

    if-eqz v1, :cond_4

    move-wide v9, v2

    goto :goto_4

    :cond_4
    move-wide/from16 v9, p7

    :goto_4
    and-int/lit16 v1, v0, 0x80

    if-eqz v1, :cond_5

    move-wide v11, v2

    goto :goto_5

    :cond_5
    move-wide/from16 v11, p9

    :goto_5
    and-int/lit16 v1, v0, 0x100

    if-eqz v1, :cond_6

    move-wide v13, v2

    goto :goto_6

    :cond_6
    move-wide/from16 v13, p11

    :goto_6
    and-int/lit16 v1, v0, 0x200

    if-eqz v1, :cond_7

    .line 31
    sget-object v1, Leb/e;->j:Leb/e;

    move-object v15, v1

    goto :goto_7

    :cond_7
    move-object/from16 v15, p13

    :goto_7
    and-int/lit16 v1, v0, 0x400

    const/4 v5, 0x0

    if-eqz v1, :cond_8

    move/from16 v16, v5

    goto :goto_8

    :cond_8
    move/from16 v16, p14

    :goto_8
    and-int/lit16 v1, v0, 0x800

    if-eqz v1, :cond_9

    .line 32
    sget-object v1, Leb/a;->d:Leb/a;

    move-object/from16 v17, v1

    goto :goto_9

    :cond_9
    move-object/from16 v17, p15

    :goto_9
    and-int/lit16 v1, v0, 0x1000

    if-eqz v1, :cond_a

    const-wide/16 v18, 0x7530

    goto :goto_a

    :cond_a
    move-wide/from16 v18, p16

    :goto_a
    and-int/lit16 v1, v0, 0x2000

    const-wide/16 v20, -0x1

    if-eqz v1, :cond_b

    move-wide/from16 v22, v20

    goto :goto_b

    :cond_b
    move-wide/from16 v22, p18

    :goto_b
    and-int/lit16 v1, v0, 0x4000

    if-eqz v1, :cond_c

    goto :goto_c

    :cond_c
    move-wide/from16 v2, p20

    :goto_c
    const v1, 0x8000

    and-int/2addr v1, v0

    if-eqz v1, :cond_d

    move-wide/from16 v24, v20

    goto :goto_d

    :cond_d
    move-wide/from16 v24, p22

    :goto_d
    const/high16 v1, 0x10000

    and-int/2addr v1, v0

    if-eqz v1, :cond_e

    move/from16 v26, v5

    goto :goto_e

    :cond_e
    move/from16 v26, p24

    :goto_e
    const/high16 v1, 0x20000

    and-int/2addr v1, v0

    if-eqz v1, :cond_f

    .line 33
    sget-object v1, Leb/e0;->d:Leb/e0;

    move-object/from16 v27, v1

    goto :goto_f

    :cond_f
    move-object/from16 v27, p25

    :goto_f
    const/high16 v1, 0x40000

    and-int/2addr v1, v0

    if-eqz v1, :cond_10

    move/from16 v28, v5

    goto :goto_10

    :cond_10
    move/from16 v28, p26

    :goto_10
    const/high16 v1, 0x100000

    and-int/2addr v1, v0

    if-eqz v1, :cond_11

    const-wide v20, 0x7fffffffffffffffL

    move-wide/from16 v30, v20

    goto :goto_11

    :cond_11
    move-wide/from16 v30, p27

    :goto_11
    const/high16 v1, 0x200000

    and-int/2addr v1, v0

    if-eqz v1, :cond_12

    move/from16 v32, v5

    goto :goto_12

    :cond_12
    move/from16 v32, p29

    :goto_12
    const/high16 v1, 0x400000

    and-int/2addr v1, v0

    if-eqz v1, :cond_13

    const/16 v1, -0x100

    move/from16 v33, v1

    goto :goto_13

    :cond_13
    move/from16 v33, p30

    :goto_13
    const/high16 v1, 0x800000

    and-int/2addr v1, v0

    if-eqz v1, :cond_14

    const/4 v1, 0x0

    move-object/from16 v34, v1

    goto :goto_14

    :cond_14
    move-object/from16 v34, p31

    :goto_14
    const/high16 v1, 0x1000000

    and-int/2addr v0, v1

    if-eqz v0, :cond_15

    .line 34
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    move-object/from16 v35, v0

    goto :goto_15

    :cond_15
    move-object/from16 v35, p32

    :goto_15
    const/16 v29, 0x0

    move-object/from16 v5, p3

    move-wide/from16 v20, v22

    move-wide/from16 v22, v2

    move-object/from16 v2, p0

    move-object/from16 v3, p1

    .line 35
    invoke-direct/range {v2 .. v35}, Lmb/o;-><init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IIJIILjava/lang/String;Ljava/lang/Boolean;)V

    return-void
.end method


# virtual methods
.method public final a()J
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lmb/o;->b:Leb/h0;

    .line 4
    .line 5
    sget-object v2, Leb/h0;->d:Leb/h0;

    .line 6
    .line 7
    if-ne v1, v2, :cond_0

    .line 8
    .line 9
    iget v1, v0, Lmb/o;->k:I

    .line 10
    .line 11
    if-lez v1, :cond_0

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    :goto_0
    move v2, v1

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    const/4 v1, 0x0

    .line 17
    goto :goto_0

    .line 18
    :goto_1
    iget-wide v7, v0, Lmb/o;->n:J

    .line 19
    .line 20
    invoke-virtual {v0}, Lmb/o;->b()Z

    .line 21
    .line 22
    .line 23
    move-result v10

    .line 24
    iget-wide v11, v0, Lmb/o;->g:J

    .line 25
    .line 26
    iget-wide v13, v0, Lmb/o;->i:J

    .line 27
    .line 28
    iget-wide v3, v0, Lmb/o;->h:J

    .line 29
    .line 30
    iget-wide v5, v0, Lmb/o;->u:J

    .line 31
    .line 32
    move-wide v15, v3

    .line 33
    iget v3, v0, Lmb/o;->k:I

    .line 34
    .line 35
    iget-object v4, v0, Lmb/o;->l:Leb/a;

    .line 36
    .line 37
    move-wide/from16 v17, v5

    .line 38
    .line 39
    iget-wide v5, v0, Lmb/o;->m:J

    .line 40
    .line 41
    iget v9, v0, Lmb/o;->s:I

    .line 42
    .line 43
    invoke-static/range {v2 .. v18}, Ljp/x0;->a(ZILeb/a;JJIZJJJJ)J

    .line 44
    .line 45
    .line 46
    move-result-wide v0

    .line 47
    return-wide v0
.end method

.method public final b()Z
    .locals 4

    .line 1
    iget-wide v0, p0, Lmb/o;->h:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long p0, v0, v2

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lmb/o;

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
    check-cast p1, Lmb/o;

    .line 12
    .line 13
    iget-object v1, p0, Lmb/o;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lmb/o;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lmb/o;->b:Leb/h0;

    .line 25
    .line 26
    iget-object v3, p1, Lmb/o;->b:Leb/h0;

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lmb/o;->c:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lmb/o;->c:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lmb/o;->d:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v3, p1, Lmb/o;->d:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lmb/o;->e:Leb/h;

    .line 54
    .line 55
    iget-object v3, p1, Lmb/o;->e:Leb/h;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-object v1, p0, Lmb/o;->f:Leb/h;

    .line 65
    .line 66
    iget-object v3, p1, Lmb/o;->f:Leb/h;

    .line 67
    .line 68
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-wide v3, p0, Lmb/o;->g:J

    .line 76
    .line 77
    iget-wide v5, p1, Lmb/o;->g:J

    .line 78
    .line 79
    cmp-long v1, v3, v5

    .line 80
    .line 81
    if-eqz v1, :cond_8

    .line 82
    .line 83
    return v2

    .line 84
    :cond_8
    iget-wide v3, p0, Lmb/o;->h:J

    .line 85
    .line 86
    iget-wide v5, p1, Lmb/o;->h:J

    .line 87
    .line 88
    cmp-long v1, v3, v5

    .line 89
    .line 90
    if-eqz v1, :cond_9

    .line 91
    .line 92
    return v2

    .line 93
    :cond_9
    iget-wide v3, p0, Lmb/o;->i:J

    .line 94
    .line 95
    iget-wide v5, p1, Lmb/o;->i:J

    .line 96
    .line 97
    cmp-long v1, v3, v5

    .line 98
    .line 99
    if-eqz v1, :cond_a

    .line 100
    .line 101
    return v2

    .line 102
    :cond_a
    iget-object v1, p0, Lmb/o;->j:Leb/e;

    .line 103
    .line 104
    iget-object v3, p1, Lmb/o;->j:Leb/e;

    .line 105
    .line 106
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    if-nez v1, :cond_b

    .line 111
    .line 112
    return v2

    .line 113
    :cond_b
    iget v1, p0, Lmb/o;->k:I

    .line 114
    .line 115
    iget v3, p1, Lmb/o;->k:I

    .line 116
    .line 117
    if-eq v1, v3, :cond_c

    .line 118
    .line 119
    return v2

    .line 120
    :cond_c
    iget-object v1, p0, Lmb/o;->l:Leb/a;

    .line 121
    .line 122
    iget-object v3, p1, Lmb/o;->l:Leb/a;

    .line 123
    .line 124
    if-eq v1, v3, :cond_d

    .line 125
    .line 126
    return v2

    .line 127
    :cond_d
    iget-wide v3, p0, Lmb/o;->m:J

    .line 128
    .line 129
    iget-wide v5, p1, Lmb/o;->m:J

    .line 130
    .line 131
    cmp-long v1, v3, v5

    .line 132
    .line 133
    if-eqz v1, :cond_e

    .line 134
    .line 135
    return v2

    .line 136
    :cond_e
    iget-wide v3, p0, Lmb/o;->n:J

    .line 137
    .line 138
    iget-wide v5, p1, Lmb/o;->n:J

    .line 139
    .line 140
    cmp-long v1, v3, v5

    .line 141
    .line 142
    if-eqz v1, :cond_f

    .line 143
    .line 144
    return v2

    .line 145
    :cond_f
    iget-wide v3, p0, Lmb/o;->o:J

    .line 146
    .line 147
    iget-wide v5, p1, Lmb/o;->o:J

    .line 148
    .line 149
    cmp-long v1, v3, v5

    .line 150
    .line 151
    if-eqz v1, :cond_10

    .line 152
    .line 153
    return v2

    .line 154
    :cond_10
    iget-wide v3, p0, Lmb/o;->p:J

    .line 155
    .line 156
    iget-wide v5, p1, Lmb/o;->p:J

    .line 157
    .line 158
    cmp-long v1, v3, v5

    .line 159
    .line 160
    if-eqz v1, :cond_11

    .line 161
    .line 162
    return v2

    .line 163
    :cond_11
    iget-boolean v1, p0, Lmb/o;->q:Z

    .line 164
    .line 165
    iget-boolean v3, p1, Lmb/o;->q:Z

    .line 166
    .line 167
    if-eq v1, v3, :cond_12

    .line 168
    .line 169
    return v2

    .line 170
    :cond_12
    iget-object v1, p0, Lmb/o;->r:Leb/e0;

    .line 171
    .line 172
    iget-object v3, p1, Lmb/o;->r:Leb/e0;

    .line 173
    .line 174
    if-eq v1, v3, :cond_13

    .line 175
    .line 176
    return v2

    .line 177
    :cond_13
    iget v1, p0, Lmb/o;->s:I

    .line 178
    .line 179
    iget v3, p1, Lmb/o;->s:I

    .line 180
    .line 181
    if-eq v1, v3, :cond_14

    .line 182
    .line 183
    return v2

    .line 184
    :cond_14
    iget v1, p0, Lmb/o;->t:I

    .line 185
    .line 186
    iget v3, p1, Lmb/o;->t:I

    .line 187
    .line 188
    if-eq v1, v3, :cond_15

    .line 189
    .line 190
    return v2

    .line 191
    :cond_15
    iget-wide v3, p0, Lmb/o;->u:J

    .line 192
    .line 193
    iget-wide v5, p1, Lmb/o;->u:J

    .line 194
    .line 195
    cmp-long v1, v3, v5

    .line 196
    .line 197
    if-eqz v1, :cond_16

    .line 198
    .line 199
    return v2

    .line 200
    :cond_16
    iget v1, p0, Lmb/o;->v:I

    .line 201
    .line 202
    iget v3, p1, Lmb/o;->v:I

    .line 203
    .line 204
    if-eq v1, v3, :cond_17

    .line 205
    .line 206
    return v2

    .line 207
    :cond_17
    iget v1, p0, Lmb/o;->w:I

    .line 208
    .line 209
    iget v3, p1, Lmb/o;->w:I

    .line 210
    .line 211
    if-eq v1, v3, :cond_18

    .line 212
    .line 213
    return v2

    .line 214
    :cond_18
    iget-object v1, p0, Lmb/o;->x:Ljava/lang/String;

    .line 215
    .line 216
    iget-object v3, p1, Lmb/o;->x:Ljava/lang/String;

    .line 217
    .line 218
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 219
    .line 220
    .line 221
    move-result v1

    .line 222
    if-nez v1, :cond_19

    .line 223
    .line 224
    return v2

    .line 225
    :cond_19
    iget-object p0, p0, Lmb/o;->y:Ljava/lang/Boolean;

    .line 226
    .line 227
    iget-object p1, p1, Lmb/o;->y:Ljava/lang/Boolean;

    .line 228
    .line 229
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    move-result p0

    .line 233
    if-nez p0, :cond_1a

    .line 234
    .line 235
    return v2

    .line 236
    :cond_1a
    return v0
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    iget-object v0, p0, Lmb/o;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget-object v2, p0, Lmb/o;->b:Leb/h0;

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
    iget-object v0, p0, Lmb/o;->c:Ljava/lang/String;

    .line 19
    .line 20
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-object v2, p0, Lmb/o;->d:Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget-object v2, p0, Lmb/o;->e:Leb/h;

    .line 31
    .line 32
    invoke-virtual {v2}, Leb/h;->hashCode()I

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    add-int/2addr v2, v0

    .line 37
    mul-int/2addr v2, v1

    .line 38
    iget-object v0, p0, Lmb/o;->f:Leb/h;

    .line 39
    .line 40
    invoke-virtual {v0}, Leb/h;->hashCode()I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    add-int/2addr v0, v2

    .line 45
    mul-int/2addr v0, v1

    .line 46
    iget-wide v2, p0, Lmb/o;->g:J

    .line 47
    .line 48
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-wide v2, p0, Lmb/o;->h:J

    .line 53
    .line 54
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget-wide v2, p0, Lmb/o;->i:J

    .line 59
    .line 60
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    iget-object v2, p0, Lmb/o;->j:Leb/e;

    .line 65
    .line 66
    invoke-virtual {v2}, Leb/e;->hashCode()I

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    add-int/2addr v2, v0

    .line 71
    mul-int/2addr v2, v1

    .line 72
    iget v0, p0, Lmb/o;->k:I

    .line 73
    .line 74
    invoke-static {v0, v2, v1}, Lc1/j0;->g(III)I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    iget-object v2, p0, Lmb/o;->l:Leb/a;

    .line 79
    .line 80
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    add-int/2addr v2, v0

    .line 85
    mul-int/2addr v2, v1

    .line 86
    iget-wide v3, p0, Lmb/o;->m:J

    .line 87
    .line 88
    invoke-static {v3, v4, v2, v1}, La7/g0;->f(JII)I

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    iget-wide v2, p0, Lmb/o;->n:J

    .line 93
    .line 94
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    iget-wide v2, p0, Lmb/o;->o:J

    .line 99
    .line 100
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    iget-wide v2, p0, Lmb/o;->p:J

    .line 105
    .line 106
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 107
    .line 108
    .line 109
    move-result v0

    .line 110
    iget-boolean v2, p0, Lmb/o;->q:Z

    .line 111
    .line 112
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    iget-object v2, p0, Lmb/o;->r:Leb/e0;

    .line 117
    .line 118
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 119
    .line 120
    .line 121
    move-result v2

    .line 122
    add-int/2addr v2, v0

    .line 123
    mul-int/2addr v2, v1

    .line 124
    iget v0, p0, Lmb/o;->s:I

    .line 125
    .line 126
    invoke-static {v0, v2, v1}, Lc1/j0;->g(III)I

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    iget v2, p0, Lmb/o;->t:I

    .line 131
    .line 132
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    iget-wide v2, p0, Lmb/o;->u:J

    .line 137
    .line 138
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    iget v2, p0, Lmb/o;->v:I

    .line 143
    .line 144
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 145
    .line 146
    .line 147
    move-result v0

    .line 148
    iget v2, p0, Lmb/o;->w:I

    .line 149
    .line 150
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 151
    .line 152
    .line 153
    move-result v0

    .line 154
    iget-object v2, p0, Lmb/o;->x:Ljava/lang/String;

    .line 155
    .line 156
    const/4 v3, 0x0

    .line 157
    if-nez v2, :cond_0

    .line 158
    .line 159
    move v2, v3

    .line 160
    goto :goto_0

    .line 161
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 162
    .line 163
    .line 164
    move-result v2

    .line 165
    :goto_0
    add-int/2addr v0, v2

    .line 166
    mul-int/2addr v0, v1

    .line 167
    iget-object p0, p0, Lmb/o;->y:Ljava/lang/Boolean;

    .line 168
    .line 169
    if-nez p0, :cond_1

    .line 170
    .line 171
    goto :goto_1

    .line 172
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 173
    .line 174
    .line 175
    move-result v3

    .line 176
    :goto_1
    add-int/2addr v0, v3

    .line 177
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "{WorkSpec: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lmb/o;->a:Ljava/lang/String;

    .line 9
    .line 10
    const/16 v1, 0x7d

    .line 11
    .line 12
    invoke-static {v0, p0, v1}, La7/g0;->j(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
