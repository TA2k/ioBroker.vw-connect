.class public final Lm1/i;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lm1/h;

.field public final g:Lo1/d0;

.field public final h:J

.field public final synthetic i:Z

.field public final synthetic j:Lo1/d0;

.field public final synthetic k:I

.field public final synthetic l:I

.field public final synthetic m:Lx2/d;

.field public final synthetic n:Lx2/i;

.field public final synthetic o:I

.field public final synthetic p:I

.field public final synthetic q:J

.field public final synthetic r:Lm1/t;


# direct methods
.method public constructor <init>(JZLm1/h;Lo1/d0;IILx2/d;Lx2/i;IIJLm1/t;)V
    .locals 0

    .line 1
    iput-boolean p3, p0, Lm1/i;->i:Z

    .line 2
    .line 3
    iput-object p5, p0, Lm1/i;->j:Lo1/d0;

    .line 4
    .line 5
    iput p6, p0, Lm1/i;->k:I

    .line 6
    .line 7
    iput p7, p0, Lm1/i;->l:I

    .line 8
    .line 9
    iput-object p8, p0, Lm1/i;->m:Lx2/d;

    .line 10
    .line 11
    iput-object p9, p0, Lm1/i;->n:Lx2/i;

    .line 12
    .line 13
    iput p10, p0, Lm1/i;->o:I

    .line 14
    .line 15
    iput p11, p0, Lm1/i;->p:I

    .line 16
    .line 17
    iput-wide p12, p0, Lm1/i;->q:J

    .line 18
    .line 19
    iput-object p14, p0, Lm1/i;->r:Lm1/t;

    .line 20
    .line 21
    const/4 p6, 0x5

    .line 22
    invoke-direct {p0, p6}, Lap0/o;-><init>(I)V

    .line 23
    .line 24
    .line 25
    iput-object p4, p0, Lm1/i;->f:Lm1/h;

    .line 26
    .line 27
    iput-object p5, p0, Lm1/i;->g:Lo1/d0;

    .line 28
    .line 29
    const p4, 0x7fffffff

    .line 30
    .line 31
    .line 32
    if-eqz p3, :cond_0

    .line 33
    .line 34
    invoke-static {p1, p2}, Lt4/a;->h(J)I

    .line 35
    .line 36
    .line 37
    move-result p5

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move p5, p4

    .line 40
    :goto_0
    if-nez p3, :cond_1

    .line 41
    .line 42
    invoke-static {p1, p2}, Lt4/a;->g(J)I

    .line 43
    .line 44
    .line 45
    move-result p4

    .line 46
    :cond_1
    const/4 p1, 0x5

    .line 47
    invoke-static {p5, p4, p1}, Lt4/b;->b(III)J

    .line 48
    .line 49
    .line 50
    move-result-wide p1

    .line 51
    iput-wide p1, p0, Lm1/i;->h:J

    .line 52
    .line 53
    return-void
.end method


# virtual methods
.method public final B(JIII)Lo1/e0;
    .locals 0

    .line 1
    invoke-virtual {p0, p3, p1, p2}, Lm1/i;->b0(IJ)Lm1/m;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final b0(IJ)Lm1/m;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lm1/i;->f:Lm1/h;

    .line 6
    .line 7
    invoke-virtual {v2, v1}, Lm1/h;->d(I)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v12

    .line 11
    iget-object v2, v2, Lm1/h;->b:Lm1/f;

    .line 12
    .line 13
    invoke-virtual {v2, v1}, Lo1/y;->j(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v13

    .line 17
    iget-object v2, v0, Lm1/i;->g:Lo1/d0;

    .line 18
    .line 19
    move-wide/from16 v3, p2

    .line 20
    .line 21
    invoke-virtual {v0, v2, v1, v3, v4}, Lap0/o;->E(Lo1/d0;IJ)Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    iget v5, v0, Lm1/i;->k:I

    .line 26
    .line 27
    add-int/lit8 v5, v5, -0x1

    .line 28
    .line 29
    if-ne v1, v5, :cond_0

    .line 30
    .line 31
    const/4 v5, 0x0

    .line 32
    :goto_0
    move v9, v5

    .line 33
    goto :goto_1

    .line 34
    :cond_0
    iget v5, v0, Lm1/i;->l:I

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :goto_1
    new-instance v5, Lm1/m;

    .line 38
    .line 39
    iget-object v6, v0, Lm1/i;->j:Lo1/d0;

    .line 40
    .line 41
    iget-object v6, v6, Lo1/d0;->e:Lt3/p1;

    .line 42
    .line 43
    invoke-interface {v6}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    iget-object v7, v0, Lm1/i;->r:Lm1/t;

    .line 48
    .line 49
    iget-object v14, v7, Lm1/t;->n:Landroidx/compose/foundation/lazy/layout/b;

    .line 50
    .line 51
    iget-boolean v3, v0, Lm1/i;->i:Z

    .line 52
    .line 53
    iget-object v4, v0, Lm1/i;->m:Lx2/d;

    .line 54
    .line 55
    move-object v7, v5

    .line 56
    iget-object v5, v0, Lm1/i;->n:Lx2/i;

    .line 57
    .line 58
    move-object v8, v7

    .line 59
    iget v7, v0, Lm1/i;->o:I

    .line 60
    .line 61
    move-object v10, v8

    .line 62
    iget v8, v0, Lm1/i;->p:I

    .line 63
    .line 64
    iget-wide v0, v0, Lm1/i;->q:J

    .line 65
    .line 66
    move-wide v15, v0

    .line 67
    move-object v0, v10

    .line 68
    move-wide v10, v15

    .line 69
    move/from16 v1, p1

    .line 70
    .line 71
    move-wide/from16 v15, p2

    .line 72
    .line 73
    invoke-direct/range {v0 .. v16}, Lm1/m;-><init>(ILjava/util/List;ZLx2/d;Lx2/i;Lt4/m;IIIJLjava/lang/Object;Ljava/lang/Object;Landroidx/compose/foundation/lazy/layout/b;J)V

    .line 74
    .line 75
    .line 76
    return-object v0
.end method
