.class public final Ln1/k;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Ln1/h;

.field public final g:Lo1/d0;

.field public final h:I

.field public final synthetic i:Lo1/d0;

.field public final synthetic j:Ln1/v;

.field public final synthetic k:I

.field public final synthetic l:I

.field public final synthetic m:J


# direct methods
.method public constructor <init>(Ln1/h;Lo1/d0;ILn1/v;IIJ)V
    .locals 0

    .line 1
    iput-object p2, p0, Ln1/k;->i:Lo1/d0;

    .line 2
    .line 3
    iput-object p4, p0, Ln1/k;->j:Ln1/v;

    .line 4
    .line 5
    iput p5, p0, Ln1/k;->k:I

    .line 6
    .line 7
    iput p6, p0, Ln1/k;->l:I

    .line 8
    .line 9
    iput-wide p7, p0, Ln1/k;->m:J

    .line 10
    .line 11
    const/4 p4, 0x5

    .line 12
    invoke-direct {p0, p4}, Lap0/o;-><init>(I)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Ln1/k;->f:Ln1/h;

    .line 16
    .line 17
    iput-object p2, p0, Ln1/k;->g:Lo1/d0;

    .line 18
    .line 19
    iput p3, p0, Ln1/k;->h:I

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final B(JIII)Lo1/e0;
    .locals 7

    .line 1
    iget v6, p0, Ln1/k;->h:I

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    move-wide v1, p1

    .line 5
    move v3, p3

    .line 6
    move v4, p4

    .line 7
    move v5, p5

    .line 8
    invoke-virtual/range {v0 .. v6}, Ln1/k;->b0(JIIII)Ln1/o;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public final b0(JIIII)Ln1/o;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p3

    .line 4
    .line 5
    iget-object v2, v0, Ln1/k;->f:Ln1/h;

    .line 6
    .line 7
    invoke-virtual {v2, v1}, Ln1/h;->d(I)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    iget-object v2, v2, Ln1/h;->b:Ln1/g;

    .line 12
    .line 13
    invoke-virtual {v2, v1}, Lo1/y;->j(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v11

    .line 17
    iget-object v2, v0, Ln1/k;->g:Lo1/d0;

    .line 18
    .line 19
    move-wide/from16 v13, p1

    .line 20
    .line 21
    invoke-virtual {v0, v2, v1, v13, v14}, Lap0/o;->E(Lo1/d0;IJ)Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object v8

    .line 25
    invoke-static {v13, v14}, Lt4/a;->f(J)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-eqz v2, :cond_0

    .line 30
    .line 31
    invoke-static {v13, v14}, Lt4/a;->j(J)I

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    invoke-static {v13, v14}, Lt4/a;->e(J)Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-nez v2, :cond_1

    .line 41
    .line 42
    const-string v2, "does not have fixed height"

    .line 43
    .line 44
    invoke-static {v2}, Lj1/b;->a(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    :cond_1
    invoke-static {v13, v14}, Lt4/a;->i(J)I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    :goto_0
    iget-object v4, v0, Ln1/k;->i:Lo1/d0;

    .line 52
    .line 53
    iget-object v4, v4, Lo1/d0;->e:Lt3/p1;

    .line 54
    .line 55
    invoke-interface {v4}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    iget-object v4, v0, Ln1/k;->j:Ln1/v;

    .line 60
    .line 61
    iget-object v12, v4, Ln1/v;->m:Landroidx/compose/foundation/lazy/layout/b;

    .line 62
    .line 63
    new-instance v4, Ln1/o;

    .line 64
    .line 65
    iget v7, v0, Ln1/k;->l:I

    .line 66
    .line 67
    iget-wide v9, v0, Ln1/k;->m:J

    .line 68
    .line 69
    iget v6, v0, Ln1/k;->k:I

    .line 70
    .line 71
    move-object v0, v3

    .line 72
    move v3, v2

    .line 73
    move-object v2, v0

    .line 74
    move/from16 v15, p4

    .line 75
    .line 76
    move/from16 v16, p5

    .line 77
    .line 78
    move-object v0, v4

    .line 79
    move/from16 v4, p6

    .line 80
    .line 81
    invoke-direct/range {v0 .. v16}, Ln1/o;-><init>(ILjava/lang/Object;IILt4/m;IILjava/util/List;JLjava/lang/Object;Landroidx/compose/foundation/lazy/layout/b;JII)V

    .line 82
    .line 83
    .line 84
    return-object v0
.end method
