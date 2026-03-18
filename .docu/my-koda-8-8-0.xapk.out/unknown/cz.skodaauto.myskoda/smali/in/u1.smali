.class public final Lin/u1;
.super Lin/v1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Landroid/graphics/Path;

.field public final synthetic e:Lin/z1;


# direct methods
.method public constructor <init>(Lin/z1;Landroid/graphics/Path;F)V
    .locals 1

    .line 1
    iput-object p1, p0, Lin/u1;->e:Lin/z1;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-direct {p0, p1, p3, v0}, Lin/v1;-><init>(Lin/z1;FF)V

    .line 5
    .line 6
    .line 7
    iput-object p2, p0, Lin/u1;->d:Landroid/graphics/Path;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final d(Ljava/lang/String;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lin/u1;->e:Lin/z1;

    .line 4
    .line 5
    invoke-virtual {v1}, Lin/z1;->m0()Z

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    if-eqz v2, :cond_1

    .line 10
    .line 11
    iget-object v2, v1, Lin/z1;->c:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v2, Lin/x1;

    .line 14
    .line 15
    iget-boolean v3, v2, Lin/x1;->b:Z

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    iget-object v3, v1, Lin/z1;->a:Ljava/lang/Object;

    .line 20
    .line 21
    move-object v4, v3

    .line 22
    check-cast v4, Landroid/graphics/Canvas;

    .line 23
    .line 24
    iget v7, v0, Lin/v1;->a:F

    .line 25
    .line 26
    iget v8, v0, Lin/v1;->b:F

    .line 27
    .line 28
    iget-object v9, v2, Lin/x1;->d:Landroid/graphics/Paint;

    .line 29
    .line 30
    iget-object v6, v0, Lin/u1;->d:Landroid/graphics/Path;

    .line 31
    .line 32
    move-object/from16 v5, p1

    .line 33
    .line 34
    invoke-virtual/range {v4 .. v9}, Landroid/graphics/Canvas;->drawTextOnPath(Ljava/lang/String;Landroid/graphics/Path;FFLandroid/graphics/Paint;)V

    .line 35
    .line 36
    .line 37
    :cond_0
    iget-object v2, v1, Lin/z1;->c:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v2, Lin/x1;

    .line 40
    .line 41
    iget-boolean v3, v2, Lin/x1;->c:Z

    .line 42
    .line 43
    if-eqz v3, :cond_1

    .line 44
    .line 45
    iget-object v3, v1, Lin/z1;->a:Ljava/lang/Object;

    .line 46
    .line 47
    move-object v10, v3

    .line 48
    check-cast v10, Landroid/graphics/Canvas;

    .line 49
    .line 50
    iget v13, v0, Lin/v1;->a:F

    .line 51
    .line 52
    iget v14, v0, Lin/v1;->b:F

    .line 53
    .line 54
    iget-object v15, v2, Lin/x1;->e:Landroid/graphics/Paint;

    .line 55
    .line 56
    iget-object v12, v0, Lin/u1;->d:Landroid/graphics/Path;

    .line 57
    .line 58
    move-object/from16 v11, p1

    .line 59
    .line 60
    invoke-virtual/range {v10 .. v15}, Landroid/graphics/Canvas;->drawTextOnPath(Ljava/lang/String;Landroid/graphics/Path;FFLandroid/graphics/Paint;)V

    .line 61
    .line 62
    .line 63
    :cond_1
    iget v2, v0, Lin/v1;->a:F

    .line 64
    .line 65
    iget-object v1, v1, Lin/z1;->c:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v1, Lin/x1;

    .line 68
    .line 69
    iget-object v1, v1, Lin/x1;->d:Landroid/graphics/Paint;

    .line 70
    .line 71
    move-object/from16 v5, p1

    .line 72
    .line 73
    invoke-virtual {v1, v5}, Landroid/graphics/Paint;->measureText(Ljava/lang/String;)F

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    add-float/2addr v1, v2

    .line 78
    iput v1, v0, Lin/v1;->a:F

    .line 79
    .line 80
    return-void
.end method
