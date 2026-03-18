.class public final Lg3/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg3/d;


# instance fields
.field public final d:Lg3/a;

.field public final e:Lgw0/c;

.field public f:Le3/g;

.field public g:Le3/g;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lg3/a;

    .line 5
    .line 6
    sget-object v1, Lt4/m;->d:Lt4/m;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    sget-object v2, Lg3/c;->a:Lt4/d;

    .line 12
    .line 13
    iput-object v2, v0, Lg3/a;->a:Lt4/c;

    .line 14
    .line 15
    iput-object v1, v0, Lg3/a;->b:Lt4/m;

    .line 16
    .line 17
    sget-object v1, Lg3/f;->a:Lg3/f;

    .line 18
    .line 19
    iput-object v1, v0, Lg3/a;->c:Le3/r;

    .line 20
    .line 21
    const-wide/16 v1, 0x0

    .line 22
    .line 23
    iput-wide v1, v0, Lg3/a;->d:J

    .line 24
    .line 25
    iput-object v0, p0, Lg3/b;->d:Lg3/a;

    .line 26
    .line 27
    new-instance v0, Lgw0/c;

    .line 28
    .line 29
    invoke-direct {v0, p0}, Lgw0/c;-><init>(Lg3/b;)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Lg3/b;->e:Lgw0/c;

    .line 33
    .line 34
    return-void
.end method

.method public static b(Lg3/b;JLg3/e;FLe3/m;I)Le3/g;
    .locals 2

    .line 1
    invoke-virtual {p0, p3}, Lg3/b;->d(Lg3/e;)Le3/g;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p3, p0, Le3/g;->a:Landroid/graphics/Paint;

    .line 6
    .line 7
    const/high16 v0, 0x3f800000    # 1.0f

    .line 8
    .line 9
    cmpg-float v0, p4, v0

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-static {p1, p2}, Le3/s;->d(J)F

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    mul-float/2addr v0, p4

    .line 19
    invoke-static {p1, p2, v0}, Le3/s;->b(JF)J

    .line 20
    .line 21
    .line 22
    move-result-wide p1

    .line 23
    :goto_0
    invoke-virtual {p3}, Landroid/graphics/Paint;->getColor()I

    .line 24
    .line 25
    .line 26
    move-result p4

    .line 27
    invoke-static {p4}, Le3/j0;->c(I)J

    .line 28
    .line 29
    .line 30
    move-result-wide v0

    .line 31
    invoke-static {v0, v1, p1, p2}, Le3/s;->c(JJ)Z

    .line 32
    .line 33
    .line 34
    move-result p4

    .line 35
    if-nez p4, :cond_1

    .line 36
    .line 37
    invoke-virtual {p0, p1, p2}, Le3/g;->e(J)V

    .line 38
    .line 39
    .line 40
    :cond_1
    iget-object p1, p0, Le3/g;->c:Landroid/graphics/Shader;

    .line 41
    .line 42
    if-eqz p1, :cond_2

    .line 43
    .line 44
    const/4 p1, 0x0

    .line 45
    invoke-virtual {p0, p1}, Le3/g;->i(Landroid/graphics/Shader;)V

    .line 46
    .line 47
    .line 48
    :cond_2
    iget-object p1, p0, Le3/g;->d:Le3/m;

    .line 49
    .line 50
    invoke-static {p1, p5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    if-nez p1, :cond_3

    .line 55
    .line 56
    invoke-virtual {p0, p5}, Le3/g;->f(Le3/m;)V

    .line 57
    .line 58
    .line 59
    :cond_3
    iget p1, p0, Le3/g;->b:I

    .line 60
    .line 61
    if-ne p1, p6, :cond_4

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_4
    invoke-virtual {p0, p6}, Le3/g;->d(I)V

    .line 65
    .line 66
    .line 67
    :goto_1
    invoke-virtual {p3}, Landroid/graphics/Paint;->isFilterBitmap()Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    const/4 p2, 0x1

    .line 72
    if-ne p1, p2, :cond_5

    .line 73
    .line 74
    return-object p0

    .line 75
    :cond_5
    invoke-virtual {p0, p2}, Le3/g;->g(I)V

    .line 76
    .line 77
    .line 78
    return-object p0
.end method


# virtual methods
.method public final H(Le3/i;Le3/p;FLg3/e;I)V
    .locals 8

    .line 1
    iget-object v0, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v0, v0, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    const/4 v7, 0x1

    .line 6
    const/4 v5, 0x0

    .line 7
    move-object v1, p0

    .line 8
    move-object v2, p2

    .line 9
    move v4, p3

    .line 10
    move-object v3, p4

    .line 11
    move v6, p5

    .line 12
    invoke-virtual/range {v1 .. v7}, Lg3/b;->c(Le3/p;Lg3/e;FLe3/m;II)Le3/g;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-interface {v0, p1, p0}, Le3/r;->s(Le3/i;Le3/g;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public final M(JJJFLg3/e;Le3/m;I)V
    .locals 12

    .line 1
    iget-object v1, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v7, v1, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    const/16 v1, 0x20

    .line 6
    .line 7
    shr-long v2, p3, v1

    .line 8
    .line 9
    long-to-int v2, v2

    .line 10
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 11
    .line 12
    .line 13
    move-result v8

    .line 14
    const-wide v3, 0xffffffffL

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    and-long v5, p3, v3

    .line 20
    .line 21
    long-to-int v5, v5

    .line 22
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 23
    .line 24
    .line 25
    move-result v9

    .line 26
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    shr-long v10, p5, v1

    .line 31
    .line 32
    long-to-int v1, v10

    .line 33
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    add-float v10, v1, v2

    .line 38
    .line 39
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    and-long v2, p5, v3

    .line 44
    .line 45
    long-to-int v2, v2

    .line 46
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    add-float v11, v2, v1

    .line 51
    .line 52
    move-object v0, p0

    .line 53
    move-wide v1, p1

    .line 54
    move/from16 v4, p7

    .line 55
    .line 56
    move-object/from16 v3, p8

    .line 57
    .line 58
    move-object/from16 v5, p9

    .line 59
    .line 60
    move/from16 v6, p10

    .line 61
    .line 62
    invoke-static/range {v0 .. v6}, Lg3/b;->b(Lg3/b;JLg3/e;FLe3/m;I)Le3/g;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    move-object/from16 p5, v0

    .line 67
    .line 68
    move-object p0, v7

    .line 69
    move p1, v8

    .line 70
    move p2, v9

    .line 71
    move p3, v10

    .line 72
    move/from16 p4, v11

    .line 73
    .line 74
    invoke-interface/range {p0 .. p5}, Le3/r;->r(FFFFLe3/g;)V

    .line 75
    .line 76
    .line 77
    return-void
.end method

.method public final S(JFFJJFLg3/e;I)V
    .locals 12

    .line 1
    iget-object v1, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v7, v1, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    const/16 v1, 0x20

    .line 6
    .line 7
    shr-long v2, p5, v1

    .line 8
    .line 9
    long-to-int v2, v2

    .line 10
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 11
    .line 12
    .line 13
    move-result v8

    .line 14
    const-wide v3, 0xffffffffL

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    and-long v5, p5, v3

    .line 20
    .line 21
    long-to-int v5, v5

    .line 22
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 23
    .line 24
    .line 25
    move-result v9

    .line 26
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    shr-long v10, p7, v1

    .line 31
    .line 32
    long-to-int v1, v10

    .line 33
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    add-float v10, v1, v2

    .line 38
    .line 39
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    and-long v2, p7, v3

    .line 44
    .line 45
    long-to-int v2, v2

    .line 46
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    add-float v11, v2, v1

    .line 51
    .line 52
    const/4 v5, 0x0

    .line 53
    move-object v0, p0

    .line 54
    move-wide v1, p1

    .line 55
    move/from16 v4, p9

    .line 56
    .line 57
    move-object/from16 v3, p10

    .line 58
    .line 59
    move/from16 v6, p11

    .line 60
    .line 61
    invoke-static/range {v0 .. v6}, Lg3/b;->b(Lg3/b;JLg3/e;FLe3/m;I)Le3/g;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    move-object v2, v7

    .line 66
    move v3, v8

    .line 67
    move v4, v9

    .line 68
    move v5, v10

    .line 69
    move v6, v11

    .line 70
    move v7, p3

    .line 71
    move/from16 v8, p4

    .line 72
    .line 73
    move-object v9, v0

    .line 74
    invoke-interface/range {v2 .. v9}, Le3/r;->j(FFFFFFLe3/g;)V

    .line 75
    .line 76
    .line 77
    return-void
.end method

.method public final T(JJLg3/e;)V
    .locals 12

    .line 1
    iget-object v1, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v7, v1, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    const-wide/16 v1, 0x0

    .line 6
    .line 7
    long-to-int v3, v1

    .line 8
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 9
    .line 10
    .line 11
    move-result v8

    .line 12
    long-to-int v1, v1

    .line 13
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 14
    .line 15
    .line 16
    move-result v9

    .line 17
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/16 v3, 0x20

    .line 22
    .line 23
    shr-long v3, p3, v3

    .line 24
    .line 25
    long-to-int v3, v3

    .line 26
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    add-float v10, v3, v2

    .line 31
    .line 32
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    const-wide v2, 0xffffffffL

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    and-long/2addr v2, p3

    .line 42
    long-to-int v2, v2

    .line 43
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    add-float v11, v2, v1

    .line 48
    .line 49
    const/high16 v4, 0x3f800000    # 1.0f

    .line 50
    .line 51
    const/4 v5, 0x0

    .line 52
    const/4 v6, 0x3

    .line 53
    move-object v0, p0

    .line 54
    move-wide v1, p1

    .line 55
    move-object/from16 v3, p5

    .line 56
    .line 57
    invoke-static/range {v0 .. v6}, Lg3/b;->b(Lg3/b;JLg3/e;FLe3/m;I)Le3/g;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    move-object/from16 p5, v0

    .line 62
    .line 63
    move-object p0, v7

    .line 64
    move p1, v8

    .line 65
    move p2, v9

    .line 66
    move p3, v10

    .line 67
    move/from16 p4, v11

    .line 68
    .line 69
    invoke-interface/range {p0 .. p5}, Le3/r;->n(FFFFLe3/g;)V

    .line 70
    .line 71
    .line 72
    return-void
.end method

.method public final U(JJJJLg3/e;)V
    .locals 14

    .line 1
    iget-object v1, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v7, v1, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    const/16 v1, 0x20

    .line 6
    .line 7
    shr-long v2, p3, v1

    .line 8
    .line 9
    long-to-int v2, v2

    .line 10
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 11
    .line 12
    .line 13
    move-result v8

    .line 14
    const-wide v3, 0xffffffffL

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    and-long v5, p3, v3

    .line 20
    .line 21
    long-to-int v5, v5

    .line 22
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 23
    .line 24
    .line 25
    move-result v9

    .line 26
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    shr-long v10, p5, v1

    .line 31
    .line 32
    long-to-int v6, v10

    .line 33
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    add-float v10, v6, v2

    .line 38
    .line 39
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    and-long v5, p5, v3

    .line 44
    .line 45
    long-to-int v5, v5

    .line 46
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    add-float v11, v5, v2

    .line 51
    .line 52
    shr-long v1, p7, v1

    .line 53
    .line 54
    long-to-int v1, v1

    .line 55
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 56
    .line 57
    .line 58
    move-result v12

    .line 59
    and-long v1, p7, v3

    .line 60
    .line 61
    long-to-int v1, v1

    .line 62
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 63
    .line 64
    .line 65
    move-result v13

    .line 66
    const/high16 v4, 0x3f800000    # 1.0f

    .line 67
    .line 68
    const/4 v5, 0x0

    .line 69
    const/4 v6, 0x3

    .line 70
    move-object v0, p0

    .line 71
    move-wide v1, p1

    .line 72
    move-object/from16 v3, p9

    .line 73
    .line 74
    invoke-static/range {v0 .. v6}, Lg3/b;->b(Lg3/b;JLg3/e;FLe3/m;I)Le3/g;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    move-object/from16 p7, v0

    .line 79
    .line 80
    move-object p0, v7

    .line 81
    move p1, v8

    .line 82
    move/from16 p2, v9

    .line 83
    .line 84
    move/from16 p3, v10

    .line 85
    .line 86
    move/from16 p4, v11

    .line 87
    .line 88
    move/from16 p5, v12

    .line 89
    .line 90
    move/from16 p6, v13

    .line 91
    .line 92
    invoke-interface/range {p0 .. p7}, Le3/r;->b(FFFFFFLe3/g;)V

    .line 93
    .line 94
    .line 95
    return-void
.end method

.method public final W(Le3/f;JFLe3/m;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v0, v0, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v7, 0x1

    .line 7
    sget-object v3, Lg3/g;->a:Lg3/g;

    .line 8
    .line 9
    const/4 v6, 0x3

    .line 10
    move-object v1, p0

    .line 11
    move v4, p4

    .line 12
    move-object v5, p5

    .line 13
    invoke-virtual/range {v1 .. v7}, Lg3/b;->c(Le3/p;Lg3/e;FLe3/m;II)Le3/g;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-interface {v0, p1, p2, p3, p0}, Le3/r;->l(Le3/f;JLe3/g;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final Y(Le3/b0;FJJLg3/h;)V
    .locals 12

    .line 1
    iget-object v1, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v7, v1, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    const/16 v1, 0x20

    .line 6
    .line 7
    shr-long v2, p3, v1

    .line 8
    .line 9
    long-to-int v2, v2

    .line 10
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 11
    .line 12
    .line 13
    move-result v8

    .line 14
    const-wide v3, 0xffffffffL

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    and-long v5, p3, v3

    .line 20
    .line 21
    long-to-int v5, v5

    .line 22
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 23
    .line 24
    .line 25
    move-result v9

    .line 26
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    shr-long v10, p5, v1

    .line 31
    .line 32
    long-to-int v1, v10

    .line 33
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    add-float v10, v1, v2

    .line 38
    .line 39
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    and-long v2, p5, v3

    .line 44
    .line 45
    long-to-int v2, v2

    .line 46
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    add-float v11, v2, v1

    .line 51
    .line 52
    const/4 v6, 0x1

    .line 53
    const/high16 v3, 0x3f800000    # 1.0f

    .line 54
    .line 55
    const/4 v4, 0x0

    .line 56
    const/4 v5, 0x3

    .line 57
    move-object v0, p0

    .line 58
    move-object v1, p1

    .line 59
    move-object/from16 v2, p7

    .line 60
    .line 61
    invoke-virtual/range {v0 .. v6}, Lg3/b;->c(Le3/p;Lg3/e;FLe3/m;II)Le3/g;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    move-object v2, v7

    .line 66
    const/high16 v7, -0x3d4c0000    # -90.0f

    .line 67
    .line 68
    move v3, v8

    .line 69
    move v4, v9

    .line 70
    move v5, v10

    .line 71
    move v6, v11

    .line 72
    move v8, p2

    .line 73
    move-object v9, v0

    .line 74
    invoke-interface/range {v2 .. v9}, Le3/r;->j(FFFFFFLe3/g;)V

    .line 75
    .line 76
    .line 77
    return-void
.end method

.method public final a()F
    .locals 0

    .line 1
    iget-object p0, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object p0, p0, Lg3/a;->a:Lt4/c;

    .line 4
    .line 5
    invoke-interface {p0}, Lt4/c;->a()F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final c(Le3/p;Lg3/e;FLe3/m;II)Le3/g;
    .locals 3

    .line 1
    invoke-virtual {p0, p2}, Lg3/b;->d(Lg3/e;)Le3/g;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    iget-object v0, p2, Le3/g;->a:Landroid/graphics/Paint;

    .line 6
    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    invoke-interface {p0}, Lg3/d;->e()J

    .line 10
    .line 11
    .line 12
    move-result-wide v1

    .line 13
    invoke-virtual {p1, p3, v1, v2, p2}, Le3/p;->a(FJLe3/g;)V

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    iget-object p0, p2, Le3/g;->c:Landroid/graphics/Shader;

    .line 18
    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    const/4 p0, 0x0

    .line 22
    invoke-virtual {p2, p0}, Le3/g;->i(Landroid/graphics/Shader;)V

    .line 23
    .line 24
    .line 25
    :cond_1
    invoke-virtual {v0}, Landroid/graphics/Paint;->getColor()I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    invoke-static {p0}, Le3/j0;->c(I)J

    .line 30
    .line 31
    .line 32
    move-result-wide p0

    .line 33
    sget-wide v1, Le3/s;->b:J

    .line 34
    .line 35
    invoke-static {p0, p1, v1, v2}, Le3/s;->c(JJ)Z

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    if-nez p0, :cond_2

    .line 40
    .line 41
    invoke-virtual {p2, v1, v2}, Le3/g;->e(J)V

    .line 42
    .line 43
    .line 44
    :cond_2
    invoke-virtual {v0}, Landroid/graphics/Paint;->getAlpha()I

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    int-to-float p0, p0

    .line 49
    const/high16 p1, 0x437f0000    # 255.0f

    .line 50
    .line 51
    div-float/2addr p0, p1

    .line 52
    cmpg-float p0, p0, p3

    .line 53
    .line 54
    if-nez p0, :cond_3

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_3
    invoke-virtual {p2, p3}, Le3/g;->c(F)V

    .line 58
    .line 59
    .line 60
    :goto_0
    iget-object p0, p2, Le3/g;->d:Le3/m;

    .line 61
    .line 62
    invoke-static {p0, p4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    if-nez p0, :cond_4

    .line 67
    .line 68
    invoke-virtual {p2, p4}, Le3/g;->f(Le3/m;)V

    .line 69
    .line 70
    .line 71
    :cond_4
    iget p0, p2, Le3/g;->b:I

    .line 72
    .line 73
    if-ne p0, p5, :cond_5

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_5
    invoke-virtual {p2, p5}, Le3/g;->d(I)V

    .line 77
    .line 78
    .line 79
    :goto_1
    invoke-virtual {v0}, Landroid/graphics/Paint;->isFilterBitmap()Z

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    if-ne p0, p6, :cond_6

    .line 84
    .line 85
    return-object p2

    .line 86
    :cond_6
    invoke-virtual {p2, p6}, Le3/g;->g(I)V

    .line 87
    .line 88
    .line 89
    return-object p2
.end method

.method public final d(Lg3/e;)Le3/g;
    .locals 4

    .line 1
    sget-object v0, Lg3/g;->a:Lg3/g;

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    iget-object p1, p0, Lg3/b;->f:Le3/g;

    .line 10
    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    const/4 v0, 0x0

    .line 18
    invoke-virtual {p1, v0}, Le3/g;->m(I)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lg3/b;->f:Le3/g;

    .line 22
    .line 23
    :cond_0
    return-object p1

    .line 24
    :cond_1
    instance-of v0, p1, Lg3/h;

    .line 25
    .line 26
    if-eqz v0, :cond_8

    .line 27
    .line 28
    iget-object v0, p0, Lg3/b;->g:Le3/g;

    .line 29
    .line 30
    if-nez v0, :cond_2

    .line 31
    .line 32
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    const/4 v1, 0x1

    .line 37
    invoke-virtual {v0, v1}, Le3/g;->m(I)V

    .line 38
    .line 39
    .line 40
    iput-object v0, p0, Lg3/b;->g:Le3/g;

    .line 41
    .line 42
    :cond_2
    iget-object p0, v0, Le3/g;->a:Landroid/graphics/Paint;

    .line 43
    .line 44
    invoke-virtual {p0}, Landroid/graphics/Paint;->getStrokeWidth()F

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    check-cast p1, Lg3/h;

    .line 49
    .line 50
    iget-object v2, p1, Lg3/h;->e:Le3/j;

    .line 51
    .line 52
    iget v3, p1, Lg3/h;->a:F

    .line 53
    .line 54
    cmpg-float v1, v1, v3

    .line 55
    .line 56
    if-nez v1, :cond_3

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_3
    invoke-virtual {v0, v3}, Le3/g;->l(F)V

    .line 60
    .line 61
    .line 62
    :goto_0
    invoke-virtual {v0}, Le3/g;->a()I

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    iget v3, p1, Lg3/h;->c:I

    .line 67
    .line 68
    if-ne v1, v3, :cond_4

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_4
    invoke-virtual {v0, v3}, Le3/g;->j(I)V

    .line 72
    .line 73
    .line 74
    :goto_1
    invoke-virtual {p0}, Landroid/graphics/Paint;->getStrokeMiter()F

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    iget v3, p1, Lg3/h;->b:F

    .line 79
    .line 80
    cmpg-float v1, v1, v3

    .line 81
    .line 82
    if-nez v1, :cond_5

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_5
    invoke-virtual {p0, v3}, Landroid/graphics/Paint;->setStrokeMiter(F)V

    .line 86
    .line 87
    .line 88
    :goto_2
    invoke-virtual {v0}, Le3/g;->b()I

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    iget p1, p1, Lg3/h;->d:I

    .line 93
    .line 94
    if-ne p0, p1, :cond_6

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_6
    invoke-virtual {v0, p1}, Le3/g;->k(I)V

    .line 98
    .line 99
    .line 100
    :goto_3
    iget-object p0, v0, Le3/g;->e:Le3/j;

    .line 101
    .line 102
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result p0

    .line 106
    if-nez p0, :cond_7

    .line 107
    .line 108
    invoke-virtual {v0, v2}, Le3/g;->h(Le3/j;)V

    .line 109
    .line 110
    .line 111
    :cond_7
    return-object v0

    .line 112
    :cond_8
    new-instance p0, La8/r0;

    .line 113
    .line 114
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 115
    .line 116
    .line 117
    throw p0
.end method

.method public final f0(Le3/p;JJFLg3/e;I)V
    .locals 11

    .line 1
    iget-object v0, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v0, v0, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    const/16 v1, 0x20

    .line 6
    .line 7
    shr-long v2, p2, v1

    .line 8
    .line 9
    long-to-int v2, v2

    .line 10
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    const-wide v4, 0xffffffffL

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    and-long/2addr p2, v4

    .line 20
    long-to-int p2, p2

    .line 21
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 22
    .line 23
    .line 24
    move-result p3

    .line 25
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    shr-long v6, p4, v1

    .line 30
    .line 31
    long-to-int v1, v6

    .line 32
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    add-float/2addr v1, v2

    .line 37
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    and-long/2addr v4, p4

    .line 42
    long-to-int v2, v4

    .line 43
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    add-float/2addr v2, p2

    .line 48
    const/4 v10, 0x1

    .line 49
    const/4 v8, 0x0

    .line 50
    move-object v4, p0

    .line 51
    move-object v5, p1

    .line 52
    move/from16 v7, p6

    .line 53
    .line 54
    move-object/from16 v6, p7

    .line 55
    .line 56
    move/from16 v9, p8

    .line 57
    .line 58
    invoke-virtual/range {v4 .. v10}, Lg3/b;->c(Le3/p;Lg3/e;FLe3/m;II)Le3/g;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    move-object/from16 p5, p0

    .line 63
    .line 64
    move p2, p3

    .line 65
    move-object p0, v0

    .line 66
    move p3, v1

    .line 67
    move p4, v2

    .line 68
    move p1, v3

    .line 69
    invoke-interface/range {p0 .. p5}, Le3/r;->r(FFFFLe3/g;)V

    .line 70
    .line 71
    .line 72
    return-void
.end method

.method public final getLayoutDirection()Lt4/m;
    .locals 0

    .line 1
    iget-object p0, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object p0, p0, Lg3/a;->b:Lt4/m;

    .line 4
    .line 5
    return-object p0
.end method

.method public final j(JFJLg3/e;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v0, v0, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    const/high16 v5, 0x3f800000    # 1.0f

    .line 6
    .line 7
    const/4 v6, 0x0

    .line 8
    const/4 v7, 0x3

    .line 9
    move-object v1, p0

    .line 10
    move-wide v2, p1

    .line 11
    move-object v4, p6

    .line 12
    invoke-static/range {v1 .. v7}, Lg3/b;->b(Lg3/b;JLg3/e;FLe3/m;I)Le3/g;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-interface {v0, p3, p4, p5, p0}, Le3/r;->f(FJLe3/g;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public final k(Le3/f;JJJFLe3/m;I)V
    .locals 10

    .line 1
    iget-object v0, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v1, v0, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    const/4 v3, 0x0

    .line 6
    sget-object v4, Lg3/g;->a:Lg3/g;

    .line 7
    .line 8
    const/4 v7, 0x3

    .line 9
    move-object v2, p0

    .line 10
    move/from16 v5, p8

    .line 11
    .line 12
    move-object/from16 v6, p9

    .line 13
    .line 14
    move/from16 v8, p10

    .line 15
    .line 16
    invoke-virtual/range {v2 .. v8}, Lg3/b;->c(Le3/p;Lg3/e;FLe3/m;II)Le3/g;

    .line 17
    .line 18
    .line 19
    move-result-object v9

    .line 20
    move-object v2, p1

    .line 21
    move-wide v3, p2

    .line 22
    move-wide v5, p4

    .line 23
    move-wide/from16 v7, p6

    .line 24
    .line 25
    invoke-interface/range {v1 .. v9}, Le3/r;->u(Le3/f;JJJLe3/g;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final k0(Le3/p;JJJFLg3/e;)V
    .locals 14

    .line 1
    iget-object v1, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v7, v1, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    const/16 v1, 0x20

    .line 6
    .line 7
    shr-long v2, p2, v1

    .line 8
    .line 9
    long-to-int v2, v2

    .line 10
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 11
    .line 12
    .line 13
    move-result v8

    .line 14
    const-wide v3, 0xffffffffL

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    and-long v5, p2, v3

    .line 20
    .line 21
    long-to-int v5, v5

    .line 22
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 23
    .line 24
    .line 25
    move-result v9

    .line 26
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    shr-long v10, p4, v1

    .line 31
    .line 32
    long-to-int v6, v10

    .line 33
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    add-float v10, v6, v2

    .line 38
    .line 39
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    and-long v5, p4, v3

    .line 44
    .line 45
    long-to-int v5, v5

    .line 46
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    add-float v11, v5, v2

    .line 51
    .line 52
    shr-long v1, p6, v1

    .line 53
    .line 54
    long-to-int v1, v1

    .line 55
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 56
    .line 57
    .line 58
    move-result v12

    .line 59
    and-long v1, p6, v3

    .line 60
    .line 61
    long-to-int v1, v1

    .line 62
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 63
    .line 64
    .line 65
    move-result v13

    .line 66
    const/4 v6, 0x1

    .line 67
    const/4 v4, 0x0

    .line 68
    const/4 v5, 0x3

    .line 69
    move-object v0, p0

    .line 70
    move-object v1, p1

    .line 71
    move/from16 v3, p8

    .line 72
    .line 73
    move-object/from16 v2, p9

    .line 74
    .line 75
    invoke-virtual/range {v0 .. v6}, Lg3/b;->c(Le3/p;Lg3/e;FLe3/m;II)Le3/g;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    move-object/from16 p7, v0

    .line 80
    .line 81
    move-object p0, v7

    .line 82
    move p1, v8

    .line 83
    move/from16 p2, v9

    .line 84
    .line 85
    move/from16 p3, v10

    .line 86
    .line 87
    move/from16 p4, v11

    .line 88
    .line 89
    move/from16 p5, v12

    .line 90
    .line 91
    move/from16 p6, v13

    .line 92
    .line 93
    invoke-interface/range {p0 .. p7}, Le3/r;->b(FFFFFFLe3/g;)V

    .line 94
    .line 95
    .line 96
    return-void
.end method

.method public final r(Le3/p;JJFIFI)V
    .locals 6

    .line 1
    iget-object v0, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v0, v0, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    iget-object v1, p0, Lg3/b;->g:Le3/g;

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v1, v2}, Le3/g;->m(I)V

    .line 15
    .line 16
    .line 17
    iput-object v1, p0, Lg3/b;->g:Le3/g;

    .line 18
    .line 19
    :cond_0
    iget-object v3, v1, Le3/g;->a:Landroid/graphics/Paint;

    .line 20
    .line 21
    invoke-interface {p0}, Lg3/d;->e()J

    .line 22
    .line 23
    .line 24
    move-result-wide v4

    .line 25
    invoke-virtual {p1, p8, v4, v5, v1}, Le3/p;->a(FJLe3/g;)V

    .line 26
    .line 27
    .line 28
    iget-object p0, v1, Le3/g;->d:Le3/m;

    .line 29
    .line 30
    const/4 p1, 0x0

    .line 31
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    if-nez p0, :cond_1

    .line 36
    .line 37
    invoke-virtual {v1, p1}, Le3/g;->f(Le3/m;)V

    .line 38
    .line 39
    .line 40
    :cond_1
    iget p0, v1, Le3/g;->b:I

    .line 41
    .line 42
    if-ne p0, p9, :cond_2

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_2
    invoke-virtual {v1, p9}, Le3/g;->d(I)V

    .line 46
    .line 47
    .line 48
    :goto_0
    invoke-virtual {v3}, Landroid/graphics/Paint;->getStrokeWidth()F

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    cmpg-float p0, p0, p6

    .line 53
    .line 54
    if-nez p0, :cond_3

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-virtual {v1, p6}, Le3/g;->l(F)V

    .line 58
    .line 59
    .line 60
    :goto_1
    invoke-virtual {v3}, Landroid/graphics/Paint;->getStrokeMiter()F

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    const/high16 p6, 0x40800000    # 4.0f

    .line 65
    .line 66
    cmpg-float p0, p0, p6

    .line 67
    .line 68
    if-nez p0, :cond_4

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_4
    invoke-virtual {v3, p6}, Landroid/graphics/Paint;->setStrokeMiter(F)V

    .line 72
    .line 73
    .line 74
    :goto_2
    invoke-virtual {v1}, Le3/g;->a()I

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    if-ne p0, p7, :cond_5

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_5
    invoke-virtual {v1, p7}, Le3/g;->j(I)V

    .line 82
    .line 83
    .line 84
    :goto_3
    invoke-virtual {v1}, Le3/g;->b()I

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    if-nez p0, :cond_6

    .line 89
    .line 90
    goto :goto_4

    .line 91
    :cond_6
    const/4 p0, 0x0

    .line 92
    invoke-virtual {v1, p0}, Le3/g;->k(I)V

    .line 93
    .line 94
    .line 95
    :goto_4
    iget-object p0, v1, Le3/g;->e:Le3/j;

    .line 96
    .line 97
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    if-nez p0, :cond_7

    .line 102
    .line 103
    invoke-virtual {v1, p1}, Le3/g;->h(Le3/j;)V

    .line 104
    .line 105
    .line 106
    :cond_7
    invoke-virtual {v3}, Landroid/graphics/Paint;->isFilterBitmap()Z

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    if-ne p0, v2, :cond_8

    .line 111
    .line 112
    :goto_5
    move-wide p1, p2

    .line 113
    move-wide p3, p4

    .line 114
    move-object p0, v0

    .line 115
    move-object p5, v1

    .line 116
    goto :goto_6

    .line 117
    :cond_8
    invoke-virtual {v1, v2}, Le3/g;->g(I)V

    .line 118
    .line 119
    .line 120
    goto :goto_5

    .line 121
    :goto_6
    invoke-interface/range {p0 .. p5}, Le3/r;->c(JJLe3/g;)V

    .line 122
    .line 123
    .line 124
    return-void
.end method

.method public final s0(Le3/i;JFLg3/e;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v0, v0, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    const/4 v6, 0x0

    .line 6
    const/4 v7, 0x3

    .line 7
    move-object v1, p0

    .line 8
    move-wide v2, p2

    .line 9
    move v5, p4

    .line 10
    move-object v4, p5

    .line 11
    invoke-static/range {v1 .. v7}, Lg3/b;->b(Lg3/b;JLg3/e;FLe3/m;I)Le3/g;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-interface {v0, p1, p0}, Le3/r;->s(Le3/i;Le3/g;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final t0()F
    .locals 0

    .line 1
    iget-object p0, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object p0, p0, Lg3/a;->a:Lt4/c;

    .line 4
    .line 5
    invoke-interface {p0}, Lt4/c;->t0()F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final u(JJJFILe3/j;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lg3/b;->d:Lg3/a;

    .line 2
    .line 3
    iget-object v0, v0, Lg3/a;->c:Le3/r;

    .line 4
    .line 5
    iget-object v1, p0, Lg3/b;->g:Le3/g;

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v1, v2}, Le3/g;->m(I)V

    .line 15
    .line 16
    .line 17
    iput-object v1, p0, Lg3/b;->g:Le3/g;

    .line 18
    .line 19
    :cond_0
    iget-object p0, v1, Le3/g;->a:Landroid/graphics/Paint;

    .line 20
    .line 21
    invoke-virtual {p0}, Landroid/graphics/Paint;->getColor()I

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    invoke-static {v3}, Le3/j0;->c(I)J

    .line 26
    .line 27
    .line 28
    move-result-wide v3

    .line 29
    invoke-static {v3, v4, p1, p2}, Le3/s;->c(JJ)Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-nez v3, :cond_1

    .line 34
    .line 35
    invoke-virtual {v1, p1, p2}, Le3/g;->e(J)V

    .line 36
    .line 37
    .line 38
    :cond_1
    iget-object p1, v1, Le3/g;->c:Landroid/graphics/Shader;

    .line 39
    .line 40
    const/4 p2, 0x0

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    invoke-virtual {v1, p2}, Le3/g;->i(Landroid/graphics/Shader;)V

    .line 44
    .line 45
    .line 46
    :cond_2
    iget-object p1, v1, Le3/g;->d:Le3/m;

    .line 47
    .line 48
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    if-nez p1, :cond_3

    .line 53
    .line 54
    invoke-virtual {v1, p2}, Le3/g;->f(Le3/m;)V

    .line 55
    .line 56
    .line 57
    :cond_3
    iget p1, v1, Le3/g;->b:I

    .line 58
    .line 59
    const/4 p2, 0x3

    .line 60
    if-ne p1, p2, :cond_4

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_4
    invoke-virtual {v1, p2}, Le3/g;->d(I)V

    .line 64
    .line 65
    .line 66
    :goto_0
    invoke-virtual {p0}, Landroid/graphics/Paint;->getStrokeWidth()F

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    cmpg-float p1, p1, p7

    .line 71
    .line 72
    if-nez p1, :cond_5

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_5
    invoke-virtual {v1, p7}, Le3/g;->l(F)V

    .line 76
    .line 77
    .line 78
    :goto_1
    invoke-virtual {p0}, Landroid/graphics/Paint;->getStrokeMiter()F

    .line 79
    .line 80
    .line 81
    move-result p1

    .line 82
    const/high16 p2, 0x40800000    # 4.0f

    .line 83
    .line 84
    cmpg-float p1, p1, p2

    .line 85
    .line 86
    if-nez p1, :cond_6

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_6
    invoke-virtual {p0, p2}, Landroid/graphics/Paint;->setStrokeMiter(F)V

    .line 90
    .line 91
    .line 92
    :goto_2
    invoke-virtual {v1}, Le3/g;->a()I

    .line 93
    .line 94
    .line 95
    move-result p1

    .line 96
    if-ne p1, p8, :cond_7

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_7
    invoke-virtual {v1, p8}, Le3/g;->j(I)V

    .line 100
    .line 101
    .line 102
    :goto_3
    invoke-virtual {v1}, Le3/g;->b()I

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    if-nez p1, :cond_8

    .line 107
    .line 108
    goto :goto_4

    .line 109
    :cond_8
    const/4 p1, 0x0

    .line 110
    invoke-virtual {v1, p1}, Le3/g;->k(I)V

    .line 111
    .line 112
    .line 113
    :goto_4
    iget-object p1, v1, Le3/g;->e:Le3/j;

    .line 114
    .line 115
    invoke-static {p1, p9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result p1

    .line 119
    if-nez p1, :cond_9

    .line 120
    .line 121
    invoke-virtual {v1, p9}, Le3/g;->h(Le3/j;)V

    .line 122
    .line 123
    .line 124
    :cond_9
    invoke-virtual {p0}, Landroid/graphics/Paint;->isFilterBitmap()Z

    .line 125
    .line 126
    .line 127
    move-result p0

    .line 128
    if-ne p0, v2, :cond_a

    .line 129
    .line 130
    :goto_5
    move-wide p1, p3

    .line 131
    move-wide p3, p5

    .line 132
    move-object p0, v0

    .line 133
    move-object p5, v1

    .line 134
    goto :goto_6

    .line 135
    :cond_a
    invoke-virtual {v1, v2}, Le3/g;->g(I)V

    .line 136
    .line 137
    .line 138
    goto :goto_5

    .line 139
    :goto_6
    invoke-interface/range {p0 .. p5}, Le3/r;->c(JJLe3/g;)V

    .line 140
    .line 141
    .line 142
    return-void
.end method

.method public final x0()Lgw0/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lg3/b;->e:Lgw0/c;

    .line 2
    .line 3
    return-object p0
.end method
