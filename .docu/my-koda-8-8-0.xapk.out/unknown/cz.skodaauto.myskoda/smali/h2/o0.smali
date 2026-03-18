.class public abstract Lh2/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lk1/a1;

.field public static final b:F

.field public static final c:F

.field public static final d:F


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    sget v0, Lk2/f;->a:F

    .line 2
    .line 3
    sget v1, Lk2/f;->b:F

    .line 4
    .line 5
    const/16 v2, 0x10

    .line 6
    .line 7
    int-to-float v2, v2

    .line 8
    sget v3, Lk2/g;->a:F

    .line 9
    .line 10
    const/16 v3, 0x8

    .line 11
    .line 12
    int-to-float v3, v3

    .line 13
    new-instance v4, Lk1/a1;

    .line 14
    .line 15
    invoke-direct {v4, v0, v3, v1, v3}, Lk1/a1;-><init>(FFFF)V

    .line 16
    .line 17
    .line 18
    invoke-static {v2, v3, v1, v3}, Landroidx/compose/foundation/layout/a;->b(FFFF)Lk1/a1;

    .line 19
    .line 20
    .line 21
    const/16 v0, 0xc

    .line 22
    .line 23
    int-to-float v0, v0

    .line 24
    new-instance v1, Lk1/a1;

    .line 25
    .line 26
    invoke-direct {v1, v0, v3, v0, v3}, Lk1/a1;-><init>(FFFF)V

    .line 27
    .line 28
    .line 29
    sput-object v1, Lh2/o0;->a:Lk1/a1;

    .line 30
    .line 31
    invoke-static {v0, v3, v2, v3}, Landroidx/compose/foundation/layout/a;->b(FFFF)Lk1/a1;

    .line 32
    .line 33
    .line 34
    const/16 v0, 0x3a

    .line 35
    .line 36
    int-to-float v0, v0

    .line 37
    sput v0, Lh2/o0;->b:F

    .line 38
    .line 39
    sget v0, Lk2/g;->a:F

    .line 40
    .line 41
    sput v0, Lh2/o0;->c:F

    .line 42
    .line 43
    sget v0, Lk2/g;->c:F

    .line 44
    .line 45
    sput v0, Lh2/o0;->d:F

    .line 46
    .line 47
    return-void
.end method

.method public static a(JJJJLl2/o;I)Lh2/n0;
    .locals 20

    .line 1
    and-int/lit8 v0, p9, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-wide v0, Le3/s;->i:J

    .line 6
    .line 7
    move-wide v5, v0

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move-wide/from16 v5, p2

    .line 10
    .line 11
    :goto_0
    and-int/lit8 v0, p9, 0x4

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    sget-wide v0, Le3/s;->i:J

    .line 16
    .line 17
    move-wide v7, v0

    .line 18
    goto :goto_1

    .line 19
    :cond_1
    move-wide/from16 v7, p4

    .line 20
    .line 21
    :goto_1
    and-int/lit8 v0, p9, 0x8

    .line 22
    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    sget-wide v0, Le3/s;->i:J

    .line 26
    .line 27
    move-wide v9, v0

    .line 28
    goto :goto_2

    .line 29
    :cond_2
    move-wide/from16 v9, p6

    .line 30
    .line 31
    :goto_2
    sget-object v0, Lh2/g1;->a:Ll2/u2;

    .line 32
    .line 33
    move-object/from16 v1, p8

    .line 34
    .line 35
    check-cast v1, Ll2/t;

    .line 36
    .line 37
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    check-cast v0, Lh2/f1;

    .line 42
    .line 43
    iget-object v1, v0, Lh2/f1;->W:Lh2/n0;

    .line 44
    .line 45
    if-nez v1, :cond_3

    .line 46
    .line 47
    new-instance v11, Lh2/n0;

    .line 48
    .line 49
    sget-object v1, Lk2/q;->a:Lk2/l;

    .line 50
    .line 51
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 52
    .line 53
    .line 54
    move-result-wide v12

    .line 55
    sget-object v1, Lk2/q;->j:Lk2/l;

    .line 56
    .line 57
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 58
    .line 59
    .line 60
    move-result-wide v14

    .line 61
    sget-object v1, Lk2/q;->c:Lk2/l;

    .line 62
    .line 63
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 64
    .line 65
    .line 66
    move-result-wide v1

    .line 67
    sget v3, Lk2/q;->e:F

    .line 68
    .line 69
    invoke-static {v1, v2, v3}, Le3/s;->b(JF)J

    .line 70
    .line 71
    .line 72
    move-result-wide v16

    .line 73
    sget-object v1, Lk2/q;->f:Lk2/l;

    .line 74
    .line 75
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 76
    .line 77
    .line 78
    move-result-wide v1

    .line 79
    sget v3, Lk2/q;->g:F

    .line 80
    .line 81
    invoke-static {v1, v2, v3}, Le3/s;->b(JF)J

    .line 82
    .line 83
    .line 84
    move-result-wide v18

    .line 85
    invoke-direct/range {v11 .. v19}, Lh2/n0;-><init>(JJJJ)V

    .line 86
    .line 87
    .line 88
    iput-object v11, v0, Lh2/f1;->W:Lh2/n0;

    .line 89
    .line 90
    move-object v2, v11

    .line 91
    :goto_3
    move-wide/from16 v3, p0

    .line 92
    .line 93
    goto :goto_4

    .line 94
    :cond_3
    move-object v2, v1

    .line 95
    goto :goto_3

    .line 96
    :goto_4
    invoke-virtual/range {v2 .. v10}, Lh2/n0;->a(JJJJ)Lh2/n0;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    return-object v0
.end method

.method public static b(FFFFFI)Lh2/q0;
    .locals 6

    .line 1
    and-int/lit8 v0, p5, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget p0, Lk2/q;->b:F

    .line 6
    .line 7
    :cond_0
    move v1, p0

    .line 8
    and-int/lit8 p0, p5, 0x2

    .line 9
    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    sget p1, Lk2/q;->k:F

    .line 13
    .line 14
    :cond_1
    move v2, p1

    .line 15
    and-int/lit8 p0, p5, 0x4

    .line 16
    .line 17
    if-eqz p0, :cond_2

    .line 18
    .line 19
    sget p2, Lk2/q;->h:F

    .line 20
    .line 21
    :cond_2
    move v3, p2

    .line 22
    and-int/lit8 p0, p5, 0x8

    .line 23
    .line 24
    if-eqz p0, :cond_3

    .line 25
    .line 26
    sget p3, Lk2/q;->i:F

    .line 27
    .line 28
    :cond_3
    move v4, p3

    .line 29
    and-int/lit8 p0, p5, 0x10

    .line 30
    .line 31
    if-eqz p0, :cond_4

    .line 32
    .line 33
    sget p4, Lk2/q;->d:F

    .line 34
    .line 35
    :cond_4
    move v5, p4

    .line 36
    new-instance v0, Lh2/q0;

    .line 37
    .line 38
    invoke-direct/range {v0 .. v5}, Lh2/q0;-><init>(FFFFF)V

    .line 39
    .line 40
    .line 41
    return-object v0
.end method

.method public static c(Lh2/f1;)Lh2/n0;
    .locals 10

    .line 1
    iget-object v0, p0, Lh2/f1;->X:Lh2/n0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v1, Lh2/n0;

    .line 6
    .line 7
    sget-wide v2, Le3/s;->h:J

    .line 8
    .line 9
    sget-object v0, Lk2/l;->n:Lk2/l;

    .line 10
    .line 11
    invoke-static {p0, v0}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 12
    .line 13
    .line 14
    move-result-wide v4

    .line 15
    sget-object v0, Lk2/m0;->a:Lk2/l;

    .line 16
    .line 17
    invoke-static {p0, v0}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 18
    .line 19
    .line 20
    move-result-wide v6

    .line 21
    sget v0, Lk2/m0;->b:F

    .line 22
    .line 23
    invoke-static {v6, v7, v0}, Le3/s;->b(JF)J

    .line 24
    .line 25
    .line 26
    move-result-wide v8

    .line 27
    move-wide v6, v2

    .line 28
    invoke-direct/range {v1 .. v9}, Lh2/n0;-><init>(JJJJ)V

    .line 29
    .line 30
    .line 31
    iput-object v1, p0, Lh2/f1;->X:Lh2/n0;

    .line 32
    .line 33
    return-object v1

    .line 34
    :cond_0
    return-object v0
.end method

.method public static d(JLl2/o;)Lh2/n0;
    .locals 9

    .line 1
    sget-wide v1, Le3/s;->i:J

    .line 2
    .line 3
    sget-object v0, Lh2/g1;->a:Ll2/u2;

    .line 4
    .line 5
    check-cast p2, Ll2/t;

    .line 6
    .line 7
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    check-cast p2, Lh2/f1;

    .line 12
    .line 13
    invoke-static {p2}, Lh2/o0;->c(Lh2/f1;)Lh2/n0;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    move-wide v5, v1

    .line 18
    move-wide v7, v1

    .line 19
    move-wide v3, p0

    .line 20
    invoke-virtual/range {v0 .. v8}, Lh2/n0;->a(JJJJ)Lh2/n0;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method
