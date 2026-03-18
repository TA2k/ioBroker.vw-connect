.class public final Le2/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lg4/g;

.field public final b:J

.field public final c:Lg4/l0;

.field public final d:Ll4/p;

.field public final e:Le2/c1;

.field public f:J

.field public final g:Lg4/g;

.field public final h:Ll4/v;

.field public final i:Lt1/j1;


# direct methods
.method public constructor <init>(Ll4/v;Ll4/p;Lt1/j1;Le2/c1;)V
    .locals 4

    .line 1
    iget-object v0, p1, Ll4/v;->a:Lg4/g;

    .line 2
    .line 3
    iget-wide v1, p1, Ll4/v;->b:J

    .line 4
    .line 5
    if-eqz p3, :cond_0

    .line 6
    .line 7
    iget-object v3, p3, Lt1/j1;->a:Lg4/l0;

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v3, 0x0

    .line 11
    :goto_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Le2/m0;->a:Lg4/g;

    .line 15
    .line 16
    iput-wide v1, p0, Le2/m0;->b:J

    .line 17
    .line 18
    iput-object v3, p0, Le2/m0;->c:Lg4/l0;

    .line 19
    .line 20
    iput-object p2, p0, Le2/m0;->d:Ll4/p;

    .line 21
    .line 22
    iput-object p4, p0, Le2/m0;->e:Le2/c1;

    .line 23
    .line 24
    iput-wide v1, p0, Le2/m0;->f:J

    .line 25
    .line 26
    iput-object v0, p0, Le2/m0;->g:Lg4/g;

    .line 27
    .line 28
    iput-object p1, p0, Le2/m0;->h:Ll4/v;

    .line 29
    .line 30
    iput-object p3, p0, Le2/m0;->i:Lt1/j1;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final a(Lay0/k;)Ljava/util/List;
    .locals 5

    .line 1
    iget-wide v0, p0, Le2/m0;->f:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lg4/o0;->c(J)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ll4/g;

    .line 14
    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return-object p0

    .line 24
    :cond_1
    new-instance p1, Ll4/a;

    .line 25
    .line 26
    const-string v0, ""

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    invoke-direct {p1, v0, v1}, Ll4/a;-><init>(Ljava/lang/String;I)V

    .line 30
    .line 31
    .line 32
    new-instance v0, Ll4/u;

    .line 33
    .line 34
    iget-wide v2, p0, Le2/m0;->f:J

    .line 35
    .line 36
    invoke-static {v2, v3}, Lg4/o0;->f(J)I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    iget-wide v3, p0, Le2/m0;->f:J

    .line 41
    .line 42
    invoke-static {v3, v4}, Lg4/o0;->f(J)I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    invoke-direct {v0, v2, p0}, Ll4/u;-><init>(II)V

    .line 47
    .line 48
    .line 49
    const/4 p0, 0x2

    .line 50
    new-array p0, p0, [Ll4/g;

    .line 51
    .line 52
    aput-object p1, p0, v1

    .line 53
    .line 54
    const/4 p1, 0x1

    .line 55
    aput-object v0, p0, p1

    .line 56
    .line 57
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0
.end method

.method public final b()Ljava/lang/Integer;
    .locals 3

    .line 1
    iget-object v0, p0, Le2/m0;->c:Lg4/l0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, v0, Lg4/l0;->b:Lg4/o;

    .line 6
    .line 7
    iget-wide v1, p0, Le2/m0;->f:J

    .line 8
    .line 9
    invoke-static {v1, v2}, Lg4/o0;->e(J)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    iget-object p0, p0, Le2/m0;->d:Ll4/p;

    .line 14
    .line 15
    invoke-interface {p0, v1}, Ll4/p;->R(I)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-virtual {v0, v1}, Lg4/o;->d(I)I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    const/4 v2, 0x1

    .line 24
    invoke-virtual {v0, v1, v2}, Lg4/o;->c(IZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    invoke-interface {p0, v0}, Ll4/p;->E(I)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :cond_0
    const/4 p0, 0x0

    .line 38
    return-object p0
.end method

.method public final c()Ljava/lang/Integer;
    .locals 3

    .line 1
    iget-object v0, p0, Le2/m0;->c:Lg4/l0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-wide v1, p0, Le2/m0;->f:J

    .line 6
    .line 7
    invoke-static {v1, v2}, Lg4/o0;->f(J)I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    iget-object p0, p0, Le2/m0;->d:Ll4/p;

    .line 12
    .line 13
    invoke-interface {p0, v1}, Ll4/p;->R(I)I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    iget-object v2, v0, Lg4/l0;->b:Lg4/o;

    .line 18
    .line 19
    invoke-virtual {v2, v1}, Lg4/o;->d(I)I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    invoke-virtual {v0, v1}, Lg4/l0;->g(I)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    invoke-interface {p0, v0}, Ll4/p;->E(I)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :cond_0
    const/4 p0, 0x0

    .line 37
    return-object p0
.end method

.method public final d()Ljava/lang/Integer;
    .locals 6

    .line 1
    iget-object v0, p0, Le2/m0;->c:Lg4/l0;

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    invoke-virtual {p0}, Le2/m0;->r()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    :goto_0
    iget-object v2, p0, Le2/m0;->a:Lg4/g;

    .line 10
    .line 11
    iget-object v3, v2, Lg4/g;->e:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    if-lt v1, v3, :cond_0

    .line 18
    .line 19
    iget-object p0, v2, Lg4/g;->e:Ljava/lang/String;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    goto :goto_2

    .line 26
    :cond_0
    iget-object v2, p0, Le2/m0;->g:Lg4/g;

    .line 27
    .line 28
    iget-object v2, v2, Lg4/g;->e:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    add-int/lit8 v2, v2, -0x1

    .line 35
    .line 36
    if-le v1, v2, :cond_1

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move v2, v1

    .line 40
    :goto_1
    invoke-virtual {v0, v2}, Lg4/l0;->j(I)J

    .line 41
    .line 42
    .line 43
    move-result-wide v2

    .line 44
    sget v4, Lg4/o0;->c:I

    .line 45
    .line 46
    const-wide v4, 0xffffffffL

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    and-long/2addr v2, v4

    .line 52
    long-to-int v2, v2

    .line 53
    if-gt v2, v1, :cond_2

    .line 54
    .line 55
    add-int/lit8 v1, v1, 0x1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    iget-object p0, p0, Le2/m0;->d:Ll4/p;

    .line 59
    .line 60
    invoke-interface {p0, v2}, Ll4/p;->E(I)I

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    :goto_2
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    return-object p0

    .line 69
    :cond_3
    const/4 p0, 0x0

    .line 70
    return-object p0
.end method

.method public final e()Ljava/lang/Integer;
    .locals 5

    .line 1
    iget-object v0, p0, Le2/m0;->c:Lg4/l0;

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    invoke-virtual {p0}, Le2/m0;->r()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    :goto_0
    if-gtz v1, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    goto :goto_2

    .line 13
    :cond_0
    iget-object v2, p0, Le2/m0;->g:Lg4/g;

    .line 14
    .line 15
    iget-object v2, v2, Lg4/g;->e:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    add-int/lit8 v2, v2, -0x1

    .line 22
    .line 23
    if-le v1, v2, :cond_1

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_1
    move v2, v1

    .line 27
    :goto_1
    invoke-virtual {v0, v2}, Lg4/l0;->j(I)J

    .line 28
    .line 29
    .line 30
    move-result-wide v2

    .line 31
    sget v4, Lg4/o0;->c:I

    .line 32
    .line 33
    const/16 v4, 0x20

    .line 34
    .line 35
    shr-long/2addr v2, v4

    .line 36
    long-to-int v2, v2

    .line 37
    if-lt v2, v1, :cond_2

    .line 38
    .line 39
    add-int/lit8 v1, v1, -0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    iget-object p0, p0, Le2/m0;->d:Ll4/p;

    .line 43
    .line 44
    invoke-interface {p0, v2}, Ll4/p;->E(I)I

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    :goto_2
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :cond_3
    const/4 p0, 0x0

    .line 54
    return-object p0
.end method

.method public final f()Z
    .locals 1

    .line 1
    iget-object v0, p0, Le2/m0;->c:Lg4/l0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Le2/m0;->r()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-virtual {v0, p0}, Lg4/l0;->h(I)Lr4/j;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    :goto_0
    sget-object v0, Lr4/j;->e:Lr4/j;

    .line 16
    .line 17
    if-eq p0, v0, :cond_1

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_1
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public final g(Lg4/l0;I)I
    .locals 6

    .line 1
    invoke-virtual {p0}, Le2/m0;->r()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Le2/m0;->e:Le2/c1;

    .line 6
    .line 7
    iget-object v2, v1, Le2/c1;->a:Ljava/lang/Float;

    .line 8
    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    invoke-virtual {p1, v0}, Lg4/l0;->c(I)Ld3/c;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    iget v2, v2, Ld3/c;->a:F

    .line 16
    .line 17
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    iput-object v2, v1, Le2/c1;->a:Ljava/lang/Float;

    .line 22
    .line 23
    :cond_0
    iget-object v2, p1, Lg4/l0;->b:Lg4/o;

    .line 24
    .line 25
    invoke-virtual {v2, v0}, Lg4/o;->d(I)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    add-int/2addr v0, p2

    .line 30
    if-gez v0, :cond_1

    .line 31
    .line 32
    const/4 p0, 0x0

    .line 33
    return p0

    .line 34
    :cond_1
    iget p2, v2, Lg4/o;->f:I

    .line 35
    .line 36
    if-lt v0, p2, :cond_2

    .line 37
    .line 38
    iget-object p0, p0, Le2/m0;->g:Lg4/g;

    .line 39
    .line 40
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 41
    .line 42
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    return p0

    .line 47
    :cond_2
    invoke-virtual {v2, v0}, Lg4/o;->b(I)F

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    const/4 v3, 0x1

    .line 52
    int-to-float v4, v3

    .line 53
    sub-float/2addr p2, v4

    .line 54
    iget-object v1, v1, Le2/c1;->a:Ljava/lang/Float;

    .line 55
    .line 56
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    invoke-virtual {p0}, Le2/m0;->f()Z

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    if-eqz v5, :cond_3

    .line 68
    .line 69
    invoke-virtual {p1, v0}, Lg4/l0;->f(I)F

    .line 70
    .line 71
    .line 72
    move-result v5

    .line 73
    cmpl-float v5, v4, v5

    .line 74
    .line 75
    if-gez v5, :cond_4

    .line 76
    .line 77
    :cond_3
    invoke-virtual {p0}, Le2/m0;->f()Z

    .line 78
    .line 79
    .line 80
    move-result v5

    .line 81
    if-nez v5, :cond_5

    .line 82
    .line 83
    invoke-virtual {p1, v0}, Lg4/l0;->e(I)F

    .line 84
    .line 85
    .line 86
    move-result p1

    .line 87
    cmpg-float p1, v4, p1

    .line 88
    .line 89
    if-gtz p1, :cond_5

    .line 90
    .line 91
    :cond_4
    invoke-virtual {v2, v0, v3}, Lg4/o;->c(IZ)I

    .line 92
    .line 93
    .line 94
    move-result p0

    .line 95
    return p0

    .line 96
    :cond_5
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 97
    .line 98
    .line 99
    move-result p1

    .line 100
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    int-to-long v0, p1

    .line 105
    invoke-static {p2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 106
    .line 107
    .line 108
    move-result p1

    .line 109
    int-to-long p1, p1

    .line 110
    const/16 v3, 0x20

    .line 111
    .line 112
    shl-long/2addr v0, v3

    .line 113
    const-wide v3, 0xffffffffL

    .line 114
    .line 115
    .line 116
    .line 117
    .line 118
    and-long/2addr p1, v3

    .line 119
    or-long/2addr p1, v0

    .line 120
    invoke-virtual {v2, p1, p2}, Lg4/o;->g(J)I

    .line 121
    .line 122
    .line 123
    move-result p1

    .line 124
    iget-object p0, p0, Le2/m0;->d:Ll4/p;

    .line 125
    .line 126
    invoke-interface {p0, p1}, Ll4/p;->E(I)I

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    return p0
.end method

.method public final h(Lt1/j1;I)I
    .locals 8

    .line 1
    iget-object v0, p1, Lt1/j1;->b:Lt3/y;

    .line 2
    .line 3
    iget-object v1, p1, Lt1/j1;->a:Lg4/l0;

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget-object p1, p1, Lt1/j1;->c:Lt3/y;

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    invoke-interface {p1, v0, v2}, Lt3/y;->P(Lt3/y;Z)Ld3/c;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p1, 0x0

    .line 18
    :goto_0
    if-nez p1, :cond_2

    .line 19
    .line 20
    :cond_1
    sget-object p1, Ld3/c;->e:Ld3/c;

    .line 21
    .line 22
    :cond_2
    iget-object v0, p0, Le2/m0;->h:Ll4/v;

    .line 23
    .line 24
    iget-wide v2, v0, Ll4/v;->b:J

    .line 25
    .line 26
    sget v0, Lg4/o0;->c:I

    .line 27
    .line 28
    const-wide v4, 0xffffffffL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    and-long/2addr v2, v4

    .line 34
    long-to-int v0, v2

    .line 35
    iget-object p0, p0, Le2/m0;->d:Ll4/p;

    .line 36
    .line 37
    invoke-interface {p0, v0}, Ll4/p;->R(I)I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    invoke-virtual {v1, v0}, Lg4/l0;->c(I)Ld3/c;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    iget v2, v0, Ld3/c;->a:F

    .line 46
    .line 47
    iget v0, v0, Ld3/c;->b:F

    .line 48
    .line 49
    invoke-virtual {p1}, Ld3/c;->c()J

    .line 50
    .line 51
    .line 52
    move-result-wide v6

    .line 53
    and-long/2addr v6, v4

    .line 54
    long-to-int p1, v6

    .line 55
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    int-to-float p2, p2

    .line 60
    mul-float/2addr p1, p2

    .line 61
    add-float/2addr p1, v0

    .line 62
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 63
    .line 64
    .line 65
    move-result p2

    .line 66
    int-to-long v2, p2

    .line 67
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    int-to-long p1, p1

    .line 72
    const/16 v0, 0x20

    .line 73
    .line 74
    shl-long/2addr v2, v0

    .line 75
    and-long/2addr p1, v4

    .line 76
    or-long/2addr p1, v2

    .line 77
    iget-object v0, v1, Lg4/l0;->b:Lg4/o;

    .line 78
    .line 79
    invoke-virtual {v0, p1, p2}, Lg4/o;->g(J)I

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    invoke-interface {p0, p1}, Ll4/p;->E(I)I

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    return p0
.end method

.method public final i()V
    .locals 5

    .line 1
    iget-object v0, p0, Le2/m0;->e:Le2/c1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput-object v1, v0, Le2/c1;->a:Ljava/lang/Float;

    .line 5
    .line 6
    iget-object v2, p0, Le2/m0;->g:Lg4/g;

    .line 7
    .line 8
    iget-object v3, v2, Lg4/g;->e:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    if-lez v3, :cond_1

    .line 15
    .line 16
    invoke-virtual {p0}, Le2/m0;->f()Z

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    if-eqz v3, :cond_0

    .line 21
    .line 22
    invoke-virtual {p0}, Le2/m0;->k()V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    iput-object v1, v0, Le2/c1;->a:Ljava/lang/Float;

    .line 27
    .line 28
    iget-object v0, v2, Lg4/g;->e:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-lez v0, :cond_1

    .line 35
    .line 36
    iget-object v0, v2, Lg4/g;->e:Ljava/lang/String;

    .line 37
    .line 38
    iget-wide v1, p0, Le2/m0;->f:J

    .line 39
    .line 40
    sget v3, Lg4/o0;->c:I

    .line 41
    .line 42
    const-wide v3, 0xffffffffL

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    and-long/2addr v1, v3

    .line 48
    long-to-int v1, v1

    .line 49
    invoke-static {v1, v0}, Lt1/l0;->q(ILjava/lang/String;)I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    const/4 v1, -0x1

    .line 54
    if-eq v0, v1, :cond_1

    .line 55
    .line 56
    invoke-virtual {p0, v0, v0}, Le2/m0;->q(II)V

    .line 57
    .line 58
    .line 59
    :cond_1
    return-void
.end method

.method public final j()V
    .locals 4

    .line 1
    iget-object v0, p0, Le2/m0;->e:Le2/c1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput-object v1, v0, Le2/c1;->a:Ljava/lang/Float;

    .line 5
    .line 6
    iget-object v0, p0, Le2/m0;->g:Lg4/g;

    .line 7
    .line 8
    iget-object v1, v0, Lg4/g;->e:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-lez v1, :cond_1

    .line 17
    .line 18
    iget-wide v1, p0, Le2/m0;->f:J

    .line 19
    .line 20
    invoke-static {v1, v2}, Lg4/o0;->e(J)I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-static {v1, v0}, Lt1/l0;->r(ILjava/lang/CharSequence;)I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    iget-wide v2, p0, Le2/m0;->f:J

    .line 29
    .line 30
    invoke-static {v2, v3}, Lg4/o0;->e(J)I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-ne v1, v2, :cond_0

    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eq v1, v2, :cond_0

    .line 41
    .line 42
    add-int/lit8 v1, v1, 0x1

    .line 43
    .line 44
    invoke-static {v1, v0}, Lt1/l0;->r(ILjava/lang/CharSequence;)I

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    :cond_0
    invoke-virtual {p0, v1, v1}, Le2/m0;->q(II)V

    .line 49
    .line 50
    .line 51
    :cond_1
    return-void
.end method

.method public final k()V
    .locals 5

    .line 1
    iget-object v0, p0, Le2/m0;->e:Le2/c1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput-object v1, v0, Le2/c1;->a:Ljava/lang/Float;

    .line 5
    .line 6
    iget-object v0, p0, Le2/m0;->g:Lg4/g;

    .line 7
    .line 8
    iget-object v1, v0, Lg4/g;->e:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-lez v1, :cond_0

    .line 15
    .line 16
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 17
    .line 18
    iget-wide v1, p0, Le2/m0;->f:J

    .line 19
    .line 20
    sget v3, Lg4/o0;->c:I

    .line 21
    .line 22
    const-wide v3, 0xffffffffL

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    and-long/2addr v1, v3

    .line 28
    long-to-int v1, v1

    .line 29
    invoke-static {v1, v0}, Lt1/l0;->t(ILjava/lang/String;)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    const/4 v1, -0x1

    .line 34
    if-eq v0, v1, :cond_0

    .line 35
    .line 36
    invoke-virtual {p0, v0, v0}, Le2/m0;->q(II)V

    .line 37
    .line 38
    .line 39
    :cond_0
    return-void
.end method

.method public final l()V
    .locals 4

    .line 1
    iget-object v0, p0, Le2/m0;->e:Le2/c1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput-object v1, v0, Le2/c1;->a:Ljava/lang/Float;

    .line 5
    .line 6
    iget-object v0, p0, Le2/m0;->g:Lg4/g;

    .line 7
    .line 8
    iget-object v1, v0, Lg4/g;->e:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-lez v1, :cond_1

    .line 17
    .line 18
    iget-wide v1, p0, Le2/m0;->f:J

    .line 19
    .line 20
    invoke-static {v1, v2}, Lg4/o0;->f(J)I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-static {v1, v0}, Lt1/l0;->s(ILjava/lang/CharSequence;)I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    iget-wide v2, p0, Le2/m0;->f:J

    .line 29
    .line 30
    invoke-static {v2, v3}, Lg4/o0;->f(J)I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-ne v1, v2, :cond_0

    .line 35
    .line 36
    if-eqz v1, :cond_0

    .line 37
    .line 38
    add-int/lit8 v1, v1, -0x1

    .line 39
    .line 40
    invoke-static {v1, v0}, Lt1/l0;->s(ILjava/lang/CharSequence;)I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    :cond_0
    invoke-virtual {p0, v1, v1}, Le2/m0;->q(II)V

    .line 45
    .line 46
    .line 47
    :cond_1
    return-void
.end method

.method public final m()V
    .locals 5

    .line 1
    iget-object v0, p0, Le2/m0;->e:Le2/c1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput-object v1, v0, Le2/c1;->a:Ljava/lang/Float;

    .line 5
    .line 6
    iget-object v2, p0, Le2/m0;->g:Lg4/g;

    .line 7
    .line 8
    iget-object v3, v2, Lg4/g;->e:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    if-lez v3, :cond_1

    .line 15
    .line 16
    invoke-virtual {p0}, Le2/m0;->f()Z

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    if-eqz v3, :cond_0

    .line 21
    .line 22
    iput-object v1, v0, Le2/c1;->a:Ljava/lang/Float;

    .line 23
    .line 24
    iget-object v0, v2, Lg4/g;->e:Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-lez v0, :cond_1

    .line 31
    .line 32
    iget-object v0, v2, Lg4/g;->e:Ljava/lang/String;

    .line 33
    .line 34
    iget-wide v1, p0, Le2/m0;->f:J

    .line 35
    .line 36
    sget v3, Lg4/o0;->c:I

    .line 37
    .line 38
    const-wide v3, 0xffffffffL

    .line 39
    .line 40
    .line 41
    .line 42
    .line 43
    and-long/2addr v1, v3

    .line 44
    long-to-int v1, v1

    .line 45
    invoke-static {v1, v0}, Lt1/l0;->q(ILjava/lang/String;)I

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    const/4 v1, -0x1

    .line 50
    if-eq v0, v1, :cond_1

    .line 51
    .line 52
    invoke-virtual {p0, v0, v0}, Le2/m0;->q(II)V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :cond_0
    invoke-virtual {p0}, Le2/m0;->k()V

    .line 57
    .line 58
    .line 59
    :cond_1
    return-void
.end method

.method public final n()V
    .locals 2

    .line 1
    iget-object v0, p0, Le2/m0;->e:Le2/c1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput-object v1, v0, Le2/c1;->a:Ljava/lang/Float;

    .line 5
    .line 6
    iget-object v0, p0, Le2/m0;->g:Lg4/g;

    .line 7
    .line 8
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-lez v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Le2/m0;->b()Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    invoke-virtual {p0, v0, v0}, Le2/m0;->q(II)V

    .line 27
    .line 28
    .line 29
    :cond_0
    return-void
.end method

.method public final o()V
    .locals 2

    .line 1
    iget-object v0, p0, Le2/m0;->e:Le2/c1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput-object v1, v0, Le2/c1;->a:Ljava/lang/Float;

    .line 5
    .line 6
    iget-object v0, p0, Le2/m0;->g:Lg4/g;

    .line 7
    .line 8
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-lez v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Le2/m0;->c()Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    invoke-virtual {p0, v0, v0}, Le2/m0;->q(II)V

    .line 27
    .line 28
    .line 29
    :cond_0
    return-void
.end method

.method public final p()V
    .locals 5

    .line 1
    iget-object v0, p0, Le2/m0;->g:Lg4/g;

    .line 2
    .line 3
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-lez v0, :cond_0

    .line 10
    .line 11
    sget v0, Lg4/o0;->c:I

    .line 12
    .line 13
    const/16 v0, 0x20

    .line 14
    .line 15
    iget-wide v1, p0, Le2/m0;->b:J

    .line 16
    .line 17
    shr-long v0, v1, v0

    .line 18
    .line 19
    long-to-int v0, v0

    .line 20
    iget-wide v1, p0, Le2/m0;->f:J

    .line 21
    .line 22
    const-wide v3, 0xffffffffL

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    and-long/2addr v1, v3

    .line 28
    long-to-int v1, v1

    .line 29
    invoke-static {v0, v1}, Lg4/f0;->b(II)J

    .line 30
    .line 31
    .line 32
    move-result-wide v0

    .line 33
    iput-wide v0, p0, Le2/m0;->f:J

    .line 34
    .line 35
    :cond_0
    return-void
.end method

.method public final q(II)V
    .locals 0

    .line 1
    invoke-static {p1, p2}, Lg4/f0;->b(II)J

    .line 2
    .line 3
    .line 4
    move-result-wide p1

    .line 5
    iput-wide p1, p0, Le2/m0;->f:J

    .line 6
    .line 7
    return-void
.end method

.method public final r()I
    .locals 4

    .line 1
    iget-wide v0, p0, Le2/m0;->f:J

    .line 2
    .line 3
    sget v2, Lg4/o0;->c:I

    .line 4
    .line 5
    const-wide v2, 0xffffffffL

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    and-long/2addr v0, v2

    .line 11
    long-to-int v0, v0

    .line 12
    iget-object p0, p0, Le2/m0;->d:Ll4/p;

    .line 13
    .line 14
    invoke-interface {p0, v0}, Ll4/p;->R(I)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method
