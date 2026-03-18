.class public final Luj/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzb/j;


# static fields
.field public static final a:Luj/e;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Luj/e;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Luj/e;->a:Luj/e;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final E0(Llc/q;Lay0/a;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "retry"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, 0x110ef81d

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p4, 0x8

    .line 20
    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    :goto_0
    if-eqz v0, :cond_1

    .line 33
    .line 34
    const/4 v0, 0x4

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/4 v0, 0x2

    .line 37
    :goto_1
    or-int/2addr v0, p4

    .line 38
    and-int/lit8 v1, p4, 0x30

    .line 39
    .line 40
    if-nez v1, :cond_3

    .line 41
    .line 42
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_2

    .line 47
    .line 48
    const/16 v1, 0x20

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/16 v1, 0x10

    .line 52
    .line 53
    :goto_2
    or-int/2addr v0, v1

    .line 54
    :cond_3
    and-int/lit8 v1, v0, 0x13

    .line 55
    .line 56
    const/16 v2, 0x12

    .line 57
    .line 58
    if-eq v1, v2, :cond_4

    .line 59
    .line 60
    const/4 v1, 0x1

    .line 61
    goto :goto_3

    .line 62
    :cond_4
    const/4 v1, 0x0

    .line 63
    :goto_3
    and-int/lit8 v2, v0, 0x1

    .line 64
    .line 65
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-eqz v1, :cond_5

    .line 70
    .line 71
    and-int/lit8 v1, v0, 0xe

    .line 72
    .line 73
    const/16 v2, 0x8

    .line 74
    .line 75
    or-int/2addr v1, v2

    .line 76
    and-int/lit8 v0, v0, 0x70

    .line 77
    .line 78
    or-int/2addr v0, v1

    .line 79
    invoke-static {p1, p2, p3, v0}, Lhk/a;->a(Llc/q;Lay0/a;Ll2/o;I)V

    .line 80
    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_5
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 84
    .line 85
    .line 86
    :goto_4
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 87
    .line 88
    .line 89
    move-result-object p3

    .line 90
    if-eqz p3, :cond_6

    .line 91
    .line 92
    new-instance v0, Lph/a;

    .line 93
    .line 94
    const/16 v5, 0x10

    .line 95
    .line 96
    move-object v1, p0

    .line 97
    move-object v2, p1

    .line 98
    move-object v3, p2

    .line 99
    move v4, p4

    .line 100
    invoke-direct/range {v0 .. v5}, Lph/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Lay0/a;II)V

    .line 101
    .line 102
    .line 103
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 104
    .line 105
    :cond_6
    return-void
.end method

.method public final l(ZLt2/b;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, -0x205d2849

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p4, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p3, p1}, Ll2/t;->h(Z)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int/2addr v0, p4

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v0, p4

    .line 25
    :goto_1
    and-int/lit8 v1, v0, 0x13

    .line 26
    .line 27
    const/16 v2, 0x12

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    if-eq v1, v2, :cond_2

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    move v1, v3

    .line 35
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 36
    .line 37
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_3

    .line 42
    .line 43
    and-int/lit8 v0, v0, 0x7e

    .line 44
    .line 45
    invoke-static {p1, p2, p3, v0, v3}, Llp/pb;->b(ZLt2/b;Ll2/o;II)V

    .line 46
    .line 47
    .line 48
    goto :goto_3

    .line 49
    :cond_3
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 50
    .line 51
    .line 52
    :goto_3
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 53
    .line 54
    .line 55
    move-result-object p3

    .line 56
    if-eqz p3, :cond_4

    .line 57
    .line 58
    new-instance v0, Le2/x0;

    .line 59
    .line 60
    const/16 v5, 0xc

    .line 61
    .line 62
    move-object v1, p0

    .line 63
    move v2, p1

    .line 64
    move-object v3, p2

    .line 65
    move v4, p4

    .line 66
    invoke-direct/range {v0 .. v5}, Le2/x0;-><init>(Ljava/lang/Object;ZLjava/lang/Object;II)V

    .line 67
    .line 68
    .line 69
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 70
    .line 71
    :cond_4
    return-void
.end method

.method public final o(Lmc/r;Llc/q;Lay0/k;Ll2/o;I)V
    .locals 7

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "event"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p4, Ll2/t;

    .line 12
    .line 13
    const v0, 0x4c050912    # 3.487444E7f

    .line 14
    .line 15
    .line 16
    invoke-virtual {p4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    invoke-virtual {p4, v0}, Ll2/t;->e(I)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, p5

    .line 33
    and-int/lit8 v1, p5, 0x40

    .line 34
    .line 35
    if-nez v1, :cond_1

    .line 36
    .line 37
    invoke-virtual {p4, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    invoke-virtual {p4, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    :goto_1
    if-eqz v1, :cond_2

    .line 47
    .line 48
    const/16 v1, 0x20

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/16 v1, 0x10

    .line 52
    .line 53
    :goto_2
    or-int/2addr v0, v1

    .line 54
    invoke-virtual {p4, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-eqz v1, :cond_3

    .line 59
    .line 60
    const/16 v1, 0x100

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    const/16 v1, 0x80

    .line 64
    .line 65
    :goto_3
    or-int/2addr v0, v1

    .line 66
    and-int/lit16 v1, v0, 0x93

    .line 67
    .line 68
    const/16 v2, 0x92

    .line 69
    .line 70
    if-eq v1, v2, :cond_4

    .line 71
    .line 72
    const/4 v1, 0x1

    .line 73
    goto :goto_4

    .line 74
    :cond_4
    const/4 v1, 0x0

    .line 75
    :goto_4
    and-int/lit8 v2, v0, 0x1

    .line 76
    .line 77
    invoke-virtual {p4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-eqz v1, :cond_5

    .line 82
    .line 83
    and-int/lit8 v1, v0, 0xe

    .line 84
    .line 85
    or-int/lit8 v1, v1, 0x40

    .line 86
    .line 87
    and-int/lit8 v2, v0, 0x70

    .line 88
    .line 89
    or-int/2addr v1, v2

    .line 90
    and-int/lit16 v0, v0, 0x380

    .line 91
    .line 92
    or-int/2addr v0, v1

    .line 93
    invoke-static {p1, p2, p3, p4, v0}, Lkk/a;->h(Lmc/r;Llc/q;Lay0/k;Ll2/o;I)V

    .line 94
    .line 95
    .line 96
    goto :goto_5

    .line 97
    :cond_5
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 98
    .line 99
    .line 100
    :goto_5
    invoke-virtual {p4}, Ll2/t;->s()Ll2/u1;

    .line 101
    .line 102
    .line 103
    move-result-object p4

    .line 104
    if-eqz p4, :cond_6

    .line 105
    .line 106
    new-instance v0, Lr40/f;

    .line 107
    .line 108
    const/4 v6, 0x7

    .line 109
    move-object v1, p0

    .line 110
    move-object v2, p1

    .line 111
    move-object v3, p2

    .line 112
    move-object v4, p3

    .line 113
    move v5, p5

    .line 114
    invoke-direct/range {v0 .. v6}, Lr40/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 115
    .line 116
    .line 117
    iput-object v0, p4, Ll2/u1;->d:Lay0/n;

    .line 118
    .line 119
    :cond_6
    return-void
.end method

.method public final u(Ll2/o;)J
    .locals 2

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const p0, -0x5c95e46d

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Lj91/h;->a:Ll2/u2;

    .line 10
    .line 11
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lj91/e;

    .line 16
    .line 17
    invoke-virtual {p0}, Lj91/e;->e()J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    const/4 p0, 0x0

    .line 22
    invoke-virtual {p1, p0}, Ll2/t;->q(Z)V

    .line 23
    .line 24
    .line 25
    return-wide v0
.end method

.method public final v0(ZLl2/o;I)V
    .locals 3

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, -0x3a01e212

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p2, p1}, Ll2/t;->h(Z)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x2

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v1

    .line 19
    :goto_0
    or-int/2addr v0, p3

    .line 20
    and-int/lit8 v2, v0, 0x3

    .line 21
    .line 22
    if-eq v2, v1, :cond_1

    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    const/4 v1, 0x0

    .line 27
    :goto_1
    and-int/lit8 v2, v0, 0x1

    .line 28
    .line 29
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    and-int/lit8 v0, v0, 0xe

    .line 36
    .line 37
    invoke-static {p1, p2, v0}, Ldk/b;->j(ZLl2/o;I)V

    .line 38
    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 42
    .line 43
    .line 44
    :goto_2
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    if-eqz p2, :cond_3

    .line 49
    .line 50
    new-instance v0, Lbl/f;

    .line 51
    .line 52
    const/4 v1, 0x6

    .line 53
    invoke-direct {v0, p0, p1, p3, v1}, Lbl/f;-><init>(Ljava/lang/Object;ZII)V

    .line 54
    .line 55
    .line 56
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 57
    .line 58
    :cond_3
    return-void
.end method
