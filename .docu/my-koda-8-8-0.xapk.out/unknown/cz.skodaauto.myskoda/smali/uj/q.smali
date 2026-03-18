.class public final Luj/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqf/d;


# static fields
.field public static final a:Luj/q;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Luj/q;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Luj/q;->a:Luj/q;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final D0(Llc/q;Lay0/k;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "event"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, -0x4eea5b71

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int/2addr v0, p4

    .line 29
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_1

    .line 34
    .line 35
    const/16 v1, 0x20

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v1, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v0, v1

    .line 41
    and-int/lit8 v1, v0, 0x13

    .line 42
    .line 43
    const/16 v2, 0x12

    .line 44
    .line 45
    if-eq v1, v2, :cond_2

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/4 v1, 0x0

    .line 50
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 51
    .line 52
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_3

    .line 57
    .line 58
    and-int/lit8 v1, v0, 0xe

    .line 59
    .line 60
    const/16 v2, 0x8

    .line 61
    .line 62
    or-int/2addr v1, v2

    .line 63
    and-int/lit8 v0, v0, 0x70

    .line 64
    .line 65
    or-int/2addr v0, v1

    .line 66
    invoke-static {p1, p2, p3, v0}, Llk/a;->o(Llc/q;Lay0/k;Ll2/o;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_3

    .line 70
    :cond_3
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 71
    .line 72
    .line 73
    :goto_3
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 74
    .line 75
    .line 76
    move-result-object p3

    .line 77
    if-eqz p3, :cond_4

    .line 78
    .line 79
    new-instance v0, Luj/p;

    .line 80
    .line 81
    const/4 v5, 0x0

    .line 82
    move-object v1, p0

    .line 83
    move-object v2, p1

    .line 84
    move-object v3, p2

    .line 85
    move v4, p4

    .line 86
    invoke-direct/range {v0 .. v5}, Luj/p;-><init>(Luj/q;Llc/q;Lay0/k;II)V

    .line 87
    .line 88
    .line 89
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 90
    .line 91
    :cond_4
    return-void
.end method

.method public final U(Llc/q;Lay0/k;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "event"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, -0x4386800c

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int/2addr v0, p4

    .line 29
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_1

    .line 34
    .line 35
    const/16 v1, 0x20

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v1, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v0, v1

    .line 41
    and-int/lit8 v1, v0, 0x13

    .line 42
    .line 43
    const/16 v2, 0x12

    .line 44
    .line 45
    if-eq v1, v2, :cond_2

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/4 v1, 0x0

    .line 50
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 51
    .line 52
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_3

    .line 57
    .line 58
    and-int/lit8 v1, v0, 0xe

    .line 59
    .line 60
    const/16 v2, 0x8

    .line 61
    .line 62
    or-int/2addr v1, v2

    .line 63
    and-int/lit8 v0, v0, 0x70

    .line 64
    .line 65
    or-int/2addr v0, v1

    .line 66
    invoke-static {p1, p2, p3, v0}, Llk/a;->l(Llc/q;Lay0/k;Ll2/o;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_3

    .line 70
    :cond_3
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 71
    .line 72
    .line 73
    :goto_3
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 74
    .line 75
    .line 76
    move-result-object p3

    .line 77
    if-eqz p3, :cond_4

    .line 78
    .line 79
    new-instance v0, Luj/p;

    .line 80
    .line 81
    const/4 v5, 0x2

    .line 82
    move-object v1, p0

    .line 83
    move-object v2, p1

    .line 84
    move-object v3, p2

    .line 85
    move v4, p4

    .line 86
    invoke-direct/range {v0 .. v5}, Luj/p;-><init>(Luj/q;Llc/q;Lay0/k;II)V

    .line 87
    .line 88
    .line 89
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 90
    .line 91
    :cond_4
    return-void
.end method

.method public final Y(Luf/p;Llc/q;Lay0/k;Ll2/o;I)V
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
    const v0, -0x30c0d516

    .line 14
    .line 15
    .line 16
    invoke-virtual {p4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p5, 0x6

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    invoke-virtual {p4, v0}, Ll2/t;->e(I)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    const/4 v0, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v0, 0x2

    .line 36
    :goto_0
    or-int/2addr v0, p5

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move v0, p5

    .line 39
    :goto_1
    and-int/lit8 v1, p5, 0x30

    .line 40
    .line 41
    if-nez v1, :cond_4

    .line 42
    .line 43
    and-int/lit8 v1, p5, 0x40

    .line 44
    .line 45
    if-nez v1, :cond_2

    .line 46
    .line 47
    invoke-virtual {p4, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    invoke-virtual {p4, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    :goto_2
    if-eqz v1, :cond_3

    .line 57
    .line 58
    const/16 v1, 0x20

    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_3
    const/16 v1, 0x10

    .line 62
    .line 63
    :goto_3
    or-int/2addr v0, v1

    .line 64
    :cond_4
    and-int/lit16 v1, p5, 0x180

    .line 65
    .line 66
    if-nez v1, :cond_6

    .line 67
    .line 68
    invoke-virtual {p4, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-eqz v1, :cond_5

    .line 73
    .line 74
    const/16 v1, 0x100

    .line 75
    .line 76
    goto :goto_4

    .line 77
    :cond_5
    const/16 v1, 0x80

    .line 78
    .line 79
    :goto_4
    or-int/2addr v0, v1

    .line 80
    :cond_6
    and-int/lit16 v1, v0, 0x93

    .line 81
    .line 82
    const/16 v2, 0x92

    .line 83
    .line 84
    if-eq v1, v2, :cond_7

    .line 85
    .line 86
    const/4 v1, 0x1

    .line 87
    goto :goto_5

    .line 88
    :cond_7
    const/4 v1, 0x0

    .line 89
    :goto_5
    and-int/lit8 v2, v0, 0x1

    .line 90
    .line 91
    invoke-virtual {p4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    if-eqz v1, :cond_8

    .line 96
    .line 97
    and-int/lit8 v1, v0, 0xe

    .line 98
    .line 99
    or-int/lit8 v1, v1, 0x40

    .line 100
    .line 101
    and-int/lit8 v2, v0, 0x70

    .line 102
    .line 103
    or-int/2addr v1, v2

    .line 104
    and-int/lit16 v0, v0, 0x380

    .line 105
    .line 106
    or-int/2addr v0, v1

    .line 107
    invoke-static {p1, p2, p3, p4, v0}, Llk/a;->m(Luf/p;Llc/q;Lay0/k;Ll2/o;I)V

    .line 108
    .line 109
    .line 110
    goto :goto_6

    .line 111
    :cond_8
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 112
    .line 113
    .line 114
    :goto_6
    invoke-virtual {p4}, Ll2/t;->s()Ll2/u1;

    .line 115
    .line 116
    .line 117
    move-result-object p4

    .line 118
    if-eqz p4, :cond_9

    .line 119
    .line 120
    new-instance v0, Lr40/f;

    .line 121
    .line 122
    const/16 v6, 0x8

    .line 123
    .line 124
    move-object v1, p0

    .line 125
    move-object v2, p1

    .line 126
    move-object v3, p2

    .line 127
    move-object v4, p3

    .line 128
    move v5, p5

    .line 129
    invoke-direct/range {v0 .. v6}, Lr40/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 130
    .line 131
    .line 132
    iput-object v0, p4, Ll2/u1;->d:Lay0/n;

    .line 133
    .line 134
    :cond_9
    return-void
.end method

.method public final r(Llc/q;Lay0/k;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "event"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, -0x790742c8

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int/2addr v0, p4

    .line 29
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_1

    .line 34
    .line 35
    const/16 v1, 0x20

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v1, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v0, v1

    .line 41
    and-int/lit8 v1, v0, 0x13

    .line 42
    .line 43
    const/16 v2, 0x12

    .line 44
    .line 45
    if-eq v1, v2, :cond_2

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/4 v1, 0x0

    .line 50
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 51
    .line 52
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_3

    .line 57
    .line 58
    and-int/lit8 v1, v0, 0xe

    .line 59
    .line 60
    const/16 v2, 0x8

    .line 61
    .line 62
    or-int/2addr v1, v2

    .line 63
    and-int/lit8 v0, v0, 0x70

    .line 64
    .line 65
    or-int/2addr v0, v1

    .line 66
    invoke-static {p1, p2, p3, v0}, Llk/a;->n(Llc/q;Lay0/k;Ll2/o;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_3

    .line 70
    :cond_3
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 71
    .line 72
    .line 73
    :goto_3
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 74
    .line 75
    .line 76
    move-result-object p3

    .line 77
    if-eqz p3, :cond_4

    .line 78
    .line 79
    new-instance v0, Luj/p;

    .line 80
    .line 81
    const/4 v5, 0x1

    .line 82
    move-object v1, p0

    .line 83
    move-object v2, p1

    .line 84
    move-object v3, p2

    .line 85
    move v4, p4

    .line 86
    invoke-direct/range {v0 .. v5}, Luj/p;-><init>(Luj/q;Llc/q;Lay0/k;II)V

    .line 87
    .line 88
    .line 89
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 90
    .line 91
    :cond_4
    return-void
.end method

.method public final y0(Luf/n;Llc/q;Lay0/k;Ll2/o;I)V
    .locals 7

    .line 1
    const-string v0, "plugAndChargeStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "uiState"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "event"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    check-cast p4, Ll2/t;

    .line 17
    .line 18
    const v0, 0x59d7a5cf

    .line 19
    .line 20
    .line 21
    invoke-virtual {p4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 22
    .line 23
    .line 24
    and-int/lit8 v0, p5, 0x6

    .line 25
    .line 26
    if-nez v0, :cond_1

    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    invoke-virtual {p4, v0}, Ll2/t;->e(I)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_0

    .line 37
    .line 38
    const/4 v0, 0x4

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    const/4 v0, 0x2

    .line 41
    :goto_0
    or-int/2addr v0, p5

    .line 42
    goto :goto_1

    .line 43
    :cond_1
    move v0, p5

    .line 44
    :goto_1
    and-int/lit8 v1, p5, 0x30

    .line 45
    .line 46
    if-nez v1, :cond_4

    .line 47
    .line 48
    and-int/lit8 v1, p5, 0x40

    .line 49
    .line 50
    if-nez v1, :cond_2

    .line 51
    .line 52
    invoke-virtual {p4, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    goto :goto_2

    .line 57
    :cond_2
    invoke-virtual {p4, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    :goto_2
    if-eqz v1, :cond_3

    .line 62
    .line 63
    const/16 v1, 0x20

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    const/16 v1, 0x10

    .line 67
    .line 68
    :goto_3
    or-int/2addr v0, v1

    .line 69
    :cond_4
    and-int/lit16 v1, p5, 0x180

    .line 70
    .line 71
    if-nez v1, :cond_6

    .line 72
    .line 73
    invoke-virtual {p4, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    if-eqz v1, :cond_5

    .line 78
    .line 79
    const/16 v1, 0x100

    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_5
    const/16 v1, 0x80

    .line 83
    .line 84
    :goto_4
    or-int/2addr v0, v1

    .line 85
    :cond_6
    and-int/lit16 v1, v0, 0x93

    .line 86
    .line 87
    const/16 v2, 0x92

    .line 88
    .line 89
    if-eq v1, v2, :cond_7

    .line 90
    .line 91
    const/4 v1, 0x1

    .line 92
    goto :goto_5

    .line 93
    :cond_7
    const/4 v1, 0x0

    .line 94
    :goto_5
    and-int/lit8 v2, v0, 0x1

    .line 95
    .line 96
    invoke-virtual {p4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-eqz v1, :cond_8

    .line 101
    .line 102
    and-int/lit8 v1, v0, 0xe

    .line 103
    .line 104
    or-int/lit8 v1, v1, 0x40

    .line 105
    .line 106
    and-int/lit8 v2, v0, 0x70

    .line 107
    .line 108
    or-int/2addr v1, v2

    .line 109
    and-int/lit16 v0, v0, 0x380

    .line 110
    .line 111
    or-int/2addr v0, v1

    .line 112
    invoke-static {p1, p2, p3, p4, v0}, Llk/a;->k(Luf/n;Llc/q;Lay0/k;Ll2/o;I)V

    .line 113
    .line 114
    .line 115
    goto :goto_6

    .line 116
    :cond_8
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 117
    .line 118
    .line 119
    :goto_6
    invoke-virtual {p4}, Ll2/t;->s()Ll2/u1;

    .line 120
    .line 121
    .line 122
    move-result-object p4

    .line 123
    if-eqz p4, :cond_9

    .line 124
    .line 125
    new-instance v0, Lr40/f;

    .line 126
    .line 127
    const/16 v6, 0x9

    .line 128
    .line 129
    move-object v1, p0

    .line 130
    move-object v2, p1

    .line 131
    move-object v3, p2

    .line 132
    move-object v4, p3

    .line 133
    move v5, p5

    .line 134
    invoke-direct/range {v0 .. v6}, Lr40/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 135
    .line 136
    .line 137
    iput-object v0, p4, Ll2/u1;->d:Lay0/n;

    .line 138
    .line 139
    :cond_9
    return-void
.end method
