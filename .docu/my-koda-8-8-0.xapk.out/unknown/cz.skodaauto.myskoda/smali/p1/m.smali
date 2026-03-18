.class public final Lp1/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo1/b0;


# instance fields
.field public final a:Lp1/v;

.field public final b:Lo1/y;

.field public final c:Lbb/g0;


# direct methods
.method public constructor <init>(Lp1/v;Lp1/l;Lbb/g0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp1/m;->a:Lp1/v;

    .line 5
    .line 6
    iput-object p2, p0, Lp1/m;->b:Lo1/y;

    .line 7
    .line 8
    iput-object p3, p0, Lp1/m;->c:Lbb/g0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/m;->b:Lo1/y;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo1/y;->k()Lbb/g0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget p0, p0, Lbb/g0;->e:I

    .line 8
    .line 9
    return p0
.end method

.method public final c(Ljava/lang/Object;)I
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/m;->c:Lbb/g0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lbb/g0;->i(Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final d(I)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lp1/m;->c:Lbb/g0;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lbb/g0;->k(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lp1/m;->b:Lo1/y;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lo1/y;->l(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    return-object v0
.end method

.method public final e(ILjava/lang/Object;Ll2/o;I)V
    .locals 8

    .line 1
    move-object v6, p3

    .line 2
    check-cast v6, Ll2/t;

    .line 3
    .line 4
    const v0, -0x479b9c4d

    .line 5
    .line 6
    .line 7
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v6, p1}, Ll2/t;->e(I)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v0, 0x2

    .line 19
    :goto_0
    or-int/2addr v0, p4

    .line 20
    invoke-virtual {v6, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_1

    .line 25
    .line 26
    const/16 v4, 0x20

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    const/16 v4, 0x10

    .line 30
    .line 31
    :goto_1
    or-int/2addr v0, v4

    .line 32
    invoke-virtual {v6, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    if-eqz v4, :cond_2

    .line 37
    .line 38
    const/16 v4, 0x100

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    const/16 v4, 0x80

    .line 42
    .line 43
    :goto_2
    or-int/2addr v0, v4

    .line 44
    and-int/lit16 v4, v0, 0x93

    .line 45
    .line 46
    const/16 v5, 0x92

    .line 47
    .line 48
    if-eq v4, v5, :cond_3

    .line 49
    .line 50
    const/4 v4, 0x1

    .line 51
    goto :goto_3

    .line 52
    :cond_3
    const/4 v4, 0x0

    .line 53
    :goto_3
    and-int/lit8 v5, v0, 0x1

    .line 54
    .line 55
    invoke-virtual {v6, v5, v4}, Ll2/t;->O(IZ)Z

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    if-eqz v4, :cond_4

    .line 60
    .line 61
    iget-object v4, p0, Lp1/m;->a:Lp1/v;

    .line 62
    .line 63
    iget-object v4, v4, Lp1/v;->B:Lo1/i0;

    .line 64
    .line 65
    new-instance v5, Lm1/g;

    .line 66
    .line 67
    const/4 v7, 0x2

    .line 68
    invoke-direct {v5, p0, p1, v7}, Lm1/g;-><init>(Lo1/b0;II)V

    .line 69
    .line 70
    .line 71
    const v7, 0x441527a7

    .line 72
    .line 73
    .line 74
    invoke-static {v7, v6, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 75
    .line 76
    .line 77
    move-result-object v5

    .line 78
    shr-int/lit8 v7, v0, 0x3

    .line 79
    .line 80
    and-int/lit8 v7, v7, 0xe

    .line 81
    .line 82
    or-int/lit16 v7, v7, 0xc00

    .line 83
    .line 84
    shl-int/lit8 v0, v0, 0x3

    .line 85
    .line 86
    and-int/lit8 v0, v0, 0x70

    .line 87
    .line 88
    or-int/2addr v7, v0

    .line 89
    move v3, p1

    .line 90
    move-object v2, p2

    .line 91
    invoke-static/range {v2 .. v7}, Lo1/y;->b(Ljava/lang/Object;ILo1/i0;Lt2/b;Ll2/o;I)V

    .line 92
    .line 93
    .line 94
    goto :goto_4

    .line 95
    :cond_4
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 96
    .line 97
    .line 98
    :goto_4
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 99
    .line 100
    .line 101
    move-result-object v6

    .line 102
    if-eqz v6, :cond_5

    .line 103
    .line 104
    new-instance v0, Ljk/b;

    .line 105
    .line 106
    const/16 v5, 0x12

    .line 107
    .line 108
    move-object v1, p0

    .line 109
    move v2, p1

    .line 110
    move-object v3, p2

    .line 111
    move v4, p4

    .line 112
    invoke-direct/range {v0 .. v5}, Ljk/b;-><init>(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 113
    .line 114
    .line 115
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 116
    .line 117
    :cond_5
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Lp1/m;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_1
    check-cast p1, Lp1/m;

    .line 12
    .line 13
    iget-object p1, p1, Lp1/m;->b:Lo1/y;

    .line 14
    .line 15
    iget-object p0, p0, Lp1/m;->b:Lo1/y;

    .line 16
    .line 17
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/m;->b:Lo1/y;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
