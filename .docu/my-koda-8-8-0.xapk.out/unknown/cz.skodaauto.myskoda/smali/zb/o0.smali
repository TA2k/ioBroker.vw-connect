.class public abstract Lzb/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;

.field public static final b:Ll2/u2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lz81/g;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lz81/g;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/u2;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lzb/o0;->a:Ll2/u2;

    .line 14
    .line 15
    new-instance v0, Lz81/g;

    .line 16
    .line 17
    const/16 v1, 0xa

    .line 18
    .line 19
    invoke-direct {v0, v1}, Lz81/g;-><init>(I)V

    .line 20
    .line 21
    .line 22
    new-instance v1, Ll2/u2;

    .line 23
    .line 24
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 25
    .line 26
    .line 27
    sput-object v1, Lzb/o0;->b:Ll2/u2;

    .line 28
    .line 29
    return-void
.end method

.method public static final a(ILjava/util/List;Ll2/o;Lt2/b;)V
    .locals 8

    .line 1
    move-object v5, p2

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p2, 0x24a984df

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v5, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    const/16 p2, 0x20

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/16 p2, 0x10

    .line 20
    .line 21
    :goto_0
    or-int/2addr p2, p0

    .line 22
    and-int/lit16 v0, p2, 0x93

    .line 23
    .line 24
    const/16 v1, 0x92

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    const/4 v3, 0x1

    .line 28
    if-eq v0, v1, :cond_1

    .line 29
    .line 30
    move v0, v3

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v0, v2

    .line 33
    :goto_1
    and-int/2addr p2, v3

    .line 34
    invoke-virtual {v5, p2, v0}, Ll2/t;->O(IZ)Z

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    if-eqz p2, :cond_2

    .line 39
    .line 40
    const-string p2, "skoda-shimmer-animation"

    .line 41
    .line 42
    invoke-static {p2, v5, v2}, Lc1/d;->r(Ljava/lang/String;Ll2/o;I)Lc1/i0;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    const/16 p2, 0x4c6

    .line 47
    .line 48
    sget-object v1, Lc1/z;->d:Lc1/y;

    .line 49
    .line 50
    const/4 v3, 0x2

    .line 51
    invoke-static {p2, v2, v1, v3}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 52
    .line 53
    .line 54
    move-result-object p2

    .line 55
    sget-object v1, Lc1/t0;->d:Lc1/t0;

    .line 56
    .line 57
    const/4 v2, 0x4

    .line 58
    invoke-static {p2, v1, v2}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    const/16 v6, 0x71b8

    .line 63
    .line 64
    const/4 v7, 0x0

    .line 65
    const/4 v1, 0x0

    .line 66
    const v2, 0x44bb8000    # 1500.0f

    .line 67
    .line 68
    .line 69
    const-string v4, "audi-shimmer-animation"

    .line 70
    .line 71
    invoke-static/range {v0 .. v7}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    .line 72
    .line 73
    .line 74
    move-result-object p2

    .line 75
    sget-object v0, Lzb/o0;->a:Ll2/u2;

    .line 76
    .line 77
    invoke-virtual {v0, p2}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    sget-object v0, Lzb/o0;->b:Ll2/u2;

    .line 82
    .line 83
    invoke-virtual {v0, p1}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    filled-new-array {p2, v0}, [Ll2/t1;

    .line 88
    .line 89
    .line 90
    move-result-object p2

    .line 91
    new-instance v0, Lzb/w;

    .line 92
    .line 93
    const/4 v1, 0x1

    .line 94
    invoke-direct {v0, p3, v1}, Lzb/w;-><init>(Lt2/b;I)V

    .line 95
    .line 96
    .line 97
    const v1, 0x54181f

    .line 98
    .line 99
    .line 100
    invoke-static {v1, v5, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    const/16 v1, 0x38

    .line 105
    .line 106
    invoke-static {p2, v0, v5, v1}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 107
    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_2
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 111
    .line 112
    .line 113
    :goto_2
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    if-eqz p2, :cond_3

    .line 118
    .line 119
    new-instance v0, Lnu0/b;

    .line 120
    .line 121
    invoke-direct {v0, p3, p1, p0}, Lnu0/b;-><init>(Lt2/b;Ljava/util/List;I)V

    .line 122
    .line 123
    .line 124
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 125
    .line 126
    :cond_3
    return-void
.end method

.method public static b(Lx2/s;)Lx2/s;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    int-to-float v1, v0

    .line 3
    int-to-float v0, v0

    .line 4
    const-string v2, "$this$shimmer"

    .line 5
    .line 6
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    new-instance v2, Lzb/m0;

    .line 10
    .line 11
    invoke-direct {v2, v1, v0}, Lzb/m0;-><init>(FF)V

    .line 12
    .line 13
    .line 14
    invoke-static {p0, v2}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method
