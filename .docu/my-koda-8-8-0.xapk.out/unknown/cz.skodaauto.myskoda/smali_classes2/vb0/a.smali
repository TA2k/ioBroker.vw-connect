.class public abstract Lvb0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Luz/l0;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    invoke-direct {v0, v1}, Luz/l0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lt2/b;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const v3, -0x1c28e5ae

    .line 12
    .line 13
    .line 14
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lvb0/a;->a:Lt2/b;

    .line 18
    .line 19
    return-void
.end method

.method public static final a(Lay0/a;Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0x50ba8c88

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    or-int/2addr v0, p2

    .line 20
    and-int/lit8 v2, v0, 0x3

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    if-eq v2, v1, :cond_1

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    move v1, v3

    .line 28
    :goto_1
    and-int/lit8 v2, v0, 0x1

    .line 29
    .line 30
    invoke-virtual {p1, v2, v1}, Ll2/t;->O(IZ)Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    and-int/lit8 v0, v0, 0xe

    .line 37
    .line 38
    invoke-static {v0, v3, p0, p1}, Lvb0/a;->b(IILay0/a;Ll2/o;)V

    .line 39
    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 43
    .line 44
    .line 45
    :goto_2
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    if-eqz p1, :cond_3

    .line 50
    .line 51
    new-instance v0, Lv50/k;

    .line 52
    .line 53
    const/16 v1, 0xf

    .line 54
    .line 55
    invoke-direct {v0, p0, p2, v1}, Lv50/k;-><init>(Lay0/a;II)V

    .line 56
    .line 57
    .line 58
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 59
    .line 60
    :cond_3
    return-void
.end method

.method public static final b(IILay0/a;Ll2/o;)V
    .locals 5

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0x5b13b438

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p1, 0x1

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    or-int/lit8 v2, p0, 0x6

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    and-int/lit8 v2, p0, 0x6

    .line 18
    .line 19
    if-nez v2, :cond_2

    .line 20
    .line 21
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    const/4 v2, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_1
    move v2, v1

    .line 30
    :goto_0
    or-int/2addr v2, p0

    .line 31
    goto :goto_1

    .line 32
    :cond_2
    move v2, p0

    .line 33
    :goto_1
    and-int/lit8 v3, v2, 0x3

    .line 34
    .line 35
    if-eq v3, v1, :cond_3

    .line 36
    .line 37
    const/4 v3, 0x1

    .line 38
    goto :goto_2

    .line 39
    :cond_3
    const/4 v3, 0x0

    .line 40
    :goto_2
    and-int/lit8 v4, v2, 0x1

    .line 41
    .line 42
    invoke-virtual {p3, v4, v3}, Ll2/t;->O(IZ)Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-eqz v3, :cond_6

    .line 47
    .line 48
    if-eqz v0, :cond_5

    .line 49
    .line 50
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 55
    .line 56
    if-ne p2, v0, :cond_4

    .line 57
    .line 58
    new-instance p2, Lz81/g;

    .line 59
    .line 60
    const/4 v0, 0x2

    .line 61
    invoke-direct {p2, v0}, Lz81/g;-><init>(I)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p3, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    :cond_4
    check-cast p2, Lay0/a;

    .line 68
    .line 69
    :cond_5
    new-instance v0, Lx4/p;

    .line 70
    .line 71
    invoke-direct {v0, v1}, Lx4/p;-><init>(I)V

    .line 72
    .line 73
    .line 74
    new-instance v1, Lv50/k;

    .line 75
    .line 76
    const/16 v3, 0x10

    .line 77
    .line 78
    invoke-direct {v1, p2, v3}, Lv50/k;-><init>(Lay0/a;I)V

    .line 79
    .line 80
    .line 81
    const v3, 0x7812f081

    .line 82
    .line 83
    .line 84
    invoke-static {v3, p3, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    and-int/lit8 v2, v2, 0xe

    .line 89
    .line 90
    or-int/lit16 v2, v2, 0x1b0

    .line 91
    .line 92
    invoke-static {p2, v0, v1, p3, v2}, Llp/ge;->a(Lay0/a;Lx4/p;Lt2/b;Ll2/o;I)V

    .line 93
    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_6
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 97
    .line 98
    .line 99
    :goto_3
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 100
    .line 101
    .line 102
    move-result-object p3

    .line 103
    if-eqz p3, :cond_7

    .line 104
    .line 105
    new-instance v0, Lak/o;

    .line 106
    .line 107
    const/4 v1, 0x3

    .line 108
    invoke-direct {v0, p2, p0, p1, v1}, Lak/o;-><init>(Ljava/lang/Object;III)V

    .line 109
    .line 110
    .line 111
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 112
    .line 113
    :cond_7
    return-void
.end method
