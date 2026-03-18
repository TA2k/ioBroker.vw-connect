.class public abstract Lhk/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;

.field public static final b:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lel/a;

    .line 2
    .line 3
    const/16 v1, 0x14

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lel/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lt2/b;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const v3, -0x68cd1cf0

    .line 12
    .line 13
    .line 14
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lhk/a;->a:Lt2/b;

    .line 18
    .line 19
    new-instance v0, Lel/a;

    .line 20
    .line 21
    const/16 v1, 0x15

    .line 22
    .line 23
    invoke-direct {v0, v1}, Lel/a;-><init>(I)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lt2/b;

    .line 27
    .line 28
    const v3, 0x301b28e7

    .line 29
    .line 30
    .line 31
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 32
    .line 33
    .line 34
    sput-object v1, Lhk/a;->b:Lt2/b;

    .line 35
    .line 36
    return-void
.end method

.method public static final a(Llc/q;Lay0/a;Ll2/o;I)V
    .locals 10

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "retry"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    move-object v7, p2

    .line 12
    check-cast v7, Ll2/t;

    .line 13
    .line 14
    const p2, 0x194c45c8

    .line 15
    .line 16
    .line 17
    invoke-virtual {v7, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v7, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    if-eqz p2, :cond_0

    .line 25
    .line 26
    const/4 p2, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p2, 0x2

    .line 29
    :goto_0
    or-int/2addr p2, p3

    .line 30
    and-int/lit8 v0, p3, 0x30

    .line 31
    .line 32
    if-nez v0, :cond_2

    .line 33
    .line 34
    invoke-virtual {v7, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_1

    .line 39
    .line 40
    const/16 v0, 0x20

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    const/16 v0, 0x10

    .line 44
    .line 45
    :goto_1
    or-int/2addr p2, v0

    .line 46
    :cond_2
    and-int/lit8 v0, p2, 0x13

    .line 47
    .line 48
    const/16 v1, 0x12

    .line 49
    .line 50
    if-eq v0, v1, :cond_3

    .line 51
    .line 52
    const/4 v0, 0x1

    .line 53
    goto :goto_2

    .line 54
    :cond_3
    const/4 v0, 0x0

    .line 55
    :goto_2
    and-int/lit8 v1, p2, 0x1

    .line 56
    .line 57
    invoke-virtual {v7, v1, v0}, Ll2/t;->O(IZ)Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-eqz v0, :cond_4

    .line 62
    .line 63
    new-instance v0, La71/k;

    .line 64
    .line 65
    const/4 v1, 0x7

    .line 66
    invoke-direct {v0, p1, v1}, La71/k;-><init>(Lay0/a;I)V

    .line 67
    .line 68
    .line 69
    const v1, 0x7a546597

    .line 70
    .line 71
    .line 72
    invoke-static {v1, v7, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    and-int/lit8 p2, p2, 0xe

    .line 77
    .line 78
    const/16 v0, 0x6d88

    .line 79
    .line 80
    or-int v8, v0, p2

    .line 81
    .line 82
    const/16 v9, 0x22

    .line 83
    .line 84
    const/4 v2, 0x0

    .line 85
    sget-object v3, Lhk/a;->a:Lt2/b;

    .line 86
    .line 87
    sget-object v4, Lhk/a;->b:Lt2/b;

    .line 88
    .line 89
    const/4 v6, 0x0

    .line 90
    move-object v1, p0

    .line 91
    invoke-static/range {v1 .. v9}, Llc/a;->a(Llc/q;Lay0/o;Lay0/o;Lt2/b;Lt2/b;Lay0/n;Ll2/o;II)V

    .line 92
    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_4
    move-object v1, p0

    .line 96
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 97
    .line 98
    .line 99
    :goto_3
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    if-eqz p0, :cond_5

    .line 104
    .line 105
    new-instance p2, La71/n0;

    .line 106
    .line 107
    const/16 v0, 0x12

    .line 108
    .line 109
    invoke-direct {p2, p3, v0, v1, p1}, La71/n0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    iput-object p2, p0, Ll2/u1;->d:Lay0/n;

    .line 113
    .line 114
    :cond_5
    return-void
.end method
