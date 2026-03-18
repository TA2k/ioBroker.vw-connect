.class public abstract Li40/a3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x72

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Li40/a3;->a:F

    .line 5
    .line 6
    const/16 v0, 0x4c

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Li40/a3;->b:F

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Lh40/w;Lx2/s;Lay0/a;Ll2/o;I)V
    .locals 11

    .line 1
    const-string v0, "requestedProduct"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v8, p3

    .line 7
    check-cast v8, Ll2/t;

    .line 8
    .line 9
    const v0, 0x4f646d46

    .line 10
    .line 11
    .line 12
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v8, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v0, 0x2

    .line 24
    :goto_0
    or-int/2addr v0, p4

    .line 25
    invoke-virtual {v8, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v4

    .line 29
    if-eqz v4, :cond_1

    .line 30
    .line 31
    const/16 v4, 0x20

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    const/16 v4, 0x10

    .line 35
    .line 36
    :goto_1
    or-int/2addr v0, v4

    .line 37
    invoke-virtual {v8, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    if-eqz v4, :cond_2

    .line 42
    .line 43
    const/16 v4, 0x100

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_2
    const/16 v4, 0x80

    .line 47
    .line 48
    :goto_2
    or-int/2addr v0, v4

    .line 49
    and-int/lit16 v4, v0, 0x93

    .line 50
    .line 51
    const/16 v5, 0x92

    .line 52
    .line 53
    if-eq v4, v5, :cond_3

    .line 54
    .line 55
    const/4 v4, 0x1

    .line 56
    goto :goto_3

    .line 57
    :cond_3
    const/4 v4, 0x0

    .line 58
    :goto_3
    and-int/lit8 v5, v0, 0x1

    .line 59
    .line 60
    invoke-virtual {v8, v5, v4}, Ll2/t;->O(IZ)Z

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    if-eqz v4, :cond_4

    .line 65
    .line 66
    new-instance v4, Li40/k0;

    .line 67
    .line 68
    const/16 v5, 0xd

    .line 69
    .line 70
    invoke-direct {v4, v5, p0, p2}, Li40/k0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    const v5, 0x734d4bb

    .line 74
    .line 75
    .line 76
    invoke-static {v5, v8, v4}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 77
    .line 78
    .line 79
    move-result-object v7

    .line 80
    shr-int/lit8 v0, v0, 0x3

    .line 81
    .line 82
    and-int/lit8 v0, v0, 0xe

    .line 83
    .line 84
    or-int/lit16 v9, v0, 0xc00

    .line 85
    .line 86
    const/4 v10, 0x6

    .line 87
    const/4 v5, 0x0

    .line 88
    const/4 v6, 0x0

    .line 89
    move-object v4, p1

    .line 90
    invoke-static/range {v4 .. v10}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 91
    .line 92
    .line 93
    goto :goto_4

    .line 94
    :cond_4
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 95
    .line 96
    .line 97
    :goto_4
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 98
    .line 99
    .line 100
    move-result-object v6

    .line 101
    if-eqz v6, :cond_5

    .line 102
    .line 103
    new-instance v0, Lf20/f;

    .line 104
    .line 105
    const/16 v5, 0x19

    .line 106
    .line 107
    move-object v1, p0

    .line 108
    move-object v2, p1

    .line 109
    move-object v3, p2

    .line 110
    move v4, p4

    .line 111
    invoke-direct/range {v0 .. v5}, Lf20/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Lay0/a;II)V

    .line 112
    .line 113
    .line 114
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 115
    .line 116
    :cond_5
    return-void
.end method
