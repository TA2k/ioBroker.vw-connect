.class public abstract Lr61/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/Set;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    const/high16 v0, -0x80000000

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const/16 v0, 0x200

    .line 8
    .line 9
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    const/16 v0, 0x20

    .line 14
    .line 15
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    const/16 v0, 0x10

    .line 20
    .line 21
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    const/16 v0, 0x8

    .line 26
    .line 27
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    const/high16 v0, 0x10000

    .line 32
    .line 33
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 34
    .line 35
    .line 36
    move-result-object v6

    .line 37
    const/16 v0, 0x100

    .line 38
    .line 39
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 40
    .line 41
    .line 42
    move-result-object v7

    .line 43
    filled-new-array/range {v1 .. v7}, [Ljava/lang/Integer;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    sput-object v0, Lr61/c;->a:Ljava/util/Set;

    .line 52
    .line 53
    return-void
.end method

.method public static final a(Ll2/o;I)V
    .locals 10

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x6e58b501

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    :goto_0
    and-int/lit8 v1, p1, 0x1

    .line 15
    .line 16
    invoke-virtual {p0, v1, v0}, Ll2/t;->O(IZ)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_4

    .line 21
    .line 22
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    const/4 v1, 0x0

    .line 27
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 28
    .line 29
    if-ne v0, v2, :cond_1

    .line 30
    .line 31
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {p0, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    :cond_1
    check-cast v0, Ll2/b1;

    .line 39
    .line 40
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    if-ne v3, v2, :cond_2

    .line 45
    .line 46
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :cond_2
    check-cast v3, Ll2/b1;

    .line 54
    .line 55
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    if-ne v1, v2, :cond_3

    .line 60
    .line 61
    new-instance v1, Lqf0/d;

    .line 62
    .line 63
    const/4 v2, 0x6

    .line 64
    invoke-direct {v1, v2}, Lqf0/d;-><init>(I)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    :cond_3
    check-cast v1, Lay0/a;

    .line 71
    .line 72
    new-instance v4, Lx4/p;

    .line 73
    .line 74
    const/4 v8, 0x0

    .line 75
    const/16 v9, 0x24

    .line 76
    .line 77
    const/4 v5, 0x0

    .line 78
    const/4 v6, 0x0

    .line 79
    const/4 v7, 0x1

    .line 80
    invoke-direct/range {v4 .. v9}, Lx4/p;-><init>(ZZZZI)V

    .line 81
    .line 82
    .line 83
    new-instance v2, Lo50/b;

    .line 84
    .line 85
    const/16 v5, 0xf

    .line 86
    .line 87
    invoke-direct {v2, v5, v0, v3}, Lo50/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    const v0, 0xb397758

    .line 91
    .line 92
    .line 93
    invoke-static {v0, p0, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    const/16 v2, 0x1b6

    .line 98
    .line 99
    invoke-static {v1, v4, v0, p0, v2}, Llp/ge;->a(Lay0/a;Lx4/p;Lt2/b;Ll2/o;I)V

    .line 100
    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_4
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 104
    .line 105
    .line 106
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    if-eqz p0, :cond_5

    .line 111
    .line 112
    new-instance v0, Lqz/a;

    .line 113
    .line 114
    const/16 v1, 0x15

    .line 115
    .line 116
    invoke-direct {v0, p1, v1}, Lqz/a;-><init>(II)V

    .line 117
    .line 118
    .line 119
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 120
    .line 121
    :cond_5
    return-void
.end method
