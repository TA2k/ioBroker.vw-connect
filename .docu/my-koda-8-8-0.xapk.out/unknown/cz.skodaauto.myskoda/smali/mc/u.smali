.class public abstract Lmc/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lzb/k;->a:Lzb/u;

    .line 2
    .line 3
    return-void
.end method

.method public static final a(Lmc/s;Lay0/k;Lx2/s;Ll2/o;I)V
    .locals 11

    .line 1
    sget-object v3, Lx2/c;->h:Lx2/j;

    .line 2
    .line 3
    const-string v0, "lookup"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object v7, p3

    .line 9
    check-cast v7, Ll2/t;

    .line 10
    .line 11
    const p3, -0xe6d18be

    .line 12
    .line 13
    .line 14
    invoke-virtual {v7, p3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v7, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p3

    .line 21
    if-eqz p3, :cond_0

    .line 22
    .line 23
    const/4 p3, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 p3, 0x2

    .line 26
    :goto_0
    or-int/2addr p3, p4

    .line 27
    invoke-virtual {v7, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    const/16 v0, 0x20

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/16 v0, 0x10

    .line 37
    .line 38
    :goto_1
    or-int/2addr p3, v0

    .line 39
    and-int/lit16 v0, p3, 0x93

    .line 40
    .line 41
    const/16 v1, 0x92

    .line 42
    .line 43
    const/4 v2, 0x1

    .line 44
    const/4 v10, 0x0

    .line 45
    if-eq v0, v1, :cond_2

    .line 46
    .line 47
    move v0, v2

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    move v0, v10

    .line 50
    :goto_2
    and-int/2addr p3, v2

    .line 51
    invoke-virtual {v7, p3, v0}, Ll2/t;->O(IZ)Z

    .line 52
    .line 53
    .line 54
    move-result p3

    .line 55
    if-eqz p3, :cond_5

    .line 56
    .line 57
    instance-of p3, p0, Lmc/v;

    .line 58
    .line 59
    const-string v0, "payment_option_image"

    .line 60
    .line 61
    if-eqz p3, :cond_3

    .line 62
    .line 63
    const p3, 0x36511734

    .line 64
    .line 65
    .line 66
    invoke-virtual {v7, p3}, Ll2/t;->Y(I)V

    .line 67
    .line 68
    .line 69
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p3

    .line 73
    check-cast p3, Ljava/lang/Number;

    .line 74
    .line 75
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 76
    .line 77
    .line 78
    move-result p3

    .line 79
    invoke-static {p3, v10, v7}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 80
    .line 81
    .line 82
    move-result-object p3

    .line 83
    invoke-static {p2, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    const/16 v8, 0x6c30

    .line 88
    .line 89
    const/16 v9, 0x60

    .line 90
    .line 91
    const-string v1, "logo"

    .line 92
    .line 93
    sget-object v4, Lt3/j;->b:Lt3/x0;

    .line 94
    .line 95
    const/4 v5, 0x0

    .line 96
    const/4 v6, 0x0

    .line 97
    move-object v0, p3

    .line 98
    invoke-static/range {v0 .. v9}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v7, v10}, Ll2/t;->q(Z)V

    .line 102
    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_3
    instance-of p3, p0, Lmc/w;

    .line 106
    .line 107
    if-eqz p3, :cond_4

    .line 108
    .line 109
    const p3, 0x365671be

    .line 110
    .line 111
    .line 112
    invoke-virtual {v7, p3}, Ll2/t;->Y(I)V

    .line 113
    .line 114
    .line 115
    move-object p3, p0

    .line 116
    check-cast p3, Lmc/w;

    .line 117
    .line 118
    iget-object p3, p3, Lmc/w;->b:Ljava/lang/String;

    .line 119
    .line 120
    invoke-static {p2, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    const/16 v1, 0x6d80

    .line 125
    .line 126
    invoke-static {v1, p3, v7, v0}, Lkc/d;->b(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v7, v10}, Ll2/t;->q(Z)V

    .line 130
    .line 131
    .line 132
    goto :goto_3

    .line 133
    :cond_4
    const p0, -0x2789cb2f

    .line 134
    .line 135
    .line 136
    invoke-static {p0, v7, v10}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    throw p0

    .line 141
    :cond_5
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 142
    .line 143
    .line 144
    :goto_3
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 145
    .line 146
    .line 147
    move-result-object p3

    .line 148
    if-eqz p3, :cond_6

    .line 149
    .line 150
    new-instance v0, Li91/k3;

    .line 151
    .line 152
    const/16 v2, 0xb

    .line 153
    .line 154
    move-object v3, p0

    .line 155
    move-object v4, p1

    .line 156
    move-object v5, p2

    .line 157
    move v1, p4

    .line 158
    invoke-direct/range {v0 .. v5}, Li91/k3;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 162
    .line 163
    :cond_6
    return-void
.end method
