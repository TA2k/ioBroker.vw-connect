.class public final synthetic Li00/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh00/b;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh00/b;Lay0/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Li00/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li00/b;->e:Lh00/b;

    .line 4
    .line 5
    iput-object p2, p0, Li00/b;->f:Lay0/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Li00/b;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    move-object v5, p1

    .line 25
    check-cast v5, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v5, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    new-instance p1, Lf30/h;

    .line 34
    .line 35
    const/4 p2, 0x5

    .line 36
    iget-object v0, p0, Li00/b;->e:Lh00/b;

    .line 37
    .line 38
    iget-object p0, p0, Li00/b;->f:Lay0/a;

    .line 39
    .line 40
    invoke-direct {p1, p2, v0, p0}, Lf30/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    const p0, 0x41febdf

    .line 44
    .line 45
    .line 46
    invoke-static {p0, v5, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    const/16 v6, 0x180

    .line 51
    .line 52
    const/4 v7, 0x3

    .line 53
    const/4 v1, 0x0

    .line 54
    const-wide/16 v2, 0x0

    .line 55
    .line 56
    invoke-static/range {v1 .. v7}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 61
    .line 62
    .line 63
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 67
    .line 68
    const/4 v1, 0x2

    .line 69
    const/4 v2, 0x1

    .line 70
    if-eq v0, v1, :cond_2

    .line 71
    .line 72
    move v0, v2

    .line 73
    goto :goto_2

    .line 74
    :cond_2
    const/4 v0, 0x0

    .line 75
    :goto_2
    and-int/2addr p2, v2

    .line 76
    check-cast p1, Ll2/t;

    .line 77
    .line 78
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 79
    .line 80
    .line 81
    move-result p2

    .line 82
    if-eqz p2, :cond_3

    .line 83
    .line 84
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 85
    .line 86
    const/high16 v0, 0x3f800000    # 1.0f

    .line 87
    .line 88
    invoke-static {p2, v0}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 89
    .line 90
    .line 91
    move-result-object p2

    .line 92
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 93
    .line 94
    invoke-virtual {p1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    check-cast v0, Lj91/e;

    .line 99
    .line 100
    invoke-virtual {v0}, Lj91/e;->b()J

    .line 101
    .line 102
    .line 103
    move-result-wide v0

    .line 104
    sget-object v2, Le3/j0;->a:Le3/i0;

    .line 105
    .line 106
    invoke-static {p2, v0, v1, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    sget-object p2, Lj91/a;->a:Ll2/u2;

    .line 111
    .line 112
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    check-cast v0, Lj91/c;

    .line 117
    .line 118
    iget v4, v0, Lj91/c;->e:F

    .line 119
    .line 120
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    check-cast v0, Lj91/c;

    .line 125
    .line 126
    iget v6, v0, Lj91/c;->b:F

    .line 127
    .line 128
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p2

    .line 132
    check-cast p2, Lj91/c;

    .line 133
    .line 134
    iget v5, p2, Lj91/c;->e:F

    .line 135
    .line 136
    const/4 v7, 0x0

    .line 137
    const/16 v8, 0x8

    .line 138
    .line 139
    invoke-static/range {v3 .. v8}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 140
    .line 141
    .line 142
    move-result-object p2

    .line 143
    iget-object v0, p0, Li00/b;->e:Lh00/b;

    .line 144
    .line 145
    iget-object p0, p0, Li00/b;->f:Lay0/a;

    .line 146
    .line 147
    const/16 v1, 0x8

    .line 148
    .line 149
    invoke-static {v0, p0, p2, p1, v1}, Li00/c;->a(Lh00/b;Lay0/a;Lx2/s;Ll2/o;I)V

    .line 150
    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 154
    .line 155
    .line 156
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 157
    .line 158
    return-object p0

    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
