.class public final synthetic Li40/l2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(III)V
    .locals 0

    .line 1
    iput p3, p0, Li40/l2;->d:I

    .line 2
    .line 3
    iput p1, p0, Li40/l2;->e:I

    .line 4
    .line 5
    iput p2, p0, Li40/l2;->f:I

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Li40/l2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lt3/s0;

    .line 7
    .line 8
    check-cast p2, Lt3/p0;

    .line 9
    .line 10
    check-cast p3, Lt4/a;

    .line 11
    .line 12
    const-string v0, "$this$layout"

    .line 13
    .line 14
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v0, "measurable"

    .line 18
    .line 19
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-wide v0, p3, Lt4/a;->a:J

    .line 23
    .line 24
    invoke-interface {p2, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    iget p3, p2, Lt3/e1;->e:I

    .line 29
    .line 30
    new-instance v0, Li2/a;

    .line 31
    .line 32
    const/4 v1, 0x3

    .line 33
    iget v2, p0, Li40/l2;->f:I

    .line 34
    .line 35
    invoke-direct {v0, p2, v2, v1}, Li2/a;-><init>(Lt3/e1;II)V

    .line 36
    .line 37
    .line 38
    sget-object p2, Lmx0/t;->d:Lmx0/t;

    .line 39
    .line 40
    iget p0, p0, Li40/l2;->e:I

    .line 41
    .line 42
    invoke-interface {p1, p0, p3, p2, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_0
    check-cast p1, Lk1/k0;

    .line 48
    .line 49
    check-cast p2, Ll2/o;

    .line 50
    .line 51
    check-cast p3, Ljava/lang/Integer;

    .line 52
    .line 53
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 54
    .line 55
    .line 56
    move-result p3

    .line 57
    const-string v0, "$this$FlowRow"

    .line 58
    .line 59
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    and-int/lit8 p1, p3, 0x11

    .line 63
    .line 64
    const/16 v0, 0x10

    .line 65
    .line 66
    const/4 v1, 0x1

    .line 67
    const/4 v2, 0x0

    .line 68
    if-eq p1, v0, :cond_0

    .line 69
    .line 70
    move p1, v1

    .line 71
    goto :goto_0

    .line 72
    :cond_0
    move p1, v2

    .line 73
    :goto_0
    and-int/2addr p3, v1

    .line 74
    move-object v8, p2

    .line 75
    check-cast v8, Ll2/t;

    .line 76
    .line 77
    invoke-virtual {v8, p3, p1}, Ll2/t;->O(IZ)Z

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    if-eqz p1, :cond_2

    .line 82
    .line 83
    move p1, v2

    .line 84
    :goto_1
    iget p2, p0, Li40/l2;->e:I

    .line 85
    .line 86
    if-ge p1, p2, :cond_3

    .line 87
    .line 88
    const p2, 0x7f0803de

    .line 89
    .line 90
    .line 91
    invoke-static {p2, v2, v8}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 96
    .line 97
    sget p3, Li40/m2;->a:F

    .line 98
    .line 99
    invoke-static {p2, p3}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 100
    .line 101
    .line 102
    move-result-object v5

    .line 103
    iget p2, p0, Li40/l2;->f:I

    .line 104
    .line 105
    if-ge p1, p2, :cond_1

    .line 106
    .line 107
    const p2, -0x4f92fa22

    .line 108
    .line 109
    .line 110
    invoke-virtual {v8, p2}, Ll2/t;->Y(I)V

    .line 111
    .line 112
    .line 113
    sget-object p2, Lj91/h;->a:Ll2/u2;

    .line 114
    .line 115
    invoke-virtual {v8, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p2

    .line 119
    check-cast p2, Lj91/e;

    .line 120
    .line 121
    invoke-virtual {p2}, Lj91/e;->a()J

    .line 122
    .line 123
    .line 124
    move-result-wide p2

    .line 125
    invoke-virtual {v8, v2}, Ll2/t;->q(Z)V

    .line 126
    .line 127
    .line 128
    :goto_2
    move-wide v6, p2

    .line 129
    goto :goto_3

    .line 130
    :cond_1
    const p2, -0x4f91f14d

    .line 131
    .line 132
    .line 133
    invoke-virtual {v8, p2}, Ll2/t;->Y(I)V

    .line 134
    .line 135
    .line 136
    sget-object p2, Lj91/h;->a:Ll2/u2;

    .line 137
    .line 138
    invoke-virtual {v8, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p2

    .line 142
    check-cast p2, Lj91/e;

    .line 143
    .line 144
    invoke-virtual {p2}, Lj91/e;->p()J

    .line 145
    .line 146
    .line 147
    move-result-wide p2

    .line 148
    invoke-virtual {v8, v2}, Ll2/t;->q(Z)V

    .line 149
    .line 150
    .line 151
    goto :goto_2

    .line 152
    :goto_3
    const/16 v9, 0x1b0

    .line 153
    .line 154
    const/4 v10, 0x0

    .line 155
    const/4 v4, 0x0

    .line 156
    invoke-static/range {v3 .. v10}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 157
    .line 158
    .line 159
    add-int/lit8 p1, p1, 0x1

    .line 160
    .line 161
    goto :goto_1

    .line 162
    :cond_2
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 163
    .line 164
    .line 165
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    return-object p0

    .line 168
    nop

    .line 169
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
