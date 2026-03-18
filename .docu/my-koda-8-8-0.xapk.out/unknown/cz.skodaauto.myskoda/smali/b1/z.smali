.class public final Lb1/z;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lb1/z;->f:I

    .line 2
    .line 3
    iput-object p2, p0, Lb1/z;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lb1/z;->h:Ljava/lang/Object;

    .line 6
    .line 7
    const/4 p1, 0x3

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lb1/z;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    move-object v7, p2

    .line 13
    check-cast v7, Ll2/o;

    .line 14
    .line 15
    check-cast p3, Ljava/lang/Number;

    .line 16
    .line 17
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    and-int/lit8 p3, p2, 0xe

    .line 22
    .line 23
    if-nez p3, :cond_1

    .line 24
    .line 25
    move-object p3, v7

    .line 26
    check-cast p3, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {p3, p1}, Ll2/t;->e(I)Z

    .line 29
    .line 30
    .line 31
    move-result p3

    .line 32
    if-eqz p3, :cond_0

    .line 33
    .line 34
    const/4 p3, 0x4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 p3, 0x2

    .line 37
    :goto_0
    or-int/2addr p2, p3

    .line 38
    :cond_1
    and-int/lit8 p2, p2, 0x5b

    .line 39
    .line 40
    const/16 p3, 0x12

    .line 41
    .line 42
    if-ne p2, p3, :cond_3

    .line 43
    .line 44
    move-object p2, v7

    .line 45
    check-cast p2, Ll2/t;

    .line 46
    .line 47
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 48
    .line 49
    .line 50
    move-result p3

    .line 51
    if-nez p3, :cond_2

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_2
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 55
    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_3
    :goto_1
    iget-object p2, p0, Lb1/z;->g:Ljava/lang/Object;

    .line 59
    .line 60
    move-object v0, p2

    .line 61
    check-cast v0, Lvv/m0;

    .line 62
    .line 63
    iget-object p0, p0, Lb1/z;->h:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast p0, [Ljava/lang/String;

    .line 66
    .line 67
    array-length p2, p0

    .line 68
    rem-int/2addr p1, p2

    .line 69
    aget-object v1, p0, p1

    .line 70
    .line 71
    const/4 v6, 0x0

    .line 72
    const/4 v8, 0x0

    .line 73
    const/4 v2, 0x0

    .line 74
    const/4 v3, 0x0

    .line 75
    const/4 v4, 0x0

    .line 76
    const/4 v5, 0x0

    .line 77
    invoke-static/range {v0 .. v8}, Lvv/l0;->c(Lvv/m0;Ljava/lang/String;Lx2/s;Lay0/k;IZILl2/o;I)V

    .line 78
    .line 79
    .line 80
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 81
    .line 82
    return-object p0

    .line 83
    :pswitch_0
    check-cast p1, Lt3/s0;

    .line 84
    .line 85
    check-cast p2, Lt3/p0;

    .line 86
    .line 87
    check-cast p3, Lt4/a;

    .line 88
    .line 89
    iget-wide v0, p3, Lt4/a;->a:J

    .line 90
    .line 91
    invoke-interface {p2, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 92
    .line 93
    .line 94
    move-result-object p2

    .line 95
    invoke-interface {p1}, Lt3/t;->I()Z

    .line 96
    .line 97
    .line 98
    move-result p3

    .line 99
    const-wide v0, 0xffffffffL

    .line 100
    .line 101
    .line 102
    .line 103
    .line 104
    const/16 v2, 0x20

    .line 105
    .line 106
    if-eqz p3, :cond_4

    .line 107
    .line 108
    iget-object p3, p0, Lb1/z;->g:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast p3, Lay0/k;

    .line 111
    .line 112
    iget-object p0, p0, Lb1/z;->h:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast p0, Lc1/w1;

    .line 115
    .line 116
    iget-object p0, p0, Lc1/w1;->d:Ll2/j1;

    .line 117
    .line 118
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    invoke-interface {p3, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    check-cast p0, Ljava/lang/Boolean;

    .line 127
    .line 128
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    if-nez p0, :cond_4

    .line 133
    .line 134
    const-wide/16 v3, 0x0

    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_4
    iget p0, p2, Lt3/e1;->d:I

    .line 138
    .line 139
    iget p3, p2, Lt3/e1;->e:I

    .line 140
    .line 141
    int-to-long v3, p0

    .line 142
    shl-long/2addr v3, v2

    .line 143
    int-to-long v5, p3

    .line 144
    and-long/2addr v5, v0

    .line 145
    or-long/2addr v3, v5

    .line 146
    :goto_3
    shr-long v5, v3, v2

    .line 147
    .line 148
    long-to-int p0, v5

    .line 149
    and-long/2addr v0, v3

    .line 150
    long-to-int p3, v0

    .line 151
    new-instance v0, Lb1/y;

    .line 152
    .line 153
    const/4 v1, 0x0

    .line 154
    invoke-direct {v0, p2, v1}, Lb1/y;-><init>(Lt3/e1;I)V

    .line 155
    .line 156
    .line 157
    sget-object p2, Lmx0/t;->d:Lmx0/t;

    .line 158
    .line 159
    invoke-interface {p1, p0, p3, p2, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    return-object p0

    .line 164
    nop

    .line 165
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
