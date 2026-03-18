.class public final synthetic Lxf0/h2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:Lxf0/t3;

.field public final synthetic h:F

.field public final synthetic i:I


# direct methods
.method public synthetic constructor <init>(JJLxf0/t3;FII)V
    .locals 0

    .line 1
    iput p8, p0, Lxf0/h2;->d:I

    .line 2
    .line 3
    iput-wide p1, p0, Lxf0/h2;->e:J

    .line 4
    .line 5
    iput-wide p3, p0, Lxf0/h2;->f:J

    .line 6
    .line 7
    iput-object p5, p0, Lxf0/h2;->g:Lxf0/t3;

    .line 8
    .line 9
    iput p6, p0, Lxf0/h2;->h:F

    .line 10
    .line 11
    iput p7, p0, Lxf0/h2;->i:I

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lxf0/h2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v1, p1

    .line 7
    check-cast v1, Lv3/j0;

    .line 8
    .line 9
    const-string p1, "$this$onDrawWithContent"

    .line 10
    .line 11
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object p1, v1, Lv3/j0;->d:Lg3/b;

    .line 15
    .line 16
    invoke-virtual {v1}, Lv3/j0;->b()V

    .line 17
    .line 18
    .line 19
    new-instance v0, Le3/s;

    .line 20
    .line 21
    iget-wide v2, p0, Lxf0/h2;->e:J

    .line 22
    .line 23
    invoke-direct {v0, v2, v3}, Le3/s;-><init>(J)V

    .line 24
    .line 25
    .line 26
    new-instance v2, Le3/s;

    .line 27
    .line 28
    iget-wide v3, p0, Lxf0/h2;->f:J

    .line 29
    .line 30
    invoke-direct {v2, v3, v4}, Le3/s;-><init>(J)V

    .line 31
    .line 32
    .line 33
    filled-new-array {v0, v2}, [Le3/s;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    iget-object v2, p0, Lxf0/h2;->g:Lxf0/t3;

    .line 42
    .line 43
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    iget v4, p0, Lxf0/h2;->h:F

    .line 48
    .line 49
    const-wide v5, 0xffffffffL

    .line 50
    .line 51
    .line 52
    .line 53
    .line 54
    const/4 v7, 0x1

    .line 55
    if-eqz v3, :cond_1

    .line 56
    .line 57
    if-ne v3, v7, :cond_0

    .line 58
    .line 59
    invoke-interface {p1}, Lg3/d;->e()J

    .line 60
    .line 61
    .line 62
    move-result-wide v8

    .line 63
    and-long/2addr v8, v5

    .line 64
    long-to-int v3, v8

    .line 65
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    invoke-virtual {v1, v4}, Lv3/j0;->w0(F)F

    .line 70
    .line 71
    .line 72
    move-result v8

    .line 73
    sub-float/2addr v3, v8

    .line 74
    goto :goto_0

    .line 75
    :cond_0
    new-instance p0, La8/r0;

    .line 76
    .line 77
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_1
    const/4 v3, 0x0

    .line 82
    :goto_0
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    if-eqz v2, :cond_3

    .line 87
    .line 88
    if-ne v2, v7, :cond_2

    .line 89
    .line 90
    invoke-interface {p1}, Lg3/d;->e()J

    .line 91
    .line 92
    .line 93
    move-result-wide v7

    .line 94
    and-long v4, v7, v5

    .line 95
    .line 96
    long-to-int p1, v4

    .line 97
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 98
    .line 99
    .line 100
    move-result p1

    .line 101
    goto :goto_1

    .line 102
    :cond_2
    new-instance p0, La8/r0;

    .line 103
    .line 104
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 105
    .line 106
    .line 107
    throw p0

    .line 108
    :cond_3
    invoke-virtual {v1, v4}, Lv3/j0;->w0(F)F

    .line 109
    .line 110
    .line 111
    move-result p1

    .line 112
    :goto_1
    const/16 v2, 0x8

    .line 113
    .line 114
    invoke-static {v0, v3, p1, v2}, Lpy/a;->t(Ljava/util/List;FFI)Le3/b0;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    const/4 v8, 0x0

    .line 119
    const/16 v10, 0x3e

    .line 120
    .line 121
    const-wide/16 v3, 0x0

    .line 122
    .line 123
    const-wide/16 v5, 0x0

    .line 124
    .line 125
    const/4 v7, 0x0

    .line 126
    iget v9, p0, Lxf0/h2;->i:I

    .line 127
    .line 128
    invoke-static/range {v1 .. v10}, Lg3/d;->i0(Lg3/d;Le3/p;JJFLg3/e;II)V

    .line 129
    .line 130
    .line 131
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    return-object p0

    .line 134
    :pswitch_0
    check-cast p1, Lb3/d;

    .line 135
    .line 136
    const-string v0, "$this$drawWithCache"

    .line 137
    .line 138
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    new-instance v1, Lxf0/h2;

    .line 142
    .line 143
    const/4 v9, 0x1

    .line 144
    iget-wide v2, p0, Lxf0/h2;->e:J

    .line 145
    .line 146
    iget-wide v4, p0, Lxf0/h2;->f:J

    .line 147
    .line 148
    iget-object v6, p0, Lxf0/h2;->g:Lxf0/t3;

    .line 149
    .line 150
    iget v7, p0, Lxf0/h2;->h:F

    .line 151
    .line 152
    iget v8, p0, Lxf0/h2;->i:I

    .line 153
    .line 154
    invoke-direct/range {v1 .. v9}, Lxf0/h2;-><init>(JJLxf0/t3;FII)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {p1, v1}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    return-object p0

    .line 162
    nop

    .line 163
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
