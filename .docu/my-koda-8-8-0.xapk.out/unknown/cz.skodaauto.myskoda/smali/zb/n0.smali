.class public final synthetic Lzb/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:F

.field public final synthetic f:Le3/b0;

.field public final synthetic g:F


# direct methods
.method public synthetic constructor <init>(FFLe3/b0;F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lzb/n0;->d:F

    .line 5
    .line 6
    iput p2, p0, Lzb/n0;->e:F

    .line 7
    .line 8
    iput-object p3, p0, Lzb/n0;->f:Le3/b0;

    .line 9
    .line 10
    iput p4, p0, Lzb/n0;->g:F

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lv3/j0;

    .line 6
    .line 7
    const-string v2, "$this$drawWithContent"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v2, v1, Lv3/j0;->d:Lg3/b;

    .line 13
    .line 14
    invoke-interface {v2}, Lg3/d;->e()J

    .line 15
    .line 16
    .line 17
    move-result-wide v3

    .line 18
    const/16 v5, 0x20

    .line 19
    .line 20
    shr-long/2addr v3, v5

    .line 21
    long-to-int v3, v3

    .line 22
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    const/4 v4, 0x2

    .line 27
    int-to-float v4, v4

    .line 28
    iget v6, v0, Lzb/n0;->d:F

    .line 29
    .line 30
    mul-float/2addr v6, v4

    .line 31
    :goto_0
    cmpl-float v7, v6, v3

    .line 32
    .line 33
    const/high16 v8, 0x40000000    # 2.0f

    .line 34
    .line 35
    if-lez v7, :cond_0

    .line 36
    .line 37
    div-float/2addr v6, v8

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    invoke-interface {v2}, Lg3/d;->e()J

    .line 40
    .line 41
    .line 42
    move-result-wide v9

    .line 43
    const-wide v11, 0xffffffffL

    .line 44
    .line 45
    .line 46
    .line 47
    .line 48
    and-long/2addr v9, v11

    .line 49
    long-to-int v3, v9

    .line 50
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    iget v7, v0, Lzb/n0;->e:F

    .line 55
    .line 56
    mul-float/2addr v7, v4

    .line 57
    :goto_1
    cmpl-float v9, v7, v3

    .line 58
    .line 59
    if-lez v9, :cond_1

    .line 60
    .line 61
    div-float/2addr v7, v8

    .line 62
    goto :goto_1

    .line 63
    :cond_1
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    int-to-long v8, v3

    .line 68
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    int-to-long v13, v3

    .line 73
    shl-long/2addr v8, v5

    .line 74
    and-long/2addr v13, v11

    .line 75
    or-long/2addr v8, v13

    .line 76
    invoke-interface {v2}, Lg3/d;->e()J

    .line 77
    .line 78
    .line 79
    move-result-wide v13

    .line 80
    shr-long/2addr v13, v5

    .line 81
    long-to-int v3, v13

    .line 82
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 83
    .line 84
    .line 85
    move-result v3

    .line 86
    mul-float/2addr v6, v4

    .line 87
    sub-float/2addr v3, v6

    .line 88
    invoke-interface {v2}, Lg3/d;->e()J

    .line 89
    .line 90
    .line 91
    move-result-wide v13

    .line 92
    and-long/2addr v13, v11

    .line 93
    long-to-int v2, v13

    .line 94
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    mul-float/2addr v4, v7

    .line 99
    sub-float/2addr v2, v4

    .line 100
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 101
    .line 102
    .line 103
    move-result v3

    .line 104
    int-to-long v3, v3

    .line 105
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    int-to-long v6, v2

    .line 110
    shl-long v2, v3, v5

    .line 111
    .line 112
    and-long/2addr v6, v11

    .line 113
    or-long/2addr v2, v6

    .line 114
    iget v4, v0, Lzb/n0;->g:F

    .line 115
    .line 116
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 117
    .line 118
    .line 119
    move-result v6

    .line 120
    int-to-long v6, v6

    .line 121
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 122
    .line 123
    .line 124
    move-result v4

    .line 125
    int-to-long v13, v4

    .line 126
    shl-long v4, v6, v5

    .line 127
    .line 128
    and-long v6, v13, v11

    .line 129
    .line 130
    or-long/2addr v6, v4

    .line 131
    move-wide v4, v2

    .line 132
    move-wide v2, v8

    .line 133
    const/4 v8, 0x0

    .line 134
    const/16 v9, 0xf0

    .line 135
    .line 136
    iget-object v0, v0, Lzb/n0;->f:Le3/b0;

    .line 137
    .line 138
    move-object v15, v1

    .line 139
    move-object v1, v0

    .line 140
    move-object v0, v15

    .line 141
    invoke-static/range {v0 .. v9}, Lg3/d;->I0(Lv3/j0;Le3/p;JJJLg3/e;I)V

    .line 142
    .line 143
    .line 144
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 145
    .line 146
    return-object v0
.end method
