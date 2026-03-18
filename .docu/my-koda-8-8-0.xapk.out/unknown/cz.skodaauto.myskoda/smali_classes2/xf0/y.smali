.class public final Lxf0/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Z

.field public final synthetic f:Lvf0/a;

.field public final synthetic g:J

.field public final synthetic h:F


# direct methods
.method public constructor <init>(ZZLvf0/a;JF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lxf0/y;->d:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Lxf0/y;->e:Z

    .line 7
    .line 8
    iput-object p3, p0, Lxf0/y;->f:Lvf0/a;

    .line 9
    .line 10
    iput-wide p4, p0, Lxf0/y;->g:J

    .line 11
    .line 12
    iput p6, p0, Lxf0/y;->h:F

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lv3/j0;

    .line 3
    .line 4
    const-string p1, "$this$drawWithContent"

    .line 5
    .line 6
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iget-object p1, v0, Lv3/j0;->d:Lg3/b;

    .line 10
    .line 11
    invoke-virtual {v0}, Lv3/j0;->b()V

    .line 12
    .line 13
    .line 14
    iget-boolean v1, p0, Lxf0/y;->d:Z

    .line 15
    .line 16
    if-eqz v1, :cond_1

    .line 17
    .line 18
    iget-boolean v1, p0, Lxf0/y;->e:Z

    .line 19
    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    iget-object v1, p0, Lxf0/y;->f:Lvf0/a;

    .line 23
    .line 24
    iget-object v2, v1, Lvf0/a;->d:Ljava/lang/Number;

    .line 25
    .line 26
    if-eqz v2, :cond_1

    .line 27
    .line 28
    iget v3, p0, Lxf0/y;->h:F

    .line 29
    .line 30
    invoke-virtual {v0, v3}, Lv3/j0;->w0(F)F

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    iget v1, v1, Lvf0/a;->c:I

    .line 35
    .line 36
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    sget v4, Lxf0/b0;->a:F

    .line 41
    .line 42
    invoke-interface {p1}, Lg3/d;->e()J

    .line 43
    .line 44
    .line 45
    move-result-wide v4

    .line 46
    const-wide v6, 0xffffffffL

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    and-long/2addr v4, v6

    .line 52
    long-to-int v4, v4

    .line 53
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    const/4 v5, 0x2

    .line 58
    int-to-float v5, v5

    .line 59
    mul-float/2addr v5, v3

    .line 60
    sub-float/2addr v4, v5

    .line 61
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    const/4 v8, 0x0

    .line 66
    cmpl-float v5, v5, v8

    .line 67
    .line 68
    if-lez v5, :cond_0

    .line 69
    .line 70
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    div-float/2addr v2, v1

    .line 79
    goto :goto_0

    .line 80
    :cond_0
    move v2, v8

    .line 81
    :goto_0
    const/4 v1, 0x1

    .line 82
    int-to-float v1, v1

    .line 83
    invoke-static {v1, v2, v4, v3}, La7/g0;->b(FFFF)F

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 88
    .line 89
    .line 90
    move-result v2

    .line 91
    int-to-long v2, v2

    .line 92
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 93
    .line 94
    .line 95
    move-result v4

    .line 96
    int-to-long v4, v4

    .line 97
    const/16 v8, 0x20

    .line 98
    .line 99
    shl-long/2addr v2, v8

    .line 100
    and-long/2addr v4, v6

    .line 101
    or-long v3, v2, v4

    .line 102
    .line 103
    invoke-interface {p1}, Lg3/d;->e()J

    .line 104
    .line 105
    .line 106
    move-result-wide v9

    .line 107
    shr-long/2addr v9, v8

    .line 108
    long-to-int p1, v9

    .line 109
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 114
    .line 115
    .line 116
    move-result p1

    .line 117
    int-to-long v9, p1

    .line 118
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 119
    .line 120
    .line 121
    move-result p1

    .line 122
    int-to-long v1, p1

    .line 123
    shl-long v8, v9, v8

    .line 124
    .line 125
    and-long/2addr v1, v6

    .line 126
    or-long v5, v8, v1

    .line 127
    .line 128
    const/4 v9, 0x0

    .line 129
    const/16 v10, 0x1f0

    .line 130
    .line 131
    iget-wide v1, p0, Lxf0/y;->g:J

    .line 132
    .line 133
    const/high16 v7, 0x40800000    # 4.0f

    .line 134
    .line 135
    const/4 v8, 0x0

    .line 136
    invoke-static/range {v0 .. v10}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 137
    .line 138
    .line 139
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    return-object p0
.end method
