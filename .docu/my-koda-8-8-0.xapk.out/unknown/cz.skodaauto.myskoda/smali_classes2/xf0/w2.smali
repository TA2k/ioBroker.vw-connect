.class public final synthetic Lxf0/w2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J


# direct methods
.method public synthetic constructor <init>(IJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lxf0/w2;->d:I

    .line 5
    .line 6
    iput-wide p2, p0, Lxf0/w2;->e:J

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lg3/d;

    .line 3
    .line 4
    const-string v1, "$this$Canvas"

    .line 5
    .line 6
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    int-to-float v2, v1

    .line 11
    invoke-interface {v0, v2}, Lt4/c;->w0(F)F

    .line 12
    .line 13
    .line 14
    move-result v7

    .line 15
    invoke-interface {v0}, Lg3/d;->e()J

    .line 16
    .line 17
    .line 18
    move-result-wide v2

    .line 19
    const-wide v4, 0xffffffffL

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    and-long/2addr v2, v4

    .line 25
    long-to-int v2, v2

    .line 26
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    iget v3, p0, Lxf0/w2;->d:I

    .line 31
    .line 32
    int-to-float v3, v3

    .line 33
    sub-float/2addr v2, v3

    .line 34
    const/4 v6, 0x0

    .line 35
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 36
    .line 37
    .line 38
    move-result v8

    .line 39
    int-to-long v8, v8

    .line 40
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    int-to-long v10, v2

    .line 45
    const/16 v2, 0x20

    .line 46
    .line 47
    shl-long/2addr v8, v2

    .line 48
    and-long/2addr v10, v4

    .line 49
    or-long/2addr v8, v10

    .line 50
    invoke-interface {v0}, Lg3/d;->e()J

    .line 51
    .line 52
    .line 53
    move-result-wide v10

    .line 54
    shr-long/2addr v10, v2

    .line 55
    long-to-int v10, v10

    .line 56
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 57
    .line 58
    .line 59
    move-result v10

    .line 60
    invoke-interface {v0}, Lg3/d;->e()J

    .line 61
    .line 62
    .line 63
    move-result-wide v11

    .line 64
    and-long/2addr v11, v4

    .line 65
    long-to-int v11, v11

    .line 66
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 67
    .line 68
    .line 69
    move-result v11

    .line 70
    sub-float/2addr v11, v3

    .line 71
    invoke-static {v10}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    int-to-long v12, v3

    .line 76
    invoke-static {v11}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    int-to-long v10, v3

    .line 81
    shl-long v2, v12, v2

    .line 82
    .line 83
    and-long/2addr v4, v10

    .line 84
    or-long/2addr v2, v4

    .line 85
    const/4 v4, 0x2

    .line 86
    int-to-float v5, v4

    .line 87
    invoke-interface {v0, v5}, Lt4/c;->w0(F)F

    .line 88
    .line 89
    .line 90
    move-result v10

    .line 91
    invoke-interface {v0, v5}, Lt4/c;->w0(F)F

    .line 92
    .line 93
    .line 94
    move-result v5

    .line 95
    new-array v4, v4, [F

    .line 96
    .line 97
    const/4 v11, 0x0

    .line 98
    aput v10, v4, v11

    .line 99
    .line 100
    aput v5, v4, v1

    .line 101
    .line 102
    move-wide v10, v8

    .line 103
    new-instance v9, Le3/j;

    .line 104
    .line 105
    new-instance v1, Landroid/graphics/DashPathEffect;

    .line 106
    .line 107
    invoke-direct {v1, v4, v6}, Landroid/graphics/DashPathEffect;-><init>([FF)V

    .line 108
    .line 109
    .line 110
    invoke-direct {v9, v1}, Le3/j;-><init>(Landroid/graphics/DashPathEffect;)V

    .line 111
    .line 112
    .line 113
    const/4 v8, 0x0

    .line 114
    move-wide v5, v2

    .line 115
    move-wide v3, v10

    .line 116
    const/16 v10, 0x1d0

    .line 117
    .line 118
    iget-wide v1, p0, Lxf0/w2;->e:J

    .line 119
    .line 120
    invoke-static/range {v0 .. v10}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 121
    .line 122
    .line 123
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 124
    .line 125
    return-object p0
.end method
