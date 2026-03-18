.class public final synthetic Lxf0/q2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:J

.field public final synthetic f:Le3/f;

.field public final synthetic g:J

.field public final synthetic h:F


# direct methods
.method public synthetic constructor <init>(JJLe3/f;JF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lxf0/q2;->d:J

    .line 5
    .line 6
    iput-wide p3, p0, Lxf0/q2;->e:J

    .line 7
    .line 8
    iput-object p5, p0, Lxf0/q2;->f:Le3/f;

    .line 9
    .line 10
    iput-wide p6, p0, Lxf0/q2;->g:J

    .line 11
    .line 12
    iput p8, p0, Lxf0/q2;->h:F

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lg3/d;

    .line 3
    .line 4
    const-string p1, "$this$Canvas"

    .line 5
    .line 6
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    sget p1, Lxf0/r2;->c:F

    .line 10
    .line 11
    invoke-interface {v0, p1}, Lt4/c;->w0(F)F

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    const/4 v6, 0x0

    .line 16
    const/16 v7, 0x7c

    .line 17
    .line 18
    iget-wide v1, p0, Lxf0/q2;->d:J

    .line 19
    .line 20
    const-wide/16 v4, 0x0

    .line 21
    .line 22
    invoke-static/range {v0 .. v7}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 23
    .line 24
    .line 25
    move-wide v8, v1

    .line 26
    invoke-interface {v0, p1}, Lt4/c;->w0(F)F

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    iget-wide v1, p0, Lxf0/q2;->e:J

    .line 31
    .line 32
    invoke-static/range {v0 .. v7}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 33
    .line 34
    .line 35
    sget v1, Lxf0/r2;->b:F

    .line 36
    .line 37
    sub-float/2addr p1, v1

    .line 38
    invoke-interface {v0, p1}, Lt4/c;->w0(F)F

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    move-wide v1, v8

    .line 43
    invoke-static/range {v0 .. v7}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 44
    .line 45
    .line 46
    invoke-interface {v0}, Lg3/d;->D0()J

    .line 47
    .line 48
    .line 49
    move-result-wide v1

    .line 50
    const/16 p1, 0x20

    .line 51
    .line 52
    shr-long/2addr v1, p1

    .line 53
    long-to-int v1, v1

    .line 54
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    move v2, v1

    .line 59
    iget-object v1, p0, Lxf0/q2;->f:Le3/f;

    .line 60
    .line 61
    iget-object v3, v1, Le3/f;->a:Landroid/graphics/Bitmap;

    .line 62
    .line 63
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getWidth()I

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    div-int/lit8 v4, v4, 0x2

    .line 68
    .line 69
    int-to-float v4, v4

    .line 70
    sub-float/2addr v2, v4

    .line 71
    invoke-interface {v0}, Lg3/d;->D0()J

    .line 72
    .line 73
    .line 74
    move-result-wide v4

    .line 75
    const-wide v6, 0xffffffffL

    .line 76
    .line 77
    .line 78
    .line 79
    .line 80
    and-long/2addr v4, v6

    .line 81
    long-to-int v4, v4

    .line 82
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 83
    .line 84
    .line 85
    move-result v4

    .line 86
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getHeight()I

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    div-int/lit8 v3, v3, 0x2

    .line 91
    .line 92
    int-to-float v3, v3

    .line 93
    sub-float/2addr v4, v3

    .line 94
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    int-to-long v2, v2

    .line 99
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 100
    .line 101
    .line 102
    move-result v4

    .line 103
    int-to-long v4, v4

    .line 104
    shl-long/2addr v2, p1

    .line 105
    and-long/2addr v4, v6

    .line 106
    or-long/2addr v2, v4

    .line 107
    new-instance v5, Le3/m;

    .line 108
    .line 109
    iget-wide v6, p0, Lxf0/q2;->g:J

    .line 110
    .line 111
    const/4 p1, 0x5

    .line 112
    invoke-direct {v5, v6, v7, p1}, Le3/m;-><init>(JI)V

    .line 113
    .line 114
    .line 115
    const/16 v6, 0x28

    .line 116
    .line 117
    iget v4, p0, Lxf0/q2;->h:F

    .line 118
    .line 119
    invoke-static/range {v0 .. v6}, Lg3/d;->v(Lg3/d;Le3/f;JFLe3/m;I)V

    .line 120
    .line 121
    .line 122
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 123
    .line 124
    return-object p0
.end method
