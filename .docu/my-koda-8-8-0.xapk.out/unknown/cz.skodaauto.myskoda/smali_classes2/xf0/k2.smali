.class public final synthetic Lxf0/k2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Li40/d;

.field public final synthetic f:J

.field public final synthetic g:F

.field public final synthetic h:F

.field public final synthetic i:F


# direct methods
.method public synthetic constructor <init>(FLi40/d;JFFF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lxf0/k2;->d:F

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/k2;->e:Li40/d;

    .line 7
    .line 8
    iput-wide p3, p0, Lxf0/k2;->f:J

    .line 9
    .line 10
    iput p5, p0, Lxf0/k2;->g:F

    .line 11
    .line 12
    iput p6, p0, Lxf0/k2;->h:F

    .line 13
    .line 14
    iput p7, p0, Lxf0/k2;->i:F

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    check-cast p1, Lv3/j0;

    .line 2
    .line 3
    const-string v0, "$this$drawWithContent"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Lv3/j0;->b()V

    .line 9
    .line 10
    .line 11
    iget-object v0, p1, Lv3/j0;->d:Lg3/b;

    .line 12
    .line 13
    iget-object v1, v0, Lg3/b;->e:Lgw0/c;

    .line 14
    .line 15
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-interface {v0}, Lg3/d;->e()J

    .line 20
    .line 21
    .line 22
    move-result-wide v2

    .line 23
    const/16 v4, 0x20

    .line 24
    .line 25
    shr-long/2addr v2, v4

    .line 26
    long-to-int v2, v2

    .line 27
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    iget v3, p0, Lxf0/k2;->d:F

    .line 32
    .line 33
    invoke-virtual {p1, v3}, Lv3/j0;->w0(F)F

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    add-float/2addr v5, v2

    .line 38
    invoke-interface {v0}, Lg3/d;->e()J

    .line 39
    .line 40
    .line 41
    move-result-wide v6

    .line 42
    const-wide v8, 0xffffffffL

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    and-long/2addr v6, v8

    .line 48
    long-to-int v2, v6

    .line 49
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    invoke-virtual {p1, v3}, Lv3/j0;->w0(F)F

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    add-float/2addr v3, v2

    .line 58
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    int-to-long v5, v2

    .line 63
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    int-to-long v2, v2

    .line 68
    shl-long v4, v5, v4

    .line 69
    .line 70
    and-long/2addr v2, v8

    .line 71
    or-long/2addr v2, v4

    .line 72
    invoke-virtual {p1}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    iget-object v5, p0, Lxf0/k2;->e:Li40/d;

    .line 77
    .line 78
    invoke-virtual {v5, v2, v3, v4, p1}, Li40/d;->a(JLt4/m;Lt4/c;)Le3/g0;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    iget-wide v4, p0, Lxf0/k2;->f:J

    .line 87
    .line 88
    invoke-virtual {v3, v4, v5}, Le3/g;->e(J)V

    .line 89
    .line 90
    .line 91
    invoke-interface {v0}, Lg3/d;->e()J

    .line 92
    .line 93
    .line 94
    move-result-wide v4

    .line 95
    const-wide/16 v6, 0x0

    .line 96
    .line 97
    invoke-static {v6, v7, v4, v5}, Ljp/cf;->c(JJ)Ld3/c;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    invoke-interface {v1, v0, v3}, Le3/r;->t(Ld3/c;Le3/g;)V

    .line 102
    .line 103
    .line 104
    invoke-static {v1, v2, v3}, Le3/j0;->m(Le3/r;Le3/g0;Le3/g;)V

    .line 105
    .line 106
    .line 107
    iget-object v0, v3, Le3/g;->a:Landroid/graphics/Paint;

    .line 108
    .line 109
    new-instance v4, Landroid/graphics/PorterDuffXfermode;

    .line 110
    .line 111
    sget-object v5, Landroid/graphics/PorterDuff$Mode;->DST_OUT:Landroid/graphics/PorterDuff$Mode;

    .line 112
    .line 113
    invoke-direct {v4, v5}, Landroid/graphics/PorterDuffXfermode;-><init>(Landroid/graphics/PorterDuff$Mode;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v0, v4}, Landroid/graphics/Paint;->setXfermode(Landroid/graphics/Xfermode;)Landroid/graphics/Xfermode;

    .line 117
    .line 118
    .line 119
    iget v4, p0, Lxf0/k2;->i:F

    .line 120
    .line 121
    invoke-virtual {p1, v4}, Lv3/j0;->w0(F)F

    .line 122
    .line 123
    .line 124
    move-result v5

    .line 125
    const/4 v6, 0x0

    .line 126
    cmpl-float v5, v5, v6

    .line 127
    .line 128
    if-lez v5, :cond_0

    .line 129
    .line 130
    new-instance v5, Landroid/graphics/BlurMaskFilter;

    .line 131
    .line 132
    invoke-virtual {p1, v4}, Lv3/j0;->w0(F)F

    .line 133
    .line 134
    .line 135
    move-result v4

    .line 136
    sget-object v6, Landroid/graphics/BlurMaskFilter$Blur;->NORMAL:Landroid/graphics/BlurMaskFilter$Blur;

    .line 137
    .line 138
    invoke-direct {v5, v4, v6}, Landroid/graphics/BlurMaskFilter;-><init>(FLandroid/graphics/BlurMaskFilter$Blur;)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v0, v5}, Landroid/graphics/Paint;->setMaskFilter(Landroid/graphics/MaskFilter;)Landroid/graphics/MaskFilter;

    .line 142
    .line 143
    .line 144
    :cond_0
    sget-wide v4, Le3/s;->b:J

    .line 145
    .line 146
    invoke-virtual {v3, v4, v5}, Le3/g;->e(J)V

    .line 147
    .line 148
    .line 149
    iget v0, p0, Lxf0/k2;->g:F

    .line 150
    .line 151
    invoke-virtual {p1, v0}, Lv3/j0;->w0(F)F

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    iget p0, p0, Lxf0/k2;->h:F

    .line 156
    .line 157
    invoke-virtual {p1, p0}, Lv3/j0;->w0(F)F

    .line 158
    .line 159
    .line 160
    move-result p0

    .line 161
    invoke-interface {v1, v0, p0}, Le3/r;->h(FF)V

    .line 162
    .line 163
    .line 164
    invoke-static {v1, v2, v3}, Le3/j0;->m(Le3/r;Le3/g0;Le3/g;)V

    .line 165
    .line 166
    .line 167
    invoke-interface {v1}, Le3/r;->i()V

    .line 168
    .line 169
    .line 170
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 171
    .line 172
    return-object p0
.end method
