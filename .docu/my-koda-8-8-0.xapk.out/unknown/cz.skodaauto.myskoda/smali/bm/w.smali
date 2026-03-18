.class public final Lbm/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/graphics/ImageDecoder$OnHeaderDecodedListener;


# instance fields
.field public final synthetic a:Lbm/e;

.field public final synthetic b:Lkotlin/jvm/internal/b0;


# direct methods
.method public constructor <init>(Lbm/e;Lkotlin/jvm/internal/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbm/w;->a:Lbm/e;

    .line 5
    .line 6
    iput-object p2, p0, Lbm/w;->b:Lkotlin/jvm/internal/b0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onHeaderDecoded(Landroid/graphics/ImageDecoder;Landroid/graphics/ImageDecoder$ImageInfo;Landroid/graphics/ImageDecoder$Source;)V
    .locals 7

    .line 1
    invoke-virtual {p2}, Landroid/graphics/ImageDecoder$ImageInfo;->getSize()Landroid/util/Size;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    invoke-virtual {p2}, Landroid/util/Size;->getWidth()I

    .line 6
    .line 7
    .line 8
    move-result p3

    .line 9
    invoke-virtual {p2}, Landroid/util/Size;->getHeight()I

    .line 10
    .line 11
    .line 12
    move-result p2

    .line 13
    iget-object v0, p0, Lbm/w;->a:Lbm/e;

    .line 14
    .line 15
    iget-object v0, v0, Lbm/e;->b:Lmm/n;

    .line 16
    .line 17
    iget-object v1, v0, Lmm/n;->b:Lnm/h;

    .line 18
    .line 19
    iget-object v2, v0, Lmm/n;->c:Lnm/g;

    .line 20
    .line 21
    sget-object v3, Lmm/h;->b:Ld8/c;

    .line 22
    .line 23
    invoke-static {v0, v3}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Lnm/h;

    .line 28
    .line 29
    invoke-static {p3, p2, v1, v2, v3}, Lno/nordicsemi/android/ble/d;->d(IILnm/h;Lnm/g;Lnm/h;)J

    .line 30
    .line 31
    .line 32
    move-result-wide v1

    .line 33
    const/16 v3, 0x20

    .line 34
    .line 35
    shr-long v3, v1, v3

    .line 36
    .line 37
    long-to-int v3, v3

    .line 38
    const-wide v4, 0xffffffffL

    .line 39
    .line 40
    .line 41
    .line 42
    .line 43
    and-long/2addr v1, v4

    .line 44
    long-to-int v1, v1

    .line 45
    const/4 v2, 0x1

    .line 46
    if-lez p3, :cond_3

    .line 47
    .line 48
    if-lez p2, :cond_3

    .line 49
    .line 50
    if-ne p3, v3, :cond_0

    .line 51
    .line 52
    if-eq p2, v1, :cond_3

    .line 53
    .line 54
    :cond_0
    iget-object v4, v0, Lmm/n;->c:Lnm/g;

    .line 55
    .line 56
    invoke-static {p3, p2, v3, v1, v4}, Lno/nordicsemi/android/ble/d;->e(IIIILnm/g;)D

    .line 57
    .line 58
    .line 59
    move-result-wide v3

    .line 60
    const-wide/high16 v5, 0x3ff0000000000000L    # 1.0

    .line 61
    .line 62
    cmpg-double v1, v3, v5

    .line 63
    .line 64
    if-gez v1, :cond_1

    .line 65
    .line 66
    move v1, v2

    .line 67
    goto :goto_0

    .line 68
    :cond_1
    const/4 v1, 0x0

    .line 69
    :goto_0
    iget-object p0, p0, Lbm/w;->b:Lkotlin/jvm/internal/b0;

    .line 70
    .line 71
    iput-boolean v1, p0, Lkotlin/jvm/internal/b0;->d:Z

    .line 72
    .line 73
    if-nez v1, :cond_2

    .line 74
    .line 75
    iget-object p0, v0, Lmm/n;->d:Lnm/d;

    .line 76
    .line 77
    sget-object v1, Lnm/d;->d:Lnm/d;

    .line 78
    .line 79
    if-ne p0, v1, :cond_3

    .line 80
    .line 81
    :cond_2
    int-to-double v5, p3

    .line 82
    mul-double/2addr v5, v3

    .line 83
    invoke-static {v5, v6}, Lcy0/a;->h(D)I

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    int-to-double p2, p2

    .line 88
    mul-double/2addr v3, p2

    .line 89
    invoke-static {v3, v4}, Lcy0/a;->h(D)I

    .line 90
    .line 91
    .line 92
    move-result p2

    .line 93
    invoke-virtual {p1, p0, p2}, Landroid/graphics/ImageDecoder;->setTargetSize(II)V

    .line 94
    .line 95
    .line 96
    :cond_3
    new-instance p0, Lbm/t;

    .line 97
    .line 98
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 99
    .line 100
    .line 101
    invoke-virtual {p1, p0}, Landroid/graphics/ImageDecoder;->setOnPartialImageListener(Landroid/graphics/ImageDecoder$OnPartialImageListener;)V

    .line 102
    .line 103
    .line 104
    invoke-static {v0}, Lmm/i;->a(Lmm/n;)Landroid/graphics/Bitmap$Config;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    sget-object p2, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 109
    .line 110
    if-ne p0, p2, :cond_4

    .line 111
    .line 112
    const/4 p0, 0x3

    .line 113
    goto :goto_1

    .line 114
    :cond_4
    move p0, v2

    .line 115
    :goto_1
    invoke-virtual {p1, p0}, Landroid/graphics/ImageDecoder;->setAllocator(I)V

    .line 116
    .line 117
    .line 118
    sget-object p0, Lmm/i;->g:Ld8/c;

    .line 119
    .line 120
    invoke-static {v0, p0}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    check-cast p0, Ljava/lang/Boolean;

    .line 125
    .line 126
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    xor-int/2addr p0, v2

    .line 131
    invoke-virtual {p1, p0}, Landroid/graphics/ImageDecoder;->setMemorySizePolicy(I)V

    .line 132
    .line 133
    .line 134
    sget-object p0, Lmm/i;->c:Ld8/c;

    .line 135
    .line 136
    invoke-static {v0, p0}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p2

    .line 140
    check-cast p2, Landroid/graphics/ColorSpace;

    .line 141
    .line 142
    if-eqz p2, :cond_5

    .line 143
    .line 144
    invoke-static {v0, p0}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    check-cast p0, Landroid/graphics/ColorSpace;

    .line 149
    .line 150
    invoke-virtual {p1, p0}, Landroid/graphics/ImageDecoder;->setTargetColorSpace(Landroid/graphics/ColorSpace;)V

    .line 151
    .line 152
    .line 153
    :cond_5
    sget-object p0, Lmm/i;->d:Ld8/c;

    .line 154
    .line 155
    invoke-static {v0, p0}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    check-cast p0, Ljava/lang/Boolean;

    .line 160
    .line 161
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    xor-int/2addr p0, v2

    .line 166
    invoke-virtual {p1, p0}, Landroid/graphics/ImageDecoder;->setUnpremultipliedRequired(Z)V

    .line 167
    .line 168
    .line 169
    return-void
.end method
