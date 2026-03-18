.class public final Lsm/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public static a(Landroid/graphics/drawable/Drawable;Landroid/graphics/Bitmap$Config;Lnm/h;Lnm/g;Z)Landroid/graphics/Bitmap;
    .locals 8

    .line 1
    instance-of v0, p0, Landroid/graphics/drawable/BitmapDrawable;

    .line 2
    .line 3
    const-wide v1, 0xffffffffL

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    const/16 v3, 0x20

    .line 9
    .line 10
    if-eqz v0, :cond_3

    .line 11
    .line 12
    move-object v0, p0

    .line 13
    check-cast v0, Landroid/graphics/drawable/BitmapDrawable;

    .line 14
    .line 15
    invoke-virtual {v0}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    if-eqz p1, :cond_1

    .line 24
    .line 25
    sget-object v5, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 26
    .line 27
    if-ne p1, v5, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    move-object v5, p1

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    :goto_0
    sget-object v5, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 33
    .line 34
    :goto_1
    if-ne v4, v5, :cond_3

    .line 35
    .line 36
    if-eqz p4, :cond_2

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_2
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getWidth()I

    .line 40
    .line 41
    .line 42
    move-result p4

    .line 43
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getHeight()I

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    sget-object v5, Lnm/h;->c:Lnm/h;

    .line 48
    .line 49
    invoke-static {p4, v4, p2, p3, v5}, Lno/nordicsemi/android/ble/d;->d(IILnm/h;Lnm/g;Lnm/h;)J

    .line 50
    .line 51
    .line 52
    move-result-wide v4

    .line 53
    shr-long v6, v4, v3

    .line 54
    .line 55
    long-to-int p4, v6

    .line 56
    and-long/2addr v4, v1

    .line 57
    long-to-int v4, v4

    .line 58
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getWidth()I

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getHeight()I

    .line 63
    .line 64
    .line 65
    move-result v6

    .line 66
    invoke-static {v5, v6, p4, v4, p3}, Lno/nordicsemi/android/ble/d;->e(IIIILnm/g;)D

    .line 67
    .line 68
    .line 69
    move-result-wide v4

    .line 70
    const-wide/high16 v6, 0x3ff0000000000000L    # 1.0

    .line 71
    .line 72
    cmpg-double p4, v4, v6

    .line 73
    .line 74
    if-nez p4, :cond_3

    .line 75
    .line 76
    :goto_2
    return-object v0

    .line 77
    :cond_3
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->mutate()Landroid/graphics/drawable/Drawable;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    invoke-static {p0}, Lsm/i;->b(Landroid/graphics/drawable/Drawable;)I

    .line 82
    .line 83
    .line 84
    move-result p4

    .line 85
    const/16 v0, 0x200

    .line 86
    .line 87
    if-lez p4, :cond_4

    .line 88
    .line 89
    goto :goto_3

    .line 90
    :cond_4
    move p4, v0

    .line 91
    :goto_3
    invoke-static {p0}, Lsm/i;->a(Landroid/graphics/drawable/Drawable;)I

    .line 92
    .line 93
    .line 94
    move-result v4

    .line 95
    if-lez v4, :cond_5

    .line 96
    .line 97
    move v0, v4

    .line 98
    :cond_5
    sget-object v4, Lnm/h;->c:Lnm/h;

    .line 99
    .line 100
    invoke-static {p4, v0, p2, p3, v4}, Lno/nordicsemi/android/ble/d;->d(IILnm/h;Lnm/g;Lnm/h;)J

    .line 101
    .line 102
    .line 103
    move-result-wide v4

    .line 104
    shr-long v6, v4, v3

    .line 105
    .line 106
    long-to-int p2, v6

    .line 107
    and-long/2addr v1, v4

    .line 108
    long-to-int v1, v1

    .line 109
    invoke-static {p4, v0, p2, v1, p3}, Lno/nordicsemi/android/ble/d;->e(IIIILnm/g;)D

    .line 110
    .line 111
    .line 112
    move-result-wide p2

    .line 113
    int-to-double v1, p4

    .line 114
    mul-double/2addr v1, p2

    .line 115
    invoke-static {v1, v2}, Lcy0/a;->h(D)I

    .line 116
    .line 117
    .line 118
    move-result p4

    .line 119
    int-to-double v0, v0

    .line 120
    mul-double/2addr p2, v0

    .line 121
    invoke-static {p2, p3}, Lcy0/a;->h(D)I

    .line 122
    .line 123
    .line 124
    move-result p2

    .line 125
    if-eqz p1, :cond_6

    .line 126
    .line 127
    sget-object p3, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 128
    .line 129
    if-ne p1, p3, :cond_7

    .line 130
    .line 131
    :cond_6
    sget-object p1, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 132
    .line 133
    :cond_7
    invoke-static {p4, p2, p1}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 138
    .line 139
    .line 140
    move-result-object p3

    .line 141
    iget v0, p3, Landroid/graphics/Rect;->left:I

    .line 142
    .line 143
    iget v1, p3, Landroid/graphics/Rect;->top:I

    .line 144
    .line 145
    iget v2, p3, Landroid/graphics/Rect;->right:I

    .line 146
    .line 147
    iget p3, p3, Landroid/graphics/Rect;->bottom:I

    .line 148
    .line 149
    const/4 v3, 0x0

    .line 150
    invoke-virtual {p0, v3, v3, p4, p2}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 151
    .line 152
    .line 153
    new-instance p2, Landroid/graphics/Canvas;

    .line 154
    .line 155
    invoke-direct {p2, p1}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {p0, p2}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {p0, v0, v1, v2, p3}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 162
    .line 163
    .line 164
    return-object p1
.end method
