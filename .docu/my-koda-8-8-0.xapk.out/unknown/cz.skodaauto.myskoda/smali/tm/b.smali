.class public final Ltm/b;
.super Landroid/text/style/BulletSpan;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Ltm/b;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:I

.field public final e:F

.field public final f:F

.field public final g:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ltm/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltm/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltm/b;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/os/Parcel;)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Landroid/os/Parcel;->readFloat()F

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p1}, Landroid/os/Parcel;->readFloat()F

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    invoke-direct {p0}, Landroid/text/style/BulletSpan;-><init>()V

    .line 18
    .line 19
    .line 20
    iput v0, p0, Ltm/b;->d:I

    .line 21
    .line 22
    iput v1, p0, Ltm/b;->e:F

    .line 23
    .line 24
    iput v2, p0, Ltm/b;->f:F

    .line 25
    .line 26
    iput p1, p0, Ltm/b;->g:I

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final drawLeadingMargin(Landroid/graphics/Canvas;Landroid/graphics/Paint;IIIIILjava/lang/CharSequence;IIZLandroid/text/Layout;)V
    .locals 1

    .line 1
    const-string p6, "canvas"

    .line 2
    .line 3
    invoke-static {p1, p6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p6, "paint"

    .line 7
    .line 8
    invoke-static {p2, p6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p6, "text"

    .line 12
    .line 13
    invoke-static {p8, p6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    check-cast p8, Landroid/text/Spanned;

    .line 17
    .line 18
    invoke-interface {p8, p0}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 19
    .line 20
    .line 21
    move-result p6

    .line 22
    if-ne p6, p9, :cond_4

    .line 23
    .line 24
    invoke-virtual {p2}, Landroid/graphics/Paint;->getStyle()Landroid/graphics/Paint$Style;

    .line 25
    .line 26
    .line 27
    move-result-object p6

    .line 28
    iget p8, p0, Ltm/b;->d:I

    .line 29
    .line 30
    if-eqz p8, :cond_0

    .line 31
    .line 32
    invoke-virtual {p2}, Landroid/graphics/Paint;->getColor()I

    .line 33
    .line 34
    .line 35
    move-result p9

    .line 36
    invoke-virtual {p2, p8}, Landroid/graphics/Paint;->setColor(I)V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    const/4 p9, 0x0

    .line 41
    :goto_0
    iget p10, p0, Ltm/b;->f:F

    .line 42
    .line 43
    invoke-static {p10}, Ljava/lang/Float;->isNaN(F)Z

    .line 44
    .line 45
    .line 46
    move-result p11

    .line 47
    const/high16 p12, 0x40000000    # 2.0f

    .line 48
    .line 49
    iget p0, p0, Ltm/b;->e:F

    .line 50
    .line 51
    if-eqz p11, :cond_1

    .line 52
    .line 53
    sget-object p11, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 54
    .line 55
    invoke-virtual {p2, p11}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 56
    .line 57
    .line 58
    const/4 p11, 0x0

    .line 59
    move v0, p0

    .line 60
    goto :goto_1

    .line 61
    :cond_1
    invoke-virtual {p2}, Landroid/graphics/Paint;->getStrokeWidth()F

    .line 62
    .line 63
    .line 64
    move-result p11

    .line 65
    sget-object v0, Landroid/graphics/Paint$Style;->STROKE:Landroid/graphics/Paint$Style;

    .line 66
    .line 67
    invoke-virtual {p2, v0}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p2, p10}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 71
    .line 72
    .line 73
    div-float v0, p10, p12

    .line 74
    .line 75
    sub-float v0, p0, v0

    .line 76
    .line 77
    :goto_1
    int-to-float p3, p3

    .line 78
    int-to-float p4, p4

    .line 79
    mul-float/2addr p4, p0

    .line 80
    add-float/2addr p4, p3

    .line 81
    add-int/2addr p5, p7

    .line 82
    int-to-float p0, p5

    .line 83
    div-float/2addr p0, p12

    .line 84
    invoke-virtual {p1, p4, p0, v0, p2}, Landroid/graphics/Canvas;->drawCircle(FFFLandroid/graphics/Paint;)V

    .line 85
    .line 86
    .line 87
    if-eqz p8, :cond_2

    .line 88
    .line 89
    invoke-virtual {p2, p9}, Landroid/graphics/Paint;->setColor(I)V

    .line 90
    .line 91
    .line 92
    :cond_2
    invoke-static {p10}, Ljava/lang/Float;->isNaN(F)Z

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    if-nez p0, :cond_3

    .line 97
    .line 98
    invoke-virtual {p2, p11}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 99
    .line 100
    .line 101
    :cond_3
    invoke-virtual {p2, p6}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 102
    .line 103
    .line 104
    :cond_4
    return-void
.end method

.method public final getBulletRadius()I
    .locals 0

    .line 1
    iget p0, p0, Ltm/b;->e:F

    .line 2
    .line 3
    float-to-int p0, p0

    .line 4
    return p0
.end method

.method public final getColor()I
    .locals 0

    .line 1
    iget p0, p0, Ltm/b;->d:I

    .line 2
    .line 3
    return p0
.end method

.method public final getGapWidth()I
    .locals 0

    .line 1
    iget p0, p0, Ltm/b;->g:I

    .line 2
    .line 3
    return p0
.end method

.method public final getLeadingMargin(Z)I
    .locals 1

    .line 1
    const/4 p1, 0x2

    .line 2
    int-to-float p1, p1

    .line 3
    iget v0, p0, Ltm/b;->e:F

    .line 4
    .line 5
    mul-float/2addr p1, v0

    .line 6
    iget p0, p0, Ltm/b;->g:I

    .line 7
    .line 8
    int-to-float p0, p0

    .line 9
    add-float/2addr p1, p0

    .line 10
    float-to-double p0, p1

    .line 11
    invoke-static {p0, p1}, Ljava/lang/Math;->ceil(D)D

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    double-to-float p0, p0

    .line 16
    float-to-int p0, p0

    .line 17
    return p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 0

    .line 1
    const-string p2, "dest"

    .line 2
    .line 3
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget p2, p0, Ltm/b;->d:I

    .line 7
    .line 8
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 9
    .line 10
    .line 11
    iget p2, p0, Ltm/b;->e:F

    .line 12
    .line 13
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeFloat(F)V

    .line 14
    .line 15
    .line 16
    iget p2, p0, Ltm/b;->f:F

    .line 17
    .line 18
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeFloat(F)V

    .line 19
    .line 20
    .line 21
    iget p0, p0, Ltm/b;->g:I

    .line 22
    .line 23
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 24
    .line 25
    .line 26
    return-void
.end method
