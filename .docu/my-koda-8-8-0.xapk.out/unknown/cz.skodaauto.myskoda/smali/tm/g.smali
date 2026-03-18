.class public final Ltm/g;
.super Landroid/text/style/QuoteSpan;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Ltm/g;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:I

.field public final e:I

.field public final f:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ltm/a;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Ltm/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltm/g;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/os/Parcel;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    invoke-direct {p0}, Landroid/text/style/QuoteSpan;-><init>()V

    .line 14
    .line 15
    .line 16
    iput v0, p0, Ltm/g;->d:I

    .line 17
    .line 18
    iput v1, p0, Ltm/g;->e:I

    .line 19
    .line 20
    iput p1, p0, Ltm/g;->f:I

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final drawLeadingMargin(Landroid/graphics/Canvas;Landroid/graphics/Paint;IIIIILjava/lang/CharSequence;IIZLandroid/text/Layout;)V
    .locals 1

    .line 1
    const-string p6, "c"

    .line 2
    .line 3
    invoke-static {p1, p6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p6, "p"

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
    const-string p6, "layout"

    .line 17
    .line 18
    invoke-static {p12, p6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p2}, Landroid/graphics/Paint;->getStyle()Landroid/graphics/Paint$Style;

    .line 22
    .line 23
    .line 24
    move-result-object p6

    .line 25
    invoke-virtual {p2}, Landroid/graphics/Paint;->getColor()I

    .line 26
    .line 27
    .line 28
    move-result p8

    .line 29
    sget-object p9, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 30
    .line 31
    invoke-virtual {p2, p9}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 32
    .line 33
    .line 34
    iget p9, p0, Ltm/g;->d:I

    .line 35
    .line 36
    invoke-virtual {p2, p9}, Landroid/graphics/Paint;->setColor(I)V

    .line 37
    .line 38
    .line 39
    move-object p9, p0

    .line 40
    move-object p0, p1

    .line 41
    int-to-float p1, p3

    .line 42
    int-to-float p5, p5

    .line 43
    iget p9, p9, Ltm/g;->e:I

    .line 44
    .line 45
    mul-int/2addr p4, p9

    .line 46
    add-int/2addr p4, p3

    .line 47
    int-to-float p3, p4

    .line 48
    int-to-float p4, p7

    .line 49
    move v0, p5

    .line 50
    move-object p5, p2

    .line 51
    move p2, v0

    .line 52
    invoke-virtual/range {p0 .. p5}, Landroid/graphics/Canvas;->drawRect(FFFFLandroid/graphics/Paint;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p5, p6}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p5, p8}, Landroid/graphics/Paint;->setColor(I)V

    .line 59
    .line 60
    .line 61
    return-void
.end method

.method public final getColor()I
    .locals 0

    .line 1
    iget p0, p0, Ltm/g;->d:I

    .line 2
    .line 3
    return p0
.end method

.method public final getGapWidth()I
    .locals 0

    .line 1
    iget p0, p0, Ltm/g;->f:I

    .line 2
    .line 3
    return p0
.end method

.method public final getLeadingMargin(Z)I
    .locals 0

    .line 1
    iget p1, p0, Ltm/g;->e:I

    .line 2
    .line 3
    iget p0, p0, Ltm/g;->f:I

    .line 4
    .line 5
    add-int/2addr p1, p0

    .line 6
    return p1
.end method

.method public final getStripeWidth()I
    .locals 0

    .line 1
    iget p0, p0, Ltm/g;->e:I

    .line 2
    .line 3
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
    iget p2, p0, Ltm/g;->d:I

    .line 7
    .line 8
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 9
    .line 10
    .line 11
    iget p2, p0, Ltm/g;->e:I

    .line 12
    .line 13
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 14
    .line 15
    .line 16
    iget p0, p0, Ltm/g;->f:I

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 19
    .line 20
    .line 21
    return-void
.end method
