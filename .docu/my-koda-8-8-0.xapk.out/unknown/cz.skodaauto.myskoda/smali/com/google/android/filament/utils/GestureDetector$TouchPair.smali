.class final Lcom/google/android/filament/utils/GestureDetector$TouchPair;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/utils/GestureDetector;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "TouchPair"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\r\n\u0002\u0010\u0007\n\u0002\u0008\r\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0000\u0008\u0082\u0008\u0018\u00002\u00020\u0001B\u001f\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0007\u0010\u0008B\t\u0008\u0016\u00a2\u0006\u0004\u0008\u0007\u0010\tB\u0019\u0008\u0016\u0012\u0006\u0010\n\u001a\u00020\u000b\u0012\u0006\u0010\u000c\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0007\u0010\rJ\t\u0010\"\u001a\u00020\u0003H\u00c6\u0003J\t\u0010#\u001a\u00020\u0003H\u00c6\u0003J\t\u0010$\u001a\u00020\u0006H\u00c6\u0003J\'\u0010%\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0006H\u00c6\u0001J\u0013\u0010&\u001a\u00020\'2\u0008\u0010(\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010)\u001a\u00020\u0006H\u00d6\u0001J\t\u0010*\u001a\u00020+H\u00d6\u0001R\u001a\u0010\u0002\u001a\u00020\u0003X\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u000e\u0010\u000f\"\u0004\u0008\u0010\u0010\u0011R\u001a\u0010\u0004\u001a\u00020\u0003X\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0012\u0010\u000f\"\u0004\u0008\u0013\u0010\u0011R\u001a\u0010\u0005\u001a\u00020\u0006X\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0014\u0010\u0015\"\u0004\u0008\u0016\u0010\u0017R\u0011\u0010\u0018\u001a\u00020\u00198F\u00a2\u0006\u0006\u001a\u0004\u0008\u001a\u0010\u001bR\u0011\u0010\u001c\u001a\u00020\u00038F\u00a2\u0006\u0006\u001a\u0004\u0008\u001d\u0010\u000fR\u0011\u0010\u001e\u001a\u00020\u00068F\u00a2\u0006\u0006\u001a\u0004\u0008\u001f\u0010\u0015R\u0011\u0010 \u001a\u00020\u00068F\u00a2\u0006\u0006\u001a\u0004\u0008!\u0010\u0015\u00a8\u0006,"
    }
    d2 = {
        "Lcom/google/android/filament/utils/GestureDetector$TouchPair;",
        "",
        "pt0",
        "Lcom/google/android/filament/utils/Float2;",
        "pt1",
        "count",
        "",
        "<init>",
        "(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;I)V",
        "()V",
        "me",
        "Landroid/view/MotionEvent;",
        "height",
        "(Landroid/view/MotionEvent;I)V",
        "getPt0",
        "()Lcom/google/android/filament/utils/Float2;",
        "setPt0",
        "(Lcom/google/android/filament/utils/Float2;)V",
        "getPt1",
        "setPt1",
        "getCount",
        "()I",
        "setCount",
        "(I)V",
        "separation",
        "",
        "getSeparation",
        "()F",
        "midpoint",
        "getMidpoint",
        "x",
        "getX",
        "y",
        "getY",
        "component1",
        "component2",
        "component3",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "toString",
        "",
        "filament-utils-android_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private count:I

.field private pt0:Lcom/google/android/filament/utils/Float2;

.field private pt1:Lcom/google/android/filament/utils/Float2;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 2
    new-instance v0, Lcom/google/android/filament/utils/Float2;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Lcom/google/android/filament/utils/Float2;-><init>(F)V

    new-instance v2, Lcom/google/android/filament/utils/Float2;

    invoke-direct {v2, v1}, Lcom/google/android/filament/utils/Float2;-><init>(F)V

    const/4 v1, 0x0

    invoke-direct {p0, v0, v2, v1}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;I)V

    return-void
.end method

.method public constructor <init>(Landroid/view/MotionEvent;I)V
    .locals 5

    const-string v0, "me"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-direct {p0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;-><init>()V

    .line 4
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getPointerCount()I

    move-result v0

    const/4 v1, 0x1

    if-lt v0, v1, :cond_0

    .line 5
    new-instance v0, Lcom/google/android/filament/utils/Float2;

    const/4 v2, 0x0

    invoke-virtual {p1, v2}, Landroid/view/MotionEvent;->getX(I)F

    move-result v3

    int-to-float v4, p2

    invoke-virtual {p1, v2}, Landroid/view/MotionEvent;->getY(I)F

    move-result v2

    sub-float/2addr v4, v2

    invoke-direct {v0, v3, v4}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    iput-object v0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt0:Lcom/google/android/filament/utils/Float2;

    .line 6
    iput-object v0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    .line 7
    iget v0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    add-int/2addr v0, v1

    iput v0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    .line 8
    :cond_0
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getPointerCount()I

    move-result v0

    const/4 v2, 0x2

    if-lt v0, v2, :cond_1

    .line 9
    new-instance v0, Lcom/google/android/filament/utils/Float2;

    invoke-virtual {p1, v1}, Landroid/view/MotionEvent;->getX(I)F

    move-result v2

    int-to-float p2, p2

    invoke-virtual {p1, v1}, Landroid/view/MotionEvent;->getY(I)F

    move-result p1

    sub-float/2addr p2, p1

    invoke-direct {v0, v2, p2}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    iput-object v0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    .line 10
    iget p1, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    add-int/2addr p1, v1

    iput p1, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    :cond_1
    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;I)V
    .locals 1

    const-string v0, "pt0"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "pt1"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt0:Lcom/google/android/filament/utils/Float2;

    iput-object p2, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    iput p3, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    return-void
.end method

.method public static synthetic copy$default(Lcom/google/android/filament/utils/GestureDetector$TouchPair;Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;IILjava/lang/Object;)Lcom/google/android/filament/utils/GestureDetector$TouchPair;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt0:Lcom/google/android/filament/utils/Float2;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget p3, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->copy(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;I)Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method


# virtual methods
.method public final component1()Lcom/google/android/filament/utils/Float2;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt0:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Lcom/google/android/filament/utils/Float2;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    .line 2
    .line 3
    return p0
.end method

.method public final copy(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;I)Lcom/google/android/filament/utils/GestureDetector$TouchPair;
    .locals 0

    .line 1
    const-string p0, "pt0"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "pt1"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 12
    .line 13
    invoke-direct {p0, p1, p2, p3}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;I)V

    .line 14
    .line 15
    .line 16
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt0:Lcom/google/android/filament/utils/Float2;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt0:Lcom/google/android/filament/utils/Float2;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget p0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    .line 36
    .line 37
    iget p1, p1, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    .line 38
    .line 39
    if-eq p0, p1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    return v0
.end method

.method public final getCount()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    .line 2
    .line 3
    return p0
.end method

.method public final getMidpoint()Lcom/google/android/filament/utils/Float2;
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt0:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    .line 4
    .line 5
    new-instance v1, Lcom/google/android/filament/utils/Float2;

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    const/high16 v4, 0x3f000000    # 0.5f

    .line 16
    .line 17
    mul-float/2addr v2, v4

    .line 18
    mul-float/2addr v3, v4

    .line 19
    add-float/2addr v3, v2

    .line 20
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    mul-float/2addr v0, v4

    .line 29
    mul-float/2addr p0, v4

    .line 30
    add-float/2addr p0, v0

    .line 31
    invoke-direct {v1, v3, p0}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 32
    .line 33
    .line 34
    return-object v1
.end method

.method public final getPt0()Lcom/google/android/filament/utils/Float2;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt0:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPt1()Lcom/google/android/filament/utils/Float2;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSeparation()F
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt0:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    .line 4
    .line 5
    new-instance v1, Lcom/google/android/filament/utils/Float2;

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    sub-float/2addr v2, v3

    .line 16
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    sub-float/2addr v0, p0

    .line 25
    invoke-direct {v1, v2, v0}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    mul-float/2addr v0, p0

    .line 37
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    mul-float/2addr v1, p0

    .line 46
    add-float/2addr v1, v0

    .line 47
    float-to-double v0, v1

    .line 48
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    .line 49
    .line 50
    .line 51
    move-result-wide v0

    .line 52
    double-to-float p0, v0

    .line 53
    return p0
.end method

.method public final getX()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getMidpoint()Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    float-to-int p0, p0

    .line 10
    return p0
.end method

.method public final getY()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getMidpoint()Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    float-to-int p0, p0

    .line 10
    return p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt0:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    .line 10
    .line 11
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget p0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    .line 19
    .line 20
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    add-int/2addr p0, v1

    .line 25
    return p0
.end method

.method public final setCount(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    .line 2
    .line 3
    return-void
.end method

.method public final setPt0(Lcom/google/android/filament/utils/Float2;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt0:Lcom/google/android/filament/utils/Float2;

    .line 7
    .line 8
    return-void
.end method

.method public final setPt1(Lcom/google/android/filament/utils/Float2;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    .line 7
    .line 8
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt0:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->pt1:Lcom/google/android/filament/utils/Float2;

    .line 4
    .line 5
    iget p0, p0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->count:I

    .line 6
    .line 7
    new-instance v2, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v3, "TouchPair(pt0="

    .line 10
    .line 11
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v0, ", pt1="

    .line 18
    .line 19
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v0, ", count="

    .line 26
    .line 27
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v0, ")"

    .line 31
    .line 32
    invoke-static {p0, v0, v2}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method
