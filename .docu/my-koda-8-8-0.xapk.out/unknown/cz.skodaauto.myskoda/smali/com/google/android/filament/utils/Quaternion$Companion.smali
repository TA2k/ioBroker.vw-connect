.class public final Lcom/google/android/filament/utils/Quaternion$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/utils/Quaternion;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/Quaternion$Companion$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0016\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u0008\u001a\u00020\tJ\u0018\u0010\n\u001a\u00020\u00052\u0006\u0010\u000b\u001a\u00020\u00072\u0008\u0008\u0002\u0010\u000c\u001a\u00020\rJ.\u0010\n\u001a\u00020\u00052\u0008\u0008\u0002\u0010\u000e\u001a\u00020\t2\u0008\u0008\u0002\u0010\u000f\u001a\u00020\t2\u0008\u0008\u0002\u0010\u0010\u001a\u00020\t2\u0008\u0008\u0002\u0010\u000c\u001a\u00020\r\u00a8\u0006\u0011"
    }
    d2 = {
        "Lcom/google/android/filament/utils/Quaternion$Companion;",
        "",
        "<init>",
        "()V",
        "fromAxisAngle",
        "Lcom/google/android/filament/utils/Quaternion;",
        "axis",
        "Lcom/google/android/filament/utils/Float3;",
        "angle",
        "",
        "fromEuler",
        "d",
        "order",
        "Lcom/google/android/filament/utils/RotationsOrder;",
        "yaw",
        "pitch",
        "roll",
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


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/google/android/filament/utils/Quaternion$Companion;-><init>()V

    return-void
.end method

.method public static synthetic fromEuler$default(Lcom/google/android/filament/utils/Quaternion$Companion;FFFLcom/google/android/filament/utils/RotationsOrder;ILjava/lang/Object;)Lcom/google/android/filament/utils/Quaternion;
    .locals 1

    and-int/lit8 p6, p5, 0x1

    const/4 v0, 0x0

    if-eqz p6, :cond_0

    move p1, v0

    :cond_0
    and-int/lit8 p6, p5, 0x2

    if-eqz p6, :cond_1

    move p2, v0

    :cond_1
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_2

    move p3, v0

    :cond_2
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_3

    .line 2
    sget-object p4, Lcom/google/android/filament/utils/RotationsOrder;->ZYX:Lcom/google/android/filament/utils/RotationsOrder;

    .line 3
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/Quaternion$Companion;->fromEuler(FFFLcom/google/android/filament/utils/RotationsOrder;)Lcom/google/android/filament/utils/Quaternion;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic fromEuler$default(Lcom/google/android/filament/utils/Quaternion$Companion;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/RotationsOrder;ILjava/lang/Object;)Lcom/google/android/filament/utils/Quaternion;
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    .line 1
    sget-object p2, Lcom/google/android/filament/utils/RotationsOrder;->ZYX:Lcom/google/android/filament/utils/RotationsOrder;

    :cond_0
    invoke-virtual {p0, p1, p2}, Lcom/google/android/filament/utils/Quaternion$Companion;->fromEuler(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/RotationsOrder;)Lcom/google/android/filament/utils/Quaternion;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final fromAxisAngle(Lcom/google/android/filament/utils/Float3;F)Lcom/google/android/filament/utils/Quaternion;
    .locals 5

    .line 1
    const-string p0, "axis"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const p0, 0x3c8efa35

    .line 7
    .line 8
    .line 9
    mul-float/2addr p2, p0

    .line 10
    new-instance p0, Lcom/google/android/filament/utils/Quaternion;

    .line 11
    .line 12
    const/high16 v0, 0x3f000000    # 0.5f

    .line 13
    .line 14
    mul-float/2addr p2, v0

    .line 15
    float-to-double v0, p2

    .line 16
    invoke-static {v0, v1}, Ljava/lang/Math;->sin(D)D

    .line 17
    .line 18
    .line 19
    move-result-wide v2

    .line 20
    double-to-float p2, v2

    .line 21
    invoke-static {p1}, Lcom/google/android/filament/utils/VectorKt;->normalize(Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Float3;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 26
    .line 27
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    mul-float/2addr v3, p2

    .line 32
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    mul-float/2addr v4, p2

    .line 37
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    mul-float/2addr p1, p2

    .line 42
    invoke-direct {v2, v3, v4, p1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 43
    .line 44
    .line 45
    invoke-static {v0, v1}, Ljava/lang/Math;->cos(D)D

    .line 46
    .line 47
    .line 48
    move-result-wide p1

    .line 49
    double-to-float p1, p1

    .line 50
    invoke-direct {p0, v2, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(Lcom/google/android/filament/utils/Float3;F)V

    .line 51
    .line 52
    .line 53
    return-object p0
.end method

.method public final fromEuler(FFFLcom/google/android/filament/utils/RotationsOrder;)Lcom/google/android/filament/utils/Quaternion;
    .locals 6

    const-string p0, "order"

    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/high16 p0, 0x3f000000    # 0.5f

    mul-float/2addr p1, p0

    float-to-double v0, p1

    .line 1
    invoke-static {v0, v1}, Ljava/lang/Math;->cos(D)D

    move-result-wide v2

    double-to-float p1, v2

    .line 2
    invoke-static {v0, v1}, Ljava/lang/Math;->sin(D)D

    move-result-wide v0

    double-to-float v0, v0

    mul-float/2addr p2, p0

    float-to-double v1, p2

    .line 3
    invoke-static {v1, v2}, Ljava/lang/Math;->cos(D)D

    move-result-wide v3

    double-to-float p2, v3

    .line 4
    invoke-static {v1, v2}, Ljava/lang/Math;->sin(D)D

    move-result-wide v1

    double-to-float v1, v1

    mul-float/2addr p3, p0

    float-to-double v2, p3

    .line 5
    invoke-static {v2, v3}, Ljava/lang/Math;->cos(D)D

    move-result-wide v4

    double-to-float p0, v4

    .line 6
    invoke-static {v2, v3}, Ljava/lang/Math;->sin(D)D

    move-result-wide v2

    double-to-float p3, v2

    .line 7
    sget-object v2, Lcom/google/android/filament/utils/Quaternion$Companion$WhenMappings;->$EnumSwitchMapping$0:[I

    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    move-result p4

    aget p4, v2, p4

    packed-switch p4, :pswitch_data_0

    new-instance p0, La8/r0;

    .line 8
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 9
    throw p0

    .line 10
    :pswitch_0
    new-instance p4, Lcom/google/android/filament/utils/Quaternion;

    mul-float v2, p1, v1

    mul-float v3, v2, p0

    mul-float v4, v0, p2

    mul-float v5, v4, p3

    sub-float/2addr v3, v5

    mul-float/2addr v0, v1

    mul-float v1, v0, p0

    mul-float/2addr p1, p2

    mul-float p2, p1, p3

    add-float/2addr p2, v1

    mul-float/2addr v4, p0

    mul-float/2addr v2, p3

    add-float/2addr v2, v4

    mul-float/2addr p1, p0

    mul-float/2addr v0, p3

    sub-float/2addr p1, v0

    invoke-direct {p4, v3, p2, v2, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object p4

    .line 11
    :pswitch_1
    new-instance p4, Lcom/google/android/filament/utils/Quaternion;

    mul-float v2, p1, p2

    mul-float v3, v2, p3

    mul-float v4, v0, v1

    mul-float v5, v4, p0

    sub-float/2addr v3, v5

    mul-float/2addr v0, p2

    mul-float p2, v0, p3

    mul-float/2addr p1, v1

    mul-float v1, p1, p0

    add-float/2addr v1, p2

    mul-float/2addr v0, p0

    mul-float/2addr p1, p3

    sub-float/2addr v0, p1

    mul-float/2addr v4, p3

    mul-float/2addr v2, p0

    add-float/2addr v2, v4

    invoke-direct {p4, v3, v1, v0, v2}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object p4

    .line 12
    :pswitch_2
    new-instance p4, Lcom/google/android/filament/utils/Quaternion;

    mul-float v2, v0, v1

    mul-float v3, v2, p0

    mul-float v4, p1, p2

    mul-float v5, v4, p3

    add-float/2addr v5, v3

    mul-float/2addr v0, p2

    mul-float p2, v0, p0

    mul-float/2addr p1, v1

    mul-float v1, p1, p3

    add-float/2addr v1, p2

    mul-float/2addr p1, p0

    mul-float/2addr v0, p3

    sub-float/2addr p1, v0

    mul-float/2addr v4, p0

    mul-float/2addr v2, p3

    sub-float/2addr v4, v2

    invoke-direct {p4, v5, v1, p1, v4}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object p4

    .line 13
    :pswitch_3
    new-instance p4, Lcom/google/android/filament/utils/Quaternion;

    mul-float v2, v0, p2

    mul-float v3, v2, p3

    mul-float v4, p1, v1

    mul-float v5, v4, p0

    add-float/2addr v5, v3

    mul-float/2addr v2, p0

    mul-float/2addr v4, p3

    sub-float/2addr v2, v4

    mul-float/2addr p1, p2

    mul-float p2, p1, p3

    mul-float/2addr v0, v1

    mul-float v1, v0, p0

    sub-float/2addr p2, v1

    mul-float/2addr v0, p3

    mul-float/2addr p1, p0

    add-float/2addr p1, v0

    invoke-direct {p4, v5, v2, p2, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object p4

    .line 14
    :pswitch_4
    new-instance p4, Lcom/google/android/filament/utils/Quaternion;

    mul-float v2, v0, p2

    mul-float/2addr v2, p0

    mul-float v3, v1, p3

    mul-float/2addr v3, p1

    add-float/2addr v3, v2

    mul-float v2, v1, p1

    mul-float/2addr v2, p0

    mul-float v4, v0, p3

    mul-float/2addr v4, p2

    sub-float/2addr v2, v4

    mul-float/2addr v0, v1

    mul-float v1, v0, p0

    mul-float v4, p3, p1

    mul-float/2addr v4, p2

    add-float/2addr v4, v1

    mul-float/2addr p1, p2

    mul-float/2addr p1, p0

    mul-float/2addr v0, p3

    sub-float/2addr p1, v0

    invoke-direct {p4, v3, v2, v4, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object p4

    .line 15
    :pswitch_5
    new-instance p4, Lcom/google/android/filament/utils/Quaternion;

    mul-float v2, v0, p2

    mul-float v3, v2, p0

    mul-float v4, p1, v1

    mul-float v5, v4, p3

    sub-float/2addr v3, v5

    mul-float/2addr p1, p2

    mul-float p2, p1, p3

    mul-float/2addr v0, v1

    mul-float v1, v0, p0

    sub-float/2addr p2, v1

    mul-float/2addr v2, p3

    mul-float/2addr v4, p0

    add-float/2addr v4, v2

    mul-float/2addr v0, p3

    mul-float/2addr p1, p0

    add-float/2addr p1, v0

    invoke-direct {p4, v3, p2, v4, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object p4

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final fromEuler(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/RotationsOrder;)Lcom/google/android/filament/utils/Quaternion;
    .locals 7

    const-string v0, "d"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "order"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v5, 0x7

    const/4 v6, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    move-object v1, p1

    .line 16
    invoke-static/range {v1 .. v6}, Lcom/google/android/filament/utils/Float3;->copy$default(Lcom/google/android/filament/utils/Float3;FFFILjava/lang/Object;)Lcom/google/android/filament/utils/Float3;

    move-result-object p1

    .line 17
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v0

    const v1, 0x3c8efa35

    mul-float/2addr v0, v1

    invoke-virtual {p1, v0}, Lcom/google/android/filament/utils/Float3;->setX(F)V

    .line 18
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v0

    mul-float/2addr v0, v1

    invoke-virtual {p1, v0}, Lcom/google/android/filament/utils/Float3;->setY(F)V

    .line 19
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v0

    mul-float/2addr v0, v1

    invoke-virtual {p1, v0}, Lcom/google/android/filament/utils/Float3;->setZ(F)V

    .line 20
    invoke-virtual {p2}, Lcom/google/android/filament/utils/RotationsOrder;->getYaw()Lcom/google/android/filament/utils/VectorComponent;

    move-result-object v0

    invoke-virtual {p1, v0}, Lcom/google/android/filament/utils/Float3;->get(Lcom/google/android/filament/utils/VectorComponent;)F

    move-result v0

    invoke-virtual {p2}, Lcom/google/android/filament/utils/RotationsOrder;->getPitch()Lcom/google/android/filament/utils/VectorComponent;

    move-result-object v1

    invoke-virtual {p1, v1}, Lcom/google/android/filament/utils/Float3;->get(Lcom/google/android/filament/utils/VectorComponent;)F

    move-result v1

    invoke-virtual {p2}, Lcom/google/android/filament/utils/RotationsOrder;->getRoll()Lcom/google/android/filament/utils/VectorComponent;

    move-result-object v2

    invoke-virtual {p1, v2}, Lcom/google/android/filament/utils/Float3;->get(Lcom/google/android/filament/utils/VectorComponent;)F

    move-result p1

    invoke-virtual {p0, v0, v1, p1, p2}, Lcom/google/android/filament/utils/Quaternion$Companion;->fromEuler(FFFLcom/google/android/filament/utils/RotationsOrder;)Lcom/google/android/filament/utils/Quaternion;

    move-result-object p0

    return-object p0
.end method
