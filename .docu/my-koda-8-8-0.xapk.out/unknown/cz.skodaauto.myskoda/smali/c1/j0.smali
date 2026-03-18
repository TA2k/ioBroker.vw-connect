.class public abstract synthetic Lc1/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static A(Lcom/google/android/filament/utils/Float4;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p0, p1

    .line 6
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static B(Lcom/google/android/filament/utils/Float4;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p0, p1

    .line 6
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static C(Lcom/google/android/filament/utils/Float4;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p0, p1

    .line 6
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static synthetic D(I)Ljava/lang/String;
    .locals 0

    .line 1
    packed-switch p0, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    throw p0

    .line 6
    :pswitch_0
    const-string p0, "MISSING_SGTM_SERVER_URL"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_1
    const-string p0, "PINNED_TO_SERVICE_UPLOAD"

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_2
    const-string p0, "SERVICE_FLAG_OFF"

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_3
    const-string p0, "CLIENT_FLAG_OFF"

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_4
    const-string p0, "NOT_ENABLED_IN_MANIFEST"

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_5
    const-string p0, "MISSING_JOB_SCHEDULER"

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_6
    const-string p0, "SDK_TOO_OLD"

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_7
    const-string p0, "NON_PLAY_MODE"

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_8
    const-string p0, "ANDROID_TOO_OLD"

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_9
    const-string p0, "MEASUREMENT_SERVICE_NOT_ENABLED"

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_a
    const-string p0, "CLIENT_UPLOAD_ELIGIBLE"

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_b
    const-string p0, "CLIENT_UPLOAD_ELIGIBILITY_UNKNOWN"

    .line 40
    .line 41
    return-object p0

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static a(I)I
    .locals 0

    .line 1
    packed-switch p0, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    packed-switch p0, :pswitch_data_1

    .line 5
    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :pswitch_0
    const/16 p0, 0xc

    .line 10
    .line 11
    return p0

    .line 12
    :pswitch_1
    const/16 p0, 0xb

    .line 13
    .line 14
    return p0

    .line 15
    :pswitch_2
    const/16 p0, 0xa

    .line 16
    .line 17
    return p0

    .line 18
    :pswitch_3
    const/16 p0, 0x9

    .line 19
    .line 20
    return p0

    .line 21
    :pswitch_4
    const/16 p0, 0x8

    .line 22
    .line 23
    return p0

    .line 24
    :pswitch_5
    const/4 p0, 0x7

    .line 25
    return p0

    .line 26
    :pswitch_6
    const/4 p0, 0x6

    .line 27
    return p0

    .line 28
    :pswitch_7
    const/4 p0, 0x5

    .line 29
    return p0

    .line 30
    :pswitch_8
    const/4 p0, 0x4

    .line 31
    return p0

    .line 32
    :pswitch_9
    const/4 p0, 0x3

    .line 33
    return p0

    .line 34
    :pswitch_a
    const/4 p0, 0x2

    .line 35
    return p0

    .line 36
    :pswitch_b
    const/4 p0, 0x1

    .line 37
    return p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
    .end packed-switch

    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    .line 54
    .line 55
    .line 56
    .line 57
    .line 58
    .line 59
    .line 60
    .line 61
    :pswitch_data_1
    .packed-switch 0x14
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static synthetic b(I)I
    .locals 0

    .line 1
    packed-switch p0, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    throw p0

    .line 6
    :pswitch_0
    const/16 p0, 0x16

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_1
    const/16 p0, 0x15

    .line 10
    .line 11
    return p0

    .line 12
    :pswitch_2
    const/16 p0, 0x14

    .line 13
    .line 14
    return p0

    .line 15
    :pswitch_3
    const/16 p0, 0x8

    .line 16
    .line 17
    return p0

    .line 18
    :pswitch_4
    const/4 p0, 0x7

    .line 19
    return p0

    .line 20
    :pswitch_5
    const/4 p0, 0x6

    .line 21
    return p0

    .line 22
    :pswitch_6
    const/4 p0, 0x5

    .line 23
    return p0

    .line 24
    :pswitch_7
    const/4 p0, 0x4

    .line 25
    return p0

    .line 26
    :pswitch_8
    const/4 p0, 0x3

    .line 27
    return p0

    .line 28
    :pswitch_9
    const/4 p0, 0x2

    .line 29
    return p0

    .line 30
    :pswitch_a
    const/4 p0, 0x1

    .line 31
    return p0

    .line 32
    :pswitch_b
    const/4 p0, 0x0

    .line 33
    return p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static c(Lcom/google/android/filament/utils/Float3;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p1, p0

    .line 6
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static d(Lcom/google/android/filament/utils/Float3;FF)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    mul-float/2addr p0, p1

    .line 6
    add-float/2addr p0, p2

    .line 7
    return p0
.end method

.method public static e(Lcom/google/android/filament/utils/Float4;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p1, p0

    .line 6
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static f(Lcom/google/android/filament/utils/Float4;FF)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    mul-float/2addr p0, p1

    .line 6
    add-float/2addr p0, p2

    .line 7
    return p0
.end method

.method public static g(III)I
    .locals 0

    .line 1
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    add-int/2addr p0, p1

    .line 6
    mul-int/2addr p0, p2

    .line 7
    return p0
.end method

.method public static h(IIII)I
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    add-int/2addr p0, p1

    .line 6
    add-int/2addr p0, p2

    .line 7
    add-int/2addr p0, p3

    .line 8
    return p0
.end method

.method public static i(Ljava/lang/Object;)La8/r0;
    .locals 0

    .line 1
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    new-instance p0, La8/r0;

    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 7
    .line 8
    .line 9
    return-object p0
.end method

.method public static j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 5
    .line 6
    .line 7
    invoke-virtual {p3, p4}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 8
    .line 9
    .line 10
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static k(Ljava/lang/String;ILx2/p;)Lx2/s;
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-static {p2, p0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static l(Lfp0/f;Lfp0/f;Llx0/l;)Z
    .locals 1

    .line 1
    new-instance v0, Llx0/l;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Llx0/l;->equals(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static m(Lcom/google/android/filament/utils/Float3;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p1, p0

    .line 6
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static n(Lcom/google/android/filament/utils/Float3;FF)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    mul-float/2addr p0, p1

    .line 6
    add-float/2addr p0, p2

    .line 7
    return p0
.end method

.method public static o(Lcom/google/android/filament/utils/Float4;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p1, p0

    .line 6
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static p(Lcom/google/android/filament/utils/Float4;FF)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    mul-float/2addr p0, p1

    .line 6
    add-float/2addr p0, p2

    .line 7
    return p0
.end method

.method public static q(III)I
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    add-int/2addr p0, p1

    .line 6
    add-int/2addr p0, p2

    .line 7
    return p0
.end method

.method public static r(Lcom/google/android/filament/utils/Float3;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p1, p0

    .line 6
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static s(Lcom/google/android/filament/utils/Float4;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p1, p0

    .line 6
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static t(Lcom/google/android/filament/utils/Float4;FF)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    mul-float/2addr p0, p1

    .line 6
    add-float/2addr p0, p2

    .line 7
    return p0
.end method

.method public static u(III)I
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    add-int/2addr p0, p1

    .line 6
    add-int/2addr p0, p2

    .line 7
    return p0
.end method

.method public static v(Lcom/google/android/filament/utils/Float3;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p0, p1

    .line 6
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static w(Lcom/google/android/filament/utils/Float4;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p1, p0

    .line 6
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static x(Lcom/google/android/filament/utils/Float3;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p0, p1

    .line 6
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static y(Lcom/google/android/filament/utils/Float4;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p0, p1

    .line 6
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static z(Lcom/google/android/filament/utils/Float3;F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sub-float/2addr p0, p1

    .line 6
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method
