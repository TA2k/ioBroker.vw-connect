.class public abstract Llp/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ljava/lang/String;Lv/d;)Z
    .locals 4

    .line 1
    const-string v0, "robolectric"

    .line 2
    .line 3
    sget-object v1, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x1

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    return v1

    .line 13
    :cond_0
    :try_start_0
    invoke-virtual {p1, p0}, Lv/d;->a(Ljava/lang/String;)Lv/b;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    sget-object p1, Landroid/hardware/camera2/CameraCharacteristics;->REQUEST_AVAILABLE_CAPABILITIES:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, [I
    :try_end_0
    .catch Lv/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 24
    .line 25
    const/4 p1, 0x0

    .line 26
    if-eqz p0, :cond_2

    .line 27
    .line 28
    array-length v0, p0

    .line 29
    move v2, p1

    .line 30
    :goto_0
    if-ge v2, v0, :cond_2

    .line 31
    .line 32
    aget v3, p0, v2

    .line 33
    .line 34
    if-nez v3, :cond_1

    .line 35
    .line 36
    return v1

    .line 37
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    return p1

    .line 41
    :catch_0
    move-exception p0

    .line 42
    new-instance p1, Lb0/c1;

    .line 43
    .line 44
    new-instance v0, Lb0/s;

    .line 45
    .line 46
    invoke-direct {v0, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 47
    .line 48
    .line 49
    invoke-direct {p1, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 50
    .line 51
    .line 52
    throw p1
.end method

.method public static final b(Lay0/k;)Lhi/b;
    .locals 2

    .line 1
    new-instance v0, Lhi/c;

    .line 2
    .line 3
    invoke-direct {v0}, Lhi/c;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    new-instance p0, Lhi/b;

    .line 10
    .line 11
    iget-object v1, v0, Lhi/c;->a:Ljava/util/ArrayList;

    .line 12
    .line 13
    iget-object v0, v0, Lhi/c;->b:Ljava/util/LinkedHashMap;

    .line 14
    .line 15
    invoke-direct {p0, v1, v0}, Lhi/b;-><init>(Ljava/util/List;Ljava/util/Map;)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method
