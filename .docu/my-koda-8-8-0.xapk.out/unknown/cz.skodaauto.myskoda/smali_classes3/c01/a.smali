.class public abstract Lc01/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[C


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "0123456789ABCDEF"

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->toCharArray()[C

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lc01/a;->a:[C

    .line 8
    .line 9
    return-void
.end method

.method public static a([B)Ljava/lang/String;
    .locals 6

    .line 1
    if-eqz p0, :cond_3

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    goto :goto_1

    .line 7
    :cond_0
    array-length v0, p0

    .line 8
    mul-int/lit8 v0, v0, 0x3

    .line 9
    .line 10
    add-int/lit8 v0, v0, -0x1

    .line 11
    .line 12
    new-array v0, v0, [C

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    :goto_0
    array-length v2, p0

    .line 16
    if-ge v1, v2, :cond_2

    .line 17
    .line 18
    aget-byte v2, p0, v1

    .line 19
    .line 20
    and-int/lit16 v3, v2, 0xff

    .line 21
    .line 22
    mul-int/lit8 v4, v1, 0x3

    .line 23
    .line 24
    ushr-int/lit8 v3, v3, 0x4

    .line 25
    .line 26
    sget-object v5, Lc01/a;->a:[C

    .line 27
    .line 28
    aget-char v3, v5, v3

    .line 29
    .line 30
    aput-char v3, v0, v4

    .line 31
    .line 32
    add-int/lit8 v3, v4, 0x1

    .line 33
    .line 34
    and-int/lit8 v2, v2, 0xf

    .line 35
    .line 36
    aget-char v2, v5, v2

    .line 37
    .line 38
    aput-char v2, v0, v3

    .line 39
    .line 40
    array-length v2, p0

    .line 41
    add-int/lit8 v2, v2, -0x1

    .line 42
    .line 43
    if-eq v1, v2, :cond_1

    .line 44
    .line 45
    add-int/lit8 v4, v4, 0x2

    .line 46
    .line 47
    const/16 v2, 0x2d

    .line 48
    .line 49
    aput-char v2, v0, v4

    .line 50
    .line 51
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_2
    new-instance p0, Ljava/lang/String;

    .line 55
    .line 56
    invoke-direct {p0, v0}, Ljava/lang/String;-><init>([C)V

    .line 57
    .line 58
    .line 59
    const-string v0, "(0x) "

    .line 60
    .line 61
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0

    .line 66
    :cond_3
    :goto_1
    const-string p0, ""

    .line 67
    .line 68
    return-object p0
.end method

.method public static b([B)Ljava/lang/String;
    .locals 6

    .line 1
    if-eqz p0, :cond_2

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    goto :goto_1

    .line 7
    :cond_0
    array-length v0, p0

    .line 8
    mul-int/lit8 v0, v0, 0x2

    .line 9
    .line 10
    new-array v0, v0, [C

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    :goto_0
    array-length v2, p0

    .line 14
    if-ge v1, v2, :cond_1

    .line 15
    .line 16
    aget-byte v2, p0, v1

    .line 17
    .line 18
    and-int/lit16 v3, v2, 0xff

    .line 19
    .line 20
    mul-int/lit8 v4, v1, 0x2

    .line 21
    .line 22
    ushr-int/lit8 v3, v3, 0x4

    .line 23
    .line 24
    sget-object v5, Lc01/a;->a:[C

    .line 25
    .line 26
    aget-char v3, v5, v3

    .line 27
    .line 28
    aput-char v3, v0, v4

    .line 29
    .line 30
    add-int/lit8 v4, v4, 0x1

    .line 31
    .line 32
    and-int/lit8 v2, v2, 0xf

    .line 33
    .line 34
    aget-char v2, v5, v2

    .line 35
    .line 36
    aput-char v2, v0, v4

    .line 37
    .line 38
    add-int/lit8 v1, v1, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    new-instance p0, Ljava/lang/String;

    .line 42
    .line 43
    invoke-direct {p0, v0}, Ljava/lang/String;-><init>([C)V

    .line 44
    .line 45
    .line 46
    const-string v0, "0x"

    .line 47
    .line 48
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :cond_2
    :goto_1
    const-string p0, "null"

    .line 54
    .line 55
    return-object p0
.end method

.method public static c(I)Ljava/lang/String;
    .locals 2

    .line 1
    packed-switch p0, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    const-string v0, "UNKNOWN ("

    .line 5
    .line 6
    const-string v1, ")"

    .line 7
    .line 8
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    const-string p0, "LE 1M, LE 2M or LE Coded"

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_1
    const-string p0, "LE 2M or LE Coded"

    .line 17
    .line 18
    return-object p0

    .line 19
    :pswitch_2
    const-string p0, "LE 1M or LE Coded"

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_3
    const-string p0, "LE Coded"

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_4
    const-string p0, "LE 1M or LE 2M"

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_5
    const-string p0, "LE 2M"

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_6
    const-string p0, "LE 1M"

    .line 32
    .line 33
    return-object p0

    .line 34
    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static d(I)Ljava/lang/String;
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eq p0, v0, :cond_2

    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    if-eq p0, v0, :cond_1

    .line 6
    .line 7
    const/4 v0, 0x3

    .line 8
    if-eq p0, v0, :cond_0

    .line 9
    .line 10
    const-string v0, "UNKNOWN ("

    .line 11
    .line 12
    const-string v1, ")"

    .line 13
    .line 14
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_0
    const-string p0, "LE Coded"

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_1
    const-string p0, "LE 2M"

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_2
    const-string p0, "LE 1M"

    .line 26
    .line 27
    return-object p0
.end method

.method public static e(I)Ljava/lang/String;
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eq p0, v0, :cond_2

    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    if-eq p0, v0, :cond_1

    .line 6
    .line 7
    const/4 v0, 0x4

    .line 8
    if-eq p0, v0, :cond_0

    .line 9
    .line 10
    const-string v0, "UNKNOWN ("

    .line 11
    .line 12
    const-string v1, ")"

    .line 13
    .line 14
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_0
    const-string p0, "WRITE SIGNED"

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_1
    const-string p0, "WRITE REQUEST"

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_2
    const-string p0, "WRITE COMMAND"

    .line 26
    .line 27
    return-object p0
.end method
