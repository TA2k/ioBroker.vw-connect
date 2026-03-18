.class public final Lorg/eclipse/paho/mqttv5/common/util/Strings;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final INDEX_NOT_FOUND:I = -0x1


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static containsAny(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z
    .locals 0

    if-nez p1, :cond_0

    const/4 p0, 0x0

    return p0

    .line 1
    :cond_0
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/util/Strings;->toCharArray(Ljava/lang/CharSequence;)[C

    move-result-object p1

    invoke-static {p0, p1}, Lorg/eclipse/paho/mqttv5/common/util/Strings;->containsAny(Ljava/lang/CharSequence;[C)Z

    move-result p0

    return p0
.end method

.method public static containsAny(Ljava/lang/CharSequence;[C)Z
    .locals 11

    .line 2
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/util/Strings;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_6

    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/util/Strings;->isEmpty([C)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_2

    .line 3
    :cond_0
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    move-result v0

    .line 4
    array-length v2, p1

    add-int/lit8 v3, v0, -0x1

    add-int/lit8 v4, v2, -0x1

    move v5, v1

    :goto_0
    if-lt v5, v0, :cond_1

    return v1

    .line 5
    :cond_1
    invoke-interface {p0, v5}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v6

    move v7, v1

    :goto_1
    if-lt v7, v2, :cond_2

    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    .line 6
    :cond_2
    aget-char v8, p1, v7

    if-ne v8, v6, :cond_5

    .line 7
    invoke-static {v6}, Ljava/lang/Character;->isHighSurrogate(C)Z

    move-result v8

    const/4 v9, 0x1

    if-eqz v8, :cond_4

    if-ne v7, v4, :cond_3

    return v9

    :cond_3
    if-ge v5, v3, :cond_5

    add-int/lit8 v8, v7, 0x1

    .line 8
    aget-char v8, p1, v8

    add-int/lit8 v10, v5, 0x1

    invoke-interface {p0, v10}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v10

    if-ne v8, v10, :cond_5

    :cond_4
    return v9

    :cond_5
    add-int/lit8 v7, v7, 0x1

    goto :goto_1

    :cond_6
    :goto_2
    return v1
.end method

.method public static countMatches(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)I
    .locals 3

    .line 1
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/util/Strings;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_2

    .line 7
    .line 8
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/util/Strings;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_0
    move v0, v1

    .line 16
    :goto_0
    invoke-static {p0, p1, v1}, Lorg/eclipse/paho/mqttv5/common/util/Strings;->indexOf(Ljava/lang/CharSequence;Ljava/lang/CharSequence;I)I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    const/4 v2, -0x1

    .line 21
    if-ne v1, v2, :cond_1

    .line 22
    .line 23
    return v0

    .line 24
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 25
    .line 26
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    add-int/2addr v1, v2

    .line 31
    goto :goto_0

    .line 32
    :cond_2
    :goto_1
    return v1
.end method

.method public static equalsAny(Ljava/lang/CharSequence;[Ljava/lang/CharSequence;)Z
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    move v2, v0

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v2, v1

    .line 10
    :goto_0
    if-eqz p1, :cond_3

    .line 11
    .line 12
    array-length v3, p1

    .line 13
    move v4, v1

    .line 14
    :goto_1
    if-lt v4, v3, :cond_1

    .line 15
    .line 16
    return v2

    .line 17
    :cond_1
    aget-object v5, p1, v4

    .line 18
    .line 19
    if-nez v2, :cond_2

    .line 20
    .line 21
    invoke-virtual {v5, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-nez v2, :cond_2

    .line 26
    .line 27
    move v2, v1

    .line 28
    goto :goto_2

    .line 29
    :cond_2
    move v2, v0

    .line 30
    :goto_2
    add-int/lit8 v4, v4, 0x1

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_3
    return v2
.end method

.method private static indexOf(Ljava/lang/CharSequence;Ljava/lang/CharSequence;I)I
    .locals 0

    .line 1
    invoke-interface {p0}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p1}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p1, p2}, Ljava/lang/String;->indexOf(Ljava/lang/String;I)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public static isEmpty(Ljava/lang/CharSequence;)Z
    .locals 0

    if-eqz p0, :cond_0

    .line 1
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    move-result p0

    if-eqz p0, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    const/4 p0, 0x1

    return p0
.end method

.method private static isEmpty([C)Z
    .locals 0

    if-eqz p0, :cond_0

    .line 2
    array-length p0, p0

    if-eqz p0, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    const/4 p0, 0x1

    return p0
.end method

.method private static toCharArray(Ljava/lang/CharSequence;)[C
    .locals 4

    .line 1
    instance-of v0, p0, Ljava/lang/String;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/String;->toCharArray()[C

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    new-array v1, v1, [C

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    :goto_0
    if-lt v2, v0, :cond_1

    .line 24
    .line 25
    return-object v1

    .line 26
    :cond_1
    invoke-interface {p0, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    aput-char v3, v1, v2

    .line 31
    .line 32
    add-int/lit8 v2, v2, 0x1

    .line 33
    .line 34
    goto :goto_0
.end method
