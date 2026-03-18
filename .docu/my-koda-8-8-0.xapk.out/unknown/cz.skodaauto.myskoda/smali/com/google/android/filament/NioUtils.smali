.class final Lcom/google/android/filament/NioUtils;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/google/android/filament/proguard/UsedByNative;
    value = "NioUtils.cpp"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/NioUtils$BufferType;
    }
.end annotation


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

.method public static getBaseArray(Ljava/nio/Buffer;)Ljava/lang/Object;
    .locals 1
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "NioUtils.cpp"
    .end annotation

    .line 1
    invoke-virtual {p0}, Ljava/nio/Buffer;->hasArray()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/nio/Buffer;->array()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public static getBaseArrayOffset(Ljava/nio/Buffer;I)I
    .locals 1
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "NioUtils.cpp"
    .end annotation

    .line 1
    invoke-virtual {p0}, Ljava/nio/Buffer;->hasArray()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/nio/Buffer;->arrayOffset()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-virtual {p0}, Ljava/nio/Buffer;->position()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    shl-int/2addr p0, p1

    .line 17
    return p0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0
.end method

.method public static getBasePointer(Ljava/nio/Buffer;JI)J
    .locals 3
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "NioUtils.cpp"
    .end annotation

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v2, p1, v0

    .line 4
    .line 5
    if-eqz v2, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/nio/Buffer;->position()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    shl-int/2addr p0, p3

    .line 12
    int-to-long v0, p0

    .line 13
    add-long/2addr p1, v0

    .line 14
    return-wide p1

    .line 15
    :cond_0
    return-wide v0
.end method

.method public static getBufferType(Ljava/nio/Buffer;)I
    .locals 1
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "NioUtils.cpp"
    .end annotation

    .line 1
    instance-of v0, p0, Ljava/nio/ByteBuffer;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lcom/google/android/filament/NioUtils$BufferType;->BYTE:Lcom/google/android/filament/NioUtils$BufferType;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    instance-of v0, p0, Ljava/nio/CharBuffer;

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    sget-object p0, Lcom/google/android/filament/NioUtils$BufferType;->CHAR:Lcom/google/android/filament/NioUtils$BufferType;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0

    .line 23
    :cond_1
    instance-of v0, p0, Ljava/nio/ShortBuffer;

    .line 24
    .line 25
    if-eqz v0, :cond_2

    .line 26
    .line 27
    sget-object p0, Lcom/google/android/filament/NioUtils$BufferType;->SHORT:Lcom/google/android/filament/NioUtils$BufferType;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    return p0

    .line 34
    :cond_2
    instance-of v0, p0, Ljava/nio/IntBuffer;

    .line 35
    .line 36
    if-eqz v0, :cond_3

    .line 37
    .line 38
    sget-object p0, Lcom/google/android/filament/NioUtils$BufferType;->INT:Lcom/google/android/filament/NioUtils$BufferType;

    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    return p0

    .line 45
    :cond_3
    instance-of v0, p0, Ljava/nio/LongBuffer;

    .line 46
    .line 47
    if-eqz v0, :cond_4

    .line 48
    .line 49
    sget-object p0, Lcom/google/android/filament/NioUtils$BufferType;->LONG:Lcom/google/android/filament/NioUtils$BufferType;

    .line 50
    .line 51
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    return p0

    .line 56
    :cond_4
    instance-of p0, p0, Ljava/nio/FloatBuffer;

    .line 57
    .line 58
    if-eqz p0, :cond_5

    .line 59
    .line 60
    sget-object p0, Lcom/google/android/filament/NioUtils$BufferType;->FLOAT:Lcom/google/android/filament/NioUtils$BufferType;

    .line 61
    .line 62
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    return p0

    .line 67
    :cond_5
    sget-object p0, Lcom/google/android/filament/NioUtils$BufferType;->DOUBLE:Lcom/google/android/filament/NioUtils$BufferType;

    .line 68
    .line 69
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    return p0
.end method
