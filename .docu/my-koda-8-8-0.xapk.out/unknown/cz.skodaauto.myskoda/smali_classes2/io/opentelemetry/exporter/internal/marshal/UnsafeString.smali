.class Lio/opentelemetry/exporter/internal/marshal/UnsafeString;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final available:Z

.field private static final byteArrayBaseOffset:I

.field private static final coderOffset:J

.field private static final valueOffset:J


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    const-class v1, [B

    .line 4
    .line 5
    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->getStringFieldOffset(Ljava/lang/String;Ljava/lang/Class;)J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    sput-wide v2, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->valueOffset:J

    .line 10
    .line 11
    const-string v0, "coder"

    .line 12
    .line 13
    sget-object v4, Ljava/lang/Byte;->TYPE:Ljava/lang/Class;

    .line 14
    .line 15
    invoke-static {v0, v4}, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->getStringFieldOffset(Ljava/lang/String;Ljava/lang/Class;)J

    .line 16
    .line 17
    .line 18
    move-result-wide v4

    .line 19
    sput-wide v4, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->coderOffset:J

    .line 20
    .line 21
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/UnsafeAccess;->isAvailable()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    invoke-static {v1}, Lio/opentelemetry/exporter/internal/marshal/UnsafeAccess;->arrayBaseOffset(Ljava/lang/Class;)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 v0, -0x1

    .line 33
    :goto_0
    sput v0, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->byteArrayBaseOffset:I

    .line 34
    .line 35
    const-wide/16 v0, -0x1

    .line 36
    .line 37
    cmp-long v2, v2, v0

    .line 38
    .line 39
    if-eqz v2, :cond_1

    .line 40
    .line 41
    cmp-long v0, v4, v0

    .line 42
    .line 43
    if-eqz v0, :cond_1

    .line 44
    .line 45
    const/4 v0, 0x1

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    const/4 v0, 0x0

    .line 48
    :goto_1
    sput-boolean v0, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->available:Z

    .line 49
    .line 50
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static getBytes(Ljava/lang/String;)[B
    .locals 2

    .line 1
    sget-wide v0, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->valueOffset:J

    .line 2
    .line 3
    invoke-static {p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/UnsafeAccess;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, [B

    .line 8
    .line 9
    return-object p0
.end method

.method public static getLong([BI)J
    .locals 2

    .line 1
    sget v0, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->byteArrayBaseOffset:I

    .line 2
    .line 3
    add-int/2addr v0, p1

    .line 4
    int-to-long v0, v0

    .line 5
    invoke-static {p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/UnsafeAccess;->getLong(Ljava/lang/Object;J)J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    return-wide p0
.end method

.method private static getStringFieldOffset(Ljava/lang/String;Ljava/lang/Class;)J
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/Class<",
            "*>;)J"
        }
    .end annotation

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/UnsafeAccess;->isAvailable()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const-wide/16 v1, -0x1

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    return-wide v1

    .line 10
    :cond_0
    :try_start_0
    const-class v0, Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-virtual {p0}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-eq v0, p1, :cond_1

    .line 21
    .line 22
    return-wide v1

    .line 23
    :cond_1
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/UnsafeAccess;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 24
    .line 25
    .line 26
    move-result-wide p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    return-wide p0

    .line 28
    :catch_0
    return-wide v1
.end method

.method public static isAvailable()Z
    .locals 1

    .line 1
    sget-boolean v0, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->available:Z

    .line 2
    .line 3
    return v0
.end method

.method public static isLatin1(Ljava/lang/String;)Z
    .locals 2

    .line 1
    sget-wide v0, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->coderOffset:J

    .line 2
    .line 3
    invoke-static {p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/UnsafeAccess;->getByte(Ljava/lang/Object;J)B

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method
