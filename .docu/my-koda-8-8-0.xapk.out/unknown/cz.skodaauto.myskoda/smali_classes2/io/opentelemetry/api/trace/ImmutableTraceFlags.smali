.class final Lio/opentelemetry/api/trace/ImmutableTraceFlags;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/trace/TraceFlags;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field static final DEFAULT:Lio/opentelemetry/api/trace/ImmutableTraceFlags;

.field static final HEX_LENGTH:I = 0x2

.field private static final INSTANCES:[Lio/opentelemetry/api/trace/ImmutableTraceFlags;

.field static final SAMPLED:Lio/opentelemetry/api/trace/ImmutableTraceFlags;

.field private static final SAMPLED_BIT:B = 0x1t


# instance fields
.field private final byteRep:B

.field private final hexRep:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->buildInstances()[Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->INSTANCES:[Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-static {v0}, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->fromByte(B)Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sput-object v0, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->DEFAULT:Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    invoke-static {v0}, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->fromByte(B)Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->SAMPLED:Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 20
    .line 21
    return-void
.end method

.method private constructor <init>(B)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    new-array v0, v0, [C

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-static {p1, v0, v1}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteToBase16(B[CI)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Ljava/lang/String;

    .line 12
    .line 13
    invoke-direct {v1, v0}, Ljava/lang/String;-><init>([C)V

    .line 14
    .line 15
    .line 16
    iput-object v1, p0, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->hexRep:Ljava/lang/String;

    .line 17
    .line 18
    iput-byte p1, p0, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->byteRep:B

    .line 19
    .line 20
    return-void
.end method

.method private static buildInstances()[Lio/opentelemetry/api/trace/ImmutableTraceFlags;
    .locals 5

    .line 1
    const/16 v0, 0x100

    .line 2
    .line 3
    new-array v1, v0, [Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    :goto_0
    if-ge v2, v0, :cond_0

    .line 7
    .line 8
    new-instance v3, Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 9
    .line 10
    int-to-byte v4, v2

    .line 11
    invoke-direct {v3, v4}, Lio/opentelemetry/api/trace/ImmutableTraceFlags;-><init>(B)V

    .line 12
    .line 13
    .line 14
    aput-object v3, v1, v2

    .line 15
    .line 16
    add-int/lit8 v2, v2, 0x1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    return-object v1
.end method

.method public static fromByte(B)Lio/opentelemetry/api/trace/ImmutableTraceFlags;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->INSTANCES:[Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0xff

    .line 4
    .line 5
    aget-object p0, v0, p0

    .line 6
    .line 7
    return-object p0
.end method

.method public static fromHex(Ljava/lang/CharSequence;I)Lio/opentelemetry/api/trace/ImmutableTraceFlags;
    .locals 1

    .line 1
    const-string v0, "src"

    .line 2
    .line 3
    invoke-static {p0, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, p1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    add-int/lit8 p1, p1, 0x1

    .line 11
    .line 12
    invoke-interface {p0, p1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    invoke-static {v0, p0}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteFromBase16(CC)B

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-static {p0}, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->fromByte(B)Lio/opentelemetry/api/trace/ImmutableTraceFlags;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method


# virtual methods
.method public asByte()B
    .locals 0

    .line 1
    iget-byte p0, p0, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->byteRep:B

    .line 2
    .line 3
    return p0
.end method

.method public asHex()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->hexRep:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public isSampled()Z
    .locals 1

    .line 1
    iget-byte p0, p0, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->byteRep:B

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    and-int/2addr p0, v0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return v0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/api/trace/ImmutableTraceFlags;->asHex()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
