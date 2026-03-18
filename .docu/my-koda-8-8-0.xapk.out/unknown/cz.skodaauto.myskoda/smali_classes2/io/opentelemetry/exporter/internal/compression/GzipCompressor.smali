.class public final Lio/opentelemetry/exporter/internal/compression/GzipCompressor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/compression/Compressor;


# static fields
.field private static final INSTANCE:Lio/opentelemetry/exporter/internal/compression/GzipCompressor;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/compression/GzipCompressor;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/compression/GzipCompressor;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/compression/GzipCompressor;->INSTANCE:Lio/opentelemetry/exporter/internal/compression/GzipCompressor;

    .line 7
    .line 8
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

.method public static getInstance()Lio/opentelemetry/exporter/internal/compression/GzipCompressor;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/compression/GzipCompressor;->INSTANCE:Lio/opentelemetry/exporter/internal/compression/GzipCompressor;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public compress(Ljava/io/OutputStream;)Ljava/io/OutputStream;
    .locals 0

    .line 1
    new-instance p0, Ljava/util/zip/GZIPOutputStream;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Ljava/util/zip/GZIPOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public getEncoding()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "gzip"

    .line 2
    .line 3
    return-object p0
.end method
