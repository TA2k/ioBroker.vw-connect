.class public final Lz81/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lz81/c;
.implements Lz81/s;


# static fields
.field public static final a:Lz81/b;

.field public static final b:Lz81/b;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lz81/b;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lz81/b;->a:Lz81/b;

    .line 7
    .line 8
    new-instance v0, Lz81/b;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lz81/b;->b:Lz81/b;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public a(Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;)Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;
    .locals 0

    .line 1
    return-object p1
.end method

.method public b(Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;)Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;
    .locals 0

    .line 1
    return-object p1
.end method
