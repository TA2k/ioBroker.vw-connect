.class Lio/opentelemetry/api/trace/DefaultTracerProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/trace/TracerProvider;


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# static fields
.field private static final INSTANCE:Lio/opentelemetry/api/trace/TracerProvider;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/trace/DefaultTracerProvider;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/trace/DefaultTracerProvider;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "io.opentelemetry.api.incubator.trace.ExtendedDefaultTracerProvider"

    .line 7
    .line 8
    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/IncubatingUtil;->incubatingApiIfAvailable(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lio/opentelemetry/api/trace/TracerProvider;

    .line 13
    .line 14
    sput-object v0, Lio/opentelemetry/api/trace/DefaultTracerProvider;->INSTANCE:Lio/opentelemetry/api/trace/TracerProvider;

    .line 15
    .line 16
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

.method public static getInstance()Lio/opentelemetry/api/trace/TracerProvider;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/trace/DefaultTracerProvider;->INSTANCE:Lio/opentelemetry/api/trace/TracerProvider;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public get(Ljava/lang/String;)Lio/opentelemetry/api/trace/Tracer;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/DefaultTracer;->getInstance()Lio/opentelemetry/api/trace/Tracer;

    move-result-object p0

    return-object p0
.end method

.method public get(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/Tracer;
    .locals 0

    .line 2
    invoke-static {}, Lio/opentelemetry/api/trace/DefaultTracer;->getInstance()Lio/opentelemetry/api/trace/Tracer;

    move-result-object p0

    return-object p0
.end method
