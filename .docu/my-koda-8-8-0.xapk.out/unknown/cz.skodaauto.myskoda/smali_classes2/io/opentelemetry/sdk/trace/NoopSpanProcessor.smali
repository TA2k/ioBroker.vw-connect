.class final Lio/opentelemetry/sdk/trace/NoopSpanProcessor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/SpanProcessor;


# static fields
.field private static final INSTANCE:Lio/opentelemetry/sdk/trace/NoopSpanProcessor;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/NoopSpanProcessor;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/trace/NoopSpanProcessor;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/sdk/trace/NoopSpanProcessor;->INSTANCE:Lio/opentelemetry/sdk/trace/NoopSpanProcessor;

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

.method public static getInstance()Lio/opentelemetry/sdk/trace/SpanProcessor;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/NoopSpanProcessor;->INSTANCE:Lio/opentelemetry/sdk/trace/NoopSpanProcessor;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public isEndRequired()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public isStartRequired()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public onEnd(Lio/opentelemetry/sdk/trace/ReadableSpan;)V
    .locals 0

    .line 1
    return-void
.end method

.method public onStart(Lio/opentelemetry/context/Context;Lio/opentelemetry/sdk/trace/ReadWriteSpan;)V
    .locals 0

    .line 1
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "NoopSpanProcessor{}"

    .line 2
    .line 3
    return-object p0
.end method
