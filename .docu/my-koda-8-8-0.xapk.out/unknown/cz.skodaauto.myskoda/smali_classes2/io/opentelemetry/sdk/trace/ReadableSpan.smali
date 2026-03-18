.class public interface abstract Lio/opentelemetry/sdk/trace/ReadableSpan;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract getAttribute(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;)TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public abstract getInstrumentationLibraryInfo()Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation
.end method

.method public getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 0

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/ReadableSpan;->getInstrumentationLibraryInfo()Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/sdk/internal/InstrumentationScopeUtil;->toInstrumentationScopeInfo(Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public abstract getKind()Lio/opentelemetry/api/trace/SpanKind;
.end method

.method public abstract getLatencyNanos()J
.end method

.method public abstract getName()Ljava/lang/String;
.end method

.method public abstract getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;
.end method

.method public abstract getSpanContext()Lio/opentelemetry/api/trace/SpanContext;
.end method

.method public abstract hasEnded()Z
.end method

.method public abstract toSpanData()Lio/opentelemetry/sdk/trace/data/SpanData;
.end method
