.class public final Lio/opentelemetry/sdk/internal/InstrumentationScopeUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


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

.method public static toInstrumentationLibraryInfo(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getName()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getVersion()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {p0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getSchemaUrl()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-static {v0, v1, p0}, Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;->create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static toInstrumentationScopeInfo(Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;->getName()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->builder(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p0}, Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;->getVersion()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;->getVersion()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setVersion(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 20
    .line 21
    .line 22
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;->getSchemaUrl()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0}, Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;->getSchemaUrl()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-virtual {v0, p0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 33
    .line 34
    .line 35
    :cond_1
    invoke-virtual {v0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->build()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method
