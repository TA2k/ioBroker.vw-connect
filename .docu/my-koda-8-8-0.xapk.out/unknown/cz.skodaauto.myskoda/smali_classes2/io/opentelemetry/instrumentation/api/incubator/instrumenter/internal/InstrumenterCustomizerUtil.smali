.class public final Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InstrumenterCustomizerUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    const-class v1, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizerProvider;

    .line 7
    .line 8
    invoke-static {v1}, Lio/opentelemetry/instrumentation/api/internal/ServiceLoaderUtil;->load(Ljava/lang/Class;)Ljava/lang/Iterable;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-eqz v2, :cond_0

    .line 21
    .line 22
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    check-cast v2, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizerProvider;

    .line 27
    .line 28
    new-instance v3, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InternalInstrumenterCustomizerProviderImpl;

    .line 29
    .line 30
    invoke-direct {v3, v2}, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InternalInstrumenterCustomizerProviderImpl;-><init>(Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizerProvider;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizerUtil;->setInstrumenterCustomizerProviders(Ljava/util/List;)V

    .line 38
    .line 39
    .line 40
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
