.class public final Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InternalInstrumenterCustomizerProviderImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizerProvider;


# instance fields
.field private final provider:Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizerProvider;


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizerProvider;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InternalInstrumenterCustomizerProviderImpl;->provider:Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizerProvider;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public customize(Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer<",
            "**>;)V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InternalInstrumenterCustomizerProviderImpl;->provider:Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizerProvider;

    .line 2
    .line 3
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InstrumenterCustomizerImpl;

    .line 4
    .line 5
    invoke-direct {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InstrumenterCustomizerImpl;-><init>(Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;)V

    .line 6
    .line 7
    .line 8
    invoke-interface {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizerProvider;->customize(Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method
