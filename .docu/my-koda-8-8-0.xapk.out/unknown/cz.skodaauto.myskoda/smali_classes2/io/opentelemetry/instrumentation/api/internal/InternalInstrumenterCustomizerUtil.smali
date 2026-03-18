.class public Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizerUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static volatile instrumenterCustomizerProviders:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizerProvider;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 2
    .line 3
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizerUtil;->instrumenterCustomizerProviders:Ljava/util/List;

    .line 4
    .line 5
    :try_start_0
    sget v0, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InstrumenterCustomizerUtil;->a:I
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 6
    .line 7
    :catch_0
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

.method public static getInstrumenterCustomizerProviders()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizerProvider;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizerUtil;->instrumenterCustomizerProviders:Ljava/util/List;

    .line 2
    .line 3
    return-object v0
.end method

.method public static setInstrumenterCustomizerProviders(Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizerProvider;",
            ">;)V"
        }
    .end annotation

    .line 1
    sput-object p0, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizerUtil;->instrumenterCustomizerProviders:Ljava/util/List;

    .line 2
    .line 3
    return-void
.end method
