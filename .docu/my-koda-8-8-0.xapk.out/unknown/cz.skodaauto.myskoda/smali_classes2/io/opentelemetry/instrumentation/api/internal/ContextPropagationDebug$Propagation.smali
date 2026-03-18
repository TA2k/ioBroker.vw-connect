.class Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug$Propagation;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Propagation"
.end annotation


# instance fields
.field final carrierClassName:Ljava/lang/String;

.field final location:[Ljava/lang/StackTraceElement;


# direct methods
.method public constructor <init>(Ljava/lang/String;[Ljava/lang/StackTraceElement;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug$Propagation;->carrierClassName:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug$Propagation;->location:[Ljava/lang/StackTraceElement;

    .line 7
    .line 8
    return-void
.end method
