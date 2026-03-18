.class public final Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/context/ImplicitContextKeyed;


# static fields
.field private static final KEY:Lio/opentelemetry/context/ContextKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/ContextKey<",
            "Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final method:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private volatile route:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private volatile span:Lio/opentelemetry/api/trace/Span;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private volatile updatedBySourceOrder:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "opentelemetry-http-server-route-key"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/context/ContextKey;->named(Ljava/lang/String;)Lio/opentelemetry/context/ContextKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;Ljava/lang/String;ILio/opentelemetry/api/trace/Span;)V
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p4    # Lio/opentelemetry/api/trace/Span;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->method:Ljava/lang/String;

    .line 5
    .line 6
    iput p3, p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->updatedBySourceOrder:I

    .line 7
    .line 8
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->route:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->span:Lio/opentelemetry/api/trace/Span;

    .line 11
    .line 12
    return-void
.end method

.method public static create(Ljava/lang/String;Ljava/lang/String;I)Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;
    .locals 1
    .param p0    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    const/4 v0, 0x0

    .line 1
    invoke-static {p0, p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->create(Ljava/lang/String;Ljava/lang/String;ILio/opentelemetry/api/trace/Span;)Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;

    move-result-object p0

    return-object p0
.end method

.method public static create(Ljava/lang/String;Ljava/lang/String;ILio/opentelemetry/api/trace/Span;)Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;
    .locals 1
    .param p0    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p3    # Lio/opentelemetry/api/trace/Span;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 2
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;

    invoke-direct {v0, p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;-><init>(Ljava/lang/String;Ljava/lang/String;ILio/opentelemetry/api/trace/Span;)V

    return-object v0
.end method

.method public static fromContextOrNull(Lio/opentelemetry/context/Context;)Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;
    .locals 1
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;

    .line 8
    .line 9
    return-object p0
.end method

.method public static updateSpan(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/Span;)V
    .locals 1

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->fromContextOrNull(Lio/opentelemetry/context/Context;)Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->span:Lio/opentelemetry/api/trace/Span;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->span:Lio/opentelemetry/api/trace/Span;

    .line 12
    .line 13
    :cond_0
    return-void
.end method


# virtual methods
.method public getMethod()Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->method:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRoute()Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->route:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSpan()Lio/opentelemetry/api/trace/Span;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->span:Lio/opentelemetry/api/trace/Span;

    .line 2
    .line 3
    return-object p0
.end method

.method public getUpdatedBySourceOrder()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->updatedBySourceOrder:I

    .line 2
    .line 3
    return p0
.end method

.method public storeInContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/context/Context;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p1, v0, p0}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ContextKey;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public update(Lio/opentelemetry/context/Context;ILjava/lang/String;)V
    .locals 0

    .line 1
    iput p2, p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->updatedBySourceOrder:I

    .line 2
    .line 3
    iput-object p3, p0, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->route:Ljava/lang/String;

    .line 4
    .line 5
    return-void
.end method
