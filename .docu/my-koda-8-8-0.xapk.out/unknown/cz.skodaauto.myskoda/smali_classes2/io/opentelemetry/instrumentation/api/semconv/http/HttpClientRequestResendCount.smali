.class public final Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final KEY:Lio/opentelemetry/context/ContextKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/ContextKey<",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;",
            ">;"
        }
    .end annotation
.end field

.field private static final resendsUpdater:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater<",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private volatile resends:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "opentelemetry-http-client-resend-key"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/context/ContextKey;->named(Ljava/lang/String;)Lio/opentelemetry/context/ContextKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 8
    .line 9
    const-class v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;

    .line 10
    .line 11
    const-string v1, "resends"

    .line 12
    .line 13
    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;->resendsUpdater:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 18
    .line 19
    return-void
.end method

.method private constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;->resends:I

    .line 6
    .line 7
    return-void
.end method

.method public static get(Lio/opentelemetry/context/Context;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    return p0

    .line 13
    :cond_0
    iget p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;->resends:I

    .line 14
    .line 15
    return p0
.end method

.method public static getAndIncrement(Lio/opentelemetry/context/Context;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    return p0

    .line 13
    :cond_0
    sget-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;->resendsUpdater:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->getAndIncrement(Ljava/lang/Object;)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public static initialize(Lio/opentelemetry/context/Context;)Lio/opentelemetry/context/Context;
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance v1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;

    .line 11
    .line 12
    invoke-direct {v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;-><init>()V

    .line 13
    .line 14
    .line 15
    invoke-interface {p0, v0, v1}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ContextKey;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
