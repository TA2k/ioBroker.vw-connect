.class final Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteGetter;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ConstantAdapter"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteGetter<",
        "Ljava/lang/String;",
        ">;"
    }
.end annotation


# static fields
.field private static final INSTANCE:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;->INSTANCE:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;

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

.method public static synthetic access$000()Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;->INSTANCE:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public bridge synthetic get(Lio/opentelemetry/context/Context;Ljava/lang/Object;)Ljava/lang/String;
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 2
    check-cast p2, Ljava/lang/String;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute$ConstantAdapter;->get(Lio/opentelemetry/context/Context;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public get(Lio/opentelemetry/context/Context;Ljava/lang/String;)Ljava/lang/String;
    .locals 0
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    return-object p2
.end method
