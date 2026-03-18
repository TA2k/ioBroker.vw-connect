.class public final Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;


# instance fields
.field address:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field port:Ljava/lang/Integer;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public getAddress()Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;->address:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getPort()Ljava/lang/Integer;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;->port:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public setAddress(Ljava/lang/String;)V
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;->address:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setPort(Ljava/lang/Integer;)V
    .locals 0
    .param p1    # Ljava/lang/Integer;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;->port:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method
