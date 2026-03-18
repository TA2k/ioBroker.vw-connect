.class public final synthetic Lio/opentelemetry/sdk/internal/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Function;


# instance fields
.field public final synthetic a:Lio/opentelemetry/sdk/internal/ComponentRegistry;

.field public final synthetic b:Ljava/lang/String;

.field public final synthetic c:Ljava/lang/String;

.field public final synthetic d:Lio/opentelemetry/api/common/Attributes;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lio/opentelemetry/sdk/internal/c;->a:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 5
    .line 6
    iput-object p3, p0, Lio/opentelemetry/sdk/internal/c;->b:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p4, p0, Lio/opentelemetry/sdk/internal/c;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p1, p0, Lio/opentelemetry/sdk/internal/c;->d:Lio/opentelemetry/api/common/Attributes;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/c;->d:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    check-cast p1, Ljava/lang/String;

    .line 4
    .line 5
    iget-object v1, p0, Lio/opentelemetry/sdk/internal/c;->a:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 6
    .line 7
    iget-object v2, p0, Lio/opentelemetry/sdk/internal/c;->b:Ljava/lang/String;

    .line 8
    .line 9
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/c;->c:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v1, v2, p0, v0, p1}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->a(Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
