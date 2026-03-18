.class public final synthetic Lio/opentelemetry/api/incubator/common/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Predicate;


# instance fields
.field public final synthetic a:Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/api/incubator/common/b;->a:Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final test(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/incubator/common/b;->a:Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 2
    .line 3
    check-cast p1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 4
    .line 5
    invoke-static {p0, p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->a(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method
