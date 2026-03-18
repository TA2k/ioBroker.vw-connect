.class public final synthetic Lio/opentelemetry/sdk/metrics/internal/view/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Predicate;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio/opentelemetry/sdk/metrics/internal/view/a;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/view/a;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final test(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/view/a;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/a;->b:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ljava/lang/String;

    .line 9
    .line 10
    check-cast p1, Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0

    .line 17
    :pswitch_0
    check-cast p0, Ljava/util/regex/Pattern;

    .line 18
    .line 19
    check-cast p1, Ljava/lang/String;

    .line 20
    .line 21
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/view/StringPredicates;->a(Ljava/util/regex/Pattern;Ljava/lang/String;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :pswitch_1
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AttributeKeyFilteringProcessor;

    .line 27
    .line 28
    check-cast p1, Lio/opentelemetry/api/common/AttributeKey;

    .line 29
    .line 30
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AttributeKeyFilteringProcessor;->a(Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AttributeKeyFilteringProcessor;Lio/opentelemetry/api/common/AttributeKey;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    return p0

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
