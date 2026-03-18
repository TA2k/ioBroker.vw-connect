.class public final Lcz/skodaauto/myskoda/library/callservicesdata/data/LocalTimeTypeConverter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u00c1\u0002\u0018\u00002\u00020\u0001J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0007\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u0007\u001a\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0007\u00a2\u0006\u0004\u0008\u0007\u0010\u0008\u00a8\u0006\t"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/library/callservicesdata/data/LocalTimeTypeConverter;",
        "",
        "",
        "value",
        "Ljava/time/LocalTime;",
        "fromJson",
        "(Ljava/lang/String;)Ljava/time/LocalTime;",
        "toJson",
        "(Ljava/time/LocalTime;)Ljava/lang/String;",
        "call-services-data_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final a:Lcz/skodaauto/myskoda/library/callservicesdata/data/LocalTimeTypeConverter;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcz/skodaauto/myskoda/library/callservicesdata/data/LocalTimeTypeConverter;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcz/skodaauto/myskoda/library/callservicesdata/data/LocalTimeTypeConverter;->a:Lcz/skodaauto/myskoda/library/callservicesdata/data/LocalTimeTypeConverter;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final fromJson(Ljava/lang/String;)Ljava/time/LocalTime;
    .locals 0
    .annotation runtime Lcom/squareup/moshi/FromJson;
    .end annotation

    .line 1
    const-string p0, "value"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    const-string p1, "parse(...)"

    .line 11
    .line 12
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public final toJson(Ljava/time/LocalTime;)Ljava/lang/String;
    .locals 0
    .annotation runtime Lcom/squareup/moshi/ToJson;
    .end annotation

    .line 1
    const-string p0, "value"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Ljava/time/format/FormatStyle;->MEDIUM:Ljava/time/format/FormatStyle;

    .line 7
    .line 8
    invoke-static {p0}, Ljava/time/format/DateTimeFormatter;->ofLocalizedTime(Ljava/time/format/FormatStyle;)Ljava/time/format/DateTimeFormatter;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p1, p0}, Ljava/time/LocalTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-string p1, "format(...)"

    .line 17
    .line 18
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object p0
.end method
