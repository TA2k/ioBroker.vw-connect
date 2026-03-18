.class public final Lcz/skodaauto/myskoda/library/callservicesdata/data/DayOfWeekTypeConverter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u00c1\u0002\u0018\u00002\u00020\u0001J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0007\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u0007\u001a\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0007\u00a2\u0006\u0004\u0008\u0007\u0010\u0008\u00a8\u0006\t"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/library/callservicesdata/data/DayOfWeekTypeConverter;",
        "",
        "",
        "value",
        "Ljava/time/DayOfWeek;",
        "fromJson",
        "(Ljava/lang/String;)Ljava/time/DayOfWeek;",
        "toJson",
        "(Ljava/time/DayOfWeek;)Ljava/lang/String;",
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
.field public static final a:Lcz/skodaauto/myskoda/library/callservicesdata/data/DayOfWeekTypeConverter;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcz/skodaauto/myskoda/library/callservicesdata/data/DayOfWeekTypeConverter;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcz/skodaauto/myskoda/library/callservicesdata/data/DayOfWeekTypeConverter;->a:Lcz/skodaauto/myskoda/library/callservicesdata/data/DayOfWeekTypeConverter;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final fromJson(Ljava/lang/String;)Ljava/time/DayOfWeek;
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
    invoke-virtual {p1}, Ljava/lang/String;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    sparse-switch p0, :sswitch_data_0

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :sswitch_0
    const-string p0, "Wed"

    .line 15
    .line 16
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-nez p0, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    sget-object p0, Ljava/time/DayOfWeek;->WEDNESDAY:Ljava/time/DayOfWeek;

    .line 24
    .line 25
    return-object p0

    .line 26
    :sswitch_1
    const-string p0, "Tue"

    .line 27
    .line 28
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-nez p0, :cond_1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    sget-object p0, Ljava/time/DayOfWeek;->TUESDAY:Ljava/time/DayOfWeek;

    .line 36
    .line 37
    return-object p0

    .line 38
    :sswitch_2
    const-string p0, "Thu"

    .line 39
    .line 40
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-nez p0, :cond_2

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_2
    sget-object p0, Ljava/time/DayOfWeek;->THURSDAY:Ljava/time/DayOfWeek;

    .line 48
    .line 49
    return-object p0

    .line 50
    :sswitch_3
    const-string p0, "Sat"

    .line 51
    .line 52
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    if-nez p0, :cond_3

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_3
    sget-object p0, Ljava/time/DayOfWeek;->SATURDAY:Ljava/time/DayOfWeek;

    .line 60
    .line 61
    return-object p0

    .line 62
    :sswitch_4
    const-string p0, "Mon"

    .line 63
    .line 64
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    if-eqz p0, :cond_4

    .line 69
    .line 70
    sget-object p0, Ljava/time/DayOfWeek;->MONDAY:Ljava/time/DayOfWeek;

    .line 71
    .line 72
    return-object p0

    .line 73
    :sswitch_5
    const-string p0, "Fri"

    .line 74
    .line 75
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    if-nez p0, :cond_5

    .line 80
    .line 81
    :cond_4
    :goto_0
    sget-object p0, Ljava/time/DayOfWeek;->SUNDAY:Ljava/time/DayOfWeek;

    .line 82
    .line 83
    return-object p0

    .line 84
    :cond_5
    sget-object p0, Ljava/time/DayOfWeek;->FRIDAY:Ljava/time/DayOfWeek;

    .line 85
    .line 86
    return-object p0

    .line 87
    :sswitch_data_0
    .sparse-switch
        0x114fd -> :sswitch_5
        0x12eec -> :sswitch_4
        0x143c6 -> :sswitch_3
        0x14861 -> :sswitch_2
        0x149e4 -> :sswitch_1
        0x15336 -> :sswitch_0
    .end sparse-switch
.end method

.method public final toJson(Ljava/time/DayOfWeek;)Ljava/lang/String;
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
    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method
