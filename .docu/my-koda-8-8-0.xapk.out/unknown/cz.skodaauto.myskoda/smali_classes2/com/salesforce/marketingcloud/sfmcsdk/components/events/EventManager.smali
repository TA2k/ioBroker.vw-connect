.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0018\u0000 \u00122\u00020\u0001:\u0001\u0012B\u0011\u0008\u0000\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J!\u0010\n\u001a\u00020\t2\u0012\u0010\u0008\u001a\n\u0012\u0006\u0008\u0001\u0012\u00020\u00070\u0006\"\u00020\u0007\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u0015\u0010\u000e\u001a\u00020\t2\u0006\u0010\r\u001a\u00020\u000c\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u0015\u0010\u0010\u001a\u00020\t2\u0006\u0010\r\u001a\u00020\u000c\u00a2\u0006\u0004\u0008\u0010\u0010\u000fR\u0014\u0010\u0003\u001a\u00020\u00028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0003\u0010\u0011\u00a8\u0006\u0013"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;",
        "",
        "",
        "moduleName",
        "<init>",
        "(Ljava/lang/String;)V",
        "",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;",
        "events",
        "Llx0/b0;",
        "track",
        "([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventSubscriber;",
        "subscriber",
        "subscribe",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventSubscriber;)V",
        "unsubscribe",
        "Ljava/lang/String;",
        "Companion",
        "sfmcsdk_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

.field public static final TAG:Ljava/lang/String; = "~$EventManager"

.field private static final subscribers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventSubscriber;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final moduleName:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

    .line 8
    .line 9
    new-instance v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->subscribers:Ljava/util/List;

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "moduleName"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->moduleName:Ljava/lang/String;

    .line 10
    .line 11
    return-void
.end method

.method public static final synthetic access$getSubscribers$cp()Ljava/util/List;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->subscribers:Ljava/util/List;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final customEvent(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;->customEvent(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    move-result-object p0

    return-object p0
.end method

.method public static final customEvent(Ljava/lang/String;Ljava/util/Map;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "+",
            "Ljava/lang/Object;",
            ">;)",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;"
        }
    .end annotation

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

    invoke-virtual {v0, p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;->customEvent(Ljava/lang/String;Ljava/util/Map;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    move-result-object p0

    return-object p0
.end method

.method public static final customEvent(Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "+",
            "Ljava/lang/Object;",
            ">;",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;",
            ")",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;"
        }
    .end annotation

    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

    invoke-virtual {v0, p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;->customEvent(Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    move-result-object p0

    return-object p0
.end method

.method public static final customEvent(Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "+",
            "Ljava/lang/Object;",
            ">;",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;",
            ")",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;"
        }
    .end annotation

    .line 4
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

    invoke-virtual {v0, p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;->customEvent(Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final subscribe(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventSubscriber;)V
    .locals 0

    .line 1
    const-string p0, "subscriber"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->subscribers:Ljava/util/List;

    .line 7
    .line 8
    monitor-enter p0

    .line 9
    :try_start_0
    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    .line 11
    .line 12
    monitor-exit p0

    .line 13
    return-void

    .line 14
    :catchall_0
    move-exception p1

    .line 15
    monitor-exit p0

    .line 16
    throw p1
.end method

.method public final varargs track([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V
    .locals 10

    .line 1
    const-string v0, "events"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->moduleName:Ljava/lang/String;

    .line 7
    .line 8
    const-string v0, "PUSH"

    .line 9
    .line 10
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;->PUSH:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    .line 17
    .line 18
    :goto_0
    move-object v3, p0

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    const-string v0, "CDP"

    .line 21
    .line 22
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    if-eqz p0, :cond_1

    .line 27
    .line 28
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;->CDP:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;->SFMC_SDK:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :goto_1
    new-instance p0, Ljava/util/ArrayList;

    .line 35
    .line 36
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 37
    .line 38
    .line 39
    array-length v7, p1

    .line 40
    const/4 v8, 0x0

    .line 41
    move v9, v8

    .line 42
    :goto_2
    if-ge v9, v7, :cond_3

    .line 43
    .line 44
    aget-object v0, p1, v9

    .line 45
    .line 46
    move-object v1, v0

    .line 47
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

    .line 48
    .line 49
    move-object v2, v1

    .line 50
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->name()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->attributes()Ljava/util/Map;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    const/16 v5, 0x8

    .line 59
    .line 60
    const/4 v6, 0x0

    .line 61
    const/4 v4, 0x0

    .line 62
    invoke-static/range {v0 .. v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;->customEvent$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    if-eqz v0, :cond_2

    .line 67
    .line 68
    invoke-interface {p0, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    :cond_2
    add-int/lit8 v9, v9, 0x1

    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_3
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

    .line 75
    .line 76
    new-array v0, v8, [Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    .line 77
    .line 78
    invoke-interface {p0, v0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, [Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    .line 83
    .line 84
    array-length v0, p0

    .line 85
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    check-cast p0, [Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    .line 90
    .line 91
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->track([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    .line 92
    .line 93
    .line 94
    return-void
.end method

.method public final unsubscribe(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventSubscriber;)V
    .locals 0

    .line 1
    const-string p0, "subscriber"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->subscribers:Ljava/util/List;

    .line 7
    .line 8
    monitor-enter p0

    .line 9
    :try_start_0
    invoke-interface {p0, p1}, Ljava/util/List;->remove(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    .line 11
    .line 12
    monitor-exit p0

    .line 13
    return-void

    .line 14
    :catchall_0
    move-exception p1

    .line 15
    monitor-exit p0

    .line 16
    throw p1
.end method
