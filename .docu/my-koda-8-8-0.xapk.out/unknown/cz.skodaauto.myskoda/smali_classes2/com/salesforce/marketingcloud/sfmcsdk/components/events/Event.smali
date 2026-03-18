.class public abstract Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;,
        Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00006\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010$\n\u0002\u0010\u000e\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0008&\u0018\u00002\u00020\u0001:\u0002\u001b\u001cB\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u001b\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00010\u0004H&\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u000f\u0010\u0008\u001a\u00020\u0005H&\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\r\u0010\u000b\u001a\u00020\n\u00a2\u0006\u0004\u0008\u000b\u0010\u0003J\r\u0010\r\u001a\u00020\u000c\u00a2\u0006\u0004\u0008\r\u0010\u000eR\u0014\u0010\u000f\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000f\u0010\u0010R\u001a\u0010\u0012\u001a\u00020\u00118\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0012\u0010\u0013\u001a\u0004\u0008\u0014\u0010\u0015R\u001a\u0010\u0017\u001a\u00020\u00168\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0017\u0010\u0018\u001a\u0004\u0008\u0019\u0010\u001a\u00a8\u0006\u001d"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;",
        "",
        "<init>",
        "()V",
        "",
        "",
        "attributes",
        "()Ljava/util/Map;",
        "name",
        "()Ljava/lang/String;",
        "Llx0/b0;",
        "track",
        "Lorg/json/JSONObject;",
        "toJson",
        "()Lorg/json/JSONObject;",
        "id",
        "Ljava/lang/String;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;",
        "producer",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;",
        "getProducer",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;",
        "category",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;",
        "getCategory",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;",
        "Category",
        "Producer",
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


# instance fields
.field private final category:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

.field public final id:Ljava/lang/String;

.field private final producer:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {v0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    const-string v1, "toString(...)"

    .line 13
    .line 14
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->id:Ljava/lang/String;

    .line 18
    .line 19
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;->SFMC_SDK:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    .line 20
    .line 21
    iput-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->producer:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    .line 22
    .line 23
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;->ENGAGEMENT:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

    .line 24
    .line 25
    iput-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->category:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

    .line 26
    .line 27
    return-void
.end method


# virtual methods
.method public abstract attributes()Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end method

.method public getCategory()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->category:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

    .line 2
    .line 3
    return-object p0
.end method

.method public getProducer()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->producer:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    .line 2
    .line 3
    return-object p0
.end method

.method public abstract name()Ljava/lang/String;
.end method

.method public final toJson()Lorg/json/JSONObject;
    .locals 6

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "name"

    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->name()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 13
    .line 14
    .line 15
    const-string v1, "id"

    .line 16
    .line 17
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->id:Ljava/lang/String;

    .line 18
    .line 19
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 20
    .line 21
    .line 22
    const-string v1, "producer"

    .line 23
    .line 24
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->getProducer()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 29
    .line 30
    .line 31
    const-string v1, "category"

    .line 32
    .line 33
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->getCategory()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 38
    .line 39
    .line 40
    new-instance v1, Lorg/json/JSONObject;

    .line 41
    .line 42
    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->attributes()Ljava/util/Map;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ljava/lang/Iterable;

    .line 54
    .line 55
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    if-eqz v2, :cond_5

    .line 64
    .line 65
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    check-cast v2, Ljava/util/Map$Entry;

    .line 70
    .line 71
    :try_start_0
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    instance-of v4, v3, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/SFMCSdkEvent;

    .line 76
    .line 77
    if-eqz v4, :cond_0

    .line 78
    .line 79
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    check-cast v3, Ljava/lang/String;

    .line 84
    .line 85
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    const-string v5, "null cannot be cast to non-null type com.salesforce.marketingcloud.sfmcsdk.components.events.SFMCSdkEvent"

    .line 90
    .line 91
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    check-cast v4, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/SFMCSdkEvent;

    .line 95
    .line 96
    invoke-interface {v4}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/SFMCSdkEvent;->toJson()Lorg/json/JSONObject;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    invoke-virtual {v1, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 101
    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_0
    instance-of v4, v3, Ljava/lang/Number;

    .line 105
    .line 106
    const/4 v5, 0x1

    .line 107
    if-eqz v4, :cond_1

    .line 108
    .line 109
    move v4, v5

    .line 110
    goto :goto_1

    .line 111
    :cond_1
    instance-of v4, v3, Ljava/lang/String;

    .line 112
    .line 113
    :goto_1
    if-eqz v4, :cond_2

    .line 114
    .line 115
    move v4, v5

    .line 116
    goto :goto_2

    .line 117
    :cond_2
    instance-of v4, v3, Ljava/lang/Character;

    .line 118
    .line 119
    :goto_2
    if-eqz v4, :cond_3

    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_3
    instance-of v5, v3, Ljava/lang/Boolean;

    .line 123
    .line 124
    :goto_3
    if-eqz v5, :cond_4

    .line 125
    .line 126
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    check-cast v3, Ljava/lang/String;

    .line 131
    .line 132
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v4

    .line 136
    invoke-virtual {v1, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 137
    .line 138
    .line 139
    goto :goto_0

    .line 140
    :cond_4
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v3

    .line 144
    check-cast v3, Ljava/lang/String;

    .line 145
    .line 146
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v4

    .line 150
    invoke-virtual {v1, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 151
    .line 152
    .line 153
    goto :goto_0

    .line 154
    :catch_0
    sget-object v3, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 155
    .line 156
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 157
    .line 158
    .line 159
    move-result-object v4

    .line 160
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v4

    .line 164
    new-instance v5, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$toJson$1$1$1$1;

    .line 165
    .line 166
    invoke-direct {v5, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$toJson$1$1$1$1;-><init>(Ljava/util/Map$Entry;)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {v3, v4, v5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->w(Ljava/lang/String;Lay0/a;)V

    .line 170
    .line 171
    .line 172
    goto :goto_0

    .line 173
    :cond_5
    const-string p0, "attributes"

    .line 174
    .line 175
    invoke-virtual {v0, p0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 176
    .line 177
    .line 178
    return-object v0
.end method

.method public final track()V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

    .line 2
    .line 3
    filled-new-array {p0}, [Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->track([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
