.class Lcom/salesforce/marketingcloud/events/c$a;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/events/c;->a([Lcom/salesforce/marketingcloud/events/Event;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:[Lcom/salesforce/marketingcloud/events/Event;

.field final synthetic d:Lcom/salesforce/marketingcloud/events/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/events/c;Ljava/lang/String;[Ljava/lang/Object;[Lcom/salesforce/marketingcloud/events/Event;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/events/c$a;->d:Lcom/salesforce/marketingcloud/events/c;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/events/c$a;->c:[Lcom/salesforce/marketingcloud/events/Event;

    .line 4
    .line 5
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()V
    .locals 8

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/c$a;->d:Lcom/salesforce/marketingcloud/events/c;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/events/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const-string v1, "event_gate_time_mills"

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-lez v0, :cond_0

    .line 17
    .line 18
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/c$a;->d:Lcom/salesforce/marketingcloud/events/c;

    .line 19
    .line 20
    iget-object v1, v1, Lcom/salesforce/marketingcloud/events/c;->o:Ljava/util/concurrent/CountDownLatch;

    .line 21
    .line 22
    int-to-long v3, v0

    .line 23
    sget-object v5, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 24
    .line 25
    invoke-virtual {v1, v3, v4, v5}, Ljava/util/concurrent/CountDownLatch;->await(JLjava/util/concurrent/TimeUnit;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-nez v1, :cond_0

    .line 30
    .line 31
    sget-object v1, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    .line 32
    .line 33
    const-string v3, "Track await time of %s milliseconds exceeded!"

    .line 34
    .line 35
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    invoke-static {v1, v3, v4}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/c$a;->d:Lcom/salesforce/marketingcloud/events/c;

    .line 47
    .line 48
    iget-object v1, v1, Lcom/salesforce/marketingcloud/events/c;->o:Ljava/util/concurrent/CountDownLatch;

    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 51
    .line 52
    .line 53
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/c$a;->d:Lcom/salesforce/marketingcloud/events/c;

    .line 54
    .line 55
    iget-object v1, v1, Lcom/salesforce/marketingcloud/events/c;->p:Lcom/salesforce/marketingcloud/config/a;

    .line 56
    .line 57
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/config/a;->j()Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-eqz v1, :cond_0

    .line 62
    .line 63
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/c$a;->d:Lcom/salesforce/marketingcloud/events/c;

    .line 64
    .line 65
    iget-object v1, v1, Lcom/salesforce/marketingcloud/events/c;->d:Lcom/salesforce/marketingcloud/analytics/m;

    .line 66
    .line 67
    new-instance v3, Lorg/json/JSONObject;

    .line 68
    .line 69
    invoke-direct {v3}, Lorg/json/JSONObject;-><init>()V

    .line 70
    .line 71
    .line 72
    const-string v4, "gateEventProcessingMs"

    .line 73
    .line 74
    invoke-virtual {v3, v4, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    invoke-interface {v1, v0}, Lcom/salesforce/marketingcloud/analytics/m;->b(Lorg/json/JSONObject;)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 79
    .line 80
    .line 81
    goto :goto_2

    .line 82
    :catch_0
    move-exception v0

    .line 83
    goto :goto_0

    .line 84
    :catch_1
    move-exception v0

    .line 85
    goto :goto_1

    .line 86
    :goto_0
    sget-object v1, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    .line 87
    .line 88
    new-array v3, v2, [Ljava/lang/Object;

    .line 89
    .line 90
    const-string v4, "Failed to log analytics for onSyncGateTimedOut"

    .line 91
    .line 92
    invoke-static {v1, v0, v4, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    goto :goto_2

    .line 96
    :goto_1
    sget-object v1, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    .line 97
    .line 98
    new-array v3, v2, [Ljava/lang/Object;

    .line 99
    .line 100
    const-string v4, "Encountered exception while awaiting at track."

    .line 101
    .line 102
    invoke-static {v1, v0, v4, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    :cond_0
    :goto_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/c$a;->c:[Lcom/salesforce/marketingcloud/events/Event;

    .line 106
    .line 107
    const/4 v1, 0x0

    .line 108
    if-eqz v0, :cond_4

    .line 109
    .line 110
    array-length v3, v0

    .line 111
    if-lez v3, :cond_4

    .line 112
    .line 113
    array-length v3, v0

    .line 114
    :goto_3
    if-ge v2, v3, :cond_4

    .line 115
    .line 116
    aget-object v4, v0, v2

    .line 117
    .line 118
    if-nez v4, :cond_1

    .line 119
    .line 120
    goto :goto_4

    .line 121
    :cond_1
    sget-object v5, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    .line 122
    .line 123
    invoke-interface {v4}, Lcom/salesforce/marketingcloud/events/Event;->name()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v6

    .line 127
    invoke-interface {v4}, Lcom/salesforce/marketingcloud/events/Event;->attributes()Ljava/util/Map;

    .line 128
    .line 129
    .line 130
    move-result-object v7

    .line 131
    filled-new-array {v6, v7}, [Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v6

    .line 135
    const-string v7, "(%s) event logged with attributes %s"

    .line 136
    .line 137
    invoke-static {v5, v7, v6}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    iget-object v5, p0, Lcom/salesforce/marketingcloud/events/c$a;->d:Lcom/salesforce/marketingcloud/events/c;

    .line 141
    .line 142
    invoke-virtual {v5, v4}, Lcom/salesforce/marketingcloud/events/c;->a(Lcom/salesforce/marketingcloud/events/Event;)Ljava/util/List;

    .line 143
    .line 144
    .line 145
    move-result-object v6

    .line 146
    invoke-virtual {v5, v4, v6}, Lcom/salesforce/marketingcloud/events/c;->a(Lcom/salesforce/marketingcloud/events/Event;Ljava/util/List;)Ljava/util/List;

    .line 147
    .line 148
    .line 149
    move-result-object v4

    .line 150
    if-eqz v4, :cond_3

    .line 151
    .line 152
    if-nez v1, :cond_2

    .line 153
    .line 154
    new-instance v1, Ljava/util/ArrayList;

    .line 155
    .line 156
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 157
    .line 158
    .line 159
    :cond_2
    invoke-interface {v1, v4}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 160
    .line 161
    .line 162
    :cond_3
    :goto_4
    add-int/lit8 v2, v2, 0x1

    .line 163
    .line 164
    goto :goto_3

    .line 165
    :cond_4
    if-eqz v1, :cond_5

    .line 166
    .line 167
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/c$a;->d:Lcom/salesforce/marketingcloud/events/c;

    .line 168
    .line 169
    invoke-virtual {p0, v1}, Lcom/salesforce/marketingcloud/events/c;->a(Ljava/util/List;)V

    .line 170
    .line 171
    .line 172
    :cond_5
    return-void
.end method
