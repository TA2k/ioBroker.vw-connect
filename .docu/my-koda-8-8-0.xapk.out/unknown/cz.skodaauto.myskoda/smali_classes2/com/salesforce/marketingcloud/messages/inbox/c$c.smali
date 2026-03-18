.class Lcom/salesforce/marketingcloud/messages/inbox/c$c;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/inbox/c;->e()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/inbox/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$c;->c:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a()V
    .locals 9

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$c;->c:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-interface {v0}, Lcom/salesforce/marketingcloud/storage/f;->i()Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-lez v1, :cond_2

    .line 18
    .line 19
    new-instance v2, Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-direct {v2, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Lorg/json/JSONArray;

    .line 25
    .line 26
    invoke-direct {v1}, Lorg/json/JSONArray;-><init>()V

    .line 27
    .line 28
    .line 29
    new-instance v3, Lorg/json/JSONObject;

    .line 30
    .line 31
    invoke-direct {v3}, Lorg/json/JSONObject;-><init>()V

    .line 32
    .line 33
    .line 34
    :try_start_0
    const-string v4, "deviceId"

    .line 35
    .line 36
    iget-object v5, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$c;->c:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 37
    .line 38
    iget-object v5, v5, Lcom/salesforce/marketingcloud/messages/inbox/c;->h:Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 41
    .line 42
    .line 43
    new-instance v4, Ljava/util/Date;

    .line 44
    .line 45
    invoke-direct {v4}, Ljava/util/Date;-><init>()V

    .line 46
    .line 47
    .line 48
    invoke-static {v4}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Date;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v4

    .line 52
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-eqz v5, :cond_1

    .line 61
    .line 62
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    check-cast v5, Lcom/salesforce/marketingcloud/storage/f$b;

    .line 67
    .line 68
    new-instance v6, Lorg/json/JSONObject;

    .line 69
    .line 70
    invoke-direct {v6}, Lorg/json/JSONObject;-><init>()V

    .line 71
    .line 72
    .line 73
    const-string v7, "actionParameters"

    .line 74
    .line 75
    invoke-virtual {v6, v7, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 76
    .line 77
    .line 78
    const-string v7, "messageId"

    .line 79
    .line 80
    iget-object v8, v5, Lcom/salesforce/marketingcloud/storage/f$b;->a:Ljava/lang/String;

    .line 81
    .line 82
    invoke-virtual {v6, v7, v8}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 83
    .line 84
    .line 85
    const-string v7, "actionDate"

    .line 86
    .line 87
    invoke-virtual {v6, v7, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 88
    .line 89
    .line 90
    const-string v7, "action"

    .line 91
    .line 92
    iget-boolean v8, v5, Lcom/salesforce/marketingcloud/storage/f$b;->e:Z

    .line 93
    .line 94
    if-eqz v8, :cond_0

    .line 95
    .line 96
    const-string v8, "Deleted"

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_0
    const-string v8, "Viewed"

    .line 100
    .line 101
    :goto_1
    invoke-virtual {v6, v7, v8}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 102
    .line 103
    .line 104
    invoke-virtual {v1, v6}, Lorg/json/JSONArray;->put(Ljava/lang/Object;)Lorg/json/JSONArray;

    .line 105
    .line 106
    .line 107
    iget-object v5, v5, Lcom/salesforce/marketingcloud/storage/f$b;->a:Ljava/lang/String;

    .line 108
    .line 109
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_1
    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->m:Lcom/salesforce/marketingcloud/http/b;

    .line 114
    .line 115
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$c;->c:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 116
    .line 117
    iget-object v4, v3, Lcom/salesforce/marketingcloud/messages/inbox/c;->g:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 118
    .line 119
    iget-object v3, v3, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 120
    .line 121
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 122
    .line 123
    .line 124
    move-result-object v3

    .line 125
    iget-object v5, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$c;->c:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 126
    .line 127
    iget-object v5, v5, Lcom/salesforce/marketingcloud/messages/inbox/c;->g:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 128
    .line 129
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v5

    .line 133
    invoke-static {v5}, Lcom/salesforce/marketingcloud/http/b;->a(Ljava/lang/String;)[Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v5

    .line 137
    invoke-virtual {v1}, Lorg/json/JSONArray;->toString()Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    invoke-virtual {v0, v4, v3, v5, v1}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;[Ljava/lang/Object;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    const-string v1, ","

    .line 146
    .line 147
    invoke-static {v1, v2}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/http/c;->a(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$c;->c:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 155
    .line 156
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->f:Lcom/salesforce/marketingcloud/http/e;

    .line 157
    .line 158
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/c;)V
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 159
    .line 160
    .line 161
    return-void

    .line 162
    :catch_0
    move-exception p0

    .line 163
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 164
    .line 165
    const/4 v1, 0x0

    .line 166
    new-array v1, v1, [Ljava/lang/Object;

    .line 167
    .line 168
    const-string v2, "Failed to create Inbox status payload.  Status updates not sent to Marketing Cloud"

    .line 169
    .line 170
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    :cond_2
    return-void
.end method
