.class Lcom/salesforce/marketingcloud/analytics/stats/c$g;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/stats/c;->b(Ljava/util/Map;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Ljava/util/Map;

.field final synthetic d:Lcom/salesforce/marketingcloud/analytics/stats/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;Ljava/util/Map;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->c:Ljava/util/Map;

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
    .locals 10

    .line 1
    const/4 v1, 0x0

    .line 2
    :try_start_0
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->g()Lcom/salesforce/marketingcloud/config/a;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    if-eqz v0, :cond_2

    .line 7
    .line 8
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->g()Lcom/salesforce/marketingcloud/config/a;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/config/a;->f()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    goto/16 :goto_0

    .line 19
    .line 20
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->c:Ljava/util/Map;

    .line 21
    .line 22
    invoke-static {v0}, Lcom/salesforce/marketingcloud/messages/push/a;->a(Ljava/util/Map;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    new-instance v4, Ljava/util/Date;

    .line 29
    .line 30
    invoke-direct {v4}, Ljava/util/Date;-><init>()V

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 34
    .line 35
    iget-object v2, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 36
    .line 37
    iget-object v2, v2, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId:Ljava/lang/String;

    .line 38
    .line 39
    iget-object v3, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;

    .line 40
    .line 41
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->c:Ljava/util/Map;

    .line 42
    .line 43
    const-string v5, "_m"

    .line 44
    .line 45
    invoke-interface {v0, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    move-object v5, v0

    .line 50
    check-cast v5, Ljava/lang/String;

    .line 51
    .line 52
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->c:Ljava/util/Map;

    .line 53
    .line 54
    const-string v6, "_r"

    .line 55
    .line 56
    invoke-interface {v0, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    move-object v6, v0

    .line 61
    check-cast v6, Ljava/lang/String;

    .line 62
    .line 63
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->c:Ljava/util/Map;

    .line 64
    .line 65
    const-string v7, "messageDateUtc"

    .line 66
    .line 67
    invoke-interface {v0, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    move-object v7, v0

    .line 72
    check-cast v7, Ljava/lang/String;

    .line 73
    .line 74
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->c:Ljava/util/Map;

    .line 75
    .line 76
    const-string v8, "_mt"

    .line 77
    .line 78
    invoke-interface {v0, v8}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    move-object v8, v0

    .line 83
    check-cast v8, Ljava/lang/String;

    .line 84
    .line 85
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->c:Ljava/util/Map;

    .line 86
    .line 87
    const-string v9, "_pb"

    .line 88
    .line 89
    invoke-interface {v0, v9}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    move-object v9, v0

    .line 94
    check-cast v9, Ljava/lang/String;

    .line 95
    .line 96
    invoke-static/range {v2 .. v9}, Lcom/salesforce/marketingcloud/analytics/stats/d;->b(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/analytics/stats/d;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    new-instance v2, Lcom/salesforce/marketingcloud/analytics/stats/a;

    .line 101
    .line 102
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 103
    .line 104
    iget-object v3, v3, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 105
    .line 106
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    iget-object v5, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 111
    .line 112
    iget-object v5, v5, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 113
    .line 114
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 115
    .line 116
    .line 117
    move-result-object v5

    .line 118
    const/16 v6, 0x70

    .line 119
    .line 120
    const/4 v7, 0x1

    .line 121
    invoke-static {v6, v4, v0, v7}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    invoke-direct {v2, v3, v5, v0}, Lcom/salesforce/marketingcloud/analytics/stats/a;-><init>(Lcom/salesforce/marketingcloud/storage/c;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/stats/b;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/analytics/stats/a;->a()V

    .line 129
    .line 130
    .line 131
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->g()Lcom/salesforce/marketingcloud/config/a;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/config/a;->f()I

    .line 136
    .line 137
    .line 138
    move-result v0

    .line 139
    if-ne v0, v7, :cond_1

    .line 140
    .line 141
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 142
    .line 143
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 144
    .line 145
    sget-object v2, Lcom/salesforce/marketingcloud/alarms/a$a;->l:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 146
    .line 147
    filled-new-array {v2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 148
    .line 149
    .line 150
    move-result-object v3

    .line 151
    invoke-virtual {v0, v3}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 152
    .line 153
    .line 154
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->g()Lcom/salesforce/marketingcloud/config/a;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/config/a;->e()I

    .line 159
    .line 160
    .line 161
    move-result v0

    .line 162
    int-to-long v3, v0

    .line 163
    invoke-virtual {v2, v3, v4}, Lcom/salesforce/marketingcloud/alarms/a$a;->a(J)V

    .line 164
    .line 165
    .line 166
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$g;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 167
    .line 168
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 169
    .line 170
    filled-new-array {v2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/alarms/b;->b([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 175
    .line 176
    .line 177
    return-void

    .line 178
    :catch_0
    move-exception v0

    .line 179
    move-object p0, v0

    .line 180
    goto :goto_1

    .line 181
    :cond_1
    return-void

    .line 182
    :cond_2
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 183
    .line 184
    const-string v0, "onPushReceived with feature disabled do not report delivery receipt"

    .line 185
    .line 186
    new-array v2, v1, [Ljava/lang/Object;

    .line 187
    .line 188
    invoke-static {p0, v0, v2}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 189
    .line 190
    .line 191
    return-void

    .line 192
    :goto_1
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 193
    .line 194
    new-array v1, v1, [Ljava/lang/Object;

    .line 195
    .line 196
    const-string v2, "Failed to record Delivery Receipt event stat"

    .line 197
    .line 198
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    return-void
.end method
