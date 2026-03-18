.class Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->a(I)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:I

.field final synthetic d:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/etanalytics/c;Ljava/lang/String;[Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 2
    .line 3
    iput p4, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->c:I

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
    const/4 v0, 0x0

    .line 2
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 3
    .line 4
    iget-object v1, v1, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 5
    .line 6
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 11
    .line 12
    iget-object v2, v2, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 13
    .line 14
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    iget v3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->c:I

    .line 19
    .line 20
    invoke-interface {v1, v2, v3}, Lcom/salesforce/marketingcloud/storage/a;->b(Lcom/salesforce/marketingcloud/util/Crypto;I)Ljava/util/List;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-nez v2, :cond_3

    .line 29
    .line 30
    sget-object v2, Lcom/salesforce/marketingcloud/http/b;->i:Lcom/salesforce/marketingcloud/http/b;

    .line 31
    .line 32
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 33
    .line 34
    iget-object v4, v3, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->d:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 35
    .line 36
    iget-object v3, v3, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 37
    .line 38
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    iget-object v5, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 43
    .line 44
    iget-object v6, v5, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->d:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 45
    .line 46
    invoke-virtual {v6}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v6

    .line 50
    iget-object v7, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 51
    .line 52
    iget-object v7, v7, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->e:Ljava/lang/String;

    .line 53
    .line 54
    invoke-virtual {v5, v6, v7, v1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Lorg/json/JSONArray;

    .line 55
    .line 56
    .line 57
    move-result-object v5

    .line 58
    invoke-virtual {v5}, Lorg/json/JSONArray;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    invoke-virtual {v2, v4, v3, v5}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    invoke-static {v1}, Lcom/salesforce/marketingcloud/analytics/c;->a(Ljava/util/List;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-virtual {v2, v3}, Lcom/salesforce/marketingcloud/http/c;->a(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    sget-object v3, Lcom/salesforce/marketingcloud/http/a;->a:Lcom/salesforce/marketingcloud/http/a;

    .line 74
    .line 75
    invoke-virtual {v3, v2}, Lcom/salesforce/marketingcloud/http/a;->a(Lcom/salesforce/marketingcloud/http/g;)I

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    const v4, 0x3e800

    .line 80
    .line 81
    .line 82
    if-le v3, v4, :cond_2

    .line 83
    .line 84
    sget-object v2, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 85
    .line 86
    const-string v4, "Bundle size of %d bytes is too large:. Reducing send batch size."

    .line 87
    .line 88
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    invoke-static {v2, v4, v3}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    iget v3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->c:I

    .line 100
    .line 101
    const/16 v4, 0x32

    .line 102
    .line 103
    if-gt v3, v4, :cond_0

    .line 104
    .line 105
    const-string p0, "Batch size already at or below minimum, cannot reduce further. Analytics not sent."

    .line 106
    .line 107
    new-array v1, v0, [Ljava/lang/Object;

    .line 108
    .line 109
    invoke-static {v2, p0, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    return-void

    .line 113
    :catch_0
    move-exception p0

    .line 114
    goto :goto_2

    .line 115
    :cond_0
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 116
    .line 117
    .line 118
    move-result v2

    .line 119
    iget v3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->c:I

    .line 120
    .line 121
    const v4, 0x3f28f5c3    # 0.66f

    .line 122
    .line 123
    .line 124
    if-ge v2, v3, :cond_1

    .line 125
    .line 126
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    int-to-float v1, v1

    .line 131
    :goto_0
    mul-float/2addr v1, v4

    .line 132
    goto :goto_1

    .line 133
    :cond_1
    int-to-float v1, v3

    .line 134
    goto :goto_0

    .line 135
    :goto_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 136
    .line 137
    float-to-int v1, v1

    .line 138
    invoke-virtual {p0, v1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->a(I)V

    .line 139
    .line 140
    .line 141
    return-void

    .line 142
    :cond_2
    sget-object v1, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 143
    .line 144
    const-string v3, "Analytics sent with batch size %d."

    .line 145
    .line 146
    iget v4, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->c:I

    .line 147
    .line 148
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 149
    .line 150
    .line 151
    move-result-object v4

    .line 152
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v4

    .line 156
    invoke-static {v1, v3, v4}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 160
    .line 161
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 162
    .line 163
    invoke-virtual {p0, v2}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/c;)V

    .line 164
    .line 165
    .line 166
    return-void

    .line 167
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c$a;->d:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 168
    .line 169
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 170
    .line 171
    sget-object v1, Lcom/salesforce/marketingcloud/alarms/a$a;->d:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 172
    .line 173
    filled-new-array {v1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    invoke-virtual {p0, v1}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 178
    .line 179
    .line 180
    return-void

    .line 181
    :goto_2
    sget-object v1, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 182
    .line 183
    new-array v0, v0, [Ljava/lang/Object;

    .line 184
    .line 185
    const-string v2, "Failed to send analytics"

    .line 186
    .line 187
    invoke-static {v1, p0, v2, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    return-void
.end method
