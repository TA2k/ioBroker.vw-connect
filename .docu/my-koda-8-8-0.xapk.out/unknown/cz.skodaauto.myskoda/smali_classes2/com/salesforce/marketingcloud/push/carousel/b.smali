.class public Lcom/salesforce/marketingcloud/push/carousel/b;
.super Lcom/salesforce/marketingcloud/push/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/carousel/b$a;
    }
.end annotation


# static fields
.field public static final k:Lcom/salesforce/marketingcloud/push/carousel/b$a;

.field public static final l:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.ACTION_CAROUSEL_NEXT"

.field public static final m:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.ACTION_CAROUSEL_PREVIOUS"

.field public static final n:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.INTENT_KEY_CAROUSEL_DATA"


# instance fields
.field private final i:Landroid/content/Context;

.field private final j:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/carousel/b$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/push/carousel/b$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/push/carousel/b;->k:Lcom/salesforce/marketingcloud/push/carousel/b$a;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "message"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/push/b;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/carousel/b;->i:Landroid/content/Context;

    .line 15
    .line 16
    iput-object p2, p0, Lcom/salesforce/marketingcloud/push/carousel/b;->j:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/carousel/a;)Landroid/app/PendingIntent;
    .locals 48

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    const-string v3, "intentAction"

    .line 8
    .line 9
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "data"

    .line 13
    .line 14
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v8, v0, Lcom/salesforce/marketingcloud/push/carousel/b;->j:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 18
    .line 19
    iget-object v9, v8, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 20
    .line 21
    if-eqz v9, :cond_2

    .line 22
    .line 23
    const-string v3, "com.salesforce.marketingcloud.notifications.ACTION_CAROUSEL_NEXT"

    .line 24
    .line 25
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    if-eqz v3, :cond_0

    .line 30
    .line 31
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/push/carousel/a;->m()I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    add-int/lit8 v3, v3, 0x1

    .line 36
    .line 37
    :goto_0
    move v4, v3

    .line 38
    goto :goto_1

    .line 39
    :cond_0
    const-string v3, "com.salesforce.marketingcloud.notifications.ACTION_CAROUSEL_PREVIOUS"

    .line 40
    .line 41
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    if-eqz v3, :cond_1

    .line 46
    .line 47
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/push/carousel/a;->m()I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    add-int/lit8 v3, v3, -0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/push/carousel/a;->m()I

    .line 55
    .line 56
    .line 57
    move-result v3

    .line 58
    goto :goto_0

    .line 59
    :goto_1
    const/4 v6, 0x5

    .line 60
    const/4 v7, 0x0

    .line 61
    const/4 v3, 0x0

    .line 62
    const/4 v5, 0x0

    .line 63
    invoke-static/range {v2 .. v7}, Lcom/salesforce/marketingcloud/push/carousel/a;->a(Lcom/salesforce/marketingcloud/push/carousel/a;Ljava/util/List;ILcom/salesforce/marketingcloud/push/data/Style;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/carousel/a;

    .line 64
    .line 65
    .line 66
    move-result-object v12

    .line 67
    const/16 v14, 0xb

    .line 68
    .line 69
    const/4 v15, 0x0

    .line 70
    const/4 v10, 0x0

    .line 71
    const/4 v11, 0x0

    .line 72
    const/4 v13, 0x0

    .line 73
    invoke-static/range {v9 .. v15}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->copy$default(Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Template;Lcom/salesforce/marketingcloud/push/buttons/a;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    :goto_2
    move-object/from16 v21, v3

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_2
    const/4 v3, 0x0

    .line 81
    goto :goto_2

    .line 82
    :goto_3
    const v24, 0x6ffff

    .line 83
    .line 84
    .line 85
    const/16 v25, 0x0

    .line 86
    .line 87
    const/4 v5, 0x0

    .line 88
    const/4 v6, 0x0

    .line 89
    const/4 v7, 0x0

    .line 90
    move-object v4, v8

    .line 91
    const/4 v8, 0x0

    .line 92
    const/4 v9, 0x0

    .line 93
    const/4 v10, 0x0

    .line 94
    const/4 v11, 0x0

    .line 95
    const/4 v12, 0x0

    .line 96
    const/4 v13, 0x0

    .line 97
    const/4 v14, 0x0

    .line 98
    const/4 v15, 0x0

    .line 99
    const/16 v16, 0x0

    .line 100
    .line 101
    const/16 v17, 0x0

    .line 102
    .line 103
    const/16 v18, 0x0

    .line 104
    .line 105
    const/16 v19, 0x0

    .line 106
    .line 107
    const/16 v20, 0x0

    .line 108
    .line 109
    const/16 v22, 0x0

    .line 110
    .line 111
    const/16 v23, 0x0

    .line 112
    .line 113
    invoke-static/range {v4 .. v25}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->copy$default(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;IILjava/lang/Object;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 114
    .line 115
    .line 116
    move-result-object v26

    .line 117
    iget-object v3, v0, Lcom/salesforce/marketingcloud/push/carousel/b;->i:Landroid/content/Context;

    .line 118
    .line 119
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 120
    .line 121
    .line 122
    move-result-object v4

    .line 123
    invoke-virtual {v4}, Ljava/util/UUID;->hashCode()I

    .line 124
    .line 125
    .line 126
    move-result v4

    .line 127
    new-instance v5, Landroid/content/Intent;

    .line 128
    .line 129
    iget-object v0, v0, Lcom/salesforce/marketingcloud/push/carousel/b;->i:Landroid/content/Context;

    .line 130
    .line 131
    const-class v6, Lcom/salesforce/marketingcloud/notifications/PushNotificationActionHandler;

    .line 132
    .line 133
    invoke-direct {v5, v0, v6}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 134
    .line 135
    .line 136
    sget-object v31, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;->NONE:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 137
    .line 138
    const v46, 0x7ffcf

    .line 139
    .line 140
    .line 141
    const/16 v47, 0x0

    .line 142
    .line 143
    const/16 v27, 0x0

    .line 144
    .line 145
    const/16 v28, 0x0

    .line 146
    .line 147
    const/16 v29, 0x0

    .line 148
    .line 149
    const/16 v30, 0x0

    .line 150
    .line 151
    const/16 v32, 0x0

    .line 152
    .line 153
    const/16 v33, 0x0

    .line 154
    .line 155
    const/16 v34, 0x0

    .line 156
    .line 157
    const/16 v35, 0x0

    .line 158
    .line 159
    const/16 v36, 0x0

    .line 160
    .line 161
    const/16 v37, 0x0

    .line 162
    .line 163
    const/16 v38, 0x0

    .line 164
    .line 165
    const/16 v39, 0x0

    .line 166
    .line 167
    const/16 v40, 0x0

    .line 168
    .line 169
    const/16 v41, 0x0

    .line 170
    .line 171
    const/16 v42, 0x0

    .line 172
    .line 173
    const/16 v43, 0x0

    .line 174
    .line 175
    const/16 v44, 0x0

    .line 176
    .line 177
    const/16 v45, 0x0

    .line 178
    .line 179
    invoke-static/range {v26 .. v47}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->copy$default(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;IILjava/lang/Object;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    const-string v6, "com.salesforce.marketingcloud.notifications.INTENT_KEY_DATA_NOTIFICATION_MESSAGE"

    .line 184
    .line 185
    invoke-virtual {v5, v6, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 186
    .line 187
    .line 188
    invoke-virtual {v5, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 189
    .line 190
    .line 191
    const-string v0, "com.salesforce.marketingcloud.notifications.INTENT_KEY_CAROUSEL_DATA"

    .line 192
    .line 193
    invoke-virtual {v5, v0, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 194
    .line 195
    .line 196
    const/high16 v0, 0x8000000

    .line 197
    .line 198
    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/j;->a(I)I

    .line 199
    .line 200
    .line 201
    move-result v0

    .line 202
    invoke-static {v3, v4, v5, v0}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    const-string v1, "getBroadcast(...)"

    .line 207
    .line 208
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    return-object v0
.end method
