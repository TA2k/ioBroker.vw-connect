.class public final enum Lcom/salesforce/marketingcloud/behaviors/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/behaviors/a;",
        ">;"
    }
.end annotation


# static fields
.field public static final enum e:Lcom/salesforce/marketingcloud/behaviors/a;

.field public static final enum f:Lcom/salesforce/marketingcloud/behaviors/a;

.field public static final enum g:Lcom/salesforce/marketingcloud/behaviors/a;

.field public static final enum h:Lcom/salesforce/marketingcloud/behaviors/a;

.field public static final enum i:Lcom/salesforce/marketingcloud/behaviors/a;

.field public static final enum j:Lcom/salesforce/marketingcloud/behaviors/a;

.field public static final enum k:Lcom/salesforce/marketingcloud/behaviors/a;

.field public static final enum l:Lcom/salesforce/marketingcloud/behaviors/a;

.field public static final enum m:Lcom/salesforce/marketingcloud/behaviors/a;

.field public static final enum n:Lcom/salesforce/marketingcloud/behaviors/a;

.field public static final enum o:Lcom/salesforce/marketingcloud/behaviors/a;

.field public static final enum p:Lcom/salesforce/marketingcloud/behaviors/a;

.field public static final enum q:Lcom/salesforce/marketingcloud/behaviors/a;

.field private static final synthetic r:[Lcom/salesforce/marketingcloud/behaviors/a;


# instance fields
.field public final b:Ljava/lang/String;
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "NoHardKeywords"
        }
    .end annotation
.end field

.field public final c:Z

.field public final d:Lcom/salesforce/marketingcloud/behaviors/a;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "com.salesforce.marketingcloud.DEVICE_SHUTDOWN"

    .line 5
    .line 6
    const-string v3, "BEHAVIOR_DEVICE_SHUTDOWN"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->e:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 12
    .line 13
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 14
    .line 15
    const-string v1, "com.salesforce.marketingcloud.BOOT_COMPLETE"

    .line 16
    .line 17
    const-string v2, "BEHAVIOR_DEVICE_BOOT_COMPLETE"

    .line 18
    .line 19
    const/4 v3, 0x1

    .line 20
    invoke-direct {v0, v2, v3, v1}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->f:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 24
    .line 25
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    const-string v2, "com.salesforce.marketingcloud.TIME_ZONE_CHANGED"

    .line 29
    .line 30
    const-string v4, "BEHAVIOR_DEVICE_TIME_ZONE_CHANGED"

    .line 31
    .line 32
    invoke-direct {v0, v4, v1, v2}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->g:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 36
    .line 37
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 38
    .line 39
    const/4 v1, 0x3

    .line 40
    const-string v2, "com.salesforce.marketingcloud.PACKAGE_REPLACED"

    .line 41
    .line 42
    const-string v4, "BEHAVIOR_APP_PACKAGE_REPLACED"

    .line 43
    .line 44
    invoke-direct {v0, v4, v1, v2}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 45
    .line 46
    .line 47
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->h:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 48
    .line 49
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 50
    .line 51
    const/4 v1, 0x4

    .line 52
    const-string v2, "com.salesforce.marketingcloud.APP_FOREGROUNDED"

    .line 53
    .line 54
    const-string v4, "BEHAVIOR_APP_FOREGROUNDED"

    .line 55
    .line 56
    invoke-direct {v0, v4, v1, v2, v3}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;Z)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 60
    .line 61
    new-instance v1, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 62
    .line 63
    const/4 v2, 0x5

    .line 64
    const-string v3, "com.salesforce.marketingcloud.APP_BACKGROUNDED"

    .line 65
    .line 66
    const-string v4, "BEHAVIOR_APP_BACKGROUNDED"

    .line 67
    .line 68
    invoke-direct {v1, v4, v2, v3, v0}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;Lcom/salesforce/marketingcloud/behaviors/a;)V

    .line 69
    .line 70
    .line 71
    sput-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->j:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 72
    .line 73
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 74
    .line 75
    const/4 v1, 0x6

    .line 76
    const-string v2, "com.salesforce.marketingcloud.REGISTRATION_SEND"

    .line 77
    .line 78
    const-string v3, "BEHAVIOR_SDK_REGISTRATION_SEND"

    .line 79
    .line 80
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 81
    .line 82
    .line 83
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->k:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 84
    .line 85
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 86
    .line 87
    const/4 v1, 0x7

    .line 88
    const-string v2, "com.salesforce.marketingcloud.PUSH_RECEIVED"

    .line 89
    .line 90
    const-string v3, "BEHAVIOR_SDK_PUSH_RECEIVED"

    .line 91
    .line 92
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 93
    .line 94
    .line 95
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->l:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 96
    .line 97
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 98
    .line 99
    const/16 v1, 0x8

    .line 100
    .line 101
    const-string v2, "com.salesforce.marketingcloud.FENCE_MESSAGING_TOGGLED"

    .line 102
    .line 103
    const-string v3, "BEHAVIOR_CUSTOMER_FENCE_MESSAGING_TOGGLED"

    .line 104
    .line 105
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 106
    .line 107
    .line 108
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->m:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 109
    .line 110
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 111
    .line 112
    const/16 v1, 0x9

    .line 113
    .line 114
    const-string v2, "com.salesforce.marketingcloud.PROXIMITY_MESSAGING_TOGGLED"

    .line 115
    .line 116
    const-string v3, "BEHAVIOR_CUSTOMER_PROXIMITY_MESSAGING_TOGGLED"

    .line 117
    .line 118
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 119
    .line 120
    .line 121
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->n:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 122
    .line 123
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 124
    .line 125
    const/16 v1, 0xa

    .line 126
    .line 127
    const-string v2, "com.salesforce.marketingcloud.PUSH_MESSAGING_TOGGLED"

    .line 128
    .line 129
    const-string v3, "BEHAVIOR_CUSTOMER_PUSH_MESSAGING_TOGGLED"

    .line 130
    .line 131
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 132
    .line 133
    .line 134
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->o:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 135
    .line 136
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 137
    .line 138
    const/16 v1, 0xb

    .line 139
    .line 140
    const-string v2, "com.salesforce.marketingcloud.NOTIFICATION_OPENED"

    .line 141
    .line 142
    const-string v3, "BEHAVIOR_SDK_NOTIFICATION_OPENED"

    .line 143
    .line 144
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 145
    .line 146
    .line 147
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->p:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 148
    .line 149
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 150
    .line 151
    const/16 v1, 0xc

    .line 152
    .line 153
    const-string v2, "com.salesforce.marketingcloud.TOKEN_REFRESHED"

    .line 154
    .line 155
    const-string v3, "BEHAVIOR_SDK_TOKEN_REFRESHED"

    .line 156
    .line 157
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 158
    .line 159
    .line 160
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->q:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 161
    .line 162
    invoke-static {}, Lcom/salesforce/marketingcloud/behaviors/a;->a()[Lcom/salesforce/marketingcloud/behaviors/a;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    sput-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->r:[Lcom/salesforce/marketingcloud/behaviors/a;

    .line 167
    .line 168
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    const/4 v0, 0x0

    .line 1
    invoke-direct {p0, p1, p2, p3, v0}, Lcom/salesforce/marketingcloud/behaviors/a;-><init>(Ljava/lang/String;ILjava/lang/String;Z)V

    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;Lcom/salesforce/marketingcloud/behaviors/a;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/behaviors/a;",
            ")V"
        }
    .end annotation

    .line 6
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    iput-object p3, p0, Lcom/salesforce/marketingcloud/behaviors/a;->b:Ljava/lang/String;

    const/4 p1, 0x0

    .line 8
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/behaviors/a;->c:Z

    .line 9
    iput-object p4, p0, Lcom/salesforce/marketingcloud/behaviors/a;->d:Lcom/salesforce/marketingcloud/behaviors/a;

    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;Z)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Z)V"
        }
    .end annotation

    .line 2
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 3
    iput-object p3, p0, Lcom/salesforce/marketingcloud/behaviors/a;->b:Ljava/lang/String;

    .line 4
    iput-boolean p4, p0, Lcom/salesforce/marketingcloud/behaviors/a;->c:Z

    const/4 p1, 0x0

    .line 5
    iput-object p1, p0, Lcom/salesforce/marketingcloud/behaviors/a;->d:Lcom/salesforce/marketingcloud/behaviors/a;

    return-void
.end method

.method public static a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/behaviors/a;
    .locals 5

    if-eqz p0, :cond_5

    .line 2
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    move-result v0

    const/4 v1, 0x0

    const/4 v2, -0x1

    sparse-switch v0, :sswitch_data_0

    goto :goto_0

    :sswitch_0
    const-string v0, "android.intent.action.ACTION_SHUTDOWN"

    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v2, 0x3

    goto :goto_0

    :sswitch_1
    const-string v0, "android.intent.action.MY_PACKAGE_REPLACED"

    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    const/4 v2, 0x2

    goto :goto_0

    :sswitch_2
    const-string v0, "android.intent.action.BOOT_COMPLETED"

    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_0

    :cond_2
    const/4 v2, 0x1

    goto :goto_0

    :sswitch_3
    const-string v0, "android.intent.action.TIMEZONE_CHANGED"

    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_0

    :cond_3
    move v2, v1

    :goto_0
    packed-switch v2, :pswitch_data_0

    .line 3
    invoke-static {}, Lcom/salesforce/marketingcloud/behaviors/a;->values()[Lcom/salesforce/marketingcloud/behaviors/a;

    move-result-object v0

    array-length v2, v0

    :goto_1
    if-ge v1, v2, :cond_5

    aget-object v3, v0, v1

    .line 4
    iget-object v4, v3, Lcom/salesforce/marketingcloud/behaviors/a;->b:Ljava/lang/String;

    invoke-virtual {p0, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_4

    return-object v3

    :cond_4
    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    .line 5
    :pswitch_0
    sget-object p0, Lcom/salesforce/marketingcloud/behaviors/a;->e:Lcom/salesforce/marketingcloud/behaviors/a;

    return-object p0

    .line 6
    :pswitch_1
    sget-object p0, Lcom/salesforce/marketingcloud/behaviors/a;->h:Lcom/salesforce/marketingcloud/behaviors/a;

    return-object p0

    .line 7
    :pswitch_2
    sget-object p0, Lcom/salesforce/marketingcloud/behaviors/a;->f:Lcom/salesforce/marketingcloud/behaviors/a;

    return-object p0

    .line 8
    :pswitch_3
    sget-object p0, Lcom/salesforce/marketingcloud/behaviors/a;->g:Lcom/salesforce/marketingcloud/behaviors/a;

    return-object p0

    :cond_5
    const/4 p0, 0x0

    return-object p0

    nop

    :sswitch_data_0
    .sparse-switch
        0x1df32313 -> :sswitch_3
        0x2f94f923 -> :sswitch_2
        0x6789a577 -> :sswitch_1
        0x741706da -> :sswitch_0
    .end sparse-switch

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method private static synthetic a()[Lcom/salesforce/marketingcloud/behaviors/a;
    .locals 13

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->e:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->f:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v2, Lcom/salesforce/marketingcloud/behaviors/a;->g:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v3, Lcom/salesforce/marketingcloud/behaviors/a;->h:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v4, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v5, Lcom/salesforce/marketingcloud/behaviors/a;->j:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v6, Lcom/salesforce/marketingcloud/behaviors/a;->k:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v7, Lcom/salesforce/marketingcloud/behaviors/a;->l:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v8, Lcom/salesforce/marketingcloud/behaviors/a;->m:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v9, Lcom/salesforce/marketingcloud/behaviors/a;->n:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v10, Lcom/salesforce/marketingcloud/behaviors/a;->o:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v11, Lcom/salesforce/marketingcloud/behaviors/a;->p:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v12, Lcom/salesforce/marketingcloud/behaviors/a;->q:Lcom/salesforce/marketingcloud/behaviors/a;

    filled-new-array/range {v0 .. v12}, [Lcom/salesforce/marketingcloud/behaviors/a;

    move-result-object v0

    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/behaviors/a;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/behaviors/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/behaviors/a;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->r:[Lcom/salesforce/marketingcloud/behaviors/a;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/salesforce/marketingcloud/behaviors/a;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/behaviors/a;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/behaviors/a;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
