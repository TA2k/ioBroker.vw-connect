.class public Lcom/salesforce/marketingcloud/location/LocationReceiver;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field private static final a:Ljava/lang/String; = "com.salesforce.marketingcloud.LOCATION_UPDATE"

.field private static final b:Ljava/lang/String; = "com.salesforce.marketingcloud.GEOFENCE_TRIGGERED"

.field private static final c:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "LocationReceiver"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/location/LocationReceiver;->c:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static a(I)I
    .locals 2

    const/4 v0, 0x1

    if-eq p0, v0, :cond_0

    const/4 v0, 0x2

    if-eq p0, v0, :cond_0

    const/4 v0, 0x4

    if-eq p0, v0, :cond_0

    .line 31
    sget-object v0, Lcom/salesforce/marketingcloud/location/LocationReceiver;->c:Ljava/lang/String;

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string v1, "Unknown geofence transition %d"

    invoke-static {v0, v1, p0}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, -0x1

    return p0

    :cond_0
    return v0
.end method

.method private static a(Landroid/content/Context;Lcom/google/android/gms/location/LocationResult;)V
    .locals 2

    const/4 v0, 0x0

    if-nez p1, :cond_0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/location/LocationReceiver;->c:Ljava/lang/String;

    new-array p1, v0, [Ljava/lang/Object;

    const-string v0, "LocationResult was null."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 3
    :cond_0
    iget-object p1, p1, Lcom/google/android/gms/location/LocationResult;->d:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v1

    if-nez v1, :cond_1

    const/4 p1, 0x0

    goto :goto_0

    :cond_1
    add-int/lit8 v1, v1, -0x1

    .line 4
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/location/Location;

    :goto_0
    if-nez p1, :cond_2

    .line 5
    sget-object p0, Lcom/salesforce/marketingcloud/location/LocationReceiver;->c:Ljava/lang/String;

    new-array p1, v0, [Ljava/lang/Object;

    const-string v0, "LastLocation was null."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 6
    :cond_2
    invoke-static {p1}, Lcom/salesforce/marketingcloud/location/f;->a(Landroid/location/Location;)Landroid/content/Intent;

    move-result-object p1

    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    return-void
.end method

.method private static a(Landroid/content/Context;Lpp/b;)V
    .locals 7

    const/4 v0, 0x0

    if-nez p1, :cond_0

    .line 7
    sget-object p0, Lcom/salesforce/marketingcloud/location/LocationReceiver;->c:Ljava/lang/String;

    new-array p1, v0, [Ljava/lang/Object;

    const-string v0, "Geofencing event was null."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 8
    :cond_0
    iget-object v1, p1, Lpp/b;->c:Ljava/util/List;

    iget v2, p1, Lpp/b;->a:I

    const/4 v3, -0x1

    if-eq v2, v3, :cond_1

    packed-switch v2, :pswitch_data_0

    .line 9
    :pswitch_0
    invoke-static {v2}, Llp/xd;->a(I)Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :pswitch_1
    const-string p1, "GEOFENCE_INSUFFICIENT_LOCATION_PERMISSION"

    goto :goto_0

    :pswitch_2
    const-string p1, "GEOFENCE_TOO_MANY_PENDING_INTENTS"

    goto :goto_0

    :pswitch_3
    const-string p1, "GEOFENCE_TOO_MANY_GEOFENCES"

    goto :goto_0

    :pswitch_4
    const-string p1, "GEOFENCE_NOT_AVAILABLE"

    .line 10
    :goto_0
    sget-object v0, Lcom/salesforce/marketingcloud/location/LocationReceiver;->c:Ljava/lang/String;

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v3, "Geofencing event contained error: %s"

    invoke-static {v0, v3, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    invoke-static {v2, p1}, Lcom/salesforce/marketingcloud/location/f;->a(ILjava/lang/String;)Landroid/content/Intent;

    move-result-object p1

    .line 12
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    move-result-object p1

    .line 13
    invoke-virtual {p0, p1}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    return-void

    :cond_1
    if-eqz v1, :cond_4

    .line 14
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_2

    goto :goto_2

    .line 15
    :cond_2
    iget v0, p1, Lpp/b;->b:I

    .line 16
    sget-object v2, Lcom/salesforce/marketingcloud/location/LocationReceiver;->c:Ljava/lang/String;

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    filled-new-array {v3}, [Ljava/lang/Object;

    move-result-object v3

    const-string v4, "Geofencing event transition: %d"

    invoke-static {v2, v4, v3}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 18
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lpp/a;

    .line 19
    sget-object v4, Lcom/salesforce/marketingcloud/location/LocationReceiver;->c:Ljava/lang/String;

    move-object v5, v3

    check-cast v5, Lgp/k;

    .line 20
    iget-object v5, v5, Lgp/k;->d:Ljava/lang/String;

    .line 21
    filled-new-array {v5}, [Ljava/lang/Object;

    move-result-object v5

    const-string v6, "Triggered fence id: %s"

    invoke-static {v4, v6, v5}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 22
    check-cast v3, Lgp/k;

    .line 23
    iget-object v3, v3, Lgp/k;->d:Ljava/lang/String;

    .line 24
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    .line 25
    :cond_3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/location/LocationReceiver;->a(I)I

    move-result v0

    .line 26
    iget-object p1, p1, Lpp/b;->d:Landroid/location/Location;

    .line 27
    invoke-static {v0, v2, p1}, Lcom/salesforce/marketingcloud/location/f;->a(ILjava/util/List;Landroid/location/Location;)Landroid/content/Intent;

    move-result-object p1

    .line 28
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    move-result-object p1

    .line 29
    invoke-virtual {p0, p1}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    return-void

    .line 30
    :cond_4
    :goto_2
    sget-object p0, Lcom/salesforce/marketingcloud/location/LocationReceiver;->c:Ljava/lang/String;

    new-array p1, v0, [Ljava/lang/Object;

    const-string v0, "GeofencingEvent without triggering geofences."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x3e8
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public static a(Landroid/content/Context;)Z
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    new-instance v1, Landroid/content/Intent;

    const-class v2, Lcom/salesforce/marketingcloud/location/LocationReceiver;

    invoke-direct {v1, p0, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/util/f;->a(Landroid/content/pm/PackageManager;Landroid/content/Intent;)Z

    move-result p0

    return p0
.end method

.method public static b(Landroid/content/Context;)Landroid/app/PendingIntent;
    .locals 3

    .line 1
    const/high16 v0, 0x8000000

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/j;->b(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-instance v1, Landroid/content/Intent;

    .line 8
    .line 9
    const-class v2, Lcom/salesforce/marketingcloud/location/LocationReceiver;

    .line 10
    .line 11
    invoke-direct {v1, p0, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 12
    .line 13
    .line 14
    const-string v2, "com.salesforce.marketingcloud.GEOFENCE_TRIGGERED"

    .line 15
    .line 16
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    const/4 v2, 0x1

    .line 21
    invoke-static {p0, v2, v1, v0}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method public static c(Landroid/content/Context;)Landroid/app/PendingIntent;
    .locals 3

    .line 1
    const/high16 v0, 0x8000000

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/j;->b(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-instance v1, Landroid/content/Intent;

    .line 8
    .line 9
    const-class v2, Lcom/salesforce/marketingcloud/location/LocationReceiver;

    .line 10
    .line 11
    invoke-direct {v1, p0, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 12
    .line 13
    .line 14
    const-string v2, "com.salesforce.marketingcloud.LOCATION_UPDATE"

    .line 15
    .line 16
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    const/4 v2, 0x0

    .line 21
    invoke-static {p0, v2, v1, v0}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method


# virtual methods
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 11

    .line 1
    if-eqz p2, :cond_e

    .line 2
    .line 3
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    goto/16 :goto_4

    .line 10
    .line 11
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/location/LocationReceiver;->c:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const-string v1, "onReceive - %s"

    .line 22
    .line 23
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    const-wide/16 v0, 0x1f4

    .line 27
    .line 28
    const-wide/16 v2, 0x32

    .line 29
    .line 30
    invoke-static {v0, v1, v2, v3}, Lcom/salesforce/marketingcloud/util/j;->a(JJ)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    const/4 v1, 0x0

    .line 35
    if-eqz v0, :cond_d

    .line 36
    .line 37
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getInstance()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    if-eqz v0, :cond_d

    .line 42
    .line 43
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    const-string v0, "com.salesforce.marketingcloud.GEOFENCE_TRIGGERED"

    .line 51
    .line 52
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    const/4 v2, 0x0

    .line 57
    if-nez v0, :cond_5

    .line 58
    .line 59
    const-string v0, "com.salesforce.marketingcloud.LOCATION_UPDATE"

    .line 60
    .line 61
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    if-nez p0, :cond_1

    .line 66
    .line 67
    goto/16 :goto_4

    .line 68
    .line 69
    :cond_1
    sget-object p0, Lcom/google/android/gms/location/LocationResult;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 70
    .line 71
    const-string p0, "com.google.android.gms.location.EXTRA_LOCATION_RESULT"

    .line 72
    .line 73
    invoke-virtual {p2, p0}, Landroid/content/Intent;->hasExtra(Ljava/lang/String;)Z

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    const-string v3, "com.google.android.gms.location.EXTRA_LOCATION_RESULT_BYTES"

    .line 78
    .line 79
    if-nez v0, :cond_2

    .line 80
    .line 81
    invoke-virtual {p2, v3}, Landroid/content/Intent;->hasExtra(Ljava/lang/String;)Z

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    if-eqz v0, :cond_4

    .line 86
    .line 87
    :cond_2
    sget-object v0, Lcom/google/android/gms/location/LocationResult;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 88
    .line 89
    invoke-virtual {p2, v3}, Landroid/content/Intent;->getByteArrayExtra(Ljava/lang/String;)[B

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    if-nez v3, :cond_3

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_3
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    array-length v4, v3

    .line 104
    invoke-virtual {v2, v3, v1, v4}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v2, v1}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 108
    .line 109
    .line 110
    invoke-interface {v0, v2}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    check-cast v0, Loo/c;

    .line 115
    .line 116
    invoke-virtual {v2}, Landroid/os/Parcel;->recycle()V

    .line 117
    .line 118
    .line 119
    move-object v2, v0

    .line 120
    :goto_0
    check-cast v2, Lcom/google/android/gms/location/LocationResult;

    .line 121
    .line 122
    if-nez v2, :cond_4

    .line 123
    .line 124
    invoke-virtual {p2, p0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    move-object v2, p0

    .line 129
    check-cast v2, Lcom/google/android/gms/location/LocationResult;

    .line 130
    .line 131
    :cond_4
    invoke-static {p1, v2}, Lcom/salesforce/marketingcloud/location/LocationReceiver;->a(Landroid/content/Context;Lcom/google/android/gms/location/LocationResult;)V

    .line 132
    .line 133
    .line 134
    return-void

    .line 135
    :cond_5
    const-string p0, "gms_error_code"

    .line 136
    .line 137
    const/4 v0, -0x1

    .line 138
    invoke-virtual {p2, p0, v0}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 139
    .line 140
    .line 141
    move-result p0

    .line 142
    const-string v3, "com.google.android.location.intent.extra.transition"

    .line 143
    .line 144
    invoke-virtual {p2, v3, v0}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 145
    .line 146
    .line 147
    move-result v3

    .line 148
    if-ne v3, v0, :cond_7

    .line 149
    .line 150
    :cond_6
    move v3, v0

    .line 151
    goto :goto_1

    .line 152
    :cond_7
    const/4 v4, 0x1

    .line 153
    if-eq v3, v4, :cond_8

    .line 154
    .line 155
    const/4 v4, 0x2

    .line 156
    if-eq v3, v4, :cond_8

    .line 157
    .line 158
    const/4 v4, 0x4

    .line 159
    if-ne v3, v4, :cond_6

    .line 160
    .line 161
    move v3, v4

    .line 162
    :cond_8
    :goto_1
    const-string v4, "com.google.android.location.intent.extra.geofence_list"

    .line 163
    .line 164
    invoke-virtual {p2, v4}, Landroid/content/Intent;->getSerializableExtra(Ljava/lang/String;)Ljava/io/Serializable;

    .line 165
    .line 166
    .line 167
    move-result-object v4

    .line 168
    check-cast v4, Ljava/util/ArrayList;

    .line 169
    .line 170
    if-nez v4, :cond_9

    .line 171
    .line 172
    move-object v5, v2

    .line 173
    goto :goto_3

    .line 174
    :cond_9
    new-instance v5, Ljava/util/ArrayList;

    .line 175
    .line 176
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 177
    .line 178
    .line 179
    move-result v6

    .line 180
    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 181
    .line 182
    .line 183
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 184
    .line 185
    .line 186
    move-result v6

    .line 187
    move v7, v1

    .line 188
    :goto_2
    if-ge v7, v6, :cond_a

    .line 189
    .line 190
    invoke-interface {v4, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v8

    .line 194
    check-cast v8, [B

    .line 195
    .line 196
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 197
    .line 198
    .line 199
    move-result-object v9

    .line 200
    array-length v10, v8

    .line 201
    invoke-virtual {v9, v8, v1, v10}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v9, v1}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 205
    .line 206
    .line 207
    sget-object v8, Lgp/k;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 208
    .line 209
    invoke-interface {v8, v9}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v8

    .line 213
    check-cast v8, Lgp/k;

    .line 214
    .line 215
    invoke-virtual {v9}, Landroid/os/Parcel;->recycle()V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 219
    .line 220
    .line 221
    add-int/lit8 v7, v7, 0x1

    .line 222
    .line 223
    goto :goto_2

    .line 224
    :cond_a
    :goto_3
    const-string v1, "com.google.android.location.intent.extra.triggering_location"

    .line 225
    .line 226
    invoke-virtual {p2, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 227
    .line 228
    .line 229
    move-result-object p2

    .line 230
    check-cast p2, Landroid/location/Location;

    .line 231
    .line 232
    if-nez v5, :cond_b

    .line 233
    .line 234
    if-eq p0, v0, :cond_c

    .line 235
    .line 236
    :cond_b
    new-instance v2, Lpp/b;

    .line 237
    .line 238
    invoke-direct {v2, p0, v3, v5, p2}, Lpp/b;-><init>(IILjava/util/ArrayList;Landroid/location/Location;)V

    .line 239
    .line 240
    .line 241
    :cond_c
    invoke-static {p1, v2}, Lcom/salesforce/marketingcloud/location/LocationReceiver;->a(Landroid/content/Context;Lpp/b;)V

    .line 242
    .line 243
    .line 244
    return-void

    .line 245
    :cond_d
    new-array p1, v1, [Ljava/lang/Object;

    .line 246
    .line 247
    const-string p2, "MarketingCloudSdk#init must be called in your application\'s onCreate"

    .line 248
    .line 249
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 250
    .line 251
    .line 252
    :cond_e
    :goto_4
    return-void
.end method
