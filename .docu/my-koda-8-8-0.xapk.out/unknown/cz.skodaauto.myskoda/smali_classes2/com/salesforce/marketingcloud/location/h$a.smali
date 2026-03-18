.class Lcom/salesforce/marketingcloud/location/h$a;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/location/h;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "a"
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/location/h;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/location/h;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/location/h$a;->a:Lcom/salesforce/marketingcloud/location/h;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 4

    .line 1
    const/4 p1, 0x0

    .line 2
    if-nez p2, :cond_0

    .line 3
    .line 4
    sget-object p0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    .line 5
    .line 6
    new-array p1, p1, [Ljava/lang/Object;

    .line 7
    .line 8
    const-string p2, "Received null intent"

    .line 9
    .line 10
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    sget-object p0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    .line 21
    .line 22
    new-array p1, p1, [Ljava/lang/Object;

    .line 23
    .line 24
    const-string p2, "Received null action"

    .line 25
    .line 26
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_1
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    const/4 v2, -0x1

    .line 35
    sparse-switch v1, :sswitch_data_0

    .line 36
    .line 37
    .line 38
    :goto_0
    move v1, v2

    .line 39
    goto :goto_1

    .line 40
    :sswitch_0
    const-string v1, "com.salesforce.marketingcloud.location.GEOFENCE_EVENT"

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-nez v1, :cond_2

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    const/4 v1, 0x2

    .line 50
    goto :goto_1

    .line 51
    :sswitch_1
    const-string v1, "com.salesforce.marketingcloud.location.GEOFENCE_ERROR"

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-nez v1, :cond_3

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_3
    const/4 v1, 0x1

    .line 61
    goto :goto_1

    .line 62
    :sswitch_2
    const-string v1, "com.salesforce.marketingcloud.location.LOCATION_UPDATE"

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-nez v1, :cond_4

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_4
    move v1, p1

    .line 72
    :goto_1
    const-string v3, "extra_location"

    .line 73
    .line 74
    packed-switch v1, :pswitch_data_0

    .line 75
    .line 76
    .line 77
    sget-object p0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    .line 78
    .line 79
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    const-string p2, "Received unknown action: %s"

    .line 84
    .line 85
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    return-void

    .line 89
    :pswitch_0
    const-string p1, "extra_transition"

    .line 90
    .line 91
    invoke-virtual {p2, p1, v2}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    if-ne p1, v2, :cond_5

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_5
    sget-object v0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    .line 99
    .line 100
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    const-string v2, "Received geofence transition %d"

    .line 109
    .line 110
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h$a;->a:Lcom/salesforce/marketingcloud/location/h;

    .line 114
    .line 115
    const-string v0, "extra_fence_ids"

    .line 116
    .line 117
    invoke-virtual {p2, v0}, Landroid/content/Intent;->getStringArrayListExtra(Ljava/lang/String;)Ljava/util/ArrayList;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    invoke-virtual {p2, v3}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 122
    .line 123
    .line 124
    move-result-object p2

    .line 125
    check-cast p2, Landroid/location/Location;

    .line 126
    .line 127
    invoke-virtual {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/location/h;->b(ILjava/util/List;Landroid/location/Location;)V

    .line 128
    .line 129
    .line 130
    return-void

    .line 131
    :pswitch_1
    const-string p1, "extra_error_code"

    .line 132
    .line 133
    invoke-virtual {p2, p1, v2}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 134
    .line 135
    .line 136
    move-result p1

    .line 137
    const-string v0, "extra_error_message"

    .line 138
    .line 139
    invoke-virtual {p2, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object p2

    .line 143
    if-eq p1, v2, :cond_6

    .line 144
    .line 145
    if-eqz p2, :cond_6

    .line 146
    .line 147
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h$a;->a:Lcom/salesforce/marketingcloud/location/h;

    .line 148
    .line 149
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/location/h;->b(ILjava/lang/String;)V

    .line 150
    .line 151
    .line 152
    :cond_6
    :goto_2
    return-void

    .line 153
    :pswitch_2
    sget-object v0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    .line 154
    .line 155
    new-array p1, p1, [Ljava/lang/Object;

    .line 156
    .line 157
    const-string v1, "Received location update."

    .line 158
    .line 159
    invoke-static {v0, v1, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/h$a;->a:Lcom/salesforce/marketingcloud/location/h;

    .line 163
    .line 164
    invoke-virtual {p2, v3}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 165
    .line 166
    .line 167
    move-result-object p1

    .line 168
    check-cast p1, Landroid/location/Location;

    .line 169
    .line 170
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/location/h;->b(Landroid/location/Location;)V

    .line 171
    .line 172
    .line 173
    return-void

    .line 174
    nop

    .line 175
    :sswitch_data_0
    .sparse-switch
        -0x10f5de69 -> :sswitch_2
        0x213d7ae5 -> :sswitch_1
        0x213f1b77 -> :sswitch_0
    .end sparse-switch

    .line 176
    .line 177
    .line 178
    .line 179
    .line 180
    .line 181
    .line 182
    .line 183
    .line 184
    .line 185
    .line 186
    .line 187
    .line 188
    .line 189
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
