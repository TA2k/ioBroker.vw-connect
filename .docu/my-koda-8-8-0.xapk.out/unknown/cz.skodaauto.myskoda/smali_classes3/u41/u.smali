.class public final synthetic Lu41/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lu41/u;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget p0, p0, Lu41/u;->d:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const-string v1, "NO_ACTIVE_VEHICLE"

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    packed-switch p0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance p0, Luz0/d;

    .line 13
    .line 14
    sget-object v0, Lvd/a;->a:Lvd/a;

    .line 15
    .line 16
    invoke-direct {p0, v0, v2}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 17
    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_0
    new-instance p0, Luz0/d;

    .line 21
    .line 22
    sget-object v0, Lvd/a;->a:Lvd/a;

    .line 23
    .line 24
    invoke-direct {p0, v0, v2}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 25
    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_1
    sget-object p0, Lvd/k;->Companion:Lvd/j;

    .line 29
    .line 30
    invoke-virtual {p0}, Lvd/j;->serializer()Lqz0/a;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_2
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_3
    const-string p0, ""

    .line 41
    .line 42
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_4
    const-string p0, "Vin for rename vehicle is null"

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_5
    const/4 p0, 0x3

    .line 51
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_6
    const-string p0, "(MDK) Pairing intent returned but SDK didn\'t recognize valid pairing code."

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_7
    const-string p0, "(MDK) Received start pairing request."

    .line 60
    .line 61
    return-object p0

    .line 62
    :pswitch_8
    sget p0, Luz/g0;->a:F

    .line 63
    .line 64
    return-object v3

    .line 65
    :pswitch_9
    sget p0, Luz/d0;->a:I

    .line 66
    .line 67
    return-object v3

    .line 68
    :pswitch_a
    sget-object p0, Luz/t;->a:Ljava/util/List;

    .line 69
    .line 70
    return-object v3

    .line 71
    :pswitch_b
    sget p0, Luz/g;->a:F

    .line 72
    .line 73
    return-object v3

    .line 74
    :pswitch_c
    invoke-static {}, Lcz/myskoda/api/bff_fueling/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0

    .line 79
    :pswitch_d
    invoke-static {}, Lcz/myskoda/api/bff_fueling/v2/infrastructure/ApiClient;->a()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0

    .line 84
    :pswitch_e
    new-instance p0, Lkj0/h;

    .line 85
    .line 86
    const-string v0, "Vehicle - Home - Delivered"

    .line 87
    .line 88
    invoke-direct {p0, v0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    return-object p0

    .line 92
    :pswitch_f
    new-instance p0, Ltu0/e;

    .line 93
    .line 94
    invoke-direct {p0, v1}, Ltu0/e;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    return-object p0

    .line 98
    :pswitch_10
    new-instance p0, Ltu0/c;

    .line 99
    .line 100
    invoke-direct {p0, v1}, Ltu0/c;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    return-object p0

    .line 104
    :pswitch_11
    new-instance p0, Ltu0/g;

    .line 105
    .line 106
    invoke-direct {p0, v1}, Ltu0/g;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    return-object p0

    .line 110
    :pswitch_12
    sget-object p0, Lsu0/a;->a:Lsu0/a;

    .line 111
    .line 112
    return-object p0

    .line 113
    :pswitch_13
    sget-object p0, Luu0/x;->q1:Ljava/util/List;

    .line 114
    .line 115
    const-string p0, "Unable to finish vehicle activation. Field devicePlatform or enrollmentVin is null."

    .line 116
    .line 117
    return-object p0

    .line 118
    :pswitch_14
    new-instance p0, Lcom/google/android/gms/maps/GoogleMapOptions;

    .line 119
    .line 120
    invoke-direct {p0}, Lcom/google/android/gms/maps/GoogleMapOptions;-><init>()V

    .line 121
    .line 122
    .line 123
    return-object p0

    .line 124
    :pswitch_15
    invoke-static {}, Luu/a;->a()Luu/g;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    return-object p0

    .line 129
    :pswitch_16
    new-instance p0, Lxr0/a;

    .line 130
    .line 131
    invoke-direct {p0, v0}, Lxr0/a;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    return-object p0

    .line 135
    :pswitch_17
    new-instance p0, Luz0/d;

    .line 136
    .line 137
    sget-object v0, Lsi/a;->a:Lsi/a;

    .line 138
    .line 139
    invoke-direct {p0, v0, v2}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 140
    .line 141
    .line 142
    return-object p0

    .line 143
    :pswitch_18
    const-string p0, "(MDK) Cannot fetch selected vehicle ID."

    .line 144
    .line 145
    return-object p0

    .line 146
    :pswitch_19
    const-string p0, "(MDK) Home opened without capability."

    .line 147
    .line 148
    return-object p0

    .line 149
    :pswitch_1a
    const-string p0, "(MDK) Pairing MDK to vehicle."

    .line 150
    .line 151
    return-object p0

    .line 152
    :pswitch_1b
    const-string p0, "(MDK) Cannot fetch VIN for selected vehicle."

    .line 153
    .line 154
    return-object p0

    .line 155
    :pswitch_1c
    new-instance p0, Luz0/e0;

    .line 156
    .line 157
    sget-object v0, Lu41/e;->a:Lu41/e;

    .line 158
    .line 159
    sget-object v1, Lu41/f;->Companion:Lu41/b;

    .line 160
    .line 161
    invoke-virtual {v1, v0}, Lu41/b;->serializer(Lqz0/a;)Lqz0/a;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    const/4 v2, 0x1

    .line 166
    invoke-direct {p0, v0, v1, v2}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 167
    .line 168
    .line 169
    return-object p0

    .line 170
    nop

    .line 171
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
