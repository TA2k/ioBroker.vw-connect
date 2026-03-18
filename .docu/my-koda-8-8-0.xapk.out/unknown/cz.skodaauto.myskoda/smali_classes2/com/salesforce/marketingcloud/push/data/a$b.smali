.class public final Lcom/salesforce/marketingcloud/push/data/a$b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/data/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "b"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/push/data/a$b;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/a;
    .locals 4

    .line 1
    const-string p0, "json"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "t"

    .line 7
    .line 8
    invoke-virtual {p1, p0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(Ljava/lang/String;)Ljava/lang/Integer;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/a$f;->b:Lcom/salesforce/marketingcloud/push/data/a$f;

    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-nez p0, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-ne v1, v0, :cond_1

    .line 30
    .line 31
    sget-object p0, Lcom/salesforce/marketingcloud/push/data/a$e;->d:Lcom/salesforce/marketingcloud/push/data/a$e;

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_1
    :goto_0
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/a$f;->c:Lcom/salesforce/marketingcloud/push/data/a$f;

    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    const-string v1, "optString(...)"

    .line 41
    .line 42
    const-string v2, "ul"

    .line 43
    .line 44
    if-nez p0, :cond_2

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_2
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    if-ne v3, v0, :cond_4

    .line 52
    .line 53
    invoke-static {p1, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    if-eqz p0, :cond_3

    .line 58
    .line 59
    new-instance p1, Lcom/salesforce/marketingcloud/push/data/a$c;

    .line 60
    .line 61
    invoke-direct {p1, p0}, Lcom/salesforce/marketingcloud/push/data/a$c;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    return-object p1

    .line 65
    :cond_3
    sget-object p0, Lcom/salesforce/marketingcloud/push/data/a$e;->d:Lcom/salesforce/marketingcloud/push/data/a$e;

    .line 66
    .line 67
    return-object p0

    .line 68
    :cond_4
    :goto_1
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/a$f;->d:Lcom/salesforce/marketingcloud/push/data/a$f;

    .line 69
    .line 70
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    if-nez p0, :cond_5

    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_5
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    if-ne v3, v0, :cond_7

    .line 82
    .line 83
    invoke-static {p1, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    if-eqz p0, :cond_6

    .line 88
    .line 89
    new-instance p1, Lcom/salesforce/marketingcloud/push/data/a$g;

    .line 90
    .line 91
    invoke-direct {p1, p0}, Lcom/salesforce/marketingcloud/push/data/a$g;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    return-object p1

    .line 95
    :cond_6
    sget-object p0, Lcom/salesforce/marketingcloud/push/data/a$e;->d:Lcom/salesforce/marketingcloud/push/data/a$e;

    .line 96
    .line 97
    return-object p0

    .line 98
    :cond_7
    :goto_2
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/a$f;->e:Lcom/salesforce/marketingcloud/push/data/a$f;

    .line 99
    .line 100
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    if-nez p0, :cond_8

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_8
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    if-ne v3, v0, :cond_a

    .line 112
    .line 113
    invoke-static {p1, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    if-eqz p0, :cond_9

    .line 118
    .line 119
    new-instance p1, Lcom/salesforce/marketingcloud/push/data/a$a;

    .line 120
    .line 121
    invoke-direct {p1, p0}, Lcom/salesforce/marketingcloud/push/data/a$a;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    return-object p1

    .line 125
    :cond_9
    sget-object p0, Lcom/salesforce/marketingcloud/push/data/a$e;->d:Lcom/salesforce/marketingcloud/push/data/a$e;

    .line 126
    .line 127
    return-object p0

    .line 128
    :cond_a
    :goto_3
    sget-object p1, Lcom/salesforce/marketingcloud/push/data/a$f;->f:Lcom/salesforce/marketingcloud/push/data/a$f;

    .line 129
    .line 130
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 131
    .line 132
    .line 133
    move-result p1

    .line 134
    if-nez p0, :cond_b

    .line 135
    .line 136
    goto :goto_4

    .line 137
    :cond_b
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 138
    .line 139
    .line 140
    move-result p0

    .line 141
    if-ne p0, p1, :cond_c

    .line 142
    .line 143
    sget-object p0, Lcom/salesforce/marketingcloud/push/data/a$d;->d:Lcom/salesforce/marketingcloud/push/data/a$d;

    .line 144
    .line 145
    return-object p0

    .line 146
    :cond_c
    :goto_4
    const/4 p0, 0x0

    .line 147
    return-object p0
.end method
