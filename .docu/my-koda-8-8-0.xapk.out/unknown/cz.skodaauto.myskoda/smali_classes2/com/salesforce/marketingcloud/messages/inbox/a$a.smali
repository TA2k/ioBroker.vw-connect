.class synthetic Lcom/salesforce/marketingcloud/messages/inbox/a$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/messages/inbox/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1009
    name = null
.end annotation


# static fields
.field static final synthetic a:[I

.field static final synthetic b:[I

.field static final synthetic c:[I


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/alarms/a$a;->values()[Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    array-length v0, v0

    .line 6
    new-array v0, v0, [I

    .line 7
    .line 8
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/a$a;->c:[I

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    :try_start_0
    sget-object v2, Lcom/salesforce/marketingcloud/alarms/a$a;->g:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 12
    .line 13
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    :catch_0
    invoke-static {}, Lcom/salesforce/marketingcloud/http/b;->values()[Lcom/salesforce/marketingcloud/http/b;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    array-length v0, v0

    .line 24
    new-array v0, v0, [I

    .line 25
    .line 26
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/a$a;->b:[I

    .line 27
    .line 28
    :try_start_1
    sget-object v2, Lcom/salesforce/marketingcloud/http/b;->k:Lcom/salesforce/marketingcloud/http/b;

    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    aput v1, v0, v2
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 35
    .line 36
    :catch_1
    const/4 v0, 0x2

    .line 37
    :try_start_2
    sget-object v2, Lcom/salesforce/marketingcloud/messages/inbox/a$a;->b:[I

    .line 38
    .line 39
    sget-object v3, Lcom/salesforce/marketingcloud/http/b;->l:Lcom/salesforce/marketingcloud/http/b;

    .line 40
    .line 41
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    aput v0, v2, v3
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 46
    .line 47
    :catch_2
    const/4 v2, 0x3

    .line 48
    :try_start_3
    sget-object v3, Lcom/salesforce/marketingcloud/messages/inbox/a$a;->b:[I

    .line 49
    .line 50
    sget-object v4, Lcom/salesforce/marketingcloud/http/b;->m:Lcom/salesforce/marketingcloud/http/b;

    .line 51
    .line 52
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    aput v2, v3, v4
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 57
    .line 58
    :catch_3
    invoke-static {}, Lcom/salesforce/marketingcloud/behaviors/a;->values()[Lcom/salesforce/marketingcloud/behaviors/a;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    array-length v3, v3

    .line 63
    new-array v3, v3, [I

    .line 64
    .line 65
    sput-object v3, Lcom/salesforce/marketingcloud/messages/inbox/a$a;->a:[I

    .line 66
    .line 67
    :try_start_4
    sget-object v4, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 68
    .line 69
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    aput v1, v3, v4
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 74
    .line 75
    :catch_4
    :try_start_5
    sget-object v1, Lcom/salesforce/marketingcloud/messages/inbox/a$a;->a:[I

    .line 76
    .line 77
    sget-object v3, Lcom/salesforce/marketingcloud/behaviors/a;->j:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 78
    .line 79
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    aput v0, v1, v3
    :try_end_5
    .catch Ljava/lang/NoSuchFieldError; {:try_start_5 .. :try_end_5} :catch_5

    .line 84
    .line 85
    :catch_5
    :try_start_6
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/a$a;->a:[I

    .line 86
    .line 87
    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->l:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 88
    .line 89
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    aput v2, v0, v1
    :try_end_6
    .catch Ljava/lang/NoSuchFieldError; {:try_start_6 .. :try_end_6} :catch_6

    .line 94
    .line 95
    :catch_6
    :try_start_7
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/a$a;->a:[I

    .line 96
    .line 97
    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->p:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 98
    .line 99
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    const/4 v2, 0x4

    .line 104
    aput v2, v0, v1
    :try_end_7
    .catch Ljava/lang/NoSuchFieldError; {:try_start_7 .. :try_end_7} :catch_7

    .line 105
    .line 106
    :catch_7
    return-void
.end method
