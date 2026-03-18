.class public final Lcom/salesforce/marketingcloud/messages/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field private static final a:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    .line 2
    .line 3
    sput-object v0, Lcom/salesforce/marketingcloud/messages/b;->a:Ljava/lang/String;

    .line 4
    .line 5
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/storage/h;)V
    .locals 18

    move-object/from16 v0, p0

    .line 1
    new-instance v1, Ljava/util/Date;

    invoke-direct {v1}, Ljava/util/Date;-><init>()V

    .line 2
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/internal/h;->a(Lcom/salesforce/marketingcloud/messages/Message;Ljava/util/Date;)V

    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/internal/h;->e(Lcom/salesforce/marketingcloud/messages/Message;)I

    move-result v2

    const/4 v3, 0x1

    add-int/2addr v2, v3

    invoke-static {v0, v2}, Lcom/salesforce/marketingcloud/internal/h;->c(Lcom/salesforce/marketingcloud/messages/Message;I)V

    .line 4
    invoke-static {v0}, Lcom/salesforce/marketingcloud/messages/b;->b(Lcom/salesforce/marketingcloud/messages/Message;)I

    move-result v2

    const/4 v4, 0x0

    const/4 v5, -0x1

    if-le v2, v5, :cond_a

    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/Message;->numberOfPeriods()I

    move-result v6

    if-le v6, v5, :cond_a

    .line 6
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/Message;->periodType()I

    move-result v6

    if-eqz v6, :cond_a

    .line 7
    invoke-static {v0}, Lcom/salesforce/marketingcloud/internal/h;->d(Lcom/salesforce/marketingcloud/messages/Message;)I

    move-result v6

    add-int/2addr v6, v3

    invoke-static {v0, v6}, Lcom/salesforce/marketingcloud/internal/h;->b(Lcom/salesforce/marketingcloud/messages/Message;I)V

    .line 8
    invoke-static {v0}, Lcom/salesforce/marketingcloud/internal/h;->d(Lcom/salesforce/marketingcloud/messages/Message;)I

    move-result v6

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/Message;->messagesPerPeriod()I

    move-result v7

    if-lt v6, v7, :cond_a

    .line 9
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/Message;->periodType()I

    move-result v6

    const/4 v7, 0x4

    const/4 v8, 0x3

    const/4 v9, 0x2

    const/4 v10, 0x5

    if-eq v6, v3, :cond_4

    if-eq v6, v9, :cond_3

    if-eq v6, v8, :cond_2

    const-wide/16 v11, 0x1

    if-eq v6, v7, :cond_1

    if-eq v6, v10, :cond_0

    const-wide/16 v11, 0x0

    goto :goto_0

    .line 10
    :cond_0
    sget-object v6, Ljava/util/concurrent/TimeUnit;->HOURS:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {v6, v11, v12}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    move-result-wide v11

    goto :goto_0

    .line 11
    :cond_1
    sget-object v6, Ljava/util/concurrent/TimeUnit;->DAYS:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {v6, v11, v12}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    move-result-wide v11

    goto :goto_0

    .line 12
    :cond_2
    sget-object v6, Ljava/util/concurrent/TimeUnit;->DAYS:Ljava/util/concurrent/TimeUnit;

    const-wide/16 v11, 0x7

    invoke-virtual {v6, v11, v12}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    move-result-wide v11

    goto :goto_0

    .line 13
    :cond_3
    sget-object v6, Ljava/util/concurrent/TimeUnit;->DAYS:Ljava/util/concurrent/TimeUnit;

    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    move-result-object v11

    invoke-virtual {v11, v10}, Ljava/util/Calendar;->getActualMaximum(I)I

    move-result v11

    int-to-long v11, v11

    invoke-virtual {v6, v11, v12}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    move-result-wide v11

    goto :goto_0

    .line 14
    :cond_4
    sget-object v6, Ljava/util/concurrent/TimeUnit;->DAYS:Ljava/util/concurrent/TimeUnit;

    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    move-result-object v11

    const/4 v12, 0x6

    invoke-virtual {v11, v12}, Ljava/util/Calendar;->getActualMaximum(I)I

    move-result v11

    int-to-long v11, v11

    invoke-virtual {v6, v11, v12}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    move-result-wide v11

    .line 15
    :goto_0
    new-instance v6, Ljava/util/Date;

    .line 16
    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    move-result-wide v13

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/Message;->numberOfPeriods()I

    move-result v1

    move-wide/from16 v16, v11

    int-to-long v10, v1

    mul-long v10, v10, v16

    add-long/2addr v10, v13

    invoke-direct {v6, v10, v11}, Ljava/util/Date;-><init>(J)V

    .line 17
    invoke-static {v0, v6}, Lcom/salesforce/marketingcloud/internal/h;->b(Lcom/salesforce/marketingcloud/messages/Message;Ljava/util/Date;)V

    .line 18
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/Message;->isRollingPeriod()Z

    move-result v1

    if-nez v1, :cond_a

    .line 19
    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    move-result-object v1

    .line 20
    invoke-static {v0}, Lcom/salesforce/marketingcloud/internal/h;->b(Lcom/salesforce/marketingcloud/messages/Message;)Ljava/util/Date;

    move-result-object v6

    invoke-virtual {v6}, Ljava/util/Date;->getTime()J

    move-result-wide v10

    invoke-virtual {v1, v10, v11}, Ljava/util/Calendar;->setTimeInMillis(J)V

    const/16 v6, 0xe

    .line 21
    invoke-virtual {v1, v6, v4}, Ljava/util/Calendar;->set(II)V

    const/16 v6, 0xd

    .line 22
    invoke-virtual {v1, v6, v4}, Ljava/util/Calendar;->set(II)V

    .line 23
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/Message;->periodType()I

    move-result v6

    const/16 v10, 0xa

    const/16 v11, 0xc

    if-eq v6, v3, :cond_9

    if-eq v6, v9, :cond_8

    if-eq v6, v8, :cond_7

    if-eq v6, v7, :cond_6

    const/4 v15, 0x5

    if-eq v6, v15, :cond_5

    goto :goto_1

    .line 24
    :cond_5
    invoke-virtual {v1, v11, v4}, Ljava/util/Calendar;->set(II)V

    goto :goto_1

    .line 25
    :cond_6
    invoke-virtual {v1, v10, v4}, Ljava/util/Calendar;->set(II)V

    .line 26
    invoke-virtual {v1, v11, v4}, Ljava/util/Calendar;->set(II)V

    goto :goto_1

    :cond_7
    const/4 v6, 0x7

    .line 27
    invoke-virtual {v1, v6, v3}, Ljava/util/Calendar;->set(II)V

    .line 28
    invoke-virtual {v1, v10, v4}, Ljava/util/Calendar;->set(II)V

    .line 29
    invoke-virtual {v1, v11, v4}, Ljava/util/Calendar;->set(II)V

    goto :goto_1

    :cond_8
    const/4 v15, 0x5

    .line 30
    invoke-virtual {v1, v15, v3}, Ljava/util/Calendar;->set(II)V

    .line 31
    invoke-virtual {v1, v10, v4}, Ljava/util/Calendar;->set(II)V

    .line 32
    invoke-virtual {v1, v11, v4}, Ljava/util/Calendar;->set(II)V

    goto :goto_1

    :cond_9
    const/4 v15, 0x5

    .line 33
    invoke-virtual {v1, v9, v4}, Ljava/util/Calendar;->set(II)V

    .line 34
    invoke-virtual {v1, v15, v3}, Ljava/util/Calendar;->set(II)V

    .line 35
    invoke-virtual {v1, v10, v4}, Ljava/util/Calendar;->set(II)V

    .line 36
    invoke-virtual {v1, v11, v4}, Ljava/util/Calendar;->set(II)V

    .line 37
    :goto_1
    invoke-virtual {v1}, Ljava/util/Calendar;->getTime()Ljava/util/Date;

    move-result-object v1

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/internal/h;->b(Lcom/salesforce/marketingcloud/messages/Message;Ljava/util/Date;)V

    .line 38
    :cond_a
    invoke-static {v0}, Lcom/salesforce/marketingcloud/internal/h;->d(Lcom/salesforce/marketingcloud/messages/Message;)I

    move-result v1

    if-le v1, v5, :cond_b

    if-le v2, v5, :cond_b

    .line 39
    invoke-static {v0}, Lcom/salesforce/marketingcloud/internal/h;->d(Lcom/salesforce/marketingcloud/messages/Message;)I

    move-result v1

    if-le v1, v2, :cond_b

    .line 40
    invoke-static {v0, v4}, Lcom/salesforce/marketingcloud/internal/h;->b(Lcom/salesforce/marketingcloud/messages/Message;I)V

    .line 41
    :cond_b
    invoke-virtual/range {p1 .. p1}, Lcom/salesforce/marketingcloud/storage/h;->n()Lcom/salesforce/marketingcloud/storage/i;

    move-result-object v1

    invoke-virtual/range {p1 .. p1}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object v2

    invoke-interface {v1, v0, v2}, Lcom/salesforce/marketingcloud/storage/i;->a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/util/Crypto;)V

    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/storage/i;Lcom/salesforce/marketingcloud/util/Crypto;)V
    .locals 1

    .line 42
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->id()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p1, v0, p2}, Lcom/salesforce/marketingcloud/storage/i;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Message;

    move-result-object p1

    if-eqz p1, :cond_0

    .line 43
    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/h;->a(Lcom/salesforce/marketingcloud/messages/Message;)Ljava/util/Date;

    move-result-object p2

    invoke-static {p0, p2}, Lcom/salesforce/marketingcloud/internal/h;->a(Lcom/salesforce/marketingcloud/messages/Message;Ljava/util/Date;)V

    .line 44
    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/h;->e(Lcom/salesforce/marketingcloud/messages/Message;)I

    move-result p2

    invoke-static {p0, p2}, Lcom/salesforce/marketingcloud/internal/h;->c(Lcom/salesforce/marketingcloud/messages/Message;I)V

    .line 45
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->periodType()I

    move-result p2

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Message;->periodType()I

    move-result v0

    if-ne p2, v0, :cond_0

    .line 46
    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/h;->d(Lcom/salesforce/marketingcloud/messages/Message;)I

    move-result p2

    invoke-static {p0, p2}, Lcom/salesforce/marketingcloud/internal/h;->b(Lcom/salesforce/marketingcloud/messages/Message;I)V

    .line 47
    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/h;->b(Lcom/salesforce/marketingcloud/messages/Message;)Ljava/util/Date;

    move-result-object p1

    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/internal/h;->b(Lcom/salesforce/marketingcloud/messages/Message;Ljava/util/Date;)V

    :cond_0
    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/messages/Message;)Z
    .locals 4

    .line 48
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->endDateUtc()Ljava/util/Date;

    move-result-object p0

    if-eqz p0, :cond_0

    .line 49
    invoke-virtual {p0}, Ljava/util/Date;->getTime()J

    move-result-wide v0

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v2

    cmp-long p0, v0, v2

    if-gez p0, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    const/4 p0, 0x1

    return p0
.end method

.method private static b(Lcom/salesforce/marketingcloud/messages/Message;)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->messagesPerPeriod()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-gtz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->numberOfPeriods()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-lez v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->periodType()I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    return v0
.end method

.method public static c(Lcom/salesforce/marketingcloud/messages/Message;)Z
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->alert()Ljava/lang/String;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    invoke-virtual {v1}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    sget-object v1, Lcom/salesforce/marketingcloud/messages/b;->a:Ljava/lang/String;

    .line 17
    .line 18
    const-string v2, "Message (%s) was tripped, but does not have an alert message"

    .line 19
    .line 20
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->id()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-static {v1, v2, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    return v0

    .line 32
    :catch_0
    move-exception p0

    .line 33
    goto/16 :goto_0

    .line 34
    .line 35
    :cond_0
    new-instance v1, Ljava/util/Date;

    .line 36
    .line 37
    invoke-direct {v1}, Ljava/util/Date;-><init>()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->endDateUtc()Ljava/util/Date;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    if-eqz v2, :cond_1

    .line 45
    .line 46
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->endDateUtc()Ljava/util/Date;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    invoke-virtual {v2, v1}, Ljava/util/Date;->before(Ljava/util/Date;)Z

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    if-eqz v2, :cond_1

    .line 55
    .line 56
    sget-object v1, Lcom/salesforce/marketingcloud/messages/b;->a:Ljava/lang/String;

    .line 57
    .line 58
    const-string v2, "Message (%s) was tripped, but has expired."

    .line 59
    .line 60
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->id()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-static {v1, v2, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    return v0

    .line 72
    :cond_1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->startDateUtc()Ljava/util/Date;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    if-eqz v2, :cond_2

    .line 77
    .line 78
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->startDateUtc()Ljava/util/Date;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    invoke-virtual {v2, v1}, Ljava/util/Date;->after(Ljava/util/Date;)Z

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    if-eqz v2, :cond_2

    .line 87
    .line 88
    sget-object v1, Lcom/salesforce/marketingcloud/messages/b;->a:Ljava/lang/String;

    .line 89
    .line 90
    const-string v2, "Message (%s) was tripped, but has not started"

    .line 91
    .line 92
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->id()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    invoke-static {v1, v2, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    return v0

    .line 104
    :cond_2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->messageLimit()I

    .line 105
    .line 106
    .line 107
    move-result v2

    .line 108
    const/4 v3, -0x1

    .line 109
    if-le v2, v3, :cond_3

    .line 110
    .line 111
    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/h;->e(Lcom/salesforce/marketingcloud/messages/Message;)I

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->messageLimit()I

    .line 116
    .line 117
    .line 118
    move-result v4

    .line 119
    if-lt v2, v4, :cond_3

    .line 120
    .line 121
    sget-object v1, Lcom/salesforce/marketingcloud/messages/b;->a:Ljava/lang/String;

    .line 122
    .line 123
    const-string v2, "Message (%s) was tripped, but has met its message limit."

    .line 124
    .line 125
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->id()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    invoke-static {v1, v2, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    return v0

    .line 137
    :cond_3
    invoke-static {p0}, Lcom/salesforce/marketingcloud/messages/b;->b(Lcom/salesforce/marketingcloud/messages/Message;)I

    .line 138
    .line 139
    .line 140
    move-result v2

    .line 141
    if-le v2, v3, :cond_4

    .line 142
    .line 143
    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/h;->d(Lcom/salesforce/marketingcloud/messages/Message;)I

    .line 144
    .line 145
    .line 146
    move-result v3

    .line 147
    if-lt v3, v2, :cond_4

    .line 148
    .line 149
    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/h;->b(Lcom/salesforce/marketingcloud/messages/Message;)Ljava/util/Date;

    .line 150
    .line 151
    .line 152
    move-result-object v2

    .line 153
    if-eqz v2, :cond_4

    .line 154
    .line 155
    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/h;->b(Lcom/salesforce/marketingcloud/messages/Message;)Ljava/util/Date;

    .line 156
    .line 157
    .line 158
    move-result-object v2

    .line 159
    invoke-virtual {v1, v2}, Ljava/util/Date;->before(Ljava/util/Date;)Z

    .line 160
    .line 161
    .line 162
    move-result v2

    .line 163
    if-eqz v2, :cond_4

    .line 164
    .line 165
    sget-object v1, Lcom/salesforce/marketingcloud/messages/b;->a:Ljava/lang/String;

    .line 166
    .line 167
    const-string v2, "Message (%s) was tripped, but has met its message per period limit"

    .line 168
    .line 169
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->id()Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    invoke-static {v1, v2, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    return v0

    .line 181
    :cond_4
    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/h;->b(Lcom/salesforce/marketingcloud/messages/Message;)Ljava/util/Date;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    if-eqz v2, :cond_5

    .line 186
    .line 187
    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/h;->b(Lcom/salesforce/marketingcloud/messages/Message;)Ljava/util/Date;

    .line 188
    .line 189
    .line 190
    move-result-object v2

    .line 191
    invoke-virtual {v1, v2}, Ljava/util/Date;->before(Ljava/util/Date;)Z

    .line 192
    .line 193
    .line 194
    move-result v1

    .line 195
    if-eqz v1, :cond_5

    .line 196
    .line 197
    sget-object v1, Lcom/salesforce/marketingcloud/messages/b;->a:Ljava/lang/String;

    .line 198
    .line 199
    const-string v2, "Message (%s) was tripped, but was before its next allowed show time."

    .line 200
    .line 201
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/Message;->id()Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    invoke-static {v1, v2, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 210
    .line 211
    .line 212
    return v0

    .line 213
    :cond_5
    const/4 p0, 0x1

    .line 214
    return p0

    .line 215
    :goto_0
    sget-object v1, Lcom/salesforce/marketingcloud/messages/b;->a:Ljava/lang/String;

    .line 216
    .line 217
    new-array v2, v0, [Ljava/lang/Object;

    .line 218
    .line 219
    const-string v3, "Failed to determine is message should be shown."

    .line 220
    .line 221
    invoke-static {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    return v0
.end method
