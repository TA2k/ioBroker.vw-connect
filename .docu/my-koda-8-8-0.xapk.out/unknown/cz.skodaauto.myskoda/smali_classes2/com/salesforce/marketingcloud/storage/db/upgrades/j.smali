.class public Lcom/salesforce/marketingcloud/storage/db/upgrades/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "Range"
    }
.end annotation


# static fields
.field private static final a:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "Version7ToVersion8"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/j;->a:Ljava/lang/String;

    .line 8
    .line 9
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

.method public static a(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 8

    .line 1
    const-string v0, "id"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    :try_start_0
    const-string v3, "SELECT id,read,message_deleted FROM cloud_page_messages WHERE message_type=1"

    .line 6
    .line 7
    invoke-virtual {p0, v3, v1}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    if-eqz v3, :cond_5

    .line 12
    .line 13
    invoke-interface {v3}, Landroid/database/Cursor;->moveToFirst()Z

    .line 14
    .line 15
    .line 16
    move-result v4
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    .line 17
    if-eqz v4, :cond_4

    .line 18
    .line 19
    :cond_0
    const/4 v4, 0x1

    .line 20
    :try_start_1
    const-string v5, "message_deleted"

    .line 21
    .line 22
    invoke-interface {v3, v5}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 23
    .line 24
    .line 25
    move-result v5

    .line 26
    invoke-interface {v3, v5}, Landroid/database/Cursor;->getInt(I)I

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    const/4 v6, -0x1

    .line 31
    if-ne v5, v4, :cond_1

    .line 32
    .line 33
    const/4 v5, 0x2

    .line 34
    goto :goto_0

    .line 35
    :cond_1
    const-string v5, "read"

    .line 36
    .line 37
    invoke-interface {v3, v5}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 38
    .line 39
    .line 40
    move-result v5

    .line 41
    invoke-interface {v3, v5}, Landroid/database/Cursor;->getInt(I)I

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    if-ne v5, v4, :cond_2

    .line 46
    .line 47
    move v5, v4

    .line 48
    goto :goto_0

    .line 49
    :cond_2
    move v5, v6

    .line 50
    :goto_0
    if-eq v5, v6, :cond_3

    .line 51
    .line 52
    new-instance v6, Landroid/content/ContentValues;

    .line 53
    .line 54
    invoke-direct {v6}, Landroid/content/ContentValues;-><init>()V

    .line 55
    .line 56
    .line 57
    invoke-interface {v3, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 58
    .line 59
    .line 60
    move-result v7

    .line 61
    invoke-interface {v3, v7}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v7

    .line 65
    invoke-virtual {v6, v0, v7}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    const-string v7, "status"

    .line 69
    .line 70
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    invoke-virtual {v6, v7, v5}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 75
    .line 76
    .line 77
    const-string v5, "inbox_message_status"

    .line 78
    .line 79
    invoke-virtual {p0, v5, v1, v6}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J

    .line 80
    .line 81
    .line 82
    goto :goto_1

    .line 83
    :catch_0
    move-exception v0

    .line 84
    goto :goto_3

    .line 85
    :cond_3
    :goto_1
    invoke-interface {v3}, Landroid/database/Cursor;->moveToNext()Z

    .line 86
    .line 87
    .line 88
    move-result v5

    .line 89
    if-nez v5, :cond_0

    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_4
    move v4, v2

    .line 93
    :goto_2
    invoke-interface {v3}, Landroid/database/Cursor;->close()V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 94
    .line 95
    .line 96
    goto :goto_4

    .line 97
    :catch_1
    move-exception v0

    .line 98
    move v4, v2

    .line 99
    goto :goto_3

    .line 100
    :cond_5
    move v4, v2

    .line 101
    goto :goto_4

    .line 102
    :goto_3
    sget-object v3, Lcom/salesforce/marketingcloud/storage/db/upgrades/j;->a:Ljava/lang/String;

    .line 103
    .line 104
    new-array v5, v2, [Ljava/lang/Object;

    .line 105
    .line 106
    const-string v6, "Unable to set inbox message statuses for legacy messages"

    .line 107
    .line 108
    invoke-static {v3, v0, v6, v5}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    :goto_4
    const-string v0, "DELETE FROM cloud_page_messages WHERE message_type=1"

    .line 112
    .line 113
    if-eqz v4, :cond_6

    .line 114
    .line 115
    :try_start_2
    new-instance v3, Landroid/content/ContentValues;

    .line 116
    .line 117
    invoke-direct {v3}, Landroid/content/ContentValues;-><init>()V

    .line 118
    .line 119
    .line 120
    const-string v4, "message_type"

    .line 121
    .line 122
    const/16 v5, 0x8

    .line 123
    .line 124
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    invoke-virtual {v3, v4, v5}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 129
    .line 130
    .line 131
    const-string v4, "cloud_page_messages"

    .line 132
    .line 133
    invoke-virtual {p0, v4, v3, v1, v1}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    .line 134
    .line 135
    .line 136
    goto :goto_5

    .line 137
    :catch_2
    move-exception v3

    .line 138
    sget-object v4, Lcom/salesforce/marketingcloud/storage/db/upgrades/j;->a:Ljava/lang/String;

    .line 139
    .line 140
    new-array v5, v2, [Ljava/lang/Object;

    .line 141
    .line 142
    const-string v6, "Unable to update message_type for legacy Inbox messages.  Attempting to delete them."

    .line 143
    .line 144
    invoke-static {v4, v3, v6, v5}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    :try_start_3
    invoke-virtual {p0, v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_3

    .line 148
    .line 149
    .line 150
    goto :goto_5

    .line 151
    :catch_3
    move-exception v3

    .line 152
    sget-object v4, Lcom/salesforce/marketingcloud/storage/db/upgrades/j;->a:Ljava/lang/String;

    .line 153
    .line 154
    new-array v5, v2, [Ljava/lang/Object;

    .line 155
    .line 156
    const-string v6, "Unable to delete legacy Inbox messages."

    .line 157
    .line 158
    invoke-static {v4, v3, v6, v5}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    :cond_6
    :goto_5
    :try_start_4
    invoke-virtual {p0, v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_4

    .line 162
    .line 163
    .line 164
    goto :goto_6

    .line 165
    :catch_4
    move-exception p0

    .line 166
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/j;->a:Ljava/lang/String;

    .line 167
    .line 168
    new-array v1, v2, [Ljava/lang/Object;

    .line 169
    .line 170
    const-string v2, "Final attempt to delete legacy Inbox messages failed."

    .line 171
    .line 172
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    :goto_6
    return-void
.end method
