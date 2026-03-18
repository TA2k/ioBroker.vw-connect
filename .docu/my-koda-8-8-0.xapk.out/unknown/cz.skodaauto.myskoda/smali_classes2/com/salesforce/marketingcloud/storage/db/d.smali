.class public final Lcom/salesforce/marketingcloud/storage/db/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Lcom/salesforce/marketingcloud/util/Crypto;)Landroid/content/ContentValues;
    .locals 5

    const-string v0, "message"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "crypto"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    .line 72
    :try_start_0
    new-instance v1, Landroid/content/ContentValues;

    invoke-direct {v1}, Landroid/content/ContentValues;-><init>()V

    .line 73
    const-string v2, "id"

    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id:Ljava/lang/String;

    invoke-virtual {v1, v2, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 74
    const-string v2, "start_date"

    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->startDateUtc:Ljava/util/Date;

    if-eqz v3, :cond_0

    invoke-virtual {v3}, Ljava/util/Date;->getTime()J

    move-result-wide v3

    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v3

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_2

    :cond_0
    move-object v3, v0

    .line 75
    :goto_0
    invoke-virtual {v1, v2, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 76
    const-string v2, "end_date"

    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->endDateUtc:Ljava/util/Date;

    if-eqz v3, :cond_1

    invoke-virtual {v3}, Ljava/util/Date;->getTime()J

    move-result-wide v3

    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v3

    goto :goto_1

    :cond_1
    move-object v3, v0

    .line 77
    :goto_1
    invoke-virtual {v1, v2, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 78
    const-string v2, "is_read"

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->getRead()Z

    move-result v3

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-virtual {v1, v2, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 79
    const-string v2, "is_deleted"

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->getDeleted()Z

    move-result v3

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-virtual {v1, v2, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 80
    const-string v2, "message_type"

    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageType:Ljava/lang/Integer;

    invoke-virtual {v1, v2, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 81
    const-string v2, "message_hash"

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->getMessageHash$sdk_release()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v2, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 82
    const-string v2, "message_json"

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->toJson$sdk_release()Lorg/json/JSONObject;

    move-result-object v3

    invoke-virtual {v3}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-interface {p1, v3}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v1, v2, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 83
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->getDirty$sdk_release()Z

    move-result p0

    if-eqz p0, :cond_2

    .line 84
    const-string p0, "is_dirty"

    const/4 p1, 0x1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {v1, p0, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :cond_2
    return-object v1

    .line 85
    :goto_2
    sget-object p1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/g;->f:Ljava/lang/String;

    const-string v2, "TAG"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v2, Lcom/salesforce/marketingcloud/storage/db/d$c;->b:Lcom/salesforce/marketingcloud/storage/db/d$c;

    invoke-virtual {p1, v1, p0, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    return-object v0
.end method

.method public static final a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const-class v2, Ljava/lang/Integer;

    const-class v3, Ljava/lang/String;

    const-string v4, "cursor"

    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "crypto"

    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    :try_start_0
    new-instance v5, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    new-instance v6, Lorg/json/JSONObject;

    const-string v7, "message_json"

    .line 3
    invoke-interface {v0, v7}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v7

    .line 4
    sget-object v8, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    invoke-virtual {v8, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 5
    invoke-virtual {v8, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    .line 6
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    const-string v11, "Unsupported type"

    sget-object v12, Ljava/lang/Short;->TYPE:Ljava/lang/Class;

    sget-object v13, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    sget-object v14, Ljava/lang/Float;->TYPE:Ljava/lang/Class;

    sget-object v15, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    sget-object v4, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    if-eqz v10, :cond_0

    :try_start_1
    invoke-interface {v0, v7}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v7

    goto :goto_0

    :catch_0
    move-exception v0

    goto/16 :goto_9

    .line 7
    :cond_0
    invoke-virtual {v8, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    .line 8
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_1

    invoke-interface {v0, v7}, Landroid/database/Cursor;->getInt(I)I

    move-result v7

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    check-cast v7, Ljava/lang/String;

    goto :goto_0

    .line 9
    :cond_1
    invoke-virtual {v8, v15}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    .line 10
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_2

    invoke-interface {v0, v7}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v9

    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v7

    check-cast v7, Ljava/lang/String;

    goto :goto_0

    .line 11
    :cond_2
    invoke-virtual {v8, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    .line 12
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_3

    invoke-interface {v0, v7}, Landroid/database/Cursor;->getFloat(I)F

    move-result v7

    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v7

    check-cast v7, Ljava/lang/String;

    goto :goto_0

    .line 13
    :cond_3
    invoke-virtual {v8, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    .line 14
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_4

    invoke-interface {v0, v7}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v9

    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v7

    check-cast v7, Ljava/lang/String;

    goto :goto_0

    .line 15
    :cond_4
    invoke-virtual {v8, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    .line 16
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_1e

    invoke-interface {v0, v7}, Landroid/database/Cursor;->getShort(I)S

    move-result v7

    invoke-static {v7}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v7

    check-cast v7, Ljava/lang/String;

    .line 17
    :goto_0
    invoke-interface {v1, v7}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_1d

    invoke-direct {v6, v1}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    const/4 v1, 0x2

    const/4 v7, 0x0

    const/4 v9, 0x0

    invoke-direct {v5, v6, v7, v1, v9}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;-><init>(Lorg/json/JSONObject;ZILkotlin/jvm/internal/g;)V

    .line 18
    const-string v1, "is_deleted"

    .line 19
    invoke-interface {v0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    .line 20
    invoke-virtual {v8, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 21
    invoke-virtual {v8, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 22
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_5

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_1

    .line 23
    :cond_5
    invoke-virtual {v8, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 24
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_6

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getInt(I)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    goto :goto_1

    .line 25
    :cond_6
    invoke-virtual {v8, v15}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 26
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_7

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v9

    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_1

    .line 27
    :cond_7
    invoke-virtual {v8, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 28
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_8

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getFloat(I)F

    move-result v1

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_1

    .line 29
    :cond_8
    invoke-virtual {v8, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 30
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_9

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v9

    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_1

    .line 31
    :cond_9
    invoke-virtual {v8, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 32
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_1c

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getShort(I)S

    move-result v1

    invoke-static {v1}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    :goto_1
    const/4 v6, 0x1

    if-nez v1, :cond_a

    goto :goto_2

    .line 33
    :cond_a
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v1

    if-ne v1, v6, :cond_b

    move v1, v6

    goto :goto_3

    :cond_b
    :goto_2
    move v1, v7

    :goto_3
    invoke-virtual {v5, v1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->setDeleted(Z)V

    .line 34
    const-string v1, "is_read"

    .line 35
    invoke-interface {v0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    .line 36
    invoke-virtual {v8, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 37
    invoke-virtual {v8, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    .line 38
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_c

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_4

    .line 39
    :cond_c
    invoke-virtual {v8, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    .line 40
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_d

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getInt(I)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    goto :goto_4

    .line 41
    :cond_d
    invoke-virtual {v8, v15}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    .line 42
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_e

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v9

    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_4

    .line 43
    :cond_e
    invoke-virtual {v8, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    .line 44
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_f

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getFloat(I)F

    move-result v1

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_4

    .line 45
    :cond_f
    invoke-virtual {v8, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    .line 46
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_10

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v9

    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_4

    .line 47
    :cond_10
    invoke-virtual {v8, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    .line 48
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_1b

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getShort(I)S

    move-result v1

    invoke-static {v1}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    :goto_4
    if-nez v1, :cond_11

    goto :goto_5

    .line 49
    :cond_11
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v1

    if-ne v1, v6, :cond_12

    move v1, v6

    goto :goto_6

    :cond_12
    :goto_5
    move v1, v7

    :goto_6
    invoke-virtual {v5, v1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->setRead(Z)V

    .line 50
    const-string v1, "is_dirty"

    .line 51
    invoke-interface {v0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    .line 52
    invoke-virtual {v8, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v2

    .line 53
    invoke-virtual {v8, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 54
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_13

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    goto :goto_7

    .line 55
    :cond_13
    invoke-virtual {v8, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 56
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_14

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getInt(I)I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    goto :goto_7

    .line 57
    :cond_14
    invoke-virtual {v8, v15}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 58
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_15

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    goto :goto_7

    .line 59
    :cond_15
    invoke-virtual {v8, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 60
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_16

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getFloat(I)F

    move-result v0

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    goto :goto_7

    .line 61
    :cond_16
    invoke-virtual {v8, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 62
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_17

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    goto :goto_7

    .line 63
    :cond_17
    invoke-virtual {v8, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 64
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1a

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getShort(I)S

    move-result v0

    invoke-static {v0}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    :goto_7
    if-nez v0, :cond_18

    goto :goto_8

    .line 65
    :cond_18
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v0

    if-ne v0, v6, :cond_19

    move v7, v6

    :cond_19
    :goto_8
    invoke-virtual {v5, v7}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->setDirty$sdk_release(Z)V

    return-object v5

    .line 66
    :cond_1a
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v11}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 67
    :cond_1b
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v11}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 68
    :cond_1c
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v11}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 69
    :cond_1d
    const-string v0, "Required value was null."

    new-instance v1, Ljava/lang/IllegalStateException;

    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    .line 70
    :cond_1e
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v11}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 71
    :goto_9
    sget-object v1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v2, Lcom/salesforce/marketingcloud/storage/db/g;->f:Ljava/lang/String;

    const-string v3, "TAG"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Lcom/salesforce/marketingcloud/storage/db/d$a;->b:Lcom/salesforce/marketingcloud/storage/db/d$a;

    invoke-virtual {v1, v2, v0, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    const/16 v16, 0x0

    return-object v16
.end method

.method private static final a(Landroid/database/Cursor;Ljava/lang/String;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Landroid/database/Cursor;",
            "Ljava/lang/String;",
            ")TT;"
        }
    .end annotation

    .line 1
    invoke-interface {p0, p1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    invoke-static {}, Lkotlin/jvm/internal/m;->k()V

    const/4 p0, 0x0

    throw p0
.end method

.method public static final b(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Message;
    .locals 37

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const-class v2, Ljava/lang/Integer;

    const-class v3, Ljava/lang/String;

    const-string v4, "cursor"

    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "crypto"

    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    :try_start_0
    const-string v5, "id"

    .line 2
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v5

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 3
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    const-string v8, "Unsupported type"

    sget-object v9, Ljava/lang/Short;->TYPE:Ljava/lang/Class;

    sget-object v10, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    sget-object v11, Ljava/lang/Float;->TYPE:Ljava/lang/Class;

    sget-object v12, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    sget-object v13, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    if-eqz v7, :cond_0

    :try_start_1
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v5

    :goto_0
    move-object v15, v5

    goto/16 :goto_1

    :catch_0
    const/16 v34, 0x0

    goto/16 :goto_2a

    .line 4
    :cond_0
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_1

    invoke-interface {v0, v5}, Landroid/database/Cursor;->getInt(I)I

    move-result v5

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    goto :goto_0

    .line 5
    :cond_1
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_2

    invoke-interface {v0, v5}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v5

    invoke-static {v5, v6}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    goto :goto_0

    .line 6
    :cond_2
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_3

    invoke-interface {v0, v5}, Landroid/database/Cursor;->getFloat(I)F

    move-result v5

    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    goto :goto_0

    .line 7
    :cond_3
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_4

    invoke-interface {v0, v5}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v5

    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    goto :goto_0

    .line 8
    :cond_4
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_aa

    invoke-interface {v0, v5}, Landroid/database/Cursor;->getShort(I)S

    move-result v5

    invoke-static {v5}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v5

    check-cast v5, Ljava/lang/String;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_0

    :goto_1
    const-string v5, "Required value was null."

    if-eqz v15, :cond_a9

    .line 9
    :try_start_2
    const-string v6, "title"

    .line 10
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v6

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 11
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_5

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v6

    goto :goto_2

    .line 12
    :cond_5
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_6

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getInt(I)I

    move-result v6

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_2

    .line 13
    :cond_6
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_7

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_2

    .line 14
    :cond_7
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_8

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getFloat(I)F

    move-result v6

    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_2

    .line 15
    :cond_8
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_9

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_2

    .line 16
    :cond_9
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_a8

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getShort(I)S

    move-result v6

    invoke-static {v6}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    .line 17
    :goto_2
    invoke-interface {v1, v6}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v16

    .line 18
    const-string v6, "alert"

    .line 19
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v6

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 20
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_a

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v6

    goto :goto_3

    .line 21
    :cond_a
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_b

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getInt(I)I

    move-result v6

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_3

    .line 22
    :cond_b
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_c

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_3

    .line 23
    :cond_c
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_d

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getFloat(I)F

    move-result v6

    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_3

    .line 24
    :cond_d
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_e

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_3

    .line 25
    :cond_e
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_a7

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getShort(I)S

    move-result v6

    invoke-static {v6}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    .line 26
    :goto_3
    invoke-interface {v1, v6}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v17

    if-eqz v17, :cond_a6

    .line 27
    const-string v6, "sound"

    .line 28
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v6

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 29
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_f

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v6

    :goto_4
    move-object/from16 v18, v6

    goto :goto_5

    .line 30
    :cond_f
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_10

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getInt(I)I

    move-result v6

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_4

    .line 31
    :cond_10
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_11

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_4

    .line 32
    :cond_11
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_12

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getFloat(I)F

    move-result v6

    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_4

    .line 33
    :cond_12
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_13

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_4

    .line 34
    :cond_13
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_a5

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getShort(I)S

    move-result v6

    invoke-static {v6}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_4

    .line 35
    :goto_5
    const-string v6, "mediaUrl"

    .line 36
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v6

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 37
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_14

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v6

    goto :goto_6

    .line 38
    :cond_14
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_15

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getInt(I)I

    move-result v6

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_6

    .line 39
    :cond_15
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_16

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_6

    .line 40
    :cond_16
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_17

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getFloat(I)F

    move-result v6

    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_6

    .line 41
    :cond_17
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_18

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    goto :goto_6

    .line 42
    :cond_18
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_a4

    invoke-interface {v0, v6}, Landroid/database/Cursor;->getShort(I)S

    move-result v6

    invoke-static {v6}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    .line 43
    :goto_6
    invoke-interface {v1, v6}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    .line 44
    const-string v7, "mediaAlt"

    .line 45
    invoke-interface {v0, v7}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v7

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    const/16 v34, 0x0

    .line 46
    :try_start_3
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v4

    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_19

    invoke-interface {v0, v7}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    goto :goto_7

    .line 47
    :cond_19
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v4

    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1a

    invoke-interface {v0, v7}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_7

    .line 48
    :cond_1a
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v4

    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1b

    invoke-interface {v0, v7}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v19

    invoke-static/range {v19 .. v20}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_7

    .line 49
    :cond_1b
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v4

    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1c

    invoke-interface {v0, v7}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_7

    .line 50
    :cond_1c
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v4

    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1d

    invoke-interface {v0, v7}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v19

    invoke-static/range {v19 .. v20}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_7

    .line 51
    :cond_1d
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v4

    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_a3

    invoke-interface {v0, v7}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    .line 52
    :goto_7
    invoke-interface {v1, v4}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    if-nez v6, :cond_1f

    if-eqz v4, :cond_1e

    goto :goto_8

    :cond_1e
    move-object/from16 v19, v34

    goto :goto_9

    .line 53
    :cond_1f
    :goto_8
    new-instance v7, Lcom/salesforce/marketingcloud/messages/Message$Media;

    invoke-direct {v7, v6, v4}, Lcom/salesforce/marketingcloud/messages/Message$Media;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    move-object/from16 v19, v7

    .line 54
    :goto_9
    const-string v4, "start_date"

    .line 55
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 56
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_20

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    goto :goto_a

    .line 57
    :cond_20
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_21

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_a

    .line 58
    :cond_21
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_22

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_a

    .line 59
    :cond_22
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_23

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_a

    .line 60
    :cond_23
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_24

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_a

    .line 61
    :cond_24
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_a2

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    :goto_a
    if-eqz v4, :cond_25

    .line 62
    invoke-static {v4}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v4

    move-object/from16 v20, v4

    goto :goto_b

    :cond_25
    move-object/from16 v20, v34

    .line 63
    :goto_b
    const-string v4, "end_date"

    .line 64
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 65
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_26

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    goto :goto_c

    .line 66
    :cond_26
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_27

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_c

    .line 67
    :cond_27
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_28

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_c

    .line 68
    :cond_28
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_29

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_c

    .line 69
    :cond_29
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_2a

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_c

    .line 70
    :cond_2a
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_a1

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    :goto_c
    if-eqz v4, :cond_2b

    .line 71
    invoke-static {v4}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v4

    move-object/from16 v21, v4

    goto :goto_d

    :cond_2b
    move-object/from16 v21, v34

    .line 72
    :goto_d
    const-string v4, "message_type"

    .line 73
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v2}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 74
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_2c

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_e

    .line 75
    :cond_2c
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_2d

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    goto :goto_e

    .line 76
    :cond_2d
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_2e

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_e

    .line 77
    :cond_2e
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_2f

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_e

    .line 78
    :cond_2f
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_30

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_e

    .line 79
    :cond_30
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_a0

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    :goto_e
    if-eqz v4, :cond_9f

    .line 80
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v22

    .line 81
    const-string v4, "content_type"

    .line 82
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v2}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 83
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_31

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_f

    .line 84
    :cond_31
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_32

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    goto :goto_f

    .line 85
    :cond_32
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_33

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_f

    .line 86
    :cond_33
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_34

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_f

    .line 87
    :cond_34
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_35

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_f

    .line 88
    :cond_35
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_9e

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    :goto_f
    if-eqz v4, :cond_9d

    .line 89
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v23

    .line 90
    const-string v4, "url"

    .line 91
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    .line 92
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_36

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    goto :goto_10

    .line 93
    :cond_36
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_37

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_10

    .line 94
    :cond_37
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_38

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_10

    .line 95
    :cond_38
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_39

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_10

    .line 96
    :cond_39
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_3a

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_10

    .line 97
    :cond_3a
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_9c

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    .line 98
    :goto_10
    invoke-interface {v1, v4}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v24

    .line 99
    const-string v4, "messages_per_period"

    .line 100
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v2}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    .line 101
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_3b

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_11

    .line 102
    :cond_3b
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_3c

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    goto :goto_11

    .line 103
    :cond_3c
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_3d

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_11

    .line 104
    :cond_3d
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_3e

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_11

    .line 105
    :cond_3e
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_3f

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_11

    .line 106
    :cond_3f
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_9b

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    :goto_11
    const/4 v5, -0x1

    if-eqz v4, :cond_40

    .line 107
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v4

    move/from16 v25, v4

    goto :goto_12

    :cond_40
    move/from16 v25, v5

    .line 108
    :goto_12
    const-string v4, "number_of_periods"

    .line 109
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v2}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 110
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_41

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_13

    .line 111
    :cond_41
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_42

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    goto :goto_13

    .line 112
    :cond_42
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_43

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_13

    .line 113
    :cond_43
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_44

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_13

    .line 114
    :cond_44
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_45

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_13

    .line 115
    :cond_45
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_9a

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    :goto_13
    if-eqz v4, :cond_46

    .line 116
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v4

    move/from16 v26, v4

    goto :goto_14

    :cond_46
    move/from16 v26, v5

    .line 117
    :goto_14
    const-string v4, "period_type"

    .line 118
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v2}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 119
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_47

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_15

    .line 120
    :cond_47
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_48

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    goto :goto_15

    .line 121
    :cond_48
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_49

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_15

    .line 122
    :cond_49
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_4a

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_15

    .line 123
    :cond_4a
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_4b

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_15

    .line 124
    :cond_4b
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_99

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    :goto_15
    const/4 v6, 0x0

    if-eqz v4, :cond_4c

    .line 125
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v4

    move/from16 v27, v4

    goto :goto_16

    :cond_4c
    move/from16 v27, v6

    .line 126
    :goto_16
    const-string v4, "rolling_period"

    .line 127
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v2}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 128
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_4d

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_17

    .line 129
    :cond_4d
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_4e

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    goto :goto_17

    .line 130
    :cond_4e
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_4f

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v28

    invoke-static/range {v28 .. v29}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_17

    .line 131
    :cond_4f
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_50

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_17

    .line 132
    :cond_50
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_51

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v28

    invoke-static/range {v28 .. v29}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_17

    .line 133
    :cond_51
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_98

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    :goto_17
    if-nez v4, :cond_52

    goto :goto_18

    .line 134
    :cond_52
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v4

    const/4 v7, 0x1

    if-ne v4, v7, :cond_53

    move/from16 v28, v7

    goto :goto_19

    :cond_53
    :goto_18
    move/from16 v28, v6

    .line 135
    :goto_19
    const-string v4, "message_limit"

    .line 136
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v2}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 137
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_54

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_1a

    .line 138
    :cond_54
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_55

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    goto :goto_1a

    .line 139
    :cond_55
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_56

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v29

    invoke-static/range {v29 .. v30}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_1a

    .line 140
    :cond_56
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_57

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_1a

    .line 141
    :cond_57
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_58

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v29

    invoke-static/range {v29 .. v30}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_1a

    .line 142
    :cond_58
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_97

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    :goto_1a
    if-eqz v4, :cond_59

    .line 143
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v4

    move/from16 v29, v4

    goto :goto_1b

    :cond_59
    move/from16 v29, v5

    .line 144
    :goto_1b
    const-string v4, "proximity"

    .line 145
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v2}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 146
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_5a

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_1c

    .line 147
    :cond_5a
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_5b

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    goto :goto_1c

    .line 148
    :cond_5b
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_5c

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v30

    invoke-static/range {v30 .. v31}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_1c

    .line 149
    :cond_5c
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_5d

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_1c

    .line 150
    :cond_5d
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_5e

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v30

    invoke-static/range {v30 .. v31}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    goto :goto_1c

    .line 151
    :cond_5e
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_96

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    :goto_1c
    if-eqz v4, :cond_5f

    .line 152
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v4

    move/from16 v30, v4

    goto :goto_1d

    :cond_5f
    move/from16 v30, v6

    .line 153
    :goto_1d
    const-string v4, "open_direct"

    .line 154
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 155
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_60

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    goto :goto_1e

    .line 156
    :cond_60
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_61

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_1e

    .line 157
    :cond_61
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_62

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v31

    invoke-static/range {v31 .. v32}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_1e

    .line 158
    :cond_62
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_63

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_1e

    .line 159
    :cond_63
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_64

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v31

    invoke-static/range {v31 .. v32}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_1e

    .line 160
    :cond_64
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_95

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    .line 161
    :goto_1e
    invoke-interface {v1, v4}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v31

    .line 162
    const-string v4, "keys"

    .line 163
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 164
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_65

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    goto :goto_1f

    .line 165
    :cond_65
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_66

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_1f

    .line 166
    :cond_66
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_67

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v32

    invoke-static/range {v32 .. v33}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_1f

    .line 167
    :cond_67
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_68

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_1f

    .line 168
    :cond_68
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_69

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v32

    invoke-static/range {v32 .. v33}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_1f

    .line 169
    :cond_69
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_94

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    .line 170
    :goto_1f
    invoke-interface {v1, v4}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    if-eqz v4, :cond_6a

    invoke-static {v4}, Lcom/salesforce/marketingcloud/util/j;->b(Ljava/lang/String;)Ljava/util/Map;

    move-result-object v4

    move-object/from16 v32, v4

    goto :goto_20

    :cond_6a
    move-object/from16 v32, v34

    .line 171
    :goto_20
    const-string v4, "custom"

    .line 172
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 173
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_6b

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    goto :goto_21

    .line 174
    :cond_6b
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_6c

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_21

    .line 175
    :cond_6c
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_6d

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v35

    invoke-static/range {v35 .. v36}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_21

    .line 176
    :cond_6d
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_6e

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_21

    .line 177
    :cond_6e
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_6f

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v35

    invoke-static/range {v35 .. v36}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    goto :goto_21

    .line 178
    :cond_6f
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    invoke-static {v7, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_93

    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    move-result v4

    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    .line 179
    :goto_21
    invoke-interface {v1, v4}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v33

    .line 180
    new-instance v14, Lcom/salesforce/marketingcloud/messages/Message;

    invoke-direct/range {v14 .. v33}, Lcom/salesforce/marketingcloud/messages/Message;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Message$Media;Ljava/util/Date;Ljava/util/Date;IILjava/lang/String;IIIZIILjava/lang/String;Ljava/util/Map;Ljava/lang/String;)V

    .line 181
    const-string v1, "notify_id"

    .line 182
    invoke-interface {v0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    invoke-static {v2}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v4

    .line 183
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_70

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_22

    .line 184
    :cond_70
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_71

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getInt(I)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    goto :goto_22

    .line 185
    :cond_71
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_72

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v15

    invoke-static/range {v15 .. v16}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_22

    .line 186
    :cond_72
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_73

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getFloat(I)F

    move-result v1

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_22

    .line 187
    :cond_73
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_74

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v15

    invoke-static/range {v15 .. v16}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_22

    .line 188
    :cond_74
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_92

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getShort(I)S

    move-result v1

    invoke-static {v1}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    :goto_22
    if-eqz v1, :cond_75

    .line 189
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v5

    .line 190
    :cond_75
    invoke-virtual {v14, v5}, Lcom/salesforce/marketingcloud/messages/Message;->setNotificationId$sdk_release(I)V

    .line 191
    const-string v1, "last_shown_date"

    .line 192
    invoke-interface {v0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v4

    .line 193
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_76

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v1

    goto :goto_23

    .line 194
    :cond_76
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_77

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getInt(I)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    goto :goto_23

    .line 195
    :cond_77
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_78

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    goto :goto_23

    .line 196
    :cond_78
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_79

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getFloat(I)F

    move-result v1

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    goto :goto_23

    .line 197
    :cond_79
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_7a

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    goto :goto_23

    .line 198
    :cond_7a
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_91

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getShort(I)S

    move-result v1

    invoke-static {v1}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    :goto_23
    if-eqz v1, :cond_7b

    .line 199
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v1

    goto :goto_24

    :cond_7b
    move-object/from16 v1, v34

    .line 200
    :goto_24
    invoke-virtual {v14, v1}, Lcom/salesforce/marketingcloud/messages/Message;->setLastShownDate$sdk_release(Ljava/util/Date;)V

    .line 201
    const-string v1, "next_allowed_show"

    .line 202
    invoke-interface {v0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v4

    .line 203
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_7c

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v1

    goto :goto_25

    .line 204
    :cond_7c
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_7d

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getInt(I)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    goto :goto_25

    .line 205
    :cond_7d
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_7e

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    goto :goto_25

    .line 206
    :cond_7e
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_7f

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getFloat(I)F

    move-result v1

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    goto :goto_25

    .line 207
    :cond_7f
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_80

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    goto :goto_25

    .line 208
    :cond_80
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_90

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getShort(I)S

    move-result v1

    invoke-static {v1}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    :goto_25
    if-eqz v1, :cond_81

    .line 209
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v1

    goto :goto_26

    :cond_81
    move-object/from16 v1, v34

    .line 210
    :goto_26
    invoke-virtual {v14, v1}, Lcom/salesforce/marketingcloud/messages/Message;->setNextAllowedShow$sdk_release(Ljava/util/Date;)V

    .line 211
    const-string v1, "period_show_count"

    .line 212
    invoke-interface {v0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    invoke-static {v2}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v4

    .line 213
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_82

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_27

    .line 214
    :cond_82
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_83

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getInt(I)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    goto :goto_27

    .line 215
    :cond_83
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_84

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_27

    .line 216
    :cond_84
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_85

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getFloat(I)F

    move-result v1

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_27

    .line 217
    :cond_85
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_86

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    goto :goto_27

    .line 218
    :cond_86
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_8f

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getShort(I)S

    move-result v1

    invoke-static {v1}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    :goto_27
    if-eqz v1, :cond_87

    .line 219
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v1

    goto :goto_28

    :cond_87
    move v1, v6

    .line 220
    :goto_28
    invoke-virtual {v14, v1}, Lcom/salesforce/marketingcloud/messages/Message;->setPeriodShowCount$sdk_release(I)V

    .line 221
    const-string v1, "show_count"

    .line 222
    invoke-interface {v0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    invoke-static {v2}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v2

    .line 223
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_88

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    goto :goto_29

    .line 224
    :cond_88
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_89

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getInt(I)I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    goto :goto_29

    .line 225
    :cond_89
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_8a

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getDouble(I)D

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    goto :goto_29

    .line 226
    :cond_8a
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_8b

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getFloat(I)F

    move-result v0

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    goto :goto_29

    .line 227
    :cond_8b
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_8c

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    goto :goto_29

    .line 228
    :cond_8c
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_8e

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getShort(I)S

    move-result v0

    invoke-static {v0}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    :goto_29
    if-eqz v0, :cond_8d

    .line 229
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v6

    .line 230
    :cond_8d
    invoke-virtual {v14, v6}, Lcom/salesforce/marketingcloud/messages/Message;->setShowCount$sdk_release(I)V

    return-object v14

    .line 231
    :cond_8e
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 232
    :cond_8f
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 233
    :cond_90
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 234
    :cond_91
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 235
    :cond_92
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 236
    :cond_93
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 237
    :cond_94
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 238
    :cond_95
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 239
    :cond_96
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 240
    :cond_97
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 241
    :cond_98
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 242
    :cond_99
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 243
    :cond_9a
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 244
    :cond_9b
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 245
    :cond_9c
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 246
    :cond_9d
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 247
    :cond_9e
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 248
    :cond_9f
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 249
    :cond_a0
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 250
    :cond_a1
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 251
    :cond_a2
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 252
    :cond_a3
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_a4
    const/16 v34, 0x0

    .line 253
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_a5
    const/16 v34, 0x0

    .line 254
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_a6
    const/16 v34, 0x0

    .line 255
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_a7
    const/16 v34, 0x0

    .line 256
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_a8
    const/16 v34, 0x0

    .line 257
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_a9
    const/16 v34, 0x0

    .line 258
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_aa
    const/16 v34, 0x0

    .line 259
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_1

    :catch_1
    :goto_2a
    return-object v34
.end method

.method public static final b(Landroid/database/Cursor;Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "Range"
        }
    .end annotation

    const-string v0, "cursor"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "columnName"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 260
    invoke-interface {p0, p1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result p1

    invoke-interface {p0, p1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final c(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Region;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-class v2, Ljava/lang/Integer;

    .line 6
    .line 7
    const-class v3, Ljava/lang/String;

    .line 8
    .line 9
    const-string v4, "cursor"

    .line 10
    .line 11
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v4, "crypto"

    .line 15
    .line 16
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    :try_start_0
    new-instance v5, Lcom/salesforce/marketingcloud/messages/Region;

    .line 20
    .line 21
    const-string v4, "id"

    .line 22
    .line 23
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 28
    .line 29
    invoke-virtual {v6, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 30
    .line 31
    .line 32
    move-result-object v7

    .line 33
    invoke-virtual {v6, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 34
    .line 35
    .line 36
    move-result-object v8

    .line 37
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v8
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 41
    const-string v9, "Unsupported type"

    .line 42
    .line 43
    sget-object v10, Ljava/lang/Short;->TYPE:Ljava/lang/Class;

    .line 44
    .line 45
    sget-object v11, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 46
    .line 47
    sget-object v12, Ljava/lang/Float;->TYPE:Ljava/lang/Class;

    .line 48
    .line 49
    sget-object v13, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    .line 50
    .line 51
    sget-object v14, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 52
    .line 53
    if-eqz v8, :cond_0

    .line 54
    .line 55
    :try_start_1
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    goto :goto_0

    .line 60
    :cond_0
    invoke-virtual {v6, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 61
    .line 62
    .line 63
    move-result-object v8

    .line 64
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v8

    .line 68
    if-eqz v8, :cond_1

    .line 69
    .line 70
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    .line 71
    .line 72
    .line 73
    move-result v4

    .line 74
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    check-cast v4, Ljava/lang/String;

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_1
    invoke-virtual {v6, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 82
    .line 83
    .line 84
    move-result-object v8

    .line 85
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v8

    .line 89
    if-eqz v8, :cond_2

    .line 90
    .line 91
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    .line 92
    .line 93
    .line 94
    move-result-wide v7

    .line 95
    invoke-static {v7, v8}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 96
    .line 97
    .line 98
    move-result-object v4

    .line 99
    check-cast v4, Ljava/lang/String;

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_2
    invoke-virtual {v6, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 103
    .line 104
    .line 105
    move-result-object v8

    .line 106
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v8

    .line 110
    if-eqz v8, :cond_3

    .line 111
    .line 112
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    .line 113
    .line 114
    .line 115
    move-result v4

    .line 116
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    check-cast v4, Ljava/lang/String;

    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_3
    invoke-virtual {v6, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 124
    .line 125
    .line 126
    move-result-object v8

    .line 127
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v8

    .line 131
    if-eqz v8, :cond_4

    .line 132
    .line 133
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    .line 134
    .line 135
    .line 136
    move-result-wide v7

    .line 137
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 138
    .line 139
    .line 140
    move-result-object v4

    .line 141
    check-cast v4, Ljava/lang/String;

    .line 142
    .line 143
    goto :goto_0

    .line 144
    :cond_4
    invoke-virtual {v6, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 145
    .line 146
    .line 147
    move-result-object v8

    .line 148
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v7

    .line 152
    if-eqz v7, :cond_4a

    .line 153
    .line 154
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    .line 155
    .line 156
    .line 157
    move-result v4

    .line 158
    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 159
    .line 160
    .line 161
    move-result-object v4

    .line 162
    check-cast v4, Ljava/lang/String;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 163
    .line 164
    :goto_0
    const-string v7, "Required value was null."

    .line 165
    .line 166
    if-eqz v4, :cond_49

    .line 167
    .line 168
    move-object v8, v7

    .line 169
    :try_start_2
    new-instance v7, Lcom/salesforce/marketingcloud/location/LatLon;

    .line 170
    .line 171
    const-string v15, "latitude"

    .line 172
    .line 173
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 174
    .line 175
    .line 176
    move-result v15

    .line 177
    move-object/from16 v16, v4

    .line 178
    .line 179
    invoke-virtual {v6, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 180
    .line 181
    .line 182
    move-result-object v4

    .line 183
    move-object/from16 v17, v5

    .line 184
    .line 185
    invoke-virtual {v6, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 186
    .line 187
    .line 188
    move-result-object v5

    .line 189
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result v5

    .line 193
    if-eqz v5, :cond_5

    .line 194
    .line 195
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object v4

    .line 199
    goto :goto_1

    .line 200
    :cond_5
    invoke-virtual {v6, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 201
    .line 202
    .line 203
    move-result-object v5

    .line 204
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result v5

    .line 208
    if-eqz v5, :cond_6

    .line 209
    .line 210
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getInt(I)I

    .line 211
    .line 212
    .line 213
    move-result v4

    .line 214
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 215
    .line 216
    .line 217
    move-result-object v4

    .line 218
    check-cast v4, Ljava/lang/String;

    .line 219
    .line 220
    goto :goto_1

    .line 221
    :cond_6
    invoke-virtual {v6, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 222
    .line 223
    .line 224
    move-result-object v5

    .line 225
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 226
    .line 227
    .line 228
    move-result v5

    .line 229
    if-eqz v5, :cond_7

    .line 230
    .line 231
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getDouble(I)D

    .line 232
    .line 233
    .line 234
    move-result-wide v4

    .line 235
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 236
    .line 237
    .line 238
    move-result-object v4

    .line 239
    check-cast v4, Ljava/lang/String;

    .line 240
    .line 241
    goto :goto_1

    .line 242
    :cond_7
    invoke-virtual {v6, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 243
    .line 244
    .line 245
    move-result-object v5

    .line 246
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 247
    .line 248
    .line 249
    move-result v5

    .line 250
    if-eqz v5, :cond_8

    .line 251
    .line 252
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getFloat(I)F

    .line 253
    .line 254
    .line 255
    move-result v4

    .line 256
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 257
    .line 258
    .line 259
    move-result-object v4

    .line 260
    check-cast v4, Ljava/lang/String;

    .line 261
    .line 262
    goto :goto_1

    .line 263
    :cond_8
    invoke-virtual {v6, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 264
    .line 265
    .line 266
    move-result-object v5

    .line 267
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 268
    .line 269
    .line 270
    move-result v5

    .line 271
    if-eqz v5, :cond_9

    .line 272
    .line 273
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getLong(I)J

    .line 274
    .line 275
    .line 276
    move-result-wide v4

    .line 277
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 278
    .line 279
    .line 280
    move-result-object v4

    .line 281
    check-cast v4, Ljava/lang/String;

    .line 282
    .line 283
    goto :goto_1

    .line 284
    :cond_9
    invoke-virtual {v6, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 285
    .line 286
    .line 287
    move-result-object v5

    .line 288
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 289
    .line 290
    .line 291
    move-result v4

    .line 292
    if-eqz v4, :cond_48

    .line 293
    .line 294
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getShort(I)S

    .line 295
    .line 296
    .line 297
    move-result v4

    .line 298
    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 299
    .line 300
    .line 301
    move-result-object v4

    .line 302
    check-cast v4, Ljava/lang/String;

    .line 303
    .line 304
    :goto_1
    invoke-interface {v1, v4}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 305
    .line 306
    .line 307
    move-result-object v4

    .line 308
    if-eqz v4, :cond_47

    .line 309
    .line 310
    invoke-static {v4}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 311
    .line 312
    .line 313
    move-result-wide v4

    .line 314
    const-string v15, "longitude"

    .line 315
    .line 316
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 317
    .line 318
    .line 319
    move-result v15

    .line 320
    move-object/from16 v18, v9

    .line 321
    .line 322
    invoke-virtual {v6, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 323
    .line 324
    .line 325
    move-result-object v9

    .line 326
    move-object/from16 v19, v8

    .line 327
    .line 328
    invoke-virtual {v6, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 329
    .line 330
    .line 331
    move-result-object v8

    .line 332
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 333
    .line 334
    .line 335
    move-result v8

    .line 336
    if-eqz v8, :cond_a

    .line 337
    .line 338
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 339
    .line 340
    .line 341
    move-result-object v8

    .line 342
    goto :goto_2

    .line 343
    :cond_a
    invoke-virtual {v6, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 344
    .line 345
    .line 346
    move-result-object v8

    .line 347
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 348
    .line 349
    .line 350
    move-result v8

    .line 351
    if-eqz v8, :cond_b

    .line 352
    .line 353
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getInt(I)I

    .line 354
    .line 355
    .line 356
    move-result v8

    .line 357
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 358
    .line 359
    .line 360
    move-result-object v8

    .line 361
    check-cast v8, Ljava/lang/String;

    .line 362
    .line 363
    goto :goto_2

    .line 364
    :cond_b
    invoke-virtual {v6, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 365
    .line 366
    .line 367
    move-result-object v8

    .line 368
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 369
    .line 370
    .line 371
    move-result v8

    .line 372
    if-eqz v8, :cond_c

    .line 373
    .line 374
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getDouble(I)D

    .line 375
    .line 376
    .line 377
    move-result-wide v8

    .line 378
    invoke-static {v8, v9}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 379
    .line 380
    .line 381
    move-result-object v8

    .line 382
    check-cast v8, Ljava/lang/String;

    .line 383
    .line 384
    goto :goto_2

    .line 385
    :cond_c
    invoke-virtual {v6, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 386
    .line 387
    .line 388
    move-result-object v8

    .line 389
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 390
    .line 391
    .line 392
    move-result v8

    .line 393
    if-eqz v8, :cond_d

    .line 394
    .line 395
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getFloat(I)F

    .line 396
    .line 397
    .line 398
    move-result v8

    .line 399
    invoke-static {v8}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 400
    .line 401
    .line 402
    move-result-object v8

    .line 403
    check-cast v8, Ljava/lang/String;

    .line 404
    .line 405
    goto :goto_2

    .line 406
    :cond_d
    invoke-virtual {v6, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 407
    .line 408
    .line 409
    move-result-object v8

    .line 410
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 411
    .line 412
    .line 413
    move-result v8

    .line 414
    if-eqz v8, :cond_e

    .line 415
    .line 416
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getLong(I)J

    .line 417
    .line 418
    .line 419
    move-result-wide v8

    .line 420
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 421
    .line 422
    .line 423
    move-result-object v8

    .line 424
    check-cast v8, Ljava/lang/String;

    .line 425
    .line 426
    goto :goto_2

    .line 427
    :cond_e
    invoke-virtual {v6, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 428
    .line 429
    .line 430
    move-result-object v8

    .line 431
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 432
    .line 433
    .line 434
    move-result v8

    .line 435
    if-eqz v8, :cond_46

    .line 436
    .line 437
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getShort(I)S

    .line 438
    .line 439
    .line 440
    move-result v8

    .line 441
    invoke-static {v8}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 442
    .line 443
    .line 444
    move-result-object v8

    .line 445
    check-cast v8, Ljava/lang/String;

    .line 446
    .line 447
    :goto_2
    invoke-interface {v1, v8}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 448
    .line 449
    .line 450
    move-result-object v8

    .line 451
    if-eqz v8, :cond_45

    .line 452
    .line 453
    invoke-static {v8}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 454
    .line 455
    .line 456
    move-result-wide v8

    .line 457
    invoke-direct {v7, v4, v5, v8, v9}, Lcom/salesforce/marketingcloud/location/LatLon;-><init>(DD)V

    .line 458
    .line 459
    .line 460
    const-string v4, "radius"

    .line 461
    .line 462
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 463
    .line 464
    .line 465
    move-result v4

    .line 466
    invoke-virtual {v6, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 467
    .line 468
    .line 469
    move-result-object v5

    .line 470
    invoke-virtual {v6, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 471
    .line 472
    .line 473
    move-result-object v8

    .line 474
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 475
    .line 476
    .line 477
    move-result v8

    .line 478
    if-eqz v8, :cond_f

    .line 479
    .line 480
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 481
    .line 482
    .line 483
    move-result-object v4

    .line 484
    check-cast v4, Ljava/lang/Integer;

    .line 485
    .line 486
    goto :goto_3

    .line 487
    :cond_f
    invoke-virtual {v6, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 488
    .line 489
    .line 490
    move-result-object v8

    .line 491
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 492
    .line 493
    .line 494
    move-result v8

    .line 495
    if-eqz v8, :cond_10

    .line 496
    .line 497
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    .line 498
    .line 499
    .line 500
    move-result v4

    .line 501
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 502
    .line 503
    .line 504
    move-result-object v4

    .line 505
    goto :goto_3

    .line 506
    :cond_10
    invoke-virtual {v6, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 507
    .line 508
    .line 509
    move-result-object v8

    .line 510
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 511
    .line 512
    .line 513
    move-result v8

    .line 514
    if-eqz v8, :cond_11

    .line 515
    .line 516
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    .line 517
    .line 518
    .line 519
    move-result-wide v4

    .line 520
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 521
    .line 522
    .line 523
    move-result-object v4

    .line 524
    check-cast v4, Ljava/lang/Integer;

    .line 525
    .line 526
    goto :goto_3

    .line 527
    :cond_11
    invoke-virtual {v6, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 528
    .line 529
    .line 530
    move-result-object v8

    .line 531
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 532
    .line 533
    .line 534
    move-result v8

    .line 535
    if-eqz v8, :cond_12

    .line 536
    .line 537
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    .line 538
    .line 539
    .line 540
    move-result v4

    .line 541
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 542
    .line 543
    .line 544
    move-result-object v4

    .line 545
    check-cast v4, Ljava/lang/Integer;

    .line 546
    .line 547
    goto :goto_3

    .line 548
    :cond_12
    invoke-virtual {v6, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 549
    .line 550
    .line 551
    move-result-object v8

    .line 552
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 553
    .line 554
    .line 555
    move-result v8

    .line 556
    if-eqz v8, :cond_13

    .line 557
    .line 558
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    .line 559
    .line 560
    .line 561
    move-result-wide v4

    .line 562
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 563
    .line 564
    .line 565
    move-result-object v4

    .line 566
    check-cast v4, Ljava/lang/Integer;

    .line 567
    .line 568
    goto :goto_3

    .line 569
    :cond_13
    invoke-virtual {v6, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 570
    .line 571
    .line 572
    move-result-object v8

    .line 573
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 574
    .line 575
    .line 576
    move-result v5

    .line 577
    if-eqz v5, :cond_44

    .line 578
    .line 579
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    .line 580
    .line 581
    .line 582
    move-result v4

    .line 583
    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 584
    .line 585
    .line 586
    move-result-object v4

    .line 587
    check-cast v4, Ljava/lang/Integer;

    .line 588
    .line 589
    :goto_3
    if-eqz v4, :cond_43

    .line 590
    .line 591
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 592
    .line 593
    .line 594
    move-result v8

    .line 595
    const-string v4, "beacon_guid"

    .line 596
    .line 597
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 598
    .line 599
    .line 600
    move-result v4

    .line 601
    invoke-virtual {v6, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 602
    .line 603
    .line 604
    move-result-object v5

    .line 605
    invoke-virtual {v6, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 606
    .line 607
    .line 608
    move-result-object v9

    .line 609
    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 610
    .line 611
    .line 612
    move-result v9

    .line 613
    if-eqz v9, :cond_14

    .line 614
    .line 615
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 616
    .line 617
    .line 618
    move-result-object v4

    .line 619
    goto :goto_4

    .line 620
    :cond_14
    invoke-virtual {v6, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 621
    .line 622
    .line 623
    move-result-object v9

    .line 624
    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 625
    .line 626
    .line 627
    move-result v9

    .line 628
    if-eqz v9, :cond_15

    .line 629
    .line 630
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    .line 631
    .line 632
    .line 633
    move-result v4

    .line 634
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 635
    .line 636
    .line 637
    move-result-object v4

    .line 638
    check-cast v4, Ljava/lang/String;

    .line 639
    .line 640
    goto :goto_4

    .line 641
    :cond_15
    invoke-virtual {v6, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 642
    .line 643
    .line 644
    move-result-object v9

    .line 645
    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 646
    .line 647
    .line 648
    move-result v9

    .line 649
    if-eqz v9, :cond_16

    .line 650
    .line 651
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    .line 652
    .line 653
    .line 654
    move-result-wide v4

    .line 655
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 656
    .line 657
    .line 658
    move-result-object v4

    .line 659
    check-cast v4, Ljava/lang/String;

    .line 660
    .line 661
    goto :goto_4

    .line 662
    :cond_16
    invoke-virtual {v6, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 663
    .line 664
    .line 665
    move-result-object v9

    .line 666
    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 667
    .line 668
    .line 669
    move-result v9

    .line 670
    if-eqz v9, :cond_17

    .line 671
    .line 672
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    .line 673
    .line 674
    .line 675
    move-result v4

    .line 676
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 677
    .line 678
    .line 679
    move-result-object v4

    .line 680
    check-cast v4, Ljava/lang/String;

    .line 681
    .line 682
    goto :goto_4

    .line 683
    :cond_17
    invoke-virtual {v6, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 684
    .line 685
    .line 686
    move-result-object v9

    .line 687
    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 688
    .line 689
    .line 690
    move-result v9

    .line 691
    if-eqz v9, :cond_18

    .line 692
    .line 693
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    .line 694
    .line 695
    .line 696
    move-result-wide v4

    .line 697
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 698
    .line 699
    .line 700
    move-result-object v4

    .line 701
    check-cast v4, Ljava/lang/String;

    .line 702
    .line 703
    goto :goto_4

    .line 704
    :cond_18
    invoke-virtual {v6, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 705
    .line 706
    .line 707
    move-result-object v9

    .line 708
    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 709
    .line 710
    .line 711
    move-result v5

    .line 712
    if-eqz v5, :cond_42

    .line 713
    .line 714
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    .line 715
    .line 716
    .line 717
    move-result v4

    .line 718
    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 719
    .line 720
    .line 721
    move-result-object v4

    .line 722
    check-cast v4, Ljava/lang/String;

    .line 723
    .line 724
    :goto_4
    invoke-interface {v1, v4}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 725
    .line 726
    .line 727
    move-result-object v9

    .line 728
    const-string v4, "beacon_major"

    .line 729
    .line 730
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 731
    .line 732
    .line 733
    move-result v4

    .line 734
    invoke-virtual {v6, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 735
    .line 736
    .line 737
    move-result-object v5

    .line 738
    invoke-virtual {v6, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 739
    .line 740
    .line 741
    move-result-object v15

    .line 742
    invoke-static {v5, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 743
    .line 744
    .line 745
    move-result v15

    .line 746
    if-eqz v15, :cond_19

    .line 747
    .line 748
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 749
    .line 750
    .line 751
    move-result-object v4

    .line 752
    check-cast v4, Ljava/lang/Integer;

    .line 753
    .line 754
    goto :goto_5

    .line 755
    :cond_19
    invoke-virtual {v6, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 756
    .line 757
    .line 758
    move-result-object v15

    .line 759
    invoke-static {v5, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 760
    .line 761
    .line 762
    move-result v15

    .line 763
    if-eqz v15, :cond_1a

    .line 764
    .line 765
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getInt(I)I

    .line 766
    .line 767
    .line 768
    move-result v4

    .line 769
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 770
    .line 771
    .line 772
    move-result-object v4

    .line 773
    goto :goto_5

    .line 774
    :cond_1a
    invoke-virtual {v6, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 775
    .line 776
    .line 777
    move-result-object v15

    .line 778
    invoke-static {v5, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 779
    .line 780
    .line 781
    move-result v15

    .line 782
    if-eqz v15, :cond_1b

    .line 783
    .line 784
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getDouble(I)D

    .line 785
    .line 786
    .line 787
    move-result-wide v4

    .line 788
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 789
    .line 790
    .line 791
    move-result-object v4

    .line 792
    check-cast v4, Ljava/lang/Integer;

    .line 793
    .line 794
    goto :goto_5

    .line 795
    :cond_1b
    invoke-virtual {v6, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 796
    .line 797
    .line 798
    move-result-object v15

    .line 799
    invoke-static {v5, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 800
    .line 801
    .line 802
    move-result v15

    .line 803
    if-eqz v15, :cond_1c

    .line 804
    .line 805
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getFloat(I)F

    .line 806
    .line 807
    .line 808
    move-result v4

    .line 809
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 810
    .line 811
    .line 812
    move-result-object v4

    .line 813
    check-cast v4, Ljava/lang/Integer;

    .line 814
    .line 815
    goto :goto_5

    .line 816
    :cond_1c
    invoke-virtual {v6, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 817
    .line 818
    .line 819
    move-result-object v15

    .line 820
    invoke-static {v5, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 821
    .line 822
    .line 823
    move-result v15

    .line 824
    if-eqz v15, :cond_1d

    .line 825
    .line 826
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getLong(I)J

    .line 827
    .line 828
    .line 829
    move-result-wide v4

    .line 830
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 831
    .line 832
    .line 833
    move-result-object v4

    .line 834
    check-cast v4, Ljava/lang/Integer;

    .line 835
    .line 836
    goto :goto_5

    .line 837
    :cond_1d
    invoke-virtual {v6, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 838
    .line 839
    .line 840
    move-result-object v15

    .line 841
    invoke-static {v5, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 842
    .line 843
    .line 844
    move-result v5

    .line 845
    if-eqz v5, :cond_41

    .line 846
    .line 847
    invoke-interface {v0, v4}, Landroid/database/Cursor;->getShort(I)S

    .line 848
    .line 849
    .line 850
    move-result v4

    .line 851
    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 852
    .line 853
    .line 854
    move-result-object v4

    .line 855
    check-cast v4, Ljava/lang/Integer;

    .line 856
    .line 857
    :goto_5
    const/16 v20, 0x0

    .line 858
    .line 859
    if-eqz v4, :cond_1e

    .line 860
    .line 861
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 862
    .line 863
    .line 864
    move-result v4

    .line 865
    goto :goto_6

    .line 866
    :cond_1e
    move/from16 v4, v20

    .line 867
    .line 868
    :goto_6
    const-string v5, "beacon_minor"

    .line 869
    .line 870
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 871
    .line 872
    .line 873
    move-result v5

    .line 874
    invoke-virtual {v6, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 875
    .line 876
    .line 877
    move-result-object v15

    .line 878
    move/from16 v21, v4

    .line 879
    .line 880
    invoke-virtual {v6, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 881
    .line 882
    .line 883
    move-result-object v4

    .line 884
    invoke-static {v15, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 885
    .line 886
    .line 887
    move-result v4

    .line 888
    if-eqz v4, :cond_1f

    .line 889
    .line 890
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 891
    .line 892
    .line 893
    move-result-object v4

    .line 894
    check-cast v4, Ljava/lang/Integer;

    .line 895
    .line 896
    goto :goto_7

    .line 897
    :cond_1f
    invoke-virtual {v6, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 898
    .line 899
    .line 900
    move-result-object v4

    .line 901
    invoke-static {v15, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 902
    .line 903
    .line 904
    move-result v4

    .line 905
    if-eqz v4, :cond_20

    .line 906
    .line 907
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getInt(I)I

    .line 908
    .line 909
    .line 910
    move-result v4

    .line 911
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 912
    .line 913
    .line 914
    move-result-object v4

    .line 915
    goto :goto_7

    .line 916
    :cond_20
    invoke-virtual {v6, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 917
    .line 918
    .line 919
    move-result-object v4

    .line 920
    invoke-static {v15, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 921
    .line 922
    .line 923
    move-result v4

    .line 924
    if-eqz v4, :cond_21

    .line 925
    .line 926
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getDouble(I)D

    .line 927
    .line 928
    .line 929
    move-result-wide v4

    .line 930
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 931
    .line 932
    .line 933
    move-result-object v4

    .line 934
    check-cast v4, Ljava/lang/Integer;

    .line 935
    .line 936
    goto :goto_7

    .line 937
    :cond_21
    invoke-virtual {v6, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 938
    .line 939
    .line 940
    move-result-object v4

    .line 941
    invoke-static {v15, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 942
    .line 943
    .line 944
    move-result v4

    .line 945
    if-eqz v4, :cond_22

    .line 946
    .line 947
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getFloat(I)F

    .line 948
    .line 949
    .line 950
    move-result v4

    .line 951
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 952
    .line 953
    .line 954
    move-result-object v4

    .line 955
    check-cast v4, Ljava/lang/Integer;

    .line 956
    .line 957
    goto :goto_7

    .line 958
    :cond_22
    invoke-virtual {v6, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 959
    .line 960
    .line 961
    move-result-object v4

    .line 962
    invoke-static {v15, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 963
    .line 964
    .line 965
    move-result v4

    .line 966
    if-eqz v4, :cond_23

    .line 967
    .line 968
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getLong(I)J

    .line 969
    .line 970
    .line 971
    move-result-wide v4

    .line 972
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 973
    .line 974
    .line 975
    move-result-object v4

    .line 976
    check-cast v4, Ljava/lang/Integer;

    .line 977
    .line 978
    goto :goto_7

    .line 979
    :cond_23
    invoke-virtual {v6, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 980
    .line 981
    .line 982
    move-result-object v4

    .line 983
    invoke-static {v15, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 984
    .line 985
    .line 986
    move-result v4

    .line 987
    if-eqz v4, :cond_40

    .line 988
    .line 989
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getShort(I)S

    .line 990
    .line 991
    .line 992
    move-result v4

    .line 993
    invoke-static {v4}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 994
    .line 995
    .line 996
    move-result-object v4

    .line 997
    check-cast v4, Ljava/lang/Integer;

    .line 998
    .line 999
    :goto_7
    if-eqz v4, :cond_24

    .line 1000
    .line 1001
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 1002
    .line 1003
    .line 1004
    move-result v4

    .line 1005
    goto :goto_8

    .line 1006
    :cond_24
    move/from16 v4, v20

    .line 1007
    .line 1008
    :goto_8
    const-string v5, "location_type"

    .line 1009
    .line 1010
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 1011
    .line 1012
    .line 1013
    move-result v5

    .line 1014
    invoke-virtual {v6, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1015
    .line 1016
    .line 1017
    move-result-object v15

    .line 1018
    move-object/from16 v22, v2

    .line 1019
    .line 1020
    invoke-virtual {v6, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1021
    .line 1022
    .line 1023
    move-result-object v2

    .line 1024
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1025
    .line 1026
    .line 1027
    move-result v2

    .line 1028
    if-eqz v2, :cond_25

    .line 1029
    .line 1030
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 1031
    .line 1032
    .line 1033
    move-result-object v2

    .line 1034
    check-cast v2, Ljava/lang/Integer;

    .line 1035
    .line 1036
    goto :goto_9

    .line 1037
    :cond_25
    invoke-virtual {v6, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1038
    .line 1039
    .line 1040
    move-result-object v2

    .line 1041
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1042
    .line 1043
    .line 1044
    move-result v2

    .line 1045
    if-eqz v2, :cond_26

    .line 1046
    .line 1047
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getInt(I)I

    .line 1048
    .line 1049
    .line 1050
    move-result v2

    .line 1051
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1052
    .line 1053
    .line 1054
    move-result-object v2

    .line 1055
    goto :goto_9

    .line 1056
    :cond_26
    invoke-virtual {v6, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1057
    .line 1058
    .line 1059
    move-result-object v2

    .line 1060
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1061
    .line 1062
    .line 1063
    move-result v2

    .line 1064
    if-eqz v2, :cond_27

    .line 1065
    .line 1066
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getDouble(I)D

    .line 1067
    .line 1068
    .line 1069
    move-result-wide v5

    .line 1070
    invoke-static {v5, v6}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1071
    .line 1072
    .line 1073
    move-result-object v2

    .line 1074
    check-cast v2, Ljava/lang/Integer;

    .line 1075
    .line 1076
    goto :goto_9

    .line 1077
    :cond_27
    invoke-virtual {v6, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1078
    .line 1079
    .line 1080
    move-result-object v2

    .line 1081
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1082
    .line 1083
    .line 1084
    move-result v2

    .line 1085
    if-eqz v2, :cond_28

    .line 1086
    .line 1087
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getFloat(I)F

    .line 1088
    .line 1089
    .line 1090
    move-result v2

    .line 1091
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1092
    .line 1093
    .line 1094
    move-result-object v2

    .line 1095
    check-cast v2, Ljava/lang/Integer;

    .line 1096
    .line 1097
    goto :goto_9

    .line 1098
    :cond_28
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1099
    .line 1100
    .line 1101
    move-result-object v2

    .line 1102
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1103
    .line 1104
    .line 1105
    move-result v2

    .line 1106
    if-eqz v2, :cond_29

    .line 1107
    .line 1108
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getLong(I)J

    .line 1109
    .line 1110
    .line 1111
    move-result-wide v5

    .line 1112
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1113
    .line 1114
    .line 1115
    move-result-object v2

    .line 1116
    check-cast v2, Ljava/lang/Integer;

    .line 1117
    .line 1118
    goto :goto_9

    .line 1119
    :cond_29
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1120
    .line 1121
    .line 1122
    move-result-object v2

    .line 1123
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1124
    .line 1125
    .line 1126
    move-result v2

    .line 1127
    if-eqz v2, :cond_3f

    .line 1128
    .line 1129
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getShort(I)S

    .line 1130
    .line 1131
    .line 1132
    move-result v2

    .line 1133
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 1134
    .line 1135
    .line 1136
    move-result-object v2

    .line 1137
    check-cast v2, Ljava/lang/Integer;

    .line 1138
    .line 1139
    :goto_9
    if-eqz v2, :cond_3e

    .line 1140
    .line 1141
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1142
    .line 1143
    .line 1144
    move-result v2

    .line 1145
    const-string v5, "name"

    .line 1146
    .line 1147
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 1148
    .line 1149
    .line 1150
    move-result v5

    .line 1151
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1152
    .line 1153
    .line 1154
    move-result-object v6

    .line 1155
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1156
    .line 1157
    .line 1158
    move-result-object v15

    .line 1159
    invoke-static {v6, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1160
    .line 1161
    .line 1162
    move-result v15

    .line 1163
    if-eqz v15, :cond_2a

    .line 1164
    .line 1165
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 1166
    .line 1167
    .line 1168
    move-result-object v5

    .line 1169
    goto :goto_a

    .line 1170
    :cond_2a
    invoke-static {v14}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1171
    .line 1172
    .line 1173
    move-result-object v15

    .line 1174
    invoke-static {v6, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1175
    .line 1176
    .line 1177
    move-result v15

    .line 1178
    if-eqz v15, :cond_2b

    .line 1179
    .line 1180
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getInt(I)I

    .line 1181
    .line 1182
    .line 1183
    move-result v5

    .line 1184
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1185
    .line 1186
    .line 1187
    move-result-object v5

    .line 1188
    check-cast v5, Ljava/lang/String;

    .line 1189
    .line 1190
    goto :goto_a

    .line 1191
    :cond_2b
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1192
    .line 1193
    .line 1194
    move-result-object v15

    .line 1195
    invoke-static {v6, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1196
    .line 1197
    .line 1198
    move-result v15

    .line 1199
    if-eqz v15, :cond_2c

    .line 1200
    .line 1201
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getDouble(I)D

    .line 1202
    .line 1203
    .line 1204
    move-result-wide v5

    .line 1205
    invoke-static {v5, v6}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1206
    .line 1207
    .line 1208
    move-result-object v5

    .line 1209
    check-cast v5, Ljava/lang/String;

    .line 1210
    .line 1211
    goto :goto_a

    .line 1212
    :cond_2c
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1213
    .line 1214
    .line 1215
    move-result-object v15

    .line 1216
    invoke-static {v6, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1217
    .line 1218
    .line 1219
    move-result v15

    .line 1220
    if-eqz v15, :cond_2d

    .line 1221
    .line 1222
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getFloat(I)F

    .line 1223
    .line 1224
    .line 1225
    move-result v5

    .line 1226
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1227
    .line 1228
    .line 1229
    move-result-object v5

    .line 1230
    check-cast v5, Ljava/lang/String;

    .line 1231
    .line 1232
    goto :goto_a

    .line 1233
    :cond_2d
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1234
    .line 1235
    .line 1236
    move-result-object v15

    .line 1237
    invoke-static {v6, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1238
    .line 1239
    .line 1240
    move-result v15

    .line 1241
    if-eqz v15, :cond_2e

    .line 1242
    .line 1243
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getLong(I)J

    .line 1244
    .line 1245
    .line 1246
    move-result-wide v5

    .line 1247
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1248
    .line 1249
    .line 1250
    move-result-object v5

    .line 1251
    check-cast v5, Ljava/lang/String;

    .line 1252
    .line 1253
    goto :goto_a

    .line 1254
    :cond_2e
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1255
    .line 1256
    .line 1257
    move-result-object v15

    .line 1258
    invoke-static {v6, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1259
    .line 1260
    .line 1261
    move-result v6

    .line 1262
    if-eqz v6, :cond_3d

    .line 1263
    .line 1264
    invoke-interface {v0, v5}, Landroid/database/Cursor;->getShort(I)S

    .line 1265
    .line 1266
    .line 1267
    move-result v5

    .line 1268
    invoke-static {v5}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 1269
    .line 1270
    .line 1271
    move-result-object v5

    .line 1272
    check-cast v5, Ljava/lang/String;

    .line 1273
    .line 1274
    :goto_a
    invoke-interface {v1, v5}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 1275
    .line 1276
    .line 1277
    move-result-object v5

    .line 1278
    const-string v6, "description"

    .line 1279
    .line 1280
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 1281
    .line 1282
    .line 1283
    move-result v6

    .line 1284
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1285
    .line 1286
    .line 1287
    move-result-object v15

    .line 1288
    move/from16 v19, v2

    .line 1289
    .line 1290
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1291
    .line 1292
    .line 1293
    move-result-object v2

    .line 1294
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1295
    .line 1296
    .line 1297
    move-result v2

    .line 1298
    if-eqz v2, :cond_2f

    .line 1299
    .line 1300
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 1301
    .line 1302
    .line 1303
    move-result-object v2

    .line 1304
    goto :goto_b

    .line 1305
    :cond_2f
    invoke-static {v14}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1306
    .line 1307
    .line 1308
    move-result-object v2

    .line 1309
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1310
    .line 1311
    .line 1312
    move-result v2

    .line 1313
    if-eqz v2, :cond_30

    .line 1314
    .line 1315
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getInt(I)I

    .line 1316
    .line 1317
    .line 1318
    move-result v2

    .line 1319
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1320
    .line 1321
    .line 1322
    move-result-object v2

    .line 1323
    check-cast v2, Ljava/lang/String;

    .line 1324
    .line 1325
    goto :goto_b

    .line 1326
    :cond_30
    invoke-static {v13}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1327
    .line 1328
    .line 1329
    move-result-object v2

    .line 1330
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1331
    .line 1332
    .line 1333
    move-result v2

    .line 1334
    if-eqz v2, :cond_31

    .line 1335
    .line 1336
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getDouble(I)D

    .line 1337
    .line 1338
    .line 1339
    move-result-wide v23

    .line 1340
    invoke-static/range {v23 .. v24}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1341
    .line 1342
    .line 1343
    move-result-object v2

    .line 1344
    check-cast v2, Ljava/lang/String;

    .line 1345
    .line 1346
    goto :goto_b

    .line 1347
    :cond_31
    invoke-static {v12}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1348
    .line 1349
    .line 1350
    move-result-object v2

    .line 1351
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1352
    .line 1353
    .line 1354
    move-result v2

    .line 1355
    if-eqz v2, :cond_32

    .line 1356
    .line 1357
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getFloat(I)F

    .line 1358
    .line 1359
    .line 1360
    move-result v2

    .line 1361
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1362
    .line 1363
    .line 1364
    move-result-object v2

    .line 1365
    check-cast v2, Ljava/lang/String;

    .line 1366
    .line 1367
    goto :goto_b

    .line 1368
    :cond_32
    invoke-static {v11}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1369
    .line 1370
    .line 1371
    move-result-object v2

    .line 1372
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1373
    .line 1374
    .line 1375
    move-result v2

    .line 1376
    if-eqz v2, :cond_33

    .line 1377
    .line 1378
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getLong(I)J

    .line 1379
    .line 1380
    .line 1381
    move-result-wide v23

    .line 1382
    invoke-static/range {v23 .. v24}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1383
    .line 1384
    .line 1385
    move-result-object v2

    .line 1386
    check-cast v2, Ljava/lang/String;

    .line 1387
    .line 1388
    goto :goto_b

    .line 1389
    :cond_33
    invoke-static {v10}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1390
    .line 1391
    .line 1392
    move-result-object v2

    .line 1393
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1394
    .line 1395
    .line 1396
    move-result v2

    .line 1397
    if-eqz v2, :cond_3c

    .line 1398
    .line 1399
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getShort(I)S

    .line 1400
    .line 1401
    .line 1402
    move-result v2

    .line 1403
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 1404
    .line 1405
    .line 1406
    move-result-object v2

    .line 1407
    check-cast v2, Ljava/lang/String;

    .line 1408
    .line 1409
    :goto_b
    invoke-interface {v1, v2}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 1410
    .line 1411
    .line 1412
    move-result-object v1

    .line 1413
    move-object/from16 v6, v16

    .line 1414
    .line 1415
    const/16 v16, 0x200

    .line 1416
    .line 1417
    move-object v2, v13

    .line 1418
    move-object v13, v5

    .line 1419
    move-object/from16 v5, v17

    .line 1420
    .line 1421
    const/16 v17, 0x0

    .line 1422
    .line 1423
    const/4 v15, 0x0

    .line 1424
    move-object/from16 v25, v14

    .line 1425
    .line 1426
    move-object v14, v1

    .line 1427
    move-object/from16 v1, v18

    .line 1428
    .line 1429
    move-object/from16 v18, v12

    .line 1430
    .line 1431
    move/from16 v12, v19

    .line 1432
    .line 1433
    move-object/from16 v19, v2

    .line 1434
    .line 1435
    move-object v2, v10

    .line 1436
    move/from16 v10, v21

    .line 1437
    .line 1438
    move-object/from16 v21, v25

    .line 1439
    .line 1440
    move-object/from16 v25, v11

    .line 1441
    .line 1442
    move v11, v4

    .line 1443
    move-object/from16 v4, v25

    .line 1444
    .line 1445
    invoke-direct/range {v5 .. v17}, Lcom/salesforce/marketingcloud/messages/Region;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;ILjava/lang/String;IIILjava/lang/String;Ljava/lang/String;Ljava/util/List;ILkotlin/jvm/internal/g;)V

    .line 1446
    .line 1447
    .line 1448
    const-string v6, "is_inside"

    .line 1449
    .line 1450
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 1451
    .line 1452
    .line 1453
    move-result v6

    .line 1454
    invoke-static/range {v22 .. v22}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1455
    .line 1456
    .line 1457
    move-result-object v7

    .line 1458
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1459
    .line 1460
    .line 1461
    move-result-object v3

    .line 1462
    invoke-static {v7, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1463
    .line 1464
    .line 1465
    move-result v3

    .line 1466
    if-eqz v3, :cond_34

    .line 1467
    .line 1468
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 1469
    .line 1470
    .line 1471
    move-result-object v0

    .line 1472
    check-cast v0, Ljava/lang/Integer;

    .line 1473
    .line 1474
    goto :goto_c

    .line 1475
    :cond_34
    invoke-static/range {v21 .. v21}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1476
    .line 1477
    .line 1478
    move-result-object v3

    .line 1479
    invoke-static {v7, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1480
    .line 1481
    .line 1482
    move-result v3

    .line 1483
    if-eqz v3, :cond_35

    .line 1484
    .line 1485
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getInt(I)I

    .line 1486
    .line 1487
    .line 1488
    move-result v0

    .line 1489
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1490
    .line 1491
    .line 1492
    move-result-object v0

    .line 1493
    goto :goto_c

    .line 1494
    :cond_35
    invoke-static/range {v19 .. v19}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1495
    .line 1496
    .line 1497
    move-result-object v3

    .line 1498
    invoke-static {v7, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1499
    .line 1500
    .line 1501
    move-result v3

    .line 1502
    if-eqz v3, :cond_36

    .line 1503
    .line 1504
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getDouble(I)D

    .line 1505
    .line 1506
    .line 1507
    move-result-wide v0

    .line 1508
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1509
    .line 1510
    .line 1511
    move-result-object v0

    .line 1512
    check-cast v0, Ljava/lang/Integer;

    .line 1513
    .line 1514
    goto :goto_c

    .line 1515
    :cond_36
    invoke-static/range {v18 .. v18}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1516
    .line 1517
    .line 1518
    move-result-object v3

    .line 1519
    invoke-static {v7, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1520
    .line 1521
    .line 1522
    move-result v3

    .line 1523
    if-eqz v3, :cond_37

    .line 1524
    .line 1525
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getFloat(I)F

    .line 1526
    .line 1527
    .line 1528
    move-result v0

    .line 1529
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1530
    .line 1531
    .line 1532
    move-result-object v0

    .line 1533
    check-cast v0, Ljava/lang/Integer;

    .line 1534
    .line 1535
    goto :goto_c

    .line 1536
    :cond_37
    invoke-static {v4}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1537
    .line 1538
    .line 1539
    move-result-object v3

    .line 1540
    invoke-static {v7, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1541
    .line 1542
    .line 1543
    move-result v3

    .line 1544
    if-eqz v3, :cond_38

    .line 1545
    .line 1546
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getLong(I)J

    .line 1547
    .line 1548
    .line 1549
    move-result-wide v0

    .line 1550
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1551
    .line 1552
    .line 1553
    move-result-object v0

    .line 1554
    check-cast v0, Ljava/lang/Integer;

    .line 1555
    .line 1556
    goto :goto_c

    .line 1557
    :cond_38
    invoke-static {v2}, Lkotlin/jvm/internal/g0;->a(Ljava/lang/Class;)Lhy0/d;

    .line 1558
    .line 1559
    .line 1560
    move-result-object v2

    .line 1561
    invoke-static {v7, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1562
    .line 1563
    .line 1564
    move-result v2

    .line 1565
    if-eqz v2, :cond_3b

    .line 1566
    .line 1567
    invoke-interface {v0, v6}, Landroid/database/Cursor;->getShort(I)S

    .line 1568
    .line 1569
    .line 1570
    move-result v0

    .line 1571
    invoke-static {v0}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 1572
    .line 1573
    .line 1574
    move-result-object v0

    .line 1575
    check-cast v0, Ljava/lang/Integer;

    .line 1576
    .line 1577
    :goto_c
    if-nez v0, :cond_39

    .line 1578
    .line 1579
    goto :goto_d

    .line 1580
    :cond_39
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 1581
    .line 1582
    .line 1583
    move-result v0

    .line 1584
    const/4 v1, 0x1

    .line 1585
    if-ne v0, v1, :cond_3a

    .line 1586
    .line 1587
    goto :goto_e

    .line 1588
    :cond_3a
    :goto_d
    move/from16 v1, v20

    .line 1589
    .line 1590
    :goto_e
    invoke-virtual {v5, v1}, Lcom/salesforce/marketingcloud/messages/Region;->setInside$sdk_release(Z)V

    .line 1591
    .line 1592
    .line 1593
    return-object v5

    .line 1594
    :cond_3b
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 1595
    .line 1596
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 1597
    .line 1598
    .line 1599
    throw v0

    .line 1600
    :cond_3c
    move-object/from16 v1, v18

    .line 1601
    .line 1602
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 1603
    .line 1604
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 1605
    .line 1606
    .line 1607
    throw v0

    .line 1608
    :cond_3d
    move-object/from16 v1, v18

    .line 1609
    .line 1610
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 1611
    .line 1612
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 1613
    .line 1614
    .line 1615
    throw v0

    .line 1616
    :cond_3e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1617
    .line 1618
    move-object/from16 v8, v19

    .line 1619
    .line 1620
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1621
    .line 1622
    .line 1623
    throw v0

    .line 1624
    :cond_3f
    move-object/from16 v1, v18

    .line 1625
    .line 1626
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 1627
    .line 1628
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 1629
    .line 1630
    .line 1631
    throw v0

    .line 1632
    :cond_40
    move-object/from16 v1, v18

    .line 1633
    .line 1634
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 1635
    .line 1636
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 1637
    .line 1638
    .line 1639
    throw v0

    .line 1640
    :cond_41
    move-object/from16 v1, v18

    .line 1641
    .line 1642
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 1643
    .line 1644
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 1645
    .line 1646
    .line 1647
    throw v0

    .line 1648
    :cond_42
    move-object/from16 v1, v18

    .line 1649
    .line 1650
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 1651
    .line 1652
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 1653
    .line 1654
    .line 1655
    throw v0

    .line 1656
    :cond_43
    move-object/from16 v8, v19

    .line 1657
    .line 1658
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1659
    .line 1660
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1661
    .line 1662
    .line 1663
    throw v0

    .line 1664
    :cond_44
    move-object/from16 v1, v18

    .line 1665
    .line 1666
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 1667
    .line 1668
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 1669
    .line 1670
    .line 1671
    throw v0

    .line 1672
    :cond_45
    move-object/from16 v8, v19

    .line 1673
    .line 1674
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1675
    .line 1676
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1677
    .line 1678
    .line 1679
    throw v0

    .line 1680
    :cond_46
    move-object/from16 v1, v18

    .line 1681
    .line 1682
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 1683
    .line 1684
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 1685
    .line 1686
    .line 1687
    throw v0

    .line 1688
    :cond_47
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1689
    .line 1690
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1691
    .line 1692
    .line 1693
    throw v0

    .line 1694
    :cond_48
    move-object v1, v9

    .line 1695
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 1696
    .line 1697
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 1698
    .line 1699
    .line 1700
    throw v0

    .line 1701
    :cond_49
    move-object v8, v7

    .line 1702
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1703
    .line 1704
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1705
    .line 1706
    .line 1707
    throw v0

    .line 1708
    :cond_4a
    move-object v1, v9

    .line 1709
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 1710
    .line 1711
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 1712
    .line 1713
    .line 1714
    throw v0
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 1715
    :catch_0
    move-exception v0

    .line 1716
    sget-object v1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 1717
    .line 1718
    sget-object v2, Lcom/salesforce/marketingcloud/storage/db/j;->g:Ljava/lang/String;

    .line 1719
    .line 1720
    const-string v3, "TAG"

    .line 1721
    .line 1722
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1723
    .line 1724
    .line 1725
    sget-object v3, Lcom/salesforce/marketingcloud/storage/db/d$b;->b:Lcom/salesforce/marketingcloud/storage/db/d$b;

    .line 1726
    .line 1727
    invoke-virtual {v1, v2, v0, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 1728
    .line 1729
    .line 1730
    const/4 v0, 0x0

    .line 1731
    return-object v0
.end method

.method public static final d(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/registration/Registration;
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "cursor"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "crypto"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v3, Lcom/salesforce/marketingcloud/registration/Registration;

    .line 16
    .line 17
    const-string v2, "id"

    .line 18
    .line 19
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 24
    .line 25
    const-class v5, Ljava/lang/Integer;

    .line 26
    .line 27
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 28
    .line 29
    .line 30
    move-result-object v6

    .line 31
    const-class v7, Ljava/lang/String;

    .line 32
    .line 33
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 34
    .line 35
    .line 36
    move-result-object v8

    .line 37
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v8

    .line 41
    const-string v9, "Unsupported type"

    .line 42
    .line 43
    sget-object v10, Ljava/lang/Short;->TYPE:Ljava/lang/Class;

    .line 44
    .line 45
    sget-object v11, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 46
    .line 47
    sget-object v12, Ljava/lang/Float;->TYPE:Ljava/lang/Class;

    .line 48
    .line 49
    sget-object v13, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    .line 50
    .line 51
    sget-object v14, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 52
    .line 53
    if-eqz v8, :cond_0

    .line 54
    .line 55
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    check-cast v2, Ljava/lang/Integer;

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 63
    .line 64
    .line 65
    move-result-object v8

    .line 66
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v8

    .line 70
    if-eqz v8, :cond_1

    .line 71
    .line 72
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getInt(I)I

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    goto :goto_0

    .line 81
    :cond_1
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 82
    .line 83
    .line 84
    move-result-object v8

    .line 85
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v8

    .line 89
    if-eqz v8, :cond_2

    .line 90
    .line 91
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getDouble(I)D

    .line 92
    .line 93
    .line 94
    move-result-wide v15

    .line 95
    invoke-static/range {v15 .. v16}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    check-cast v2, Ljava/lang/Integer;

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_2
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 103
    .line 104
    .line 105
    move-result-object v8

    .line 106
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v8

    .line 110
    if-eqz v8, :cond_3

    .line 111
    .line 112
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getFloat(I)F

    .line 113
    .line 114
    .line 115
    move-result v2

    .line 116
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    check-cast v2, Ljava/lang/Integer;

    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_3
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 124
    .line 125
    .line 126
    move-result-object v8

    .line 127
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v8

    .line 131
    if-eqz v8, :cond_4

    .line 132
    .line 133
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getLong(I)J

    .line 134
    .line 135
    .line 136
    move-result-wide v15

    .line 137
    invoke-static/range {v15 .. v16}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 138
    .line 139
    .line 140
    move-result-object v2

    .line 141
    check-cast v2, Ljava/lang/Integer;

    .line 142
    .line 143
    goto :goto_0

    .line 144
    :cond_4
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 145
    .line 146
    .line 147
    move-result-object v8

    .line 148
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v6

    .line 152
    if-eqz v6, :cond_8c

    .line 153
    .line 154
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getShort(I)S

    .line 155
    .line 156
    .line 157
    move-result v2

    .line 158
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 159
    .line 160
    .line 161
    move-result-object v2

    .line 162
    check-cast v2, Ljava/lang/Integer;

    .line 163
    .line 164
    :goto_0
    if-eqz v2, :cond_5

    .line 165
    .line 166
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 167
    .line 168
    .line 169
    move-result v2

    .line 170
    goto :goto_1

    .line 171
    :cond_5
    const/4 v2, 0x0

    .line 172
    :goto_1
    const-string v8, "uuid"

    .line 173
    .line 174
    invoke-interface {v0, v8}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 175
    .line 176
    .line 177
    move-result v8

    .line 178
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 179
    .line 180
    .line 181
    move-result-object v15

    .line 182
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 183
    .line 184
    .line 185
    move-result-object v6

    .line 186
    invoke-static {v15, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 187
    .line 188
    .line 189
    move-result v6

    .line 190
    if-eqz v6, :cond_6

    .line 191
    .line 192
    invoke-interface {v0, v8}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object v6

    .line 196
    goto :goto_2

    .line 197
    :cond_6
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 198
    .line 199
    .line 200
    move-result-object v6

    .line 201
    invoke-static {v15, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    move-result v6

    .line 205
    if-eqz v6, :cond_7

    .line 206
    .line 207
    invoke-interface {v0, v8}, Landroid/database/Cursor;->getInt(I)I

    .line 208
    .line 209
    .line 210
    move-result v6

    .line 211
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 212
    .line 213
    .line 214
    move-result-object v6

    .line 215
    check-cast v6, Ljava/lang/String;

    .line 216
    .line 217
    goto :goto_2

    .line 218
    :cond_7
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 219
    .line 220
    .line 221
    move-result-object v6

    .line 222
    invoke-static {v15, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    move-result v6

    .line 226
    if-eqz v6, :cond_8

    .line 227
    .line 228
    invoke-interface {v0, v8}, Landroid/database/Cursor;->getDouble(I)D

    .line 229
    .line 230
    .line 231
    move-result-wide v17

    .line 232
    invoke-static/range {v17 .. v18}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 233
    .line 234
    .line 235
    move-result-object v6

    .line 236
    check-cast v6, Ljava/lang/String;

    .line 237
    .line 238
    goto :goto_2

    .line 239
    :cond_8
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 240
    .line 241
    .line 242
    move-result-object v6

    .line 243
    invoke-static {v15, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result v6

    .line 247
    if-eqz v6, :cond_9

    .line 248
    .line 249
    invoke-interface {v0, v8}, Landroid/database/Cursor;->getFloat(I)F

    .line 250
    .line 251
    .line 252
    move-result v6

    .line 253
    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 254
    .line 255
    .line 256
    move-result-object v6

    .line 257
    check-cast v6, Ljava/lang/String;

    .line 258
    .line 259
    goto :goto_2

    .line 260
    :cond_9
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 261
    .line 262
    .line 263
    move-result-object v6

    .line 264
    invoke-static {v15, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    move-result v6

    .line 268
    if-eqz v6, :cond_a

    .line 269
    .line 270
    invoke-interface {v0, v8}, Landroid/database/Cursor;->getLong(I)J

    .line 271
    .line 272
    .line 273
    move-result-wide v17

    .line 274
    invoke-static/range {v17 .. v18}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 275
    .line 276
    .line 277
    move-result-object v6

    .line 278
    check-cast v6, Ljava/lang/String;

    .line 279
    .line 280
    goto :goto_2

    .line 281
    :cond_a
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 282
    .line 283
    .line 284
    move-result-object v6

    .line 285
    invoke-static {v15, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    move-result v6

    .line 289
    if-eqz v6, :cond_8b

    .line 290
    .line 291
    invoke-interface {v0, v8}, Landroid/database/Cursor;->getShort(I)S

    .line 292
    .line 293
    .line 294
    move-result v6

    .line 295
    invoke-static {v6}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 296
    .line 297
    .line 298
    move-result-object v6

    .line 299
    check-cast v6, Ljava/lang/String;

    .line 300
    .line 301
    :goto_2
    const-string v8, "Required value was null."

    .line 302
    .line 303
    if-eqz v6, :cond_8a

    .line 304
    .line 305
    const-string v15, "signed_string"

    .line 306
    .line 307
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 308
    .line 309
    .line 310
    move-result v15

    .line 311
    move/from16 v17, v2

    .line 312
    .line 313
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 314
    .line 315
    .line 316
    move-result-object v2

    .line 317
    move-object/from16 v18, v3

    .line 318
    .line 319
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 320
    .line 321
    .line 322
    move-result-object v3

    .line 323
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 324
    .line 325
    .line 326
    move-result v3

    .line 327
    if-eqz v3, :cond_b

    .line 328
    .line 329
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v2

    .line 333
    goto :goto_3

    .line 334
    :cond_b
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 335
    .line 336
    .line 337
    move-result-object v3

    .line 338
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 339
    .line 340
    .line 341
    move-result v3

    .line 342
    if-eqz v3, :cond_c

    .line 343
    .line 344
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getInt(I)I

    .line 345
    .line 346
    .line 347
    move-result v2

    .line 348
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 349
    .line 350
    .line 351
    move-result-object v2

    .line 352
    check-cast v2, Ljava/lang/String;

    .line 353
    .line 354
    goto :goto_3

    .line 355
    :cond_c
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 356
    .line 357
    .line 358
    move-result-object v3

    .line 359
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 360
    .line 361
    .line 362
    move-result v3

    .line 363
    if-eqz v3, :cond_d

    .line 364
    .line 365
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getDouble(I)D

    .line 366
    .line 367
    .line 368
    move-result-wide v2

    .line 369
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 370
    .line 371
    .line 372
    move-result-object v2

    .line 373
    check-cast v2, Ljava/lang/String;

    .line 374
    .line 375
    goto :goto_3

    .line 376
    :cond_d
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 377
    .line 378
    .line 379
    move-result-object v3

    .line 380
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 381
    .line 382
    .line 383
    move-result v3

    .line 384
    if-eqz v3, :cond_e

    .line 385
    .line 386
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getFloat(I)F

    .line 387
    .line 388
    .line 389
    move-result v2

    .line 390
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 391
    .line 392
    .line 393
    move-result-object v2

    .line 394
    check-cast v2, Ljava/lang/String;

    .line 395
    .line 396
    goto :goto_3

    .line 397
    :cond_e
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 398
    .line 399
    .line 400
    move-result-object v3

    .line 401
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 402
    .line 403
    .line 404
    move-result v3

    .line 405
    if-eqz v3, :cond_f

    .line 406
    .line 407
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getLong(I)J

    .line 408
    .line 409
    .line 410
    move-result-wide v2

    .line 411
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 412
    .line 413
    .line 414
    move-result-object v2

    .line 415
    check-cast v2, Ljava/lang/String;

    .line 416
    .line 417
    goto :goto_3

    .line 418
    :cond_f
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 419
    .line 420
    .line 421
    move-result-object v3

    .line 422
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 423
    .line 424
    .line 425
    move-result v2

    .line 426
    if-eqz v2, :cond_89

    .line 427
    .line 428
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getShort(I)S

    .line 429
    .line 430
    .line 431
    move-result v2

    .line 432
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 433
    .line 434
    .line 435
    move-result-object v2

    .line 436
    check-cast v2, Ljava/lang/String;

    .line 437
    .line 438
    :goto_3
    invoke-interface {v1, v2}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 439
    .line 440
    .line 441
    move-result-object v2

    .line 442
    const-string v3, "device_id"

    .line 443
    .line 444
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 445
    .line 446
    .line 447
    move-result v3

    .line 448
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 449
    .line 450
    .line 451
    move-result-object v15

    .line 452
    move-object/from16 v19, v2

    .line 453
    .line 454
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 455
    .line 456
    .line 457
    move-result-object v2

    .line 458
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 459
    .line 460
    .line 461
    move-result v2

    .line 462
    if-eqz v2, :cond_10

    .line 463
    .line 464
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 465
    .line 466
    .line 467
    move-result-object v2

    .line 468
    goto :goto_4

    .line 469
    :cond_10
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 470
    .line 471
    .line 472
    move-result-object v2

    .line 473
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 474
    .line 475
    .line 476
    move-result v2

    .line 477
    if-eqz v2, :cond_11

    .line 478
    .line 479
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 480
    .line 481
    .line 482
    move-result v2

    .line 483
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 484
    .line 485
    .line 486
    move-result-object v2

    .line 487
    check-cast v2, Ljava/lang/String;

    .line 488
    .line 489
    goto :goto_4

    .line 490
    :cond_11
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 491
    .line 492
    .line 493
    move-result-object v2

    .line 494
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 495
    .line 496
    .line 497
    move-result v2

    .line 498
    if-eqz v2, :cond_12

    .line 499
    .line 500
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getDouble(I)D

    .line 501
    .line 502
    .line 503
    move-result-wide v2

    .line 504
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 505
    .line 506
    .line 507
    move-result-object v2

    .line 508
    check-cast v2, Ljava/lang/String;

    .line 509
    .line 510
    goto :goto_4

    .line 511
    :cond_12
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 512
    .line 513
    .line 514
    move-result-object v2

    .line 515
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 516
    .line 517
    .line 518
    move-result v2

    .line 519
    if-eqz v2, :cond_13

    .line 520
    .line 521
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getFloat(I)F

    .line 522
    .line 523
    .line 524
    move-result v2

    .line 525
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 526
    .line 527
    .line 528
    move-result-object v2

    .line 529
    check-cast v2, Ljava/lang/String;

    .line 530
    .line 531
    goto :goto_4

    .line 532
    :cond_13
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 533
    .line 534
    .line 535
    move-result-object v2

    .line 536
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 537
    .line 538
    .line 539
    move-result v2

    .line 540
    if-eqz v2, :cond_14

    .line 541
    .line 542
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 543
    .line 544
    .line 545
    move-result-wide v2

    .line 546
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 547
    .line 548
    .line 549
    move-result-object v2

    .line 550
    check-cast v2, Ljava/lang/String;

    .line 551
    .line 552
    goto :goto_4

    .line 553
    :cond_14
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 554
    .line 555
    .line 556
    move-result-object v2

    .line 557
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 558
    .line 559
    .line 560
    move-result v2

    .line 561
    if-eqz v2, :cond_88

    .line 562
    .line 563
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getShort(I)S

    .line 564
    .line 565
    .line 566
    move-result v2

    .line 567
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 568
    .line 569
    .line 570
    move-result-object v2

    .line 571
    check-cast v2, Ljava/lang/String;

    .line 572
    .line 573
    :goto_4
    if-eqz v2, :cond_87

    .line 574
    .line 575
    const-string v3, "system_token"

    .line 576
    .line 577
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 578
    .line 579
    .line 580
    move-result v3

    .line 581
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 582
    .line 583
    .line 584
    move-result-object v15

    .line 585
    move-object/from16 v20, v2

    .line 586
    .line 587
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 588
    .line 589
    .line 590
    move-result-object v2

    .line 591
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 592
    .line 593
    .line 594
    move-result v2

    .line 595
    if-eqz v2, :cond_15

    .line 596
    .line 597
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 598
    .line 599
    .line 600
    move-result-object v2

    .line 601
    goto :goto_5

    .line 602
    :cond_15
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 603
    .line 604
    .line 605
    move-result-object v2

    .line 606
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 607
    .line 608
    .line 609
    move-result v2

    .line 610
    if-eqz v2, :cond_16

    .line 611
    .line 612
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 613
    .line 614
    .line 615
    move-result v2

    .line 616
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 617
    .line 618
    .line 619
    move-result-object v2

    .line 620
    check-cast v2, Ljava/lang/String;

    .line 621
    .line 622
    goto :goto_5

    .line 623
    :cond_16
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 624
    .line 625
    .line 626
    move-result-object v2

    .line 627
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 628
    .line 629
    .line 630
    move-result v2

    .line 631
    if-eqz v2, :cond_17

    .line 632
    .line 633
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getDouble(I)D

    .line 634
    .line 635
    .line 636
    move-result-wide v2

    .line 637
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 638
    .line 639
    .line 640
    move-result-object v2

    .line 641
    check-cast v2, Ljava/lang/String;

    .line 642
    .line 643
    goto :goto_5

    .line 644
    :cond_17
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 645
    .line 646
    .line 647
    move-result-object v2

    .line 648
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 649
    .line 650
    .line 651
    move-result v2

    .line 652
    if-eqz v2, :cond_18

    .line 653
    .line 654
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getFloat(I)F

    .line 655
    .line 656
    .line 657
    move-result v2

    .line 658
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 659
    .line 660
    .line 661
    move-result-object v2

    .line 662
    check-cast v2, Ljava/lang/String;

    .line 663
    .line 664
    goto :goto_5

    .line 665
    :cond_18
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 666
    .line 667
    .line 668
    move-result-object v2

    .line 669
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 670
    .line 671
    .line 672
    move-result v2

    .line 673
    if-eqz v2, :cond_19

    .line 674
    .line 675
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 676
    .line 677
    .line 678
    move-result-wide v2

    .line 679
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 680
    .line 681
    .line 682
    move-result-object v2

    .line 683
    check-cast v2, Ljava/lang/String;

    .line 684
    .line 685
    goto :goto_5

    .line 686
    :cond_19
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 687
    .line 688
    .line 689
    move-result-object v2

    .line 690
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 691
    .line 692
    .line 693
    move-result v2

    .line 694
    if-eqz v2, :cond_86

    .line 695
    .line 696
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getShort(I)S

    .line 697
    .line 698
    .line 699
    move-result v2

    .line 700
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 701
    .line 702
    .line 703
    move-result-object v2

    .line 704
    check-cast v2, Ljava/lang/String;

    .line 705
    .line 706
    :goto_5
    invoke-interface {v1, v2}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 707
    .line 708
    .line 709
    move-result-object v2

    .line 710
    const-string v3, "sdk_version"

    .line 711
    .line 712
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 713
    .line 714
    .line 715
    move-result v3

    .line 716
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 717
    .line 718
    .line 719
    move-result-object v15

    .line 720
    move-object/from16 v21, v2

    .line 721
    .line 722
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 723
    .line 724
    .line 725
    move-result-object v2

    .line 726
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 727
    .line 728
    .line 729
    move-result v2

    .line 730
    if-eqz v2, :cond_1a

    .line 731
    .line 732
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 733
    .line 734
    .line 735
    move-result-object v2

    .line 736
    goto :goto_6

    .line 737
    :cond_1a
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 738
    .line 739
    .line 740
    move-result-object v2

    .line 741
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 742
    .line 743
    .line 744
    move-result v2

    .line 745
    if-eqz v2, :cond_1b

    .line 746
    .line 747
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 748
    .line 749
    .line 750
    move-result v2

    .line 751
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 752
    .line 753
    .line 754
    move-result-object v2

    .line 755
    check-cast v2, Ljava/lang/String;

    .line 756
    .line 757
    goto :goto_6

    .line 758
    :cond_1b
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 759
    .line 760
    .line 761
    move-result-object v2

    .line 762
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 763
    .line 764
    .line 765
    move-result v2

    .line 766
    if-eqz v2, :cond_1c

    .line 767
    .line 768
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getDouble(I)D

    .line 769
    .line 770
    .line 771
    move-result-wide v2

    .line 772
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 773
    .line 774
    .line 775
    move-result-object v2

    .line 776
    check-cast v2, Ljava/lang/String;

    .line 777
    .line 778
    goto :goto_6

    .line 779
    :cond_1c
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 780
    .line 781
    .line 782
    move-result-object v2

    .line 783
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 784
    .line 785
    .line 786
    move-result v2

    .line 787
    if-eqz v2, :cond_1d

    .line 788
    .line 789
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getFloat(I)F

    .line 790
    .line 791
    .line 792
    move-result v2

    .line 793
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 794
    .line 795
    .line 796
    move-result-object v2

    .line 797
    check-cast v2, Ljava/lang/String;

    .line 798
    .line 799
    goto :goto_6

    .line 800
    :cond_1d
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 801
    .line 802
    .line 803
    move-result-object v2

    .line 804
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 805
    .line 806
    .line 807
    move-result v2

    .line 808
    if-eqz v2, :cond_1e

    .line 809
    .line 810
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 811
    .line 812
    .line 813
    move-result-wide v2

    .line 814
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 815
    .line 816
    .line 817
    move-result-object v2

    .line 818
    check-cast v2, Ljava/lang/String;

    .line 819
    .line 820
    goto :goto_6

    .line 821
    :cond_1e
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 822
    .line 823
    .line 824
    move-result-object v2

    .line 825
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 826
    .line 827
    .line 828
    move-result v2

    .line 829
    if-eqz v2, :cond_85

    .line 830
    .line 831
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getShort(I)S

    .line 832
    .line 833
    .line 834
    move-result v2

    .line 835
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 836
    .line 837
    .line 838
    move-result-object v2

    .line 839
    check-cast v2, Ljava/lang/String;

    .line 840
    .line 841
    :goto_6
    if-eqz v2, :cond_84

    .line 842
    .line 843
    const-string v3, "app_version"

    .line 844
    .line 845
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 846
    .line 847
    .line 848
    move-result v3

    .line 849
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 850
    .line 851
    .line 852
    move-result-object v15

    .line 853
    move-object/from16 v22, v2

    .line 854
    .line 855
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 856
    .line 857
    .line 858
    move-result-object v2

    .line 859
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 860
    .line 861
    .line 862
    move-result v2

    .line 863
    if-eqz v2, :cond_1f

    .line 864
    .line 865
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 866
    .line 867
    .line 868
    move-result-object v2

    .line 869
    goto :goto_7

    .line 870
    :cond_1f
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 871
    .line 872
    .line 873
    move-result-object v2

    .line 874
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 875
    .line 876
    .line 877
    move-result v2

    .line 878
    if-eqz v2, :cond_20

    .line 879
    .line 880
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 881
    .line 882
    .line 883
    move-result v2

    .line 884
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 885
    .line 886
    .line 887
    move-result-object v2

    .line 888
    check-cast v2, Ljava/lang/String;

    .line 889
    .line 890
    goto :goto_7

    .line 891
    :cond_20
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 892
    .line 893
    .line 894
    move-result-object v2

    .line 895
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 896
    .line 897
    .line 898
    move-result v2

    .line 899
    if-eqz v2, :cond_21

    .line 900
    .line 901
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getDouble(I)D

    .line 902
    .line 903
    .line 904
    move-result-wide v2

    .line 905
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 906
    .line 907
    .line 908
    move-result-object v2

    .line 909
    check-cast v2, Ljava/lang/String;

    .line 910
    .line 911
    goto :goto_7

    .line 912
    :cond_21
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 913
    .line 914
    .line 915
    move-result-object v2

    .line 916
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 917
    .line 918
    .line 919
    move-result v2

    .line 920
    if-eqz v2, :cond_22

    .line 921
    .line 922
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getFloat(I)F

    .line 923
    .line 924
    .line 925
    move-result v2

    .line 926
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 927
    .line 928
    .line 929
    move-result-object v2

    .line 930
    check-cast v2, Ljava/lang/String;

    .line 931
    .line 932
    goto :goto_7

    .line 933
    :cond_22
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 934
    .line 935
    .line 936
    move-result-object v2

    .line 937
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 938
    .line 939
    .line 940
    move-result v2

    .line 941
    if-eqz v2, :cond_23

    .line 942
    .line 943
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 944
    .line 945
    .line 946
    move-result-wide v2

    .line 947
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 948
    .line 949
    .line 950
    move-result-object v2

    .line 951
    check-cast v2, Ljava/lang/String;

    .line 952
    .line 953
    goto :goto_7

    .line 954
    :cond_23
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 955
    .line 956
    .line 957
    move-result-object v2

    .line 958
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 959
    .line 960
    .line 961
    move-result v2

    .line 962
    if-eqz v2, :cond_83

    .line 963
    .line 964
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getShort(I)S

    .line 965
    .line 966
    .line 967
    move-result v2

    .line 968
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 969
    .line 970
    .line 971
    move-result-object v2

    .line 972
    check-cast v2, Ljava/lang/String;

    .line 973
    .line 974
    :goto_7
    if-eqz v2, :cond_82

    .line 975
    .line 976
    const-string v3, "dst"

    .line 977
    .line 978
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 979
    .line 980
    .line 981
    move-result v3

    .line 982
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 983
    .line 984
    .line 985
    move-result-object v15

    .line 986
    move-object/from16 v23, v2

    .line 987
    .line 988
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 989
    .line 990
    .line 991
    move-result-object v2

    .line 992
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 993
    .line 994
    .line 995
    move-result v2

    .line 996
    if-eqz v2, :cond_24

    .line 997
    .line 998
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 999
    .line 1000
    .line 1001
    move-result-object v2

    .line 1002
    check-cast v2, Ljava/lang/Integer;

    .line 1003
    .line 1004
    goto :goto_8

    .line 1005
    :cond_24
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1006
    .line 1007
    .line 1008
    move-result-object v2

    .line 1009
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1010
    .line 1011
    .line 1012
    move-result v2

    .line 1013
    if-eqz v2, :cond_25

    .line 1014
    .line 1015
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 1016
    .line 1017
    .line 1018
    move-result v2

    .line 1019
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1020
    .line 1021
    .line 1022
    move-result-object v2

    .line 1023
    goto :goto_8

    .line 1024
    :cond_25
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1025
    .line 1026
    .line 1027
    move-result-object v2

    .line 1028
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1029
    .line 1030
    .line 1031
    move-result v2

    .line 1032
    if-eqz v2, :cond_26

    .line 1033
    .line 1034
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getDouble(I)D

    .line 1035
    .line 1036
    .line 1037
    move-result-wide v2

    .line 1038
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1039
    .line 1040
    .line 1041
    move-result-object v2

    .line 1042
    check-cast v2, Ljava/lang/Integer;

    .line 1043
    .line 1044
    goto :goto_8

    .line 1045
    :cond_26
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1046
    .line 1047
    .line 1048
    move-result-object v2

    .line 1049
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1050
    .line 1051
    .line 1052
    move-result v2

    .line 1053
    if-eqz v2, :cond_27

    .line 1054
    .line 1055
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getFloat(I)F

    .line 1056
    .line 1057
    .line 1058
    move-result v2

    .line 1059
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1060
    .line 1061
    .line 1062
    move-result-object v2

    .line 1063
    check-cast v2, Ljava/lang/Integer;

    .line 1064
    .line 1065
    goto :goto_8

    .line 1066
    :cond_27
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v2

    .line 1070
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1071
    .line 1072
    .line 1073
    move-result v2

    .line 1074
    if-eqz v2, :cond_28

    .line 1075
    .line 1076
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 1077
    .line 1078
    .line 1079
    move-result-wide v2

    .line 1080
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1081
    .line 1082
    .line 1083
    move-result-object v2

    .line 1084
    check-cast v2, Ljava/lang/Integer;

    .line 1085
    .line 1086
    goto :goto_8

    .line 1087
    :cond_28
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1088
    .line 1089
    .line 1090
    move-result-object v2

    .line 1091
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1092
    .line 1093
    .line 1094
    move-result v2

    .line 1095
    if-eqz v2, :cond_81

    .line 1096
    .line 1097
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getShort(I)S

    .line 1098
    .line 1099
    .line 1100
    move-result v2

    .line 1101
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 1102
    .line 1103
    .line 1104
    move-result-object v2

    .line 1105
    check-cast v2, Ljava/lang/Integer;

    .line 1106
    .line 1107
    :goto_8
    const/4 v3, 0x1

    .line 1108
    if-nez v2, :cond_29

    .line 1109
    .line 1110
    goto :goto_9

    .line 1111
    :cond_29
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1112
    .line 1113
    .line 1114
    move-result v2

    .line 1115
    if-ne v2, v3, :cond_2a

    .line 1116
    .line 1117
    move v2, v3

    .line 1118
    goto :goto_a

    .line 1119
    :cond_2a
    :goto_9
    const/4 v2, 0x0

    .line 1120
    :goto_a
    const-string v15, "location_enabled"

    .line 1121
    .line 1122
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 1123
    .line 1124
    .line 1125
    move-result v15

    .line 1126
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1127
    .line 1128
    .line 1129
    move-result-object v3

    .line 1130
    move/from16 v25, v2

    .line 1131
    .line 1132
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1133
    .line 1134
    .line 1135
    move-result-object v2

    .line 1136
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1137
    .line 1138
    .line 1139
    move-result v2

    .line 1140
    if-eqz v2, :cond_2b

    .line 1141
    .line 1142
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 1143
    .line 1144
    .line 1145
    move-result-object v2

    .line 1146
    check-cast v2, Ljava/lang/Integer;

    .line 1147
    .line 1148
    goto :goto_b

    .line 1149
    :cond_2b
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1150
    .line 1151
    .line 1152
    move-result-object v2

    .line 1153
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1154
    .line 1155
    .line 1156
    move-result v2

    .line 1157
    if-eqz v2, :cond_2c

    .line 1158
    .line 1159
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getInt(I)I

    .line 1160
    .line 1161
    .line 1162
    move-result v2

    .line 1163
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1164
    .line 1165
    .line 1166
    move-result-object v2

    .line 1167
    goto :goto_b

    .line 1168
    :cond_2c
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1169
    .line 1170
    .line 1171
    move-result-object v2

    .line 1172
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1173
    .line 1174
    .line 1175
    move-result v2

    .line 1176
    if-eqz v2, :cond_2d

    .line 1177
    .line 1178
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getDouble(I)D

    .line 1179
    .line 1180
    .line 1181
    move-result-wide v2

    .line 1182
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v2

    .line 1186
    check-cast v2, Ljava/lang/Integer;

    .line 1187
    .line 1188
    goto :goto_b

    .line 1189
    :cond_2d
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1190
    .line 1191
    .line 1192
    move-result-object v2

    .line 1193
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1194
    .line 1195
    .line 1196
    move-result v2

    .line 1197
    if-eqz v2, :cond_2e

    .line 1198
    .line 1199
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getFloat(I)F

    .line 1200
    .line 1201
    .line 1202
    move-result v2

    .line 1203
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1204
    .line 1205
    .line 1206
    move-result-object v2

    .line 1207
    check-cast v2, Ljava/lang/Integer;

    .line 1208
    .line 1209
    goto :goto_b

    .line 1210
    :cond_2e
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1211
    .line 1212
    .line 1213
    move-result-object v2

    .line 1214
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1215
    .line 1216
    .line 1217
    move-result v2

    .line 1218
    if-eqz v2, :cond_2f

    .line 1219
    .line 1220
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getLong(I)J

    .line 1221
    .line 1222
    .line 1223
    move-result-wide v2

    .line 1224
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1225
    .line 1226
    .line 1227
    move-result-object v2

    .line 1228
    check-cast v2, Ljava/lang/Integer;

    .line 1229
    .line 1230
    goto :goto_b

    .line 1231
    :cond_2f
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1232
    .line 1233
    .line 1234
    move-result-object v2

    .line 1235
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1236
    .line 1237
    .line 1238
    move-result v2

    .line 1239
    if-eqz v2, :cond_80

    .line 1240
    .line 1241
    invoke-interface {v0, v15}, Landroid/database/Cursor;->getShort(I)S

    .line 1242
    .line 1243
    .line 1244
    move-result v2

    .line 1245
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 1246
    .line 1247
    .line 1248
    move-result-object v2

    .line 1249
    check-cast v2, Ljava/lang/Integer;

    .line 1250
    .line 1251
    :goto_b
    if-nez v2, :cond_30

    .line 1252
    .line 1253
    goto :goto_c

    .line 1254
    :cond_30
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1255
    .line 1256
    .line 1257
    move-result v2

    .line 1258
    const/4 v3, 0x1

    .line 1259
    if-ne v2, v3, :cond_31

    .line 1260
    .line 1261
    const/4 v3, 0x1

    .line 1262
    goto :goto_d

    .line 1263
    :cond_31
    :goto_c
    const/4 v3, 0x0

    .line 1264
    :goto_d
    const-string v2, "proximity_enabled"

    .line 1265
    .line 1266
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 1267
    .line 1268
    .line 1269
    move-result v2

    .line 1270
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1271
    .line 1272
    .line 1273
    move-result-object v15

    .line 1274
    move/from16 v26, v3

    .line 1275
    .line 1276
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1277
    .line 1278
    .line 1279
    move-result-object v3

    .line 1280
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1281
    .line 1282
    .line 1283
    move-result v3

    .line 1284
    if-eqz v3, :cond_32

    .line 1285
    .line 1286
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 1287
    .line 1288
    .line 1289
    move-result-object v2

    .line 1290
    check-cast v2, Ljava/lang/Integer;

    .line 1291
    .line 1292
    goto :goto_e

    .line 1293
    :cond_32
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1294
    .line 1295
    .line 1296
    move-result-object v3

    .line 1297
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1298
    .line 1299
    .line 1300
    move-result v3

    .line 1301
    if-eqz v3, :cond_33

    .line 1302
    .line 1303
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getInt(I)I

    .line 1304
    .line 1305
    .line 1306
    move-result v2

    .line 1307
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1308
    .line 1309
    .line 1310
    move-result-object v2

    .line 1311
    goto :goto_e

    .line 1312
    :cond_33
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1313
    .line 1314
    .line 1315
    move-result-object v3

    .line 1316
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1317
    .line 1318
    .line 1319
    move-result v3

    .line 1320
    if-eqz v3, :cond_34

    .line 1321
    .line 1322
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getDouble(I)D

    .line 1323
    .line 1324
    .line 1325
    move-result-wide v2

    .line 1326
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1327
    .line 1328
    .line 1329
    move-result-object v2

    .line 1330
    check-cast v2, Ljava/lang/Integer;

    .line 1331
    .line 1332
    goto :goto_e

    .line 1333
    :cond_34
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1334
    .line 1335
    .line 1336
    move-result-object v3

    .line 1337
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1338
    .line 1339
    .line 1340
    move-result v3

    .line 1341
    if-eqz v3, :cond_35

    .line 1342
    .line 1343
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getFloat(I)F

    .line 1344
    .line 1345
    .line 1346
    move-result v2

    .line 1347
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1348
    .line 1349
    .line 1350
    move-result-object v2

    .line 1351
    check-cast v2, Ljava/lang/Integer;

    .line 1352
    .line 1353
    goto :goto_e

    .line 1354
    :cond_35
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1355
    .line 1356
    .line 1357
    move-result-object v3

    .line 1358
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1359
    .line 1360
    .line 1361
    move-result v3

    .line 1362
    if-eqz v3, :cond_36

    .line 1363
    .line 1364
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getLong(I)J

    .line 1365
    .line 1366
    .line 1367
    move-result-wide v2

    .line 1368
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1369
    .line 1370
    .line 1371
    move-result-object v2

    .line 1372
    check-cast v2, Ljava/lang/Integer;

    .line 1373
    .line 1374
    goto :goto_e

    .line 1375
    :cond_36
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1376
    .line 1377
    .line 1378
    move-result-object v3

    .line 1379
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1380
    .line 1381
    .line 1382
    move-result v3

    .line 1383
    if-eqz v3, :cond_7f

    .line 1384
    .line 1385
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getShort(I)S

    .line 1386
    .line 1387
    .line 1388
    move-result v2

    .line 1389
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 1390
    .line 1391
    .line 1392
    move-result-object v2

    .line 1393
    check-cast v2, Ljava/lang/Integer;

    .line 1394
    .line 1395
    :goto_e
    if-nez v2, :cond_37

    .line 1396
    .line 1397
    goto :goto_f

    .line 1398
    :cond_37
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1399
    .line 1400
    .line 1401
    move-result v2

    .line 1402
    const/4 v3, 0x1

    .line 1403
    if-ne v2, v3, :cond_38

    .line 1404
    .line 1405
    const/4 v3, 0x1

    .line 1406
    goto :goto_10

    .line 1407
    :cond_38
    :goto_f
    const/4 v3, 0x0

    .line 1408
    :goto_10
    const-string v2, "platform_version"

    .line 1409
    .line 1410
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 1411
    .line 1412
    .line 1413
    move-result v2

    .line 1414
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1415
    .line 1416
    .line 1417
    move-result-object v15

    .line 1418
    move/from16 v27, v3

    .line 1419
    .line 1420
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1421
    .line 1422
    .line 1423
    move-result-object v3

    .line 1424
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1425
    .line 1426
    .line 1427
    move-result v3

    .line 1428
    if-eqz v3, :cond_39

    .line 1429
    .line 1430
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 1431
    .line 1432
    .line 1433
    move-result-object v2

    .line 1434
    goto :goto_11

    .line 1435
    :cond_39
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1436
    .line 1437
    .line 1438
    move-result-object v3

    .line 1439
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1440
    .line 1441
    .line 1442
    move-result v3

    .line 1443
    if-eqz v3, :cond_3a

    .line 1444
    .line 1445
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getInt(I)I

    .line 1446
    .line 1447
    .line 1448
    move-result v2

    .line 1449
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1450
    .line 1451
    .line 1452
    move-result-object v2

    .line 1453
    check-cast v2, Ljava/lang/String;

    .line 1454
    .line 1455
    goto :goto_11

    .line 1456
    :cond_3a
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1457
    .line 1458
    .line 1459
    move-result-object v3

    .line 1460
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1461
    .line 1462
    .line 1463
    move-result v3

    .line 1464
    if-eqz v3, :cond_3b

    .line 1465
    .line 1466
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getDouble(I)D

    .line 1467
    .line 1468
    .line 1469
    move-result-wide v2

    .line 1470
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1471
    .line 1472
    .line 1473
    move-result-object v2

    .line 1474
    check-cast v2, Ljava/lang/String;

    .line 1475
    .line 1476
    goto :goto_11

    .line 1477
    :cond_3b
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1478
    .line 1479
    .line 1480
    move-result-object v3

    .line 1481
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1482
    .line 1483
    .line 1484
    move-result v3

    .line 1485
    if-eqz v3, :cond_3c

    .line 1486
    .line 1487
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getFloat(I)F

    .line 1488
    .line 1489
    .line 1490
    move-result v2

    .line 1491
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1492
    .line 1493
    .line 1494
    move-result-object v2

    .line 1495
    check-cast v2, Ljava/lang/String;

    .line 1496
    .line 1497
    goto :goto_11

    .line 1498
    :cond_3c
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1499
    .line 1500
    .line 1501
    move-result-object v3

    .line 1502
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1503
    .line 1504
    .line 1505
    move-result v3

    .line 1506
    if-eqz v3, :cond_3d

    .line 1507
    .line 1508
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getLong(I)J

    .line 1509
    .line 1510
    .line 1511
    move-result-wide v2

    .line 1512
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1513
    .line 1514
    .line 1515
    move-result-object v2

    .line 1516
    check-cast v2, Ljava/lang/String;

    .line 1517
    .line 1518
    goto :goto_11

    .line 1519
    :cond_3d
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1520
    .line 1521
    .line 1522
    move-result-object v3

    .line 1523
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1524
    .line 1525
    .line 1526
    move-result v3

    .line 1527
    if-eqz v3, :cond_7e

    .line 1528
    .line 1529
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getShort(I)S

    .line 1530
    .line 1531
    .line 1532
    move-result v2

    .line 1533
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 1534
    .line 1535
    .line 1536
    move-result-object v2

    .line 1537
    check-cast v2, Ljava/lang/String;

    .line 1538
    .line 1539
    :goto_11
    if-eqz v2, :cond_7d

    .line 1540
    .line 1541
    const-string v3, "push_enabled"

    .line 1542
    .line 1543
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 1544
    .line 1545
    .line 1546
    move-result v3

    .line 1547
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1548
    .line 1549
    .line 1550
    move-result-object v15

    .line 1551
    move-object/from16 v28, v2

    .line 1552
    .line 1553
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1554
    .line 1555
    .line 1556
    move-result-object v2

    .line 1557
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1558
    .line 1559
    .line 1560
    move-result v2

    .line 1561
    if-eqz v2, :cond_3e

    .line 1562
    .line 1563
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 1564
    .line 1565
    .line 1566
    move-result-object v2

    .line 1567
    check-cast v2, Ljava/lang/Integer;

    .line 1568
    .line 1569
    goto :goto_12

    .line 1570
    :cond_3e
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1571
    .line 1572
    .line 1573
    move-result-object v2

    .line 1574
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1575
    .line 1576
    .line 1577
    move-result v2

    .line 1578
    if-eqz v2, :cond_3f

    .line 1579
    .line 1580
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 1581
    .line 1582
    .line 1583
    move-result v2

    .line 1584
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1585
    .line 1586
    .line 1587
    move-result-object v2

    .line 1588
    goto :goto_12

    .line 1589
    :cond_3f
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1590
    .line 1591
    .line 1592
    move-result-object v2

    .line 1593
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1594
    .line 1595
    .line 1596
    move-result v2

    .line 1597
    if-eqz v2, :cond_40

    .line 1598
    .line 1599
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getDouble(I)D

    .line 1600
    .line 1601
    .line 1602
    move-result-wide v2

    .line 1603
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1604
    .line 1605
    .line 1606
    move-result-object v2

    .line 1607
    check-cast v2, Ljava/lang/Integer;

    .line 1608
    .line 1609
    goto :goto_12

    .line 1610
    :cond_40
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1611
    .line 1612
    .line 1613
    move-result-object v2

    .line 1614
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1615
    .line 1616
    .line 1617
    move-result v2

    .line 1618
    if-eqz v2, :cond_41

    .line 1619
    .line 1620
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getFloat(I)F

    .line 1621
    .line 1622
    .line 1623
    move-result v2

    .line 1624
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1625
    .line 1626
    .line 1627
    move-result-object v2

    .line 1628
    check-cast v2, Ljava/lang/Integer;

    .line 1629
    .line 1630
    goto :goto_12

    .line 1631
    :cond_41
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1632
    .line 1633
    .line 1634
    move-result-object v2

    .line 1635
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1636
    .line 1637
    .line 1638
    move-result v2

    .line 1639
    if-eqz v2, :cond_42

    .line 1640
    .line 1641
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 1642
    .line 1643
    .line 1644
    move-result-wide v2

    .line 1645
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1646
    .line 1647
    .line 1648
    move-result-object v2

    .line 1649
    check-cast v2, Ljava/lang/Integer;

    .line 1650
    .line 1651
    goto :goto_12

    .line 1652
    :cond_42
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1653
    .line 1654
    .line 1655
    move-result-object v2

    .line 1656
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1657
    .line 1658
    .line 1659
    move-result v2

    .line 1660
    if-eqz v2, :cond_7c

    .line 1661
    .line 1662
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getShort(I)S

    .line 1663
    .line 1664
    .line 1665
    move-result v2

    .line 1666
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 1667
    .line 1668
    .line 1669
    move-result-object v2

    .line 1670
    check-cast v2, Ljava/lang/Integer;

    .line 1671
    .line 1672
    :goto_12
    if-nez v2, :cond_43

    .line 1673
    .line 1674
    goto :goto_13

    .line 1675
    :cond_43
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1676
    .line 1677
    .line 1678
    move-result v2

    .line 1679
    const/4 v3, 0x1

    .line 1680
    if-ne v2, v3, :cond_44

    .line 1681
    .line 1682
    move v15, v3

    .line 1683
    goto :goto_14

    .line 1684
    :cond_44
    :goto_13
    const/4 v15, 0x0

    .line 1685
    :goto_14
    const-string v2, "timezone"

    .line 1686
    .line 1687
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 1688
    .line 1689
    .line 1690
    move-result v2

    .line 1691
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1692
    .line 1693
    .line 1694
    move-result-object v3

    .line 1695
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1696
    .line 1697
    .line 1698
    move-result-object v5

    .line 1699
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1700
    .line 1701
    .line 1702
    move-result v5

    .line 1703
    if-eqz v5, :cond_45

    .line 1704
    .line 1705
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 1706
    .line 1707
    .line 1708
    move-result-object v2

    .line 1709
    check-cast v2, Ljava/lang/Integer;

    .line 1710
    .line 1711
    goto :goto_15

    .line 1712
    :cond_45
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1713
    .line 1714
    .line 1715
    move-result-object v5

    .line 1716
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1717
    .line 1718
    .line 1719
    move-result v5

    .line 1720
    if-eqz v5, :cond_46

    .line 1721
    .line 1722
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getInt(I)I

    .line 1723
    .line 1724
    .line 1725
    move-result v2

    .line 1726
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1727
    .line 1728
    .line 1729
    move-result-object v2

    .line 1730
    goto :goto_15

    .line 1731
    :cond_46
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1732
    .line 1733
    .line 1734
    move-result-object v5

    .line 1735
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1736
    .line 1737
    .line 1738
    move-result v5

    .line 1739
    if-eqz v5, :cond_47

    .line 1740
    .line 1741
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getDouble(I)D

    .line 1742
    .line 1743
    .line 1744
    move-result-wide v2

    .line 1745
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1746
    .line 1747
    .line 1748
    move-result-object v2

    .line 1749
    check-cast v2, Ljava/lang/Integer;

    .line 1750
    .line 1751
    goto :goto_15

    .line 1752
    :cond_47
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1753
    .line 1754
    .line 1755
    move-result-object v5

    .line 1756
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1757
    .line 1758
    .line 1759
    move-result v5

    .line 1760
    if-eqz v5, :cond_48

    .line 1761
    .line 1762
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getFloat(I)F

    .line 1763
    .line 1764
    .line 1765
    move-result v2

    .line 1766
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1767
    .line 1768
    .line 1769
    move-result-object v2

    .line 1770
    check-cast v2, Ljava/lang/Integer;

    .line 1771
    .line 1772
    goto :goto_15

    .line 1773
    :cond_48
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1774
    .line 1775
    .line 1776
    move-result-object v5

    .line 1777
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1778
    .line 1779
    .line 1780
    move-result v5

    .line 1781
    if-eqz v5, :cond_49

    .line 1782
    .line 1783
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getLong(I)J

    .line 1784
    .line 1785
    .line 1786
    move-result-wide v2

    .line 1787
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1788
    .line 1789
    .line 1790
    move-result-object v2

    .line 1791
    check-cast v2, Ljava/lang/Integer;

    .line 1792
    .line 1793
    goto :goto_15

    .line 1794
    :cond_49
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1795
    .line 1796
    .line 1797
    move-result-object v5

    .line 1798
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1799
    .line 1800
    .line 1801
    move-result v3

    .line 1802
    if-eqz v3, :cond_7b

    .line 1803
    .line 1804
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getShort(I)S

    .line 1805
    .line 1806
    .line 1807
    move-result v2

    .line 1808
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 1809
    .line 1810
    .line 1811
    move-result-object v2

    .line 1812
    check-cast v2, Ljava/lang/Integer;

    .line 1813
    .line 1814
    :goto_15
    if-eqz v2, :cond_7a

    .line 1815
    .line 1816
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1817
    .line 1818
    .line 1819
    move-result v16

    .line 1820
    const-string v2, "subscriber_key"

    .line 1821
    .line 1822
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 1823
    .line 1824
    .line 1825
    move-result v2

    .line 1826
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1827
    .line 1828
    .line 1829
    move-result-object v3

    .line 1830
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1831
    .line 1832
    .line 1833
    move-result-object v5

    .line 1834
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1835
    .line 1836
    .line 1837
    move-result v5

    .line 1838
    if-eqz v5, :cond_4a

    .line 1839
    .line 1840
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 1841
    .line 1842
    .line 1843
    move-result-object v2

    .line 1844
    goto :goto_16

    .line 1845
    :cond_4a
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1846
    .line 1847
    .line 1848
    move-result-object v5

    .line 1849
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1850
    .line 1851
    .line 1852
    move-result v5

    .line 1853
    if-eqz v5, :cond_4b

    .line 1854
    .line 1855
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getInt(I)I

    .line 1856
    .line 1857
    .line 1858
    move-result v2

    .line 1859
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1860
    .line 1861
    .line 1862
    move-result-object v2

    .line 1863
    check-cast v2, Ljava/lang/String;

    .line 1864
    .line 1865
    goto :goto_16

    .line 1866
    :cond_4b
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1867
    .line 1868
    .line 1869
    move-result-object v5

    .line 1870
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1871
    .line 1872
    .line 1873
    move-result v5

    .line 1874
    if-eqz v5, :cond_4c

    .line 1875
    .line 1876
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getDouble(I)D

    .line 1877
    .line 1878
    .line 1879
    move-result-wide v2

    .line 1880
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1881
    .line 1882
    .line 1883
    move-result-object v2

    .line 1884
    check-cast v2, Ljava/lang/String;

    .line 1885
    .line 1886
    goto :goto_16

    .line 1887
    :cond_4c
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1888
    .line 1889
    .line 1890
    move-result-object v5

    .line 1891
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1892
    .line 1893
    .line 1894
    move-result v5

    .line 1895
    if-eqz v5, :cond_4d

    .line 1896
    .line 1897
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getFloat(I)F

    .line 1898
    .line 1899
    .line 1900
    move-result v2

    .line 1901
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1902
    .line 1903
    .line 1904
    move-result-object v2

    .line 1905
    check-cast v2, Ljava/lang/String;

    .line 1906
    .line 1907
    goto :goto_16

    .line 1908
    :cond_4d
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1909
    .line 1910
    .line 1911
    move-result-object v5

    .line 1912
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1913
    .line 1914
    .line 1915
    move-result v5

    .line 1916
    if-eqz v5, :cond_4e

    .line 1917
    .line 1918
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getLong(I)J

    .line 1919
    .line 1920
    .line 1921
    move-result-wide v2

    .line 1922
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1923
    .line 1924
    .line 1925
    move-result-object v2

    .line 1926
    check-cast v2, Ljava/lang/String;

    .line 1927
    .line 1928
    goto :goto_16

    .line 1929
    :cond_4e
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1930
    .line 1931
    .line 1932
    move-result-object v5

    .line 1933
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1934
    .line 1935
    .line 1936
    move-result v3

    .line 1937
    if-eqz v3, :cond_79

    .line 1938
    .line 1939
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getShort(I)S

    .line 1940
    .line 1941
    .line 1942
    move-result v2

    .line 1943
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 1944
    .line 1945
    .line 1946
    move-result-object v2

    .line 1947
    check-cast v2, Ljava/lang/String;

    .line 1948
    .line 1949
    :goto_16
    invoke-interface {v1, v2}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 1950
    .line 1951
    .line 1952
    move-result-object v2

    .line 1953
    const-string v3, "platform"

    .line 1954
    .line 1955
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 1956
    .line 1957
    .line 1958
    move-result v3

    .line 1959
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1960
    .line 1961
    .line 1962
    move-result-object v5

    .line 1963
    move-object/from16 v24, v2

    .line 1964
    .line 1965
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1966
    .line 1967
    .line 1968
    move-result-object v2

    .line 1969
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1970
    .line 1971
    .line 1972
    move-result v2

    .line 1973
    if-eqz v2, :cond_4f

    .line 1974
    .line 1975
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 1976
    .line 1977
    .line 1978
    move-result-object v2

    .line 1979
    goto :goto_17

    .line 1980
    :cond_4f
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1981
    .line 1982
    .line 1983
    move-result-object v2

    .line 1984
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1985
    .line 1986
    .line 1987
    move-result v2

    .line 1988
    if-eqz v2, :cond_50

    .line 1989
    .line 1990
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 1991
    .line 1992
    .line 1993
    move-result v2

    .line 1994
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1995
    .line 1996
    .line 1997
    move-result-object v2

    .line 1998
    check-cast v2, Ljava/lang/String;

    .line 1999
    .line 2000
    goto :goto_17

    .line 2001
    :cond_50
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2002
    .line 2003
    .line 2004
    move-result-object v2

    .line 2005
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2006
    .line 2007
    .line 2008
    move-result v2

    .line 2009
    if-eqz v2, :cond_51

    .line 2010
    .line 2011
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getDouble(I)D

    .line 2012
    .line 2013
    .line 2014
    move-result-wide v2

    .line 2015
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 2016
    .line 2017
    .line 2018
    move-result-object v2

    .line 2019
    check-cast v2, Ljava/lang/String;

    .line 2020
    .line 2021
    goto :goto_17

    .line 2022
    :cond_51
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2023
    .line 2024
    .line 2025
    move-result-object v2

    .line 2026
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2027
    .line 2028
    .line 2029
    move-result v2

    .line 2030
    if-eqz v2, :cond_52

    .line 2031
    .line 2032
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getFloat(I)F

    .line 2033
    .line 2034
    .line 2035
    move-result v2

    .line 2036
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2037
    .line 2038
    .line 2039
    move-result-object v2

    .line 2040
    check-cast v2, Ljava/lang/String;

    .line 2041
    .line 2042
    goto :goto_17

    .line 2043
    :cond_52
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2044
    .line 2045
    .line 2046
    move-result-object v2

    .line 2047
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2048
    .line 2049
    .line 2050
    move-result v2

    .line 2051
    if-eqz v2, :cond_53

    .line 2052
    .line 2053
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 2054
    .line 2055
    .line 2056
    move-result-wide v2

    .line 2057
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2058
    .line 2059
    .line 2060
    move-result-object v2

    .line 2061
    check-cast v2, Ljava/lang/String;

    .line 2062
    .line 2063
    goto :goto_17

    .line 2064
    :cond_53
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2065
    .line 2066
    .line 2067
    move-result-object v2

    .line 2068
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2069
    .line 2070
    .line 2071
    move-result v2

    .line 2072
    if-eqz v2, :cond_78

    .line 2073
    .line 2074
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getShort(I)S

    .line 2075
    .line 2076
    .line 2077
    move-result v2

    .line 2078
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 2079
    .line 2080
    .line 2081
    move-result-object v2

    .line 2082
    check-cast v2, Ljava/lang/String;

    .line 2083
    .line 2084
    :goto_17
    if-eqz v2, :cond_77

    .line 2085
    .line 2086
    const-string v3, "hwid"

    .line 2087
    .line 2088
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 2089
    .line 2090
    .line 2091
    move-result v3

    .line 2092
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2093
    .line 2094
    .line 2095
    move-result-object v5

    .line 2096
    move-object/from16 v29, v2

    .line 2097
    .line 2098
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2099
    .line 2100
    .line 2101
    move-result-object v2

    .line 2102
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2103
    .line 2104
    .line 2105
    move-result v2

    .line 2106
    if-eqz v2, :cond_54

    .line 2107
    .line 2108
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 2109
    .line 2110
    .line 2111
    move-result-object v2

    .line 2112
    goto :goto_18

    .line 2113
    :cond_54
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2114
    .line 2115
    .line 2116
    move-result-object v2

    .line 2117
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2118
    .line 2119
    .line 2120
    move-result v2

    .line 2121
    if-eqz v2, :cond_55

    .line 2122
    .line 2123
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 2124
    .line 2125
    .line 2126
    move-result v2

    .line 2127
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2128
    .line 2129
    .line 2130
    move-result-object v2

    .line 2131
    check-cast v2, Ljava/lang/String;

    .line 2132
    .line 2133
    goto :goto_18

    .line 2134
    :cond_55
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2135
    .line 2136
    .line 2137
    move-result-object v2

    .line 2138
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2139
    .line 2140
    .line 2141
    move-result v2

    .line 2142
    if-eqz v2, :cond_56

    .line 2143
    .line 2144
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getDouble(I)D

    .line 2145
    .line 2146
    .line 2147
    move-result-wide v2

    .line 2148
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 2149
    .line 2150
    .line 2151
    move-result-object v2

    .line 2152
    check-cast v2, Ljava/lang/String;

    .line 2153
    .line 2154
    goto :goto_18

    .line 2155
    :cond_56
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2156
    .line 2157
    .line 2158
    move-result-object v2

    .line 2159
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2160
    .line 2161
    .line 2162
    move-result v2

    .line 2163
    if-eqz v2, :cond_57

    .line 2164
    .line 2165
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getFloat(I)F

    .line 2166
    .line 2167
    .line 2168
    move-result v2

    .line 2169
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2170
    .line 2171
    .line 2172
    move-result-object v2

    .line 2173
    check-cast v2, Ljava/lang/String;

    .line 2174
    .line 2175
    goto :goto_18

    .line 2176
    :cond_57
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2177
    .line 2178
    .line 2179
    move-result-object v2

    .line 2180
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2181
    .line 2182
    .line 2183
    move-result v2

    .line 2184
    if-eqz v2, :cond_58

    .line 2185
    .line 2186
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 2187
    .line 2188
    .line 2189
    move-result-wide v2

    .line 2190
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2191
    .line 2192
    .line 2193
    move-result-object v2

    .line 2194
    check-cast v2, Ljava/lang/String;

    .line 2195
    .line 2196
    goto :goto_18

    .line 2197
    :cond_58
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2198
    .line 2199
    .line 2200
    move-result-object v2

    .line 2201
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2202
    .line 2203
    .line 2204
    move-result v2

    .line 2205
    if-eqz v2, :cond_76

    .line 2206
    .line 2207
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getShort(I)S

    .line 2208
    .line 2209
    .line 2210
    move-result v2

    .line 2211
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 2212
    .line 2213
    .line 2214
    move-result-object v2

    .line 2215
    check-cast v2, Ljava/lang/String;

    .line 2216
    .line 2217
    :goto_18
    if-eqz v2, :cond_75

    .line 2218
    .line 2219
    const-string v3, "et_app_id"

    .line 2220
    .line 2221
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 2222
    .line 2223
    .line 2224
    move-result v3

    .line 2225
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2226
    .line 2227
    .line 2228
    move-result-object v5

    .line 2229
    move-object/from16 v30, v2

    .line 2230
    .line 2231
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2232
    .line 2233
    .line 2234
    move-result-object v2

    .line 2235
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2236
    .line 2237
    .line 2238
    move-result v2

    .line 2239
    if-eqz v2, :cond_59

    .line 2240
    .line 2241
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 2242
    .line 2243
    .line 2244
    move-result-object v2

    .line 2245
    goto :goto_19

    .line 2246
    :cond_59
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2247
    .line 2248
    .line 2249
    move-result-object v2

    .line 2250
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2251
    .line 2252
    .line 2253
    move-result v2

    .line 2254
    if-eqz v2, :cond_5a

    .line 2255
    .line 2256
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 2257
    .line 2258
    .line 2259
    move-result v2

    .line 2260
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2261
    .line 2262
    .line 2263
    move-result-object v2

    .line 2264
    check-cast v2, Ljava/lang/String;

    .line 2265
    .line 2266
    goto :goto_19

    .line 2267
    :cond_5a
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2268
    .line 2269
    .line 2270
    move-result-object v2

    .line 2271
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2272
    .line 2273
    .line 2274
    move-result v2

    .line 2275
    if-eqz v2, :cond_5b

    .line 2276
    .line 2277
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getDouble(I)D

    .line 2278
    .line 2279
    .line 2280
    move-result-wide v2

    .line 2281
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 2282
    .line 2283
    .line 2284
    move-result-object v2

    .line 2285
    check-cast v2, Ljava/lang/String;

    .line 2286
    .line 2287
    goto :goto_19

    .line 2288
    :cond_5b
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2289
    .line 2290
    .line 2291
    move-result-object v2

    .line 2292
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2293
    .line 2294
    .line 2295
    move-result v2

    .line 2296
    if-eqz v2, :cond_5c

    .line 2297
    .line 2298
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getFloat(I)F

    .line 2299
    .line 2300
    .line 2301
    move-result v2

    .line 2302
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2303
    .line 2304
    .line 2305
    move-result-object v2

    .line 2306
    check-cast v2, Ljava/lang/String;

    .line 2307
    .line 2308
    goto :goto_19

    .line 2309
    :cond_5c
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2310
    .line 2311
    .line 2312
    move-result-object v2

    .line 2313
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2314
    .line 2315
    .line 2316
    move-result v2

    .line 2317
    if-eqz v2, :cond_5d

    .line 2318
    .line 2319
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 2320
    .line 2321
    .line 2322
    move-result-wide v2

    .line 2323
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2324
    .line 2325
    .line 2326
    move-result-object v2

    .line 2327
    check-cast v2, Ljava/lang/String;

    .line 2328
    .line 2329
    goto :goto_19

    .line 2330
    :cond_5d
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2331
    .line 2332
    .line 2333
    move-result-object v2

    .line 2334
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2335
    .line 2336
    .line 2337
    move-result v2

    .line 2338
    if-eqz v2, :cond_74

    .line 2339
    .line 2340
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getShort(I)S

    .line 2341
    .line 2342
    .line 2343
    move-result v2

    .line 2344
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 2345
    .line 2346
    .line 2347
    move-result-object v2

    .line 2348
    check-cast v2, Ljava/lang/String;

    .line 2349
    .line 2350
    :goto_19
    invoke-interface {v1, v2}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 2351
    .line 2352
    .line 2353
    move-result-object v2

    .line 2354
    if-eqz v2, :cond_73

    .line 2355
    .line 2356
    const-string v3, "locale"

    .line 2357
    .line 2358
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 2359
    .line 2360
    .line 2361
    move-result v3

    .line 2362
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2363
    .line 2364
    .line 2365
    move-result-object v5

    .line 2366
    move-object/from16 v31, v2

    .line 2367
    .line 2368
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2369
    .line 2370
    .line 2371
    move-result-object v2

    .line 2372
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2373
    .line 2374
    .line 2375
    move-result v2

    .line 2376
    if-eqz v2, :cond_5e

    .line 2377
    .line 2378
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 2379
    .line 2380
    .line 2381
    move-result-object v2

    .line 2382
    goto :goto_1a

    .line 2383
    :cond_5e
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2384
    .line 2385
    .line 2386
    move-result-object v2

    .line 2387
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2388
    .line 2389
    .line 2390
    move-result v2

    .line 2391
    if-eqz v2, :cond_5f

    .line 2392
    .line 2393
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 2394
    .line 2395
    .line 2396
    move-result v2

    .line 2397
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2398
    .line 2399
    .line 2400
    move-result-object v2

    .line 2401
    check-cast v2, Ljava/lang/String;

    .line 2402
    .line 2403
    goto :goto_1a

    .line 2404
    :cond_5f
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2405
    .line 2406
    .line 2407
    move-result-object v2

    .line 2408
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2409
    .line 2410
    .line 2411
    move-result v2

    .line 2412
    if-eqz v2, :cond_60

    .line 2413
    .line 2414
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getDouble(I)D

    .line 2415
    .line 2416
    .line 2417
    move-result-wide v2

    .line 2418
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 2419
    .line 2420
    .line 2421
    move-result-object v2

    .line 2422
    check-cast v2, Ljava/lang/String;

    .line 2423
    .line 2424
    goto :goto_1a

    .line 2425
    :cond_60
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2426
    .line 2427
    .line 2428
    move-result-object v2

    .line 2429
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2430
    .line 2431
    .line 2432
    move-result v2

    .line 2433
    if-eqz v2, :cond_61

    .line 2434
    .line 2435
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getFloat(I)F

    .line 2436
    .line 2437
    .line 2438
    move-result v2

    .line 2439
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2440
    .line 2441
    .line 2442
    move-result-object v2

    .line 2443
    check-cast v2, Ljava/lang/String;

    .line 2444
    .line 2445
    goto :goto_1a

    .line 2446
    :cond_61
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2447
    .line 2448
    .line 2449
    move-result-object v2

    .line 2450
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2451
    .line 2452
    .line 2453
    move-result v2

    .line 2454
    if-eqz v2, :cond_62

    .line 2455
    .line 2456
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 2457
    .line 2458
    .line 2459
    move-result-wide v2

    .line 2460
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2461
    .line 2462
    .line 2463
    move-result-object v2

    .line 2464
    check-cast v2, Ljava/lang/String;

    .line 2465
    .line 2466
    goto :goto_1a

    .line 2467
    :cond_62
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2468
    .line 2469
    .line 2470
    move-result-object v2

    .line 2471
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2472
    .line 2473
    .line 2474
    move-result v2

    .line 2475
    if-eqz v2, :cond_72

    .line 2476
    .line 2477
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getShort(I)S

    .line 2478
    .line 2479
    .line 2480
    move-result v2

    .line 2481
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 2482
    .line 2483
    .line 2484
    move-result-object v2

    .line 2485
    check-cast v2, Ljava/lang/String;

    .line 2486
    .line 2487
    :goto_1a
    if-eqz v2, :cond_71

    .line 2488
    .line 2489
    const-string v3, "tags"

    .line 2490
    .line 2491
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 2492
    .line 2493
    .line 2494
    move-result v3

    .line 2495
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2496
    .line 2497
    .line 2498
    move-result-object v5

    .line 2499
    move-object/from16 v32, v2

    .line 2500
    .line 2501
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2502
    .line 2503
    .line 2504
    move-result-object v2

    .line 2505
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2506
    .line 2507
    .line 2508
    move-result v2

    .line 2509
    if-eqz v2, :cond_63

    .line 2510
    .line 2511
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 2512
    .line 2513
    .line 2514
    move-result-object v2

    .line 2515
    goto :goto_1b

    .line 2516
    :cond_63
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2517
    .line 2518
    .line 2519
    move-result-object v2

    .line 2520
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2521
    .line 2522
    .line 2523
    move-result v2

    .line 2524
    if-eqz v2, :cond_64

    .line 2525
    .line 2526
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 2527
    .line 2528
    .line 2529
    move-result v2

    .line 2530
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2531
    .line 2532
    .line 2533
    move-result-object v2

    .line 2534
    check-cast v2, Ljava/lang/String;

    .line 2535
    .line 2536
    goto :goto_1b

    .line 2537
    :cond_64
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2538
    .line 2539
    .line 2540
    move-result-object v2

    .line 2541
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2542
    .line 2543
    .line 2544
    move-result v2

    .line 2545
    if-eqz v2, :cond_65

    .line 2546
    .line 2547
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getDouble(I)D

    .line 2548
    .line 2549
    .line 2550
    move-result-wide v2

    .line 2551
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 2552
    .line 2553
    .line 2554
    move-result-object v2

    .line 2555
    check-cast v2, Ljava/lang/String;

    .line 2556
    .line 2557
    goto :goto_1b

    .line 2558
    :cond_65
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2559
    .line 2560
    .line 2561
    move-result-object v2

    .line 2562
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2563
    .line 2564
    .line 2565
    move-result v2

    .line 2566
    if-eqz v2, :cond_66

    .line 2567
    .line 2568
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getFloat(I)F

    .line 2569
    .line 2570
    .line 2571
    move-result v2

    .line 2572
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2573
    .line 2574
    .line 2575
    move-result-object v2

    .line 2576
    check-cast v2, Ljava/lang/String;

    .line 2577
    .line 2578
    goto :goto_1b

    .line 2579
    :cond_66
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2580
    .line 2581
    .line 2582
    move-result-object v2

    .line 2583
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2584
    .line 2585
    .line 2586
    move-result v2

    .line 2587
    if-eqz v2, :cond_67

    .line 2588
    .line 2589
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 2590
    .line 2591
    .line 2592
    move-result-wide v2

    .line 2593
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2594
    .line 2595
    .line 2596
    move-result-object v2

    .line 2597
    check-cast v2, Ljava/lang/String;

    .line 2598
    .line 2599
    goto :goto_1b

    .line 2600
    :cond_67
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2601
    .line 2602
    .line 2603
    move-result-object v2

    .line 2604
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2605
    .line 2606
    .line 2607
    move-result v2

    .line 2608
    if-eqz v2, :cond_70

    .line 2609
    .line 2610
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getShort(I)S

    .line 2611
    .line 2612
    .line 2613
    move-result v2

    .line 2614
    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 2615
    .line 2616
    .line 2617
    move-result-object v2

    .line 2618
    check-cast v2, Ljava/lang/String;

    .line 2619
    .line 2620
    :goto_1b
    invoke-interface {v1, v2}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 2621
    .line 2622
    .line 2623
    move-result-object v2

    .line 2624
    if-eqz v2, :cond_6f

    .line 2625
    .line 2626
    invoke-static {v2}, Lcom/salesforce/marketingcloud/util/j;->c(Ljava/lang/String;)Ljava/util/Set;

    .line 2627
    .line 2628
    .line 2629
    move-result-object v2

    .line 2630
    const-string v3, "deserializeTags(...)"

    .line 2631
    .line 2632
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2633
    .line 2634
    .line 2635
    const-string v3, "attributes"

    .line 2636
    .line 2637
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 2638
    .line 2639
    .line 2640
    move-result v3

    .line 2641
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2642
    .line 2643
    .line 2644
    move-result-object v5

    .line 2645
    invoke-virtual {v4, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2646
    .line 2647
    .line 2648
    move-result-object v7

    .line 2649
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2650
    .line 2651
    .line 2652
    move-result v7

    .line 2653
    if-eqz v7, :cond_68

    .line 2654
    .line 2655
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 2656
    .line 2657
    .line 2658
    move-result-object v0

    .line 2659
    goto :goto_1c

    .line 2660
    :cond_68
    invoke-virtual {v4, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2661
    .line 2662
    .line 2663
    move-result-object v7

    .line 2664
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2665
    .line 2666
    .line 2667
    move-result v7

    .line 2668
    if-eqz v7, :cond_69

    .line 2669
    .line 2670
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 2671
    .line 2672
    .line 2673
    move-result v0

    .line 2674
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2675
    .line 2676
    .line 2677
    move-result-object v0

    .line 2678
    check-cast v0, Ljava/lang/String;

    .line 2679
    .line 2680
    goto :goto_1c

    .line 2681
    :cond_69
    invoke-virtual {v4, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2682
    .line 2683
    .line 2684
    move-result-object v7

    .line 2685
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2686
    .line 2687
    .line 2688
    move-result v7

    .line 2689
    if-eqz v7, :cond_6a

    .line 2690
    .line 2691
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getDouble(I)D

    .line 2692
    .line 2693
    .line 2694
    move-result-wide v3

    .line 2695
    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 2696
    .line 2697
    .line 2698
    move-result-object v0

    .line 2699
    check-cast v0, Ljava/lang/String;

    .line 2700
    .line 2701
    goto :goto_1c

    .line 2702
    :cond_6a
    invoke-virtual {v4, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2703
    .line 2704
    .line 2705
    move-result-object v7

    .line 2706
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2707
    .line 2708
    .line 2709
    move-result v7

    .line 2710
    if-eqz v7, :cond_6b

    .line 2711
    .line 2712
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getFloat(I)F

    .line 2713
    .line 2714
    .line 2715
    move-result v0

    .line 2716
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2717
    .line 2718
    .line 2719
    move-result-object v0

    .line 2720
    check-cast v0, Ljava/lang/String;

    .line 2721
    .line 2722
    goto :goto_1c

    .line 2723
    :cond_6b
    invoke-virtual {v4, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2724
    .line 2725
    .line 2726
    move-result-object v7

    .line 2727
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2728
    .line 2729
    .line 2730
    move-result v7

    .line 2731
    if-eqz v7, :cond_6c

    .line 2732
    .line 2733
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 2734
    .line 2735
    .line 2736
    move-result-wide v3

    .line 2737
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2738
    .line 2739
    .line 2740
    move-result-object v0

    .line 2741
    check-cast v0, Ljava/lang/String;

    .line 2742
    .line 2743
    goto :goto_1c

    .line 2744
    :cond_6c
    invoke-virtual {v4, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2745
    .line 2746
    .line 2747
    move-result-object v4

    .line 2748
    invoke-static {v5, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2749
    .line 2750
    .line 2751
    move-result v4

    .line 2752
    if-eqz v4, :cond_6e

    .line 2753
    .line 2754
    invoke-interface {v0, v3}, Landroid/database/Cursor;->getShort(I)S

    .line 2755
    .line 2756
    .line 2757
    move-result v0

    .line 2758
    invoke-static {v0}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    .line 2759
    .line 2760
    .line 2761
    move-result-object v0

    .line 2762
    check-cast v0, Ljava/lang/String;

    .line 2763
    .line 2764
    :goto_1c
    invoke-interface {v1, v0}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 2765
    .line 2766
    .line 2767
    move-result-object v0

    .line 2768
    if-eqz v0, :cond_6d

    .line 2769
    .line 2770
    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/j;->b(Ljava/lang/String;)Ljava/util/Map;

    .line 2771
    .line 2772
    .line 2773
    move-result-object v0

    .line 2774
    const-string v1, "deserializeKeys(...)"

    .line 2775
    .line 2776
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2777
    .line 2778
    .line 2779
    move-object v5, v6

    .line 2780
    move/from16 v4, v17

    .line 2781
    .line 2782
    move-object/from16 v3, v18

    .line 2783
    .line 2784
    move-object/from16 v6, v19

    .line 2785
    .line 2786
    move-object/from16 v7, v20

    .line 2787
    .line 2788
    move-object/from16 v8, v21

    .line 2789
    .line 2790
    move-object/from16 v9, v22

    .line 2791
    .line 2792
    move-object/from16 v10, v23

    .line 2793
    .line 2794
    move-object/from16 v17, v24

    .line 2795
    .line 2796
    move/from16 v11, v25

    .line 2797
    .line 2798
    move/from16 v12, v26

    .line 2799
    .line 2800
    move/from16 v13, v27

    .line 2801
    .line 2802
    move-object/from16 v14, v28

    .line 2803
    .line 2804
    move-object/from16 v18, v29

    .line 2805
    .line 2806
    move-object/from16 v19, v30

    .line 2807
    .line 2808
    move-object/from16 v20, v31

    .line 2809
    .line 2810
    move-object/from16 v21, v32

    .line 2811
    .line 2812
    move-object/from16 v23, v0

    .line 2813
    .line 2814
    move-object/from16 v22, v2

    .line 2815
    .line 2816
    invoke-direct/range {v3 .. v23}, Lcom/salesforce/marketingcloud/registration/Registration;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;ZILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;Ljava/util/Map;)V

    .line 2817
    .line 2818
    .line 2819
    move-object/from16 v18, v3

    .line 2820
    .line 2821
    return-object v18

    .line 2822
    :cond_6d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2823
    .line 2824
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2825
    .line 2826
    .line 2827
    throw v0

    .line 2828
    :cond_6e
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2829
    .line 2830
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2831
    .line 2832
    .line 2833
    throw v0

    .line 2834
    :cond_6f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2835
    .line 2836
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2837
    .line 2838
    .line 2839
    throw v0

    .line 2840
    :cond_70
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2841
    .line 2842
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2843
    .line 2844
    .line 2845
    throw v0

    .line 2846
    :cond_71
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2847
    .line 2848
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2849
    .line 2850
    .line 2851
    throw v0

    .line 2852
    :cond_72
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2853
    .line 2854
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2855
    .line 2856
    .line 2857
    throw v0

    .line 2858
    :cond_73
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2859
    .line 2860
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2861
    .line 2862
    .line 2863
    throw v0

    .line 2864
    :cond_74
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2865
    .line 2866
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2867
    .line 2868
    .line 2869
    throw v0

    .line 2870
    :cond_75
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2871
    .line 2872
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2873
    .line 2874
    .line 2875
    throw v0

    .line 2876
    :cond_76
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2877
    .line 2878
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2879
    .line 2880
    .line 2881
    throw v0

    .line 2882
    :cond_77
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2883
    .line 2884
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2885
    .line 2886
    .line 2887
    throw v0

    .line 2888
    :cond_78
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2889
    .line 2890
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2891
    .line 2892
    .line 2893
    throw v0

    .line 2894
    :cond_79
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2895
    .line 2896
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2897
    .line 2898
    .line 2899
    throw v0

    .line 2900
    :cond_7a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2901
    .line 2902
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2903
    .line 2904
    .line 2905
    throw v0

    .line 2906
    :cond_7b
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2907
    .line 2908
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2909
    .line 2910
    .line 2911
    throw v0

    .line 2912
    :cond_7c
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2913
    .line 2914
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2915
    .line 2916
    .line 2917
    throw v0

    .line 2918
    :cond_7d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2919
    .line 2920
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2921
    .line 2922
    .line 2923
    throw v0

    .line 2924
    :cond_7e
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2925
    .line 2926
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2927
    .line 2928
    .line 2929
    throw v0

    .line 2930
    :cond_7f
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2931
    .line 2932
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2933
    .line 2934
    .line 2935
    throw v0

    .line 2936
    :cond_80
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2937
    .line 2938
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2939
    .line 2940
    .line 2941
    throw v0

    .line 2942
    :cond_81
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2943
    .line 2944
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2945
    .line 2946
    .line 2947
    throw v0

    .line 2948
    :cond_82
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2949
    .line 2950
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2951
    .line 2952
    .line 2953
    throw v0

    .line 2954
    :cond_83
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2955
    .line 2956
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2957
    .line 2958
    .line 2959
    throw v0

    .line 2960
    :cond_84
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2961
    .line 2962
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2963
    .line 2964
    .line 2965
    throw v0

    .line 2966
    :cond_85
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2967
    .line 2968
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2969
    .line 2970
    .line 2971
    throw v0

    .line 2972
    :cond_86
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2973
    .line 2974
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2975
    .line 2976
    .line 2977
    throw v0

    .line 2978
    :cond_87
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2979
    .line 2980
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2981
    .line 2982
    .line 2983
    throw v0

    .line 2984
    :cond_88
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2985
    .line 2986
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2987
    .line 2988
    .line 2989
    throw v0

    .line 2990
    :cond_89
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 2991
    .line 2992
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 2993
    .line 2994
    .line 2995
    throw v0

    .line 2996
    :cond_8a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2997
    .line 2998
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2999
    .line 3000
    .line 3001
    throw v0

    .line 3002
    :cond_8b
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 3003
    .line 3004
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 3005
    .line 3006
    .line 3007
    throw v0

    .line 3008
    :cond_8c
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 3009
    .line 3010
    invoke-direct {v0, v9}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 3011
    .line 3012
    .line 3013
    throw v0
.end method
