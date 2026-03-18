.class public final Lcom/salesforce/marketingcloud/messages/iam/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;
    .locals 4

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 2
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;->end:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 3
    const-string v2, "alignment"

    const-string v3, "optString(...)"

    .line 4
    invoke-static {p0, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-eqz p0, :cond_0

    .line 5
    invoke-static {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    move-result-object v1

    .line 6
    :cond_0
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;-><init>(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;)V

    return-object v0
.end method

.method public static final a(Lorg/json/JSONArray;)Ljava/util/List;
    .locals 19
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lorg/json/JSONArray;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;",
            ">;"
        }
    .end annotation

    move-object/from16 v0, p0

    const-string v1, "getString(...)"

    const-string v2, "optString(...)"

    const-string v3, "<this>"

    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    invoke-virtual {v0}, Lorg/json/JSONArray;->length()I

    move-result v3

    const/4 v4, 0x0

    invoke-static {v4, v3}, Lkp/r9;->m(II)Lgy0/j;

    move-result-object v3

    .line 11
    new-instance v5, Ljava/util/ArrayList;

    const/16 v6, 0xa

    invoke-static {v3, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    invoke-virtual {v3}, Lgy0/h;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_0
    move-object v6, v3

    check-cast v6, Lgy0/i;

    .line 13
    iget-boolean v6, v6, Lgy0/i;->f:Z

    if-eqz v6, :cond_9

    .line 14
    move-object v6, v3

    check-cast v6, Lmx0/w;

    invoke-virtual {v6}, Lmx0/w;->nextInt()I

    move-result v6

    .line 15
    sget-object v7, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    const-class v8, Lorg/json/JSONObject;

    invoke-virtual {v7, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 16
    invoke-virtual {v7, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v8

    .line 17
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    const-string v10, "null cannot be cast to non-null type org.json.JSONObject"

    if-eqz v8, :cond_1

    invoke-virtual {v0, v6}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    move-result-object v6

    if-eqz v6, :cond_0

    goto/16 :goto_1

    :cond_0
    new-instance v0, Ljava/lang/NullPointerException;

    invoke-direct {v0, v10}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 18
    :cond_1
    sget-object v8, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 19
    invoke-virtual {v7, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v8

    .line 20
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_2

    invoke-virtual {v0, v6}, Lorg/json/JSONArray;->getInt(I)I

    move-result v6

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    check-cast v6, Lorg/json/JSONObject;

    goto :goto_1

    .line 21
    :cond_2
    sget-object v8, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    .line 22
    invoke-virtual {v7, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v8

    .line 23
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_3

    invoke-virtual {v0, v6}, Lorg/json/JSONArray;->getDouble(I)D

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v6

    check-cast v6, Lorg/json/JSONObject;

    goto :goto_1

    .line 24
    :cond_3
    sget-object v8, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 25
    invoke-virtual {v7, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v8

    .line 26
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_4

    invoke-virtual {v0, v6}, Lorg/json/JSONArray;->getLong(I)J

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v6

    check-cast v6, Lorg/json/JSONObject;

    goto :goto_1

    .line 27
    :cond_4
    sget-object v8, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 28
    invoke-virtual {v7, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v8

    .line 29
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_5

    invoke-virtual {v0, v6}, Lorg/json/JSONArray;->getBoolean(I)Z

    move-result v6

    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v6

    check-cast v6, Lorg/json/JSONObject;

    goto :goto_1

    .line 30
    :cond_5
    const-class v8, Ljava/lang/String;

    .line 31
    invoke-virtual {v7, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 32
    invoke-static {v9, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_7

    invoke-virtual {v0, v6}, Lorg/json/JSONArray;->getString(I)Ljava/lang/String;

    move-result-object v6

    if-eqz v6, :cond_6

    check-cast v6, Lorg/json/JSONObject;

    goto :goto_1

    :cond_6
    new-instance v0, Ljava/lang/NullPointerException;

    invoke-direct {v0, v10}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 33
    :cond_7
    invoke-virtual {v0, v6}, Lorg/json/JSONArray;->get(I)Ljava/lang/Object;

    move-result-object v6

    if-eqz v6, :cond_8

    check-cast v6, Lorg/json/JSONObject;

    .line 34
    :goto_1
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto/16 :goto_0

    .line 35
    :cond_8
    new-instance v0, Ljava/lang/NullPointerException;

    invoke-direct {v0, v10}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 36
    :cond_9
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 37
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_f

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    .line 38
    check-cast v5, Lorg/json/JSONObject;

    .line 39
    :try_start_0
    new-instance v6, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 40
    const-string v7, "id"

    invoke-virtual {v5, v7}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    invoke-static {v7, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    const-string v8, "index"

    invoke-virtual {v5, v8, v4}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v8

    .line 42
    const-string v9, "text"

    invoke-virtual {v5, v9}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v9

    invoke-static {v9, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    const-string v10, "actionType"

    sget-object v11, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;->close:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    .line 44
    invoke-virtual {v5, v10}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v10

    invoke-static {v10, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v10}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v10

    if-eqz v10, :cond_a

    .line 45
    invoke-static {v10}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    move-result-object v11

    :cond_a
    move-object v10, v11

    goto :goto_3

    :catch_0
    move-object/from16 v18, v1

    goto/16 :goto_6

    .line 46
    :goto_3
    const-string v11, "actionAndroid"

    invoke-virtual {v5, v11}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v11

    invoke-static {v11, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v11}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v11

    .line 47
    const-string v12, "fontColor"

    invoke-virtual {v5, v12}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v12

    invoke-static {v12, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v12}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v12

    .line 48
    const-string v13, "fontSize"

    sget-object v14, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 49
    invoke-virtual {v5, v13}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    invoke-static {v13, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v13}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    if-eqz v13, :cond_b

    .line 50
    invoke-static {v13}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object v13

    goto :goto_4

    :cond_b
    move-object v13, v14

    .line 51
    :goto_4
    const-string v15, "backgroundColor"

    invoke-virtual {v5, v15}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v15

    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v15}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v15

    .line 52
    const-string v4, "borderColor"

    invoke-virtual {v5, v4}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v4}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    move-object/from16 v18, v1

    .line 53
    :try_start_1
    const-string v1, "borderWidth"

    .line 54
    invoke-virtual {v5, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_c

    .line 55
    invoke-static {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object v1

    move-object/from16 v16, v1

    goto :goto_5

    :cond_c
    move-object/from16 v16, v14

    .line 56
    :goto_5
    const-string v1, "cornerRadius"

    .line 57
    invoke-virtual {v5, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_d

    .line 58
    invoke-static {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object v14

    :cond_d
    move-object/from16 v17, v14

    move-object v14, v15

    move-object v15, v4

    .line 59
    invoke-direct/range {v6 .. v17}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;-><init>(Ljava/lang/String;ILjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_7

    :catch_1
    :goto_6
    const/4 v6, 0x0

    :goto_7
    if-eqz v6, :cond_e

    .line 60
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_e
    move-object/from16 v1, v18

    const/4 v4, 0x0

    goto/16 :goto_2

    :cond_f
    return-object v0
.end method

.method public static final b(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;
    .locals 9

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 7
    .line 8
    const-string v0, "url"

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    const-string v0, "getString(...)"

    .line 15
    .line 16
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;->e2e:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;

    .line 20
    .line 21
    const-string v3, "size"

    .line 22
    .line 23
    const-string v4, "optString(...)"

    .line 24
    .line 25
    invoke-static {p0, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    if-eqz v3, :cond_0

    .line 30
    .line 31
    invoke-static {v3}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    :cond_0
    move-object v3, v0

    .line 36
    const-string v0, "altText"

    .line 37
    .line 38
    invoke-static {p0, v0, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    sget-object v5, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 43
    .line 44
    const-string v6, "borderWidth"

    .line 45
    .line 46
    invoke-static {p0, v6, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v6

    .line 50
    if-eqz v6, :cond_1

    .line 51
    .line 52
    invoke-static {v6}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 53
    .line 54
    .line 55
    move-result-object v6

    .line 56
    goto :goto_0

    .line 57
    :cond_1
    move-object v6, v5

    .line 58
    :goto_0
    const-string v7, "borderColor"

    .line 59
    .line 60
    invoke-static {p0, v7, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v7

    .line 64
    const-string v8, "cornerRadius"

    .line 65
    .line 66
    invoke-static {p0, v8, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    if-eqz p0, :cond_2

    .line 71
    .line 72
    invoke-static {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    :cond_2
    move-object v4, v7

    .line 77
    move-object v7, v5

    .line 78
    move-object v5, v6

    .line 79
    move-object v6, v4

    .line 80
    move-object v4, v0

    .line 81
    invoke-direct/range {v1 .. v7}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media$ImageSize;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)V

    .line 82
    .line 83
    .line 84
    return-object v1
.end method

.method public static final c(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;
    .locals 7

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 7
    .line 8
    const-string v1, "text"

    .line 9
    .line 10
    invoke-virtual {p0, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    const-string v2, "getString(...)"

    .line 15
    .line 16
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sget-object v2, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 20
    .line 21
    const-string v3, "fontSize"

    .line 22
    .line 23
    const-string v4, "optString(...)"

    .line 24
    .line 25
    invoke-static {p0, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    if-eqz v3, :cond_0

    .line 30
    .line 31
    invoke-static {v3}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    :cond_0
    const-string v3, "fontColor"

    .line 36
    .line 37
    invoke-static {p0, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    sget-object v5, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;->center:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 42
    .line 43
    const-string v6, "alignment"

    .line 44
    .line 45
    invoke-static {p0, v6, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    if-eqz p0, :cond_1

    .line 50
    .line 51
    invoke-static {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 52
    .line 53
    .line 54
    move-result-object v5

    .line 55
    :cond_1
    invoke-direct {v0, v1, v2, v3, v5}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;)V

    .line 56
    .line 57
    .line 58
    return-object v0
.end method
