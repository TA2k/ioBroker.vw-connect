.class public final Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;,
        Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;,
        Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;,
        Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;,
        Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;,
        Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;,
        Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;,
        Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;,
        Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final activityInstanceId:Ljava/lang/String;

.field public final backgroundColor:Ljava/lang/String;

.field public final body:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

.field public final borderColor:Ljava/lang/String;

.field public final borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

.field public final buttonConfiguration:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

.field public final buttons:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;",
            ">;"
        }
    .end annotation
.end field

.field public final closeButton:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

.field public final cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

.field public final displayDuration:J

.field public final displayLimit:I

.field public final displayLimitOverride:Z

.field public final endDateUtc:Ljava/util/Date;

.field public final id:Ljava/lang/String;

.field public final layoutOrder:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

.field public final media:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

.field public final messageDelaySec:I

.field public final modifiedDateUtc:Ljava/util/Date;

.field public final priority:I

.field public final startDateUtc:Ljava/util/Date;

.field public final title:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

.field public final type:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

.field public final windowColor:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;ILjava/util/Date;Ljava/util/Date;Ljava/util/Date;ILcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;Ljava/lang/String;JLjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;Ljava/util/List;IZ)V
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "I",
            "Ljava/util/Date;",
            "Ljava/util/Date;",
            "Ljava/util/Date;",
            "I",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;",
            "Ljava/lang/String;",
            "J",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;",
            ">;IZ)V"
        }
    .end annotation

    move-object/from16 v0, p13

    move-object/from16 v1, p15

    move-object/from16 v2, p16

    move-object/from16 v3, p21

    const-string v4, "id"

    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "activityInstanceId"

    invoke-static {p2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "type"

    invoke-static {p8, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "borderWidth"

    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "cornerRadius"

    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "layoutOrder"

    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "buttonConfiguration"

    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->activityInstanceId:Ljava/lang/String;

    .line 4
    iput p3, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->priority:I

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->startDateUtc:Ljava/util/Date;

    .line 6
    iput-object p5, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->endDateUtc:Ljava/util/Date;

    .line 7
    iput-object p6, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->modifiedDateUtc:Ljava/util/Date;

    .line 8
    iput p7, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimit:I

    .line 9
    iput-object p8, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    .line 10
    iput-object p9, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->windowColor:Ljava/lang/String;

    move-wide p1, p10

    .line 11
    iput-wide p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayDuration:J

    move-object/from16 p1, p12

    .line 12
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->backgroundColor:Ljava/lang/String;

    .line 13
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-object/from16 p1, p14

    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderColor:Ljava/lang/String;

    .line 15
    iput-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 16
    iput-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->layoutOrder:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    move-object/from16 p1, p17

    .line 17
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    move-object/from16 p1, p18

    .line 18
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->title:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    move-object/from16 p1, p19

    .line 19
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->body:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    move-object/from16 p1, p20

    .line 20
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 21
    iput-object v3, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttonConfiguration:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    move-object/from16 p1, p22

    .line 22
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons:Ljava/util/List;

    move/from16 p1, p23

    .line 23
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->messageDelaySec:I

    move/from16 p1, p24

    .line 24
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimitOverride:Z

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;ILjava/util/Date;Ljava/util/Date;Ljava/util/Date;ILcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;Ljava/lang/String;JLjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;Ljava/util/List;IZILkotlin/jvm/internal/g;)V
    .locals 27

    move/from16 v0, p25

    and-int/lit8 v1, v0, 0x4

    if-eqz v1, :cond_0

    const/16 v1, 0x3e7

    move v5, v1

    goto :goto_0

    :cond_0
    move/from16 v5, p3

    :goto_0
    and-int/lit8 v1, v0, 0x8

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    move-object v6, v2

    goto :goto_1

    :cond_1
    move-object/from16 v6, p4

    :goto_1
    and-int/lit8 v1, v0, 0x10

    if-eqz v1, :cond_2

    move-object v7, v2

    goto :goto_2

    :cond_2
    move-object/from16 v7, p5

    :goto_2
    and-int/lit8 v1, v0, 0x20

    if-eqz v1, :cond_3

    move-object v8, v2

    goto :goto_3

    :cond_3
    move-object/from16 v8, p6

    :goto_3
    and-int/lit8 v1, v0, 0x40

    if-eqz v1, :cond_4

    const/4 v1, 0x1

    move v9, v1

    goto :goto_4

    :cond_4
    move/from16 v9, p7

    :goto_4
    and-int/lit16 v1, v0, 0x100

    if-eqz v1, :cond_5

    move-object v11, v2

    goto :goto_5

    :cond_5
    move-object/from16 v11, p9

    :goto_5
    and-int/lit16 v1, v0, 0x200

    if-eqz v1, :cond_6

    const-wide/16 v3, -0x1

    move-wide v12, v3

    goto :goto_6

    :cond_6
    move-wide/from16 v12, p10

    :goto_6
    and-int/lit16 v1, v0, 0x800

    if-eqz v1, :cond_7

    .line 25
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-object v15, v1

    goto :goto_7

    :cond_7
    move-object/from16 v15, p13

    :goto_7
    and-int/lit16 v1, v0, 0x1000

    if-eqz v1, :cond_8

    move-object/from16 v16, v2

    goto :goto_8

    :cond_8
    move-object/from16 v16, p14

    :goto_8
    and-int/lit16 v1, v0, 0x2000

    if-eqz v1, :cond_9

    .line 26
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-object/from16 v17, v1

    goto :goto_9

    :cond_9
    move-object/from16 v17, p15

    :goto_9
    and-int/lit16 v1, v0, 0x4000

    if-eqz v1, :cond_a

    .line 27
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;->ImageTitleBody:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    move-object/from16 v18, v1

    goto :goto_a

    :cond_a
    move-object/from16 v18, p16

    :goto_a
    const v1, 0x8000

    and-int/2addr v1, v0

    if-eqz v1, :cond_b

    move-object/from16 v19, v2

    goto :goto_b

    :cond_b
    move-object/from16 v19, p17

    :goto_b
    const/high16 v1, 0x10000

    and-int/2addr v1, v0

    if-eqz v1, :cond_c

    move-object/from16 v20, v2

    goto :goto_c

    :cond_c
    move-object/from16 v20, p18

    :goto_c
    const/high16 v1, 0x20000

    and-int/2addr v1, v0

    if-eqz v1, :cond_d

    move-object/from16 v21, v2

    goto :goto_d

    :cond_d
    move-object/from16 v21, p19

    :goto_d
    const/high16 v1, 0x40000

    and-int/2addr v1, v0

    if-eqz v1, :cond_e

    move-object/from16 v22, v2

    goto :goto_e

    :cond_e
    move-object/from16 v22, p20

    :goto_e
    const/high16 v1, 0x80000

    and-int/2addr v1, v0

    if-eqz v1, :cond_f

    .line 28
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;->twoUp:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    move-object/from16 v23, v1

    goto :goto_f

    :cond_f
    move-object/from16 v23, p21

    :goto_f
    const/high16 v1, 0x100000

    and-int/2addr v1, v0

    if-eqz v1, :cond_10

    move-object/from16 v24, v2

    goto :goto_10

    :cond_10
    move-object/from16 v24, p22

    :goto_10
    const/high16 v1, 0x200000

    and-int/2addr v1, v0

    const/4 v2, 0x0

    if-eqz v1, :cond_11

    move/from16 v25, v2

    goto :goto_11

    :cond_11
    move/from16 v25, p23

    :goto_11
    const/high16 v1, 0x400000

    and-int/2addr v0, v1

    if-eqz v0, :cond_12

    move/from16 v26, v2

    move-object/from16 v3, p1

    move-object/from16 v4, p2

    move-object/from16 v10, p8

    move-object/from16 v14, p12

    move-object/from16 v2, p0

    goto :goto_12

    :cond_12
    move/from16 v26, p24

    move-object/from16 v2, p0

    move-object/from16 v3, p1

    move-object/from16 v4, p2

    move-object/from16 v10, p8

    move-object/from16 v14, p12

    .line 29
    :goto_12
    invoke-direct/range {v2 .. v26}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;-><init>(Ljava/lang/String;Ljava/lang/String;ILjava/util/Date;Ljava/util/Date;Ljava/util/Date;ILcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;Ljava/lang/String;JLjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;Ljava/util/List;IZ)V

    return-void
.end method

.method public constructor <init>(Lorg/json/JSONObject;)V
    .locals 27

    move-object/from16 v0, p1

    const-string v1, "json"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    const-string v1, "id"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    const-string v1, "getString(...)"

    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    const-string v2, "activityInstanceId"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    const-string v2, "priority"

    const/16 v5, 0x3e7

    invoke-virtual {v0, v2, v5}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v5

    .line 33
    const-string v2, "startDateUtc"

    const-string v6, "optString(...)"

    invoke-static {v0, v2, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_0

    .line 34
    invoke-static {v2}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v2

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    .line 35
    :goto_0
    const-string v8, "endDateUtc"

    .line 36
    invoke-static {v0, v8, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v8

    if-eqz v8, :cond_1

    .line 37
    invoke-static {v8}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v8

    goto :goto_1

    :cond_1
    const/4 v8, 0x0

    .line 38
    :goto_1
    const-string v9, "modifiedDateUtc"

    .line 39
    invoke-static {v0, v9, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v9

    if-eqz v9, :cond_2

    .line 40
    invoke-static {v9}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v9

    goto :goto_2

    :cond_2
    const/4 v9, 0x0

    .line 41
    :goto_2
    const-string v10, "displayLimit"

    const/4 v11, 0x1

    invoke-virtual {v0, v10, v11}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v10

    .line 42
    const-string v11, "type"

    invoke-virtual {v0, v11}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v11

    invoke-static {v11, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v11}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    move-result-object v1

    .line 43
    const-string v11, "windowColor"

    .line 44
    invoke-static {v0, v11, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v11

    .line 45
    const-string v12, "displayDuration"

    const-wide/16 v13, -0x1

    invoke-virtual {v0, v12, v13, v14}, Lorg/json/JSONObject;->optLong(Ljava/lang/String;J)J

    move-result-wide v12

    .line 46
    const-string v14, "backgroundColor"

    .line 47
    invoke-static {v0, v14, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v14

    .line 48
    sget-object v15, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 49
    const-string v7, "borderWidth"

    .line 50
    invoke-static {v0, v7, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    if-eqz v7, :cond_3

    .line 51
    invoke-static {v7}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object v7

    :goto_3
    move-object/from16 v17, v1

    goto :goto_4

    :cond_3
    move-object v7, v15

    goto :goto_3

    .line 52
    :goto_4
    const-string v1, "borderColor"

    .line 53
    invoke-static {v0, v1, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    move-object/from16 v18, v1

    .line 54
    const-string v1, "cornerRadius"

    .line 55
    invoke-static {v0, v1, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_4

    .line 56
    invoke-static {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-result-object v15

    .line 57
    :cond_4
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;->ImageTitleBody:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    move-object/from16 v19, v1

    .line 58
    const-string v1, "layoutOrder"

    .line 59
    invoke-static {v0, v1, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_5

    .line 60
    invoke-static {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    move-result-object v1

    move-object/from16 v19, v1

    .line 61
    :cond_5
    const-string v1, "media"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v1

    if-eqz v1, :cond_6

    invoke-static {v1}, Lcom/salesforce/marketingcloud/messages/iam/h;->b(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    move-result-object v1

    move-object/from16 v20, v1

    goto :goto_5

    :cond_6
    const/16 v20, 0x0

    .line 62
    :goto_5
    const-string v1, "title"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v1

    if-eqz v1, :cond_7

    invoke-static {v1}, Lcom/salesforce/marketingcloud/messages/iam/h;->c(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    move-result-object v1

    move-object/from16 v21, v1

    goto :goto_6

    :cond_7
    const/16 v21, 0x0

    .line 63
    :goto_6
    const-string v1, "body"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v1

    if-eqz v1, :cond_8

    invoke-static {v1}, Lcom/salesforce/marketingcloud/messages/iam/h;->c(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    move-result-object v1

    move-object/from16 v22, v1

    goto :goto_7

    :cond_8
    const/16 v22, 0x0

    .line 64
    :goto_7
    const-string v1, "closeButton"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v1

    if-eqz v1, :cond_9

    invoke-static {v1}, Lcom/salesforce/marketingcloud/messages/iam/h;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    move-result-object v1

    goto :goto_8

    :cond_9
    const/4 v1, 0x0

    .line 65
    :goto_8
    sget-object v23, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;->twoUp:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    move-object/from16 v24, v1

    .line 66
    const-string v1, "buttonConfiguration"

    .line 67
    invoke-static {v0, v1, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_a

    .line 68
    invoke-static {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    move-result-object v23

    .line 69
    :cond_a
    const-string v1, "buttons"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object v1

    if-eqz v1, :cond_b

    invoke-static {v1}, Lcom/salesforce/marketingcloud/messages/iam/h;->a(Lorg/json/JSONArray;)Ljava/util/List;

    move-result-object v1

    move-object/from16 v16, v1

    goto :goto_9

    :cond_b
    const/16 v16, 0x0

    .line 70
    :goto_9
    const-string v1, "messageDelaySec"

    const/4 v6, 0x0

    invoke-virtual {v0, v1, v6}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v25

    .line 71
    const-string v1, "displayLimitOverride"

    invoke-virtual {v0, v1, v6}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;Z)Z

    move-result v26

    move-object v6, v15

    move-object v15, v7

    move-object v7, v8

    move-object v8, v9

    move v9, v10

    move-object/from16 v10, v17

    move-object/from16 v17, v6

    move-object/from16 v6, v24

    move-object/from16 v24, v16

    move-object/from16 v16, v18

    move-object/from16 v18, v19

    move-object/from16 v19, v20

    move-object/from16 v20, v21

    move-object/from16 v21, v22

    move-object/from16 v22, v6

    move-object v6, v2

    move-object/from16 v2, p0

    .line 72
    invoke-direct/range {v2 .. v26}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;-><init>(Ljava/lang/String;Ljava/lang/String;ILjava/util/Date;Ljava/util/Date;Ljava/util/Date;ILcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;Ljava/lang/String;JLjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;Ljava/util/List;IZ)V

    return-void
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Ljava/lang/String;Ljava/lang/String;ILjava/util/Date;Ljava/util/Date;Ljava/util/Date;ILcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;Ljava/lang/String;JLjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;Ljava/util/List;IZILjava/lang/Object;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    move/from16 v1, p25

    and-int/lit8 v2, v1, 0x1

    if-eqz v2, :cond_0

    iget-object v2, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id:Ljava/lang/String;

    goto :goto_0

    :cond_0
    move-object/from16 v2, p1

    :goto_0
    and-int/lit8 v3, v1, 0x2

    if-eqz v3, :cond_1

    iget-object v3, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->activityInstanceId:Ljava/lang/String;

    goto :goto_1

    :cond_1
    move-object/from16 v3, p2

    :goto_1
    and-int/lit8 v4, v1, 0x4

    if-eqz v4, :cond_2

    iget v4, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->priority:I

    goto :goto_2

    :cond_2
    move/from16 v4, p3

    :goto_2
    and-int/lit8 v5, v1, 0x8

    if-eqz v5, :cond_3

    iget-object v5, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->startDateUtc:Ljava/util/Date;

    goto :goto_3

    :cond_3
    move-object/from16 v5, p4

    :goto_3
    and-int/lit8 v6, v1, 0x10

    if-eqz v6, :cond_4

    iget-object v6, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->endDateUtc:Ljava/util/Date;

    goto :goto_4

    :cond_4
    move-object/from16 v6, p5

    :goto_4
    and-int/lit8 v7, v1, 0x20

    if-eqz v7, :cond_5

    iget-object v7, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->modifiedDateUtc:Ljava/util/Date;

    goto :goto_5

    :cond_5
    move-object/from16 v7, p6

    :goto_5
    and-int/lit8 v8, v1, 0x40

    if-eqz v8, :cond_6

    iget v8, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimit:I

    goto :goto_6

    :cond_6
    move/from16 v8, p7

    :goto_6
    and-int/lit16 v9, v1, 0x80

    if-eqz v9, :cond_7

    iget-object v9, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    goto :goto_7

    :cond_7
    move-object/from16 v9, p8

    :goto_7
    and-int/lit16 v10, v1, 0x100

    if-eqz v10, :cond_8

    iget-object v10, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->windowColor:Ljava/lang/String;

    goto :goto_8

    :cond_8
    move-object/from16 v10, p9

    :goto_8
    and-int/lit16 v11, v1, 0x200

    if-eqz v11, :cond_9

    iget-wide v11, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayDuration:J

    goto :goto_9

    :cond_9
    move-wide/from16 v11, p10

    :goto_9
    and-int/lit16 v13, v1, 0x400

    if-eqz v13, :cond_a

    iget-object v13, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->backgroundColor:Ljava/lang/String;

    goto :goto_a

    :cond_a
    move-object/from16 v13, p12

    :goto_a
    and-int/lit16 v14, v1, 0x800

    if-eqz v14, :cond_b

    iget-object v14, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    goto :goto_b

    :cond_b
    move-object/from16 v14, p13

    :goto_b
    and-int/lit16 v15, v1, 0x1000

    if-eqz v15, :cond_c

    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderColor:Ljava/lang/String;

    goto :goto_c

    :cond_c
    move-object/from16 v15, p14

    :goto_c
    move-object/from16 p1, v2

    and-int/lit16 v2, v1, 0x2000

    if-eqz v2, :cond_d

    iget-object v2, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    goto :goto_d

    :cond_d
    move-object/from16 v2, p15

    :goto_d
    move-object/from16 p2, v2

    and-int/lit16 v2, v1, 0x4000

    if-eqz v2, :cond_e

    iget-object v2, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->layoutOrder:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    goto :goto_e

    :cond_e
    move-object/from16 v2, p16

    :goto_e
    const v16, 0x8000

    and-int v16, v1, v16

    if-eqz v16, :cond_f

    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    goto :goto_f

    :cond_f
    move-object/from16 v1, p17

    :goto_f
    const/high16 v16, 0x10000

    and-int v16, p25, v16

    move-object/from16 p3, v1

    if-eqz v16, :cond_10

    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->title:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    goto :goto_10

    :cond_10
    move-object/from16 v1, p18

    :goto_10
    const/high16 v16, 0x20000

    and-int v16, p25, v16

    move-object/from16 p4, v1

    if-eqz v16, :cond_11

    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->body:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    goto :goto_11

    :cond_11
    move-object/from16 v1, p19

    :goto_11
    const/high16 v16, 0x40000

    and-int v16, p25, v16

    move-object/from16 p5, v1

    if-eqz v16, :cond_12

    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    goto :goto_12

    :cond_12
    move-object/from16 v1, p20

    :goto_12
    const/high16 v16, 0x80000

    and-int v16, p25, v16

    move-object/from16 p6, v1

    if-eqz v16, :cond_13

    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttonConfiguration:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    goto :goto_13

    :cond_13
    move-object/from16 v1, p21

    :goto_13
    const/high16 v16, 0x100000

    and-int v16, p25, v16

    move-object/from16 p7, v1

    if-eqz v16, :cond_14

    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons:Ljava/util/List;

    goto :goto_14

    :cond_14
    move-object/from16 v1, p22

    :goto_14
    const/high16 v16, 0x200000

    and-int v16, p25, v16

    move-object/from16 p8, v1

    if-eqz v16, :cond_15

    iget v1, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->messageDelaySec:I

    goto :goto_15

    :cond_15
    move/from16 v1, p23

    :goto_15
    const/high16 v16, 0x400000

    and-int v16, p25, v16

    if-eqz v16, :cond_16

    move/from16 p9, v1

    iget-boolean v1, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimitOverride:Z

    move/from16 p24, p9

    move/from16 p25, v1

    :goto_16
    move-object/from16 p16, p2

    move-object/from16 p18, p3

    move-object/from16 p19, p4

    move-object/from16 p20, p5

    move-object/from16 p21, p6

    move-object/from16 p22, p7

    move-object/from16 p23, p8

    move-object/from16 p17, v2

    move-object/from16 p3, v3

    move/from16 p4, v4

    move-object/from16 p5, v5

    move-object/from16 p6, v6

    move-object/from16 p7, v7

    move/from16 p8, v8

    move-object/from16 p9, v9

    move-object/from16 p10, v10

    move-wide/from16 p11, v11

    move-object/from16 p13, v13

    move-object/from16 p14, v14

    move-object/from16 p15, v15

    move-object/from16 p2, p1

    move-object/from16 p1, v0

    goto :goto_17

    :cond_16
    move/from16 p25, p24

    move/from16 p24, v1

    goto :goto_16

    :goto_17
    invoke-virtual/range {p1 .. p25}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->copy(Ljava/lang/String;Ljava/lang/String;ILjava/util/Date;Ljava/util/Date;Ljava/util/Date;ILcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;Ljava/lang/String;JLjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;Ljava/util/List;IZ)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    move-result-object v0

    return-object v0
.end method


# virtual methods
.method public final backgroundColor()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->backgroundColor:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final body()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->body:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 2
    .line 3
    return-object p0
.end method

.method public final borderColor()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderColor:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final borderWidth()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 2
    .line 3
    return-object p0
.end method

.method public final buttonConfiguration()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttonConfiguration:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    .line 2
    .line 3
    return-object p0
.end method

.method public final buttons()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;",
            ">;"
        }
    .end annotation

    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final closeButton()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayDuration:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final component11()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->backgroundColor:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component12()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component13()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderColor:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component14()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component15()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->layoutOrder:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component16()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component17()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->title:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component18()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->body:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component19()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->activityInstanceId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component20()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttonConfiguration:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component21()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component22()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->messageDelaySec:I

    .line 2
    .line 3
    return p0
.end method

.method public final component23()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimitOverride:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component3()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->priority:I

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->startDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->endDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->modifiedDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimit:I

    .line 2
    .line 3
    return p0
.end method

.method public final component8()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->windowColor:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;ILjava/util/Date;Ljava/util/Date;Ljava/util/Date;ILcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;Ljava/lang/String;JLjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;Ljava/util/List;IZ)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;
    .locals 26
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "I",
            "Ljava/util/Date;",
            "Ljava/util/Date;",
            "Ljava/util/Date;",
            "I",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;",
            "Ljava/lang/String;",
            "J",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;",
            ">;IZ)",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;"
        }
    .end annotation

    .line 1
    const-string v0, "id"

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "activityInstanceId"

    .line 9
    .line 10
    move-object/from16 v3, p2

    .line 11
    .line 12
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "type"

    .line 16
    .line 17
    move-object/from16 v9, p8

    .line 18
    .line 19
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v0, "borderWidth"

    .line 23
    .line 24
    move-object/from16 v14, p13

    .line 25
    .line 26
    invoke-static {v14, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    const-string v0, "cornerRadius"

    .line 30
    .line 31
    move-object/from16 v1, p15

    .line 32
    .line 33
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string v0, "layoutOrder"

    .line 37
    .line 38
    move-object/from16 v4, p16

    .line 39
    .line 40
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const-string v0, "buttonConfiguration"

    .line 44
    .line 45
    move-object/from16 v5, p21

    .line 46
    .line 47
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    new-instance v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 51
    .line 52
    move-object/from16 v6, p5

    .line 53
    .line 54
    move-object/from16 v7, p6

    .line 55
    .line 56
    move/from16 v8, p7

    .line 57
    .line 58
    move-object/from16 v10, p9

    .line 59
    .line 60
    move-wide/from16 v11, p10

    .line 61
    .line 62
    move-object/from16 v13, p12

    .line 63
    .line 64
    move-object/from16 v15, p14

    .line 65
    .line 66
    move-object/from16 v16, p15

    .line 67
    .line 68
    move-object/from16 v18, p17

    .line 69
    .line 70
    move-object/from16 v19, p18

    .line 71
    .line 72
    move-object/from16 v20, p19

    .line 73
    .line 74
    move-object/from16 v21, p20

    .line 75
    .line 76
    move-object/from16 v23, p22

    .line 77
    .line 78
    move/from16 v24, p23

    .line 79
    .line 80
    move/from16 v25, p24

    .line 81
    .line 82
    move-object/from16 v17, v4

    .line 83
    .line 84
    move-object/from16 v22, v5

    .line 85
    .line 86
    move/from16 v4, p3

    .line 87
    .line 88
    move-object/from16 v5, p4

    .line 89
    .line 90
    invoke-direct/range {v1 .. v25}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;-><init>(Ljava/lang/String;Ljava/lang/String;ILjava/util/Date;Ljava/util/Date;Ljava/util/Date;ILcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;Ljava/lang/String;JLjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;Ljava/util/List;IZ)V

    .line 91
    .line 92
    .line 93
    return-object v1
.end method

.method public final cornerRadius()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 2
    .line 3
    return-object p0
.end method

.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final displayDuration()J
    .locals 2
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayDuration:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final displayLimit()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimit:I

    .line 2
    .line 3
    return p0
.end method

.method public final displayLimitOverride()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimitOverride:Z

    .line 2
    .line 3
    return p0
.end method

.method public final endDateUtc()Ljava/util/Date;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->endDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->activityInstanceId:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->activityInstanceId:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->priority:I

    .line 36
    .line 37
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->priority:I

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->startDateUtc:Ljava/util/Date;

    .line 43
    .line 44
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->startDateUtc:Ljava/util/Date;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->endDateUtc:Ljava/util/Date;

    .line 54
    .line 55
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->endDateUtc:Ljava/util/Date;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->modifiedDateUtc:Ljava/util/Date;

    .line 65
    .line 66
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->modifiedDateUtc:Ljava/util/Date;

    .line 67
    .line 68
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimit:I

    .line 76
    .line 77
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimit:I

    .line 78
    .line 79
    if-eq v1, v3, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    .line 83
    .line 84
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    .line 85
    .line 86
    if-eq v1, v3, :cond_9

    .line 87
    .line 88
    return v2

    .line 89
    :cond_9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->windowColor:Ljava/lang/String;

    .line 90
    .line 91
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->windowColor:Ljava/lang/String;

    .line 92
    .line 93
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    if-nez v1, :cond_a

    .line 98
    .line 99
    return v2

    .line 100
    :cond_a
    iget-wide v3, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayDuration:J

    .line 101
    .line 102
    iget-wide v5, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayDuration:J

    .line 103
    .line 104
    cmp-long v1, v3, v5

    .line 105
    .line 106
    if-eqz v1, :cond_b

    .line 107
    .line 108
    return v2

    .line 109
    :cond_b
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->backgroundColor:Ljava/lang/String;

    .line 110
    .line 111
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->backgroundColor:Ljava/lang/String;

    .line 112
    .line 113
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v1

    .line 117
    if-nez v1, :cond_c

    .line 118
    .line 119
    return v2

    .line 120
    :cond_c
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 121
    .line 122
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 123
    .line 124
    if-eq v1, v3, :cond_d

    .line 125
    .line 126
    return v2

    .line 127
    :cond_d
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderColor:Ljava/lang/String;

    .line 128
    .line 129
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderColor:Ljava/lang/String;

    .line 130
    .line 131
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-nez v1, :cond_e

    .line 136
    .line 137
    return v2

    .line 138
    :cond_e
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 139
    .line 140
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 141
    .line 142
    if-eq v1, v3, :cond_f

    .line 143
    .line 144
    return v2

    .line 145
    :cond_f
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->layoutOrder:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 146
    .line 147
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->layoutOrder:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 148
    .line 149
    if-eq v1, v3, :cond_10

    .line 150
    .line 151
    return v2

    .line 152
    :cond_10
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 153
    .line 154
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 155
    .line 156
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    move-result v1

    .line 160
    if-nez v1, :cond_11

    .line 161
    .line 162
    return v2

    .line 163
    :cond_11
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->title:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 164
    .line 165
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->title:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 166
    .line 167
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result v1

    .line 171
    if-nez v1, :cond_12

    .line 172
    .line 173
    return v2

    .line 174
    :cond_12
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->body:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 175
    .line 176
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->body:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 177
    .line 178
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v1

    .line 182
    if-nez v1, :cond_13

    .line 183
    .line 184
    return v2

    .line 185
    :cond_13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 186
    .line 187
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 188
    .line 189
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result v1

    .line 193
    if-nez v1, :cond_14

    .line 194
    .line 195
    return v2

    .line 196
    :cond_14
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttonConfiguration:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    .line 197
    .line 198
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttonConfiguration:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    .line 199
    .line 200
    if-eq v1, v3, :cond_15

    .line 201
    .line 202
    return v2

    .line 203
    :cond_15
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons:Ljava/util/List;

    .line 204
    .line 205
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons:Ljava/util/List;

    .line 206
    .line 207
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    move-result v1

    .line 211
    if-nez v1, :cond_16

    .line 212
    .line 213
    return v2

    .line 214
    :cond_16
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->messageDelaySec:I

    .line 215
    .line 216
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->messageDelaySec:I

    .line 217
    .line 218
    if-eq v1, v3, :cond_17

    .line 219
    .line 220
    return v2

    .line 221
    :cond_17
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimitOverride:Z

    .line 222
    .line 223
    iget-boolean p1, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimitOverride:Z

    .line 224
    .line 225
    if-eq p0, p1, :cond_18

    .line 226
    .line 227
    return v2

    .line 228
    :cond_18
    return v0
.end method

.method public final getActivityInstanceId$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->activityInstanceId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 6

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->activityInstanceId:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->priority:I

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->startDateUtc:Ljava/util/Date;

    .line 23
    .line 24
    const/4 v3, 0x0

    .line 25
    if-nez v2, :cond_0

    .line 26
    .line 27
    move v2, v3

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-virtual {v2}, Ljava/util/Date;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    :goto_0
    add-int/2addr v0, v2

    .line 34
    mul-int/2addr v0, v1

    .line 35
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->endDateUtc:Ljava/util/Date;

    .line 36
    .line 37
    if-nez v2, :cond_1

    .line 38
    .line 39
    move v2, v3

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    invoke-virtual {v2}, Ljava/util/Date;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    :goto_1
    add-int/2addr v0, v2

    .line 46
    mul-int/2addr v0, v1

    .line 47
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->modifiedDateUtc:Ljava/util/Date;

    .line 48
    .line 49
    if-nez v2, :cond_2

    .line 50
    .line 51
    move v2, v3

    .line 52
    goto :goto_2

    .line 53
    :cond_2
    invoke-virtual {v2}, Ljava/util/Date;->hashCode()I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    :goto_2
    add-int/2addr v0, v2

    .line 58
    mul-int/2addr v0, v1

    .line 59
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimit:I

    .line 60
    .line 61
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    .line 66
    .line 67
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    add-int/2addr v2, v0

    .line 72
    mul-int/2addr v2, v1

    .line 73
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->windowColor:Ljava/lang/String;

    .line 74
    .line 75
    if-nez v0, :cond_3

    .line 76
    .line 77
    move v0, v3

    .line 78
    goto :goto_3

    .line 79
    :cond_3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    :goto_3
    add-int/2addr v2, v0

    .line 84
    mul-int/2addr v2, v1

    .line 85
    iget-wide v4, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayDuration:J

    .line 86
    .line 87
    invoke-static {v4, v5, v2, v1}, La7/g0;->f(JII)I

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->backgroundColor:Ljava/lang/String;

    .line 92
    .line 93
    if-nez v2, :cond_4

    .line 94
    .line 95
    move v2, v3

    .line 96
    goto :goto_4

    .line 97
    :cond_4
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    :goto_4
    add-int/2addr v0, v2

    .line 102
    mul-int/2addr v0, v1

    .line 103
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 104
    .line 105
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    add-int/2addr v2, v0

    .line 110
    mul-int/2addr v2, v1

    .line 111
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderColor:Ljava/lang/String;

    .line 112
    .line 113
    if-nez v0, :cond_5

    .line 114
    .line 115
    move v0, v3

    .line 116
    goto :goto_5

    .line 117
    :cond_5
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    :goto_5
    add-int/2addr v2, v0

    .line 122
    mul-int/2addr v2, v1

    .line 123
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 124
    .line 125
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    add-int/2addr v0, v2

    .line 130
    mul-int/2addr v0, v1

    .line 131
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->layoutOrder:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 132
    .line 133
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 134
    .line 135
    .line 136
    move-result v2

    .line 137
    add-int/2addr v2, v0

    .line 138
    mul-int/2addr v2, v1

    .line 139
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 140
    .line 141
    if-nez v0, :cond_6

    .line 142
    .line 143
    move v0, v3

    .line 144
    goto :goto_6

    .line 145
    :cond_6
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->hashCode()I

    .line 146
    .line 147
    .line 148
    move-result v0

    .line 149
    :goto_6
    add-int/2addr v2, v0

    .line 150
    mul-int/2addr v2, v1

    .line 151
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->title:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 152
    .line 153
    if-nez v0, :cond_7

    .line 154
    .line 155
    move v0, v3

    .line 156
    goto :goto_7

    .line 157
    :cond_7
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->hashCode()I

    .line 158
    .line 159
    .line 160
    move-result v0

    .line 161
    :goto_7
    add-int/2addr v2, v0

    .line 162
    mul-int/2addr v2, v1

    .line 163
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->body:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 164
    .line 165
    if-nez v0, :cond_8

    .line 166
    .line 167
    move v0, v3

    .line 168
    goto :goto_8

    .line 169
    :cond_8
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->hashCode()I

    .line 170
    .line 171
    .line 172
    move-result v0

    .line 173
    :goto_8
    add-int/2addr v2, v0

    .line 174
    mul-int/2addr v2, v1

    .line 175
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 176
    .line 177
    if-nez v0, :cond_9

    .line 178
    .line 179
    move v0, v3

    .line 180
    goto :goto_9

    .line 181
    :cond_9
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->hashCode()I

    .line 182
    .line 183
    .line 184
    move-result v0

    .line 185
    :goto_9
    add-int/2addr v2, v0

    .line 186
    mul-int/2addr v2, v1

    .line 187
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttonConfiguration:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    .line 188
    .line 189
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 190
    .line 191
    .line 192
    move-result v0

    .line 193
    add-int/2addr v0, v2

    .line 194
    mul-int/2addr v0, v1

    .line 195
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons:Ljava/util/List;

    .line 196
    .line 197
    if-nez v2, :cond_a

    .line 198
    .line 199
    goto :goto_a

    .line 200
    :cond_a
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 201
    .line 202
    .line 203
    move-result v3

    .line 204
    :goto_a
    add-int/2addr v0, v3

    .line 205
    mul-int/2addr v0, v1

    .line 206
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->messageDelaySec:I

    .line 207
    .line 208
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 209
    .line 210
    .line 211
    move-result v0

    .line 212
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimitOverride:Z

    .line 213
    .line 214
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 215
    .line 216
    .line 217
    move-result p0

    .line 218
    add-int/2addr p0, v0

    .line 219
    return p0
.end method

.method public final id()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final layoutOrder()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->layoutOrder:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 2
    .line 3
    return-object p0
.end method

.method public final media()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 2
    .line 3
    return-object p0
.end method

.method public final messageDelaySec()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->messageDelaySec:I

    .line 2
    .line 3
    return p0
.end method

.method public final modifiedDateUtc()Ljava/util/Date;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->modifiedDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final priority()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->priority:I

    .line 2
    .line 3
    return p0
.end method

.method public final startDateUtc()Ljava/util/Date;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->startDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final title()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->title:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 2
    .line 3
    return-object p0
.end method

.method public final toJson()Lorg/json/JSONObject;
    .locals 4

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id:Ljava/lang/String;

    .line 7
    .line 8
    const-string v2, "id"

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->activityInstanceId:Ljava/lang/String;

    .line 14
    .line 15
    const-string v2, "activityInstanceId"

    .line 16
    .line 17
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 18
    .line 19
    .line 20
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->priority:I

    .line 21
    .line 22
    const-string v2, "priority"

    .line 23
    .line 24
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 25
    .line 26
    .line 27
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->startDateUtc:Ljava/util/Date;

    .line 28
    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/util/Date;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    const-string v2, "startDateUtc"

    .line 36
    .line 37
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 38
    .line 39
    .line 40
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->endDateUtc:Ljava/util/Date;

    .line 41
    .line 42
    if-eqz v1, :cond_1

    .line 43
    .line 44
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/util/Date;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    const-string v2, "endDateUtc"

    .line 49
    .line 50
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 51
    .line 52
    .line 53
    :cond_1
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->modifiedDateUtc:Ljava/util/Date;

    .line 54
    .line 55
    if-eqz v1, :cond_2

    .line 56
    .line 57
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/util/Date;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    const-string v2, "modifiedDateUtc"

    .line 62
    .line 63
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 64
    .line 65
    .line 66
    :cond_2
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimit:I

    .line 67
    .line 68
    const-string v2, "displayLimit"

    .line 69
    .line 70
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 71
    .line 72
    .line 73
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    .line 74
    .line 75
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    const-string v2, "type"

    .line 80
    .line 81
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 82
    .line 83
    .line 84
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->windowColor:Ljava/lang/String;

    .line 85
    .line 86
    if-eqz v1, :cond_3

    .line 87
    .line 88
    const-string v2, "windowColor"

    .line 89
    .line 90
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 91
    .line 92
    .line 93
    :cond_3
    iget-wide v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayDuration:J

    .line 94
    .line 95
    const-string v3, "displayDuration"

    .line 96
    .line 97
    invoke-virtual {v0, v3, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;J)Lorg/json/JSONObject;

    .line 98
    .line 99
    .line 100
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->backgroundColor:Ljava/lang/String;

    .line 101
    .line 102
    if-eqz v1, :cond_4

    .line 103
    .line 104
    const-string v2, "backgroundColor"

    .line 105
    .line 106
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 107
    .line 108
    .line 109
    :cond_4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 110
    .line 111
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    const-string v2, "borderWidth"

    .line 116
    .line 117
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 118
    .line 119
    .line 120
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderColor:Ljava/lang/String;

    .line 121
    .line 122
    if-eqz v1, :cond_5

    .line 123
    .line 124
    const-string v2, "borderColor"

    .line 125
    .line 126
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 127
    .line 128
    .line 129
    :cond_5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 130
    .line 131
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    const-string v2, "cornerRadius"

    .line 136
    .line 137
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 138
    .line 139
    .line 140
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->layoutOrder:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 141
    .line 142
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    const-string v2, "layoutOrder"

    .line 147
    .line 148
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 149
    .line 150
    .line 151
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 152
    .line 153
    if-eqz v1, :cond_6

    .line 154
    .line 155
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->toJson$sdk_release()Lorg/json/JSONObject;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    const-string v2, "media"

    .line 160
    .line 161
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 162
    .line 163
    .line 164
    :cond_6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->title:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 165
    .line 166
    if-eqz v1, :cond_7

    .line 167
    .line 168
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->toJson$sdk_release()Lorg/json/JSONObject;

    .line 169
    .line 170
    .line 171
    move-result-object v1

    .line 172
    const-string v2, "title"

    .line 173
    .line 174
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 175
    .line 176
    .line 177
    :cond_7
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->body:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 178
    .line 179
    if-eqz v1, :cond_8

    .line 180
    .line 181
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->toJson$sdk_release()Lorg/json/JSONObject;

    .line 182
    .line 183
    .line 184
    move-result-object v1

    .line 185
    const-string v2, "body"

    .line 186
    .line 187
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 188
    .line 189
    .line 190
    :cond_8
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 191
    .line 192
    if-eqz v1, :cond_9

    .line 193
    .line 194
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->toJson$sdk_release()Lorg/json/JSONObject;

    .line 195
    .line 196
    .line 197
    move-result-object v1

    .line 198
    const-string v2, "closeButton"

    .line 199
    .line 200
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 201
    .line 202
    .line 203
    :cond_9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttonConfiguration:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    .line 204
    .line 205
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object v1

    .line 209
    const-string v2, "buttonConfiguration"

    .line 210
    .line 211
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 212
    .line 213
    .line 214
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons:Ljava/util/List;

    .line 215
    .line 216
    if-eqz v1, :cond_b

    .line 217
    .line 218
    new-instance v1, Lorg/json/JSONArray;

    .line 219
    .line 220
    invoke-direct {v1}, Lorg/json/JSONArray;-><init>()V

    .line 221
    .line 222
    .line 223
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons:Ljava/util/List;

    .line 224
    .line 225
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 226
    .line 227
    .line 228
    move-result-object v2

    .line 229
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 230
    .line 231
    .line 232
    move-result v3

    .line 233
    if-eqz v3, :cond_a

    .line 234
    .line 235
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v3

    .line 239
    check-cast v3, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 240
    .line 241
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->toJson$sdk_release()Lorg/json/JSONObject;

    .line 242
    .line 243
    .line 244
    move-result-object v3

    .line 245
    invoke-virtual {v1, v3}, Lorg/json/JSONArray;->put(Ljava/lang/Object;)Lorg/json/JSONArray;

    .line 246
    .line 247
    .line 248
    goto :goto_0

    .line 249
    :cond_a
    const-string v2, "buttons"

    .line 250
    .line 251
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 252
    .line 253
    .line 254
    :cond_b
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->messageDelaySec:I

    .line 255
    .line 256
    const-string v2, "messageDelaySec"

    .line 257
    .line 258
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 259
    .line 260
    .line 261
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimitOverride:Z

    .line 262
    .line 263
    const-string v1, "displayLimitOverride"

    .line 264
    .line 265
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 266
    .line 267
    .line 268
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->activityInstanceId:Ljava/lang/String;

    .line 6
    .line 7
    iget v3, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->priority:I

    .line 8
    .line 9
    iget-object v4, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->startDateUtc:Ljava/util/Date;

    .line 10
    .line 11
    iget-object v5, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->endDateUtc:Ljava/util/Date;

    .line 12
    .line 13
    iget-object v6, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->modifiedDateUtc:Ljava/util/Date;

    .line 14
    .line 15
    iget v7, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimit:I

    .line 16
    .line 17
    iget-object v8, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    .line 18
    .line 19
    iget-object v9, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->windowColor:Ljava/lang/String;

    .line 20
    .line 21
    iget-wide v10, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayDuration:J

    .line 22
    .line 23
    iget-object v12, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->backgroundColor:Ljava/lang/String;

    .line 24
    .line 25
    iget-object v13, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 26
    .line 27
    iget-object v14, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderColor:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 30
    .line 31
    move-object/from16 v16, v15

    .line 32
    .line 33
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->layoutOrder:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 34
    .line 35
    move-object/from16 v17, v15

    .line 36
    .line 37
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 38
    .line 39
    move-object/from16 v18, v15

    .line 40
    .line 41
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->title:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 42
    .line 43
    move-object/from16 v19, v15

    .line 44
    .line 45
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->body:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 46
    .line 47
    move-object/from16 v20, v15

    .line 48
    .line 49
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 50
    .line 51
    move-object/from16 v21, v15

    .line 52
    .line 53
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttonConfiguration:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    .line 54
    .line 55
    move-object/from16 v22, v15

    .line 56
    .line 57
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons:Ljava/util/List;

    .line 58
    .line 59
    move-object/from16 v23, v15

    .line 60
    .line 61
    iget v15, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->messageDelaySec:I

    .line 62
    .line 63
    iget-boolean v0, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimitOverride:Z

    .line 64
    .line 65
    move/from16 p0, v0

    .line 66
    .line 67
    const-string v0, ", activityInstanceId="

    .line 68
    .line 69
    move/from16 v24, v15

    .line 70
    .line 71
    const-string v15, ", priority="

    .line 72
    .line 73
    move-object/from16 v25, v14

    .line 74
    .line 75
    const-string v14, "InAppMessage(id="

    .line 76
    .line 77
    invoke-static {v14, v1, v0, v2, v15}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v1, ", startDateUtc="

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string v1, ", endDateUtc="

    .line 93
    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    const-string v1, ", modifiedDateUtc="

    .line 101
    .line 102
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    const-string v1, ", displayLimit="

    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    const-string v1, ", type="

    .line 117
    .line 118
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    const-string v1, ", windowColor="

    .line 125
    .line 126
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    const-string v1, ", displayDuration="

    .line 133
    .line 134
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    invoke-virtual {v0, v10, v11}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    const-string v1, ", backgroundColor="

    .line 141
    .line 142
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    invoke-virtual {v0, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    const-string v1, ", borderWidth="

    .line 149
    .line 150
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    const-string v1, ", borderColor="

    .line 157
    .line 158
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    move-object/from16 v1, v25

    .line 162
    .line 163
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    const-string v1, ", cornerRadius="

    .line 167
    .line 168
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    move-object/from16 v1, v16

    .line 172
    .line 173
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 174
    .line 175
    .line 176
    const-string v1, ", layoutOrder="

    .line 177
    .line 178
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    move-object/from16 v1, v17

    .line 182
    .line 183
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    const-string v1, ", media="

    .line 187
    .line 188
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 189
    .line 190
    .line 191
    move-object/from16 v1, v18

    .line 192
    .line 193
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    const-string v1, ", title="

    .line 197
    .line 198
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    move-object/from16 v1, v19

    .line 202
    .line 203
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    const-string v1, ", body="

    .line 207
    .line 208
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 209
    .line 210
    .line 211
    move-object/from16 v1, v20

    .line 212
    .line 213
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 214
    .line 215
    .line 216
    const-string v1, ", closeButton="

    .line 217
    .line 218
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 219
    .line 220
    .line 221
    move-object/from16 v1, v21

    .line 222
    .line 223
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 224
    .line 225
    .line 226
    const-string v1, ", buttonConfiguration="

    .line 227
    .line 228
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    move-object/from16 v1, v22

    .line 232
    .line 233
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 234
    .line 235
    .line 236
    const-string v1, ", buttons="

    .line 237
    .line 238
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 239
    .line 240
    .line 241
    move-object/from16 v1, v23

    .line 242
    .line 243
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 244
    .line 245
    .line 246
    const-string v1, ", messageDelaySec="

    .line 247
    .line 248
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 249
    .line 250
    .line 251
    move/from16 v1, v24

    .line 252
    .line 253
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 254
    .line 255
    .line 256
    const-string v1, ", displayLimitOverride="

    .line 257
    .line 258
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 259
    .line 260
    .line 261
    move/from16 v1, p0

    .line 262
    .line 263
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 264
    .line 265
    .line 266
    const-string v1, ")"

    .line 267
    .line 268
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 269
    .line 270
    .line 271
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    return-object v0
.end method

.method public final type()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final windowColor()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->windowColor:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 3

    .line 1
    const-string v0, "out"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->activityInstanceId:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->priority:I

    .line 17
    .line 18
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->startDateUtc:Ljava/util/Date;

    .line 22
    .line 23
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeSerializable(Ljava/io/Serializable;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->endDateUtc:Ljava/util/Date;

    .line 27
    .line 28
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeSerializable(Ljava/io/Serializable;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->modifiedDateUtc:Ljava/util/Date;

    .line 32
    .line 33
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeSerializable(Ljava/io/Serializable;)V

    .line 34
    .line 35
    .line 36
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimit:I

    .line 37
    .line 38
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 39
    .line 40
    .line 41
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->windowColor:Ljava/lang/String;

    .line 51
    .line 52
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayDuration:J

    .line 56
    .line 57
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 58
    .line 59
    .line 60
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->backgroundColor:Ljava/lang/String;

    .line 61
    .line 62
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 66
    .line 67
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->borderColor:Ljava/lang/String;

    .line 75
    .line 76
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 80
    .line 81
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->layoutOrder:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 89
    .line 90
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    .line 98
    .line 99
    const/4 v1, 0x1

    .line 100
    const/4 v2, 0x0

    .line 101
    if-nez v0, :cond_0

    .line 102
    .line 103
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :cond_0
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->writeToParcel(Landroid/os/Parcel;I)V

    .line 111
    .line 112
    .line 113
    :goto_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->title:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 114
    .line 115
    if-nez v0, :cond_1

    .line 116
    .line 117
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 118
    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_1
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->writeToParcel(Landroid/os/Parcel;I)V

    .line 125
    .line 126
    .line 127
    :goto_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->body:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;

    .line 128
    .line 129
    if-nez v0, :cond_2

    .line 130
    .line 131
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 132
    .line 133
    .line 134
    goto :goto_2

    .line 135
    :cond_2
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$TextField;->writeToParcel(Landroid/os/Parcel;I)V

    .line 139
    .line 140
    .line 141
    :goto_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->closeButton:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 142
    .line 143
    if-nez v0, :cond_3

    .line 144
    .line 145
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 146
    .line 147
    .line 148
    goto :goto_3

    .line 149
    :cond_3
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->writeToParcel(Landroid/os/Parcel;I)V

    .line 153
    .line 154
    .line 155
    :goto_3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttonConfiguration:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$ButtonConfig;

    .line 156
    .line 157
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->buttons:Ljava/util/List;

    .line 165
    .line 166
    if-nez v0, :cond_4

    .line 167
    .line 168
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 169
    .line 170
    .line 171
    goto :goto_5

    .line 172
    :cond_4
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 173
    .line 174
    .line 175
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 176
    .line 177
    .line 178
    move-result v1

    .line 179
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 180
    .line 181
    .line 182
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 187
    .line 188
    .line 189
    move-result v1

    .line 190
    if-eqz v1, :cond_5

    .line 191
    .line 192
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    check-cast v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 197
    .line 198
    invoke-virtual {v1, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->writeToParcel(Landroid/os/Parcel;I)V

    .line 199
    .line 200
    .line 201
    goto :goto_4

    .line 202
    :cond_5
    :goto_5
    iget p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->messageDelaySec:I

    .line 203
    .line 204
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 205
    .line 206
    .line 207
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimitOverride:Z

    .line 208
    .line 209
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 210
    .line 211
    .line 212
    return-void
.end method
