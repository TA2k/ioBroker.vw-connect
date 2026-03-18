.class public final Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Button"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final action:Ljava/lang/String;

.field public final actionType:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

.field public final backgroundColor:Ljava/lang/String;

.field public final borderColor:Ljava/lang/String;

.field public final borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

.field public final cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

.field public final fontColor:Ljava/lang/String;

.field public final fontSize:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

.field public final id:Ljava/lang/String;

.field public final index:I

.field public final text:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)V
    .locals 1

    const-string v0, "id"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "text"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "actionType"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fontSize"

    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "borderWidth"

    invoke-static {p10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "cornerRadius"

    invoke-static {p11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->id:Ljava/lang/String;

    .line 3
    iput p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->index:I

    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->text:Ljava/lang/String;

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->actionType:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    .line 6
    iput-object p5, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->action:Ljava/lang/String;

    .line 7
    iput-object p6, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontColor:Ljava/lang/String;

    .line 8
    iput-object p7, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontSize:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 9
    iput-object p8, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->backgroundColor:Ljava/lang/String;

    .line 10
    iput-object p9, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderColor:Ljava/lang/String;

    .line 11
    iput-object p10, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 12
    iput-object p11, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;ILjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;ILkotlin/jvm/internal/g;)V
    .locals 14

    move/from16 v0, p12

    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_0

    const/4 v1, 0x0

    move v4, v1

    goto :goto_0

    :cond_0
    move/from16 v4, p2

    :goto_0
    and-int/lit8 v1, v0, 0x8

    if-eqz v1, :cond_1

    .line 13
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;->close:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    move-object v6, v1

    goto :goto_1

    :cond_1
    move-object/from16 v6, p4

    :goto_1
    and-int/lit8 v1, v0, 0x10

    const/4 v2, 0x0

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

    .line 14
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-object v9, v1

    goto :goto_4

    :cond_4
    move-object/from16 v9, p7

    :goto_4
    and-int/lit16 v1, v0, 0x80

    if-eqz v1, :cond_5

    move-object v10, v2

    goto :goto_5

    :cond_5
    move-object/from16 v10, p8

    :goto_5
    and-int/lit16 v1, v0, 0x100

    if-eqz v1, :cond_6

    move-object v11, v2

    goto :goto_6

    :cond_6
    move-object/from16 v11, p9

    :goto_6
    and-int/lit16 v1, v0, 0x200

    if-eqz v1, :cond_7

    .line 15
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-object v12, v1

    goto :goto_7

    :cond_7
    move-object/from16 v12, p10

    :goto_7
    and-int/lit16 v0, v0, 0x400

    if-eqz v0, :cond_8

    .line 16
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;->s:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    move-object v13, v0

    :goto_8
    move-object v2, p0

    move-object v3, p1

    move-object/from16 v5, p3

    goto :goto_9

    :cond_8
    move-object/from16 v13, p11

    goto :goto_8

    .line 17
    :goto_9
    invoke-direct/range {v2 .. v13}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;-><init>(Ljava/lang/String;ILjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)V

    return-void
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;Ljava/lang/String;ILjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;
    .locals 0

    .line 1
    and-int/lit8 p13, p12, 0x1

    .line 2
    .line 3
    if-eqz p13, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->id:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p13, p12, 0x2

    .line 8
    .line 9
    if-eqz p13, :cond_1

    .line 10
    .line 11
    iget p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->index:I

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p13, p12, 0x4

    .line 14
    .line 15
    if-eqz p13, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->text:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p13, p12, 0x8

    .line 20
    .line 21
    if-eqz p13, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->actionType:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p13, p12, 0x10

    .line 26
    .line 27
    if-eqz p13, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->action:Ljava/lang/String;

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p13, p12, 0x20

    .line 32
    .line 33
    if-eqz p13, :cond_5

    .line 34
    .line 35
    iget-object p6, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontColor:Ljava/lang/String;

    .line 36
    .line 37
    :cond_5
    and-int/lit8 p13, p12, 0x40

    .line 38
    .line 39
    if-eqz p13, :cond_6

    .line 40
    .line 41
    iget-object p7, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontSize:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 42
    .line 43
    :cond_6
    and-int/lit16 p13, p12, 0x80

    .line 44
    .line 45
    if-eqz p13, :cond_7

    .line 46
    .line 47
    iget-object p8, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->backgroundColor:Ljava/lang/String;

    .line 48
    .line 49
    :cond_7
    and-int/lit16 p13, p12, 0x100

    .line 50
    .line 51
    if-eqz p13, :cond_8

    .line 52
    .line 53
    iget-object p9, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderColor:Ljava/lang/String;

    .line 54
    .line 55
    :cond_8
    and-int/lit16 p13, p12, 0x200

    .line 56
    .line 57
    if-eqz p13, :cond_9

    .line 58
    .line 59
    iget-object p10, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 60
    .line 61
    :cond_9
    and-int/lit16 p12, p12, 0x400

    .line 62
    .line 63
    if-eqz p12, :cond_a

    .line 64
    .line 65
    iget-object p11, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 66
    .line 67
    :cond_a
    move-object p12, p10

    .line 68
    move-object p13, p11

    .line 69
    move-object p10, p8

    .line 70
    move-object p11, p9

    .line 71
    move-object p8, p6

    .line 72
    move-object p9, p7

    .line 73
    move-object p6, p4

    .line 74
    move-object p7, p5

    .line 75
    move p4, p2

    .line 76
    move-object p5, p3

    .line 77
    move-object p2, p0

    .line 78
    move-object p3, p1

    .line 79
    invoke-virtual/range {p2 .. p13}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->copy(Ljava/lang/String;ILjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0
.end method


# virtual methods
.method public final action()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->action:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final actionType()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->actionType:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    .line 2
    .line 3
    return-object p0
.end method

.method public final backgroundColor()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->backgroundColor:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final borderColor()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderColor:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final borderWidth()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component11()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->index:I

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->text:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->actionType:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->action:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontColor:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontSize:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->backgroundColor:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderColor:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;ILjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;
    .locals 12

    .line 1
    const-string p0, "id"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "text"

    .line 7
    .line 8
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "actionType"

    .line 12
    .line 13
    move-object/from16 v4, p4

    .line 14
    .line 15
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-string p0, "fontSize"

    .line 19
    .line 20
    move-object/from16 v7, p7

    .line 21
    .line 22
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-string p0, "borderWidth"

    .line 26
    .line 27
    move-object/from16 v10, p10

    .line 28
    .line 29
    invoke-static {v10, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const-string p0, "cornerRadius"

    .line 33
    .line 34
    move-object/from16 v11, p11

    .line 35
    .line 36
    invoke-static {v11, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 40
    .line 41
    move-object v1, p1

    .line 42
    move v2, p2

    .line 43
    move-object v3, p3

    .line 44
    move-object/from16 v5, p5

    .line 45
    .line 46
    move-object/from16 v6, p6

    .line 47
    .line 48
    move-object/from16 v8, p8

    .line 49
    .line 50
    move-object/from16 v9, p9

    .line 51
    .line 52
    invoke-direct/range {v0 .. v11}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;-><init>(Ljava/lang/String;ILjava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;)V

    .line 53
    .line 54
    .line 55
    return-object v0
.end method

.method public final cornerRadius()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

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

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

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
    check-cast p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->id:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->id:Ljava/lang/String;

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
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->index:I

    .line 25
    .line 26
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->index:I

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->text:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->text:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->actionType:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    .line 43
    .line 44
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->actionType:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    .line 45
    .line 46
    if-eq v1, v3, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->action:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->action:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-nez v1, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontColor:Ljava/lang/String;

    .line 61
    .line 62
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontColor:Ljava/lang/String;

    .line 63
    .line 64
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-nez v1, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontSize:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 72
    .line 73
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontSize:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 74
    .line 75
    if-eq v1, v3, :cond_8

    .line 76
    .line 77
    return v2

    .line 78
    :cond_8
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->backgroundColor:Ljava/lang/String;

    .line 79
    .line 80
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->backgroundColor:Ljava/lang/String;

    .line 81
    .line 82
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    if-nez v1, :cond_9

    .line 87
    .line 88
    return v2

    .line 89
    :cond_9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderColor:Ljava/lang/String;

    .line 90
    .line 91
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderColor:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 101
    .line 102
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 103
    .line 104
    if-eq v1, v3, :cond_b

    .line 105
    .line 106
    return v2

    .line 107
    :cond_b
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 108
    .line 109
    iget-object p1, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 110
    .line 111
    if-eq p0, p1, :cond_c

    .line 112
    .line 113
    return v2

    .line 114
    :cond_c
    return v0
.end method

.method public final fontColor()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontColor:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final fontSize()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontSize:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->id:Ljava/lang/String;

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
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->index:I

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->text:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->actionType:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    .line 23
    .line 24
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    add-int/2addr v2, v0

    .line 29
    mul-int/2addr v2, v1

    .line 30
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->action:Ljava/lang/String;

    .line 31
    .line 32
    const/4 v3, 0x0

    .line 33
    if-nez v0, :cond_0

    .line 34
    .line 35
    move v0, v3

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    :goto_0
    add-int/2addr v2, v0

    .line 42
    mul-int/2addr v2, v1

    .line 43
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontColor:Ljava/lang/String;

    .line 44
    .line 45
    if-nez v0, :cond_1

    .line 46
    .line 47
    move v0, v3

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    :goto_1
    add-int/2addr v2, v0

    .line 54
    mul-int/2addr v2, v1

    .line 55
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontSize:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    add-int/2addr v0, v2

    .line 62
    mul-int/2addr v0, v1

    .line 63
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->backgroundColor:Ljava/lang/String;

    .line 64
    .line 65
    if-nez v2, :cond_2

    .line 66
    .line 67
    move v2, v3

    .line 68
    goto :goto_2

    .line 69
    :cond_2
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    :goto_2
    add-int/2addr v0, v2

    .line 74
    mul-int/2addr v0, v1

    .line 75
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderColor:Ljava/lang/String;

    .line 76
    .line 77
    if-nez v2, :cond_3

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_3
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    :goto_3
    add-int/2addr v0, v3

    .line 85
    mul-int/2addr v0, v1

    .line 86
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 87
    .line 88
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    add-int/2addr v2, v0

    .line 93
    mul-int/2addr v2, v1

    .line 94
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 95
    .line 96
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    add-int/2addr p0, v2

    .line 101
    return p0
.end method

.method public final id()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final index()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->index:I

    .line 2
    .line 3
    return p0
.end method

.method public final text()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->text:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final toJson$sdk_release()Lorg/json/JSONObject;
    .locals 3

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->id:Ljava/lang/String;

    .line 7
    .line 8
    const-string v2, "id"

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->index:I

    .line 14
    .line 15
    const-string v2, "index"

    .line 16
    .line 17
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->text:Ljava/lang/String;

    .line 21
    .line 22
    const-string v2, "text"

    .line 23
    .line 24
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 25
    .line 26
    .line 27
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->actionType:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    const-string v2, "actionType"

    .line 34
    .line 35
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->action:Ljava/lang/String;

    .line 39
    .line 40
    if-eqz v1, :cond_0

    .line 41
    .line 42
    const-string v2, "actionAndroid"

    .line 43
    .line 44
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 45
    .line 46
    .line 47
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontColor:Ljava/lang/String;

    .line 48
    .line 49
    if-eqz v1, :cond_1

    .line 50
    .line 51
    const-string v2, "fontColor"

    .line 52
    .line 53
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 54
    .line 55
    .line 56
    :cond_1
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontSize:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 57
    .line 58
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    const-string v2, "fontSize"

    .line 63
    .line 64
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 65
    .line 66
    .line 67
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->backgroundColor:Ljava/lang/String;

    .line 68
    .line 69
    if-eqz v1, :cond_2

    .line 70
    .line 71
    const-string v2, "backgroundColor"

    .line 72
    .line 73
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 74
    .line 75
    .line 76
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderColor:Ljava/lang/String;

    .line 77
    .line 78
    if-eqz v1, :cond_3

    .line 79
    .line 80
    const-string v2, "borderColor"

    .line 81
    .line 82
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 83
    .line 84
    .line 85
    :cond_3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 86
    .line 87
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    const-string v2, "borderWidth"

    .line 92
    .line 93
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 94
    .line 95
    .line 96
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 97
    .line 98
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    const-string v1, "cornerRadius"

    .line 103
    .line 104
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 105
    .line 106
    .line 107
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 13

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->id:Ljava/lang/String;

    .line 2
    .line 3
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->index:I

    .line 4
    .line 5
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->text:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->actionType:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    .line 8
    .line 9
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->action:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v5, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontColor:Ljava/lang/String;

    .line 12
    .line 13
    iget-object v6, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontSize:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 14
    .line 15
    iget-object v7, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->backgroundColor:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v8, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderColor:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v9, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 20
    .line 21
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 22
    .line 23
    const-string v10, ", index="

    .line 24
    .line 25
    const-string v11, ", text="

    .line 26
    .line 27
    const-string v12, "Button(id="

    .line 28
    .line 29
    invoke-static {v12, v1, v0, v10, v11}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string v1, ", actionType="

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", action="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string v1, ", fontColor="

    .line 50
    .line 51
    const-string v2, ", fontSize="

    .line 52
    .line 53
    invoke-static {v0, v4, v1, v5, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, ", backgroundColor="

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const-string v1, ", borderColor="

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v1, ", borderWidth="

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", cornerRadius="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    const-string p0, ")"

    .line 92
    .line 93
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 0

    .line 1
    const-string p2, "out"

    .line 2
    .line 3
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->id:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->index:I

    .line 12
    .line 13
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 14
    .line 15
    .line 16
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->text:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->actionType:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    .line 22
    .line 23
    invoke-virtual {p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->action:Ljava/lang/String;

    .line 31
    .line 32
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontColor:Ljava/lang/String;

    .line 36
    .line 37
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->fontSize:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 41
    .line 42
    invoke-virtual {p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->backgroundColor:Ljava/lang/String;

    .line 50
    .line 51
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderColor:Ljava/lang/String;

    .line 55
    .line 56
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->borderWidth:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 60
    .line 61
    invoke-virtual {p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->cornerRadius:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Size;

    .line 69
    .line 70
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    return-void
.end method
