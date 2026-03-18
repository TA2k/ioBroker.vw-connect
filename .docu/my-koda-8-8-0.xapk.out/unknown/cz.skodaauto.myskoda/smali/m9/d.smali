.class public final Lm9/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lcom/salesforce/marketingcloud/analytics/piwama/m;


# instance fields
.field public final a:Lv7/b;

.field public final b:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 2
    .line 3
    const/16 v1, 0xf

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lm9/d;->c:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Landroid/text/SpannableStringBuilder;Landroid/text/Layout$Alignment;FIFIZII)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    if-eqz p7, :cond_0

    .line 7
    .line 8
    move/from16 v17, p8

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/high16 v1, -0x1000000

    .line 12
    .line 13
    move/from16 v17, v1

    .line 14
    .line 15
    :goto_0
    new-instance v2, Lv7/b;

    .line 16
    .line 17
    const/4 v5, 0x0

    .line 18
    const/4 v6, 0x0

    .line 19
    const/4 v8, 0x0

    .line 20
    const/high16 v12, -0x80000000

    .line 21
    .line 22
    const v13, -0x800001

    .line 23
    .line 24
    .line 25
    const v14, -0x800001

    .line 26
    .line 27
    .line 28
    const/16 v19, 0x0

    .line 29
    .line 30
    const/16 v20, 0x0

    .line 31
    .line 32
    move v15, v13

    .line 33
    move/from16 v18, v12

    .line 34
    .line 35
    move-object/from16 v3, p1

    .line 36
    .line 37
    move-object/from16 v4, p2

    .line 38
    .line 39
    move/from16 v7, p3

    .line 40
    .line 41
    move/from16 v9, p4

    .line 42
    .line 43
    move/from16 v10, p5

    .line 44
    .line 45
    move/from16 v11, p6

    .line 46
    .line 47
    move/from16 v16, p7

    .line 48
    .line 49
    invoke-direct/range {v2 .. v20}, Lv7/b;-><init>(Ljava/lang/CharSequence;Landroid/text/Layout$Alignment;Landroid/text/Layout$Alignment;Landroid/graphics/Bitmap;FIIFIIFFFZIIFI)V

    .line 50
    .line 51
    .line 52
    iput-object v2, v0, Lm9/d;->a:Lv7/b;

    .line 53
    .line 54
    move/from16 v1, p9

    .line 55
    .line 56
    iput v1, v0, Lm9/d;->b:I

    .line 57
    .line 58
    return-void
.end method
