.class public final Lcom/salesforce/marketingcloud/push/style/a$b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/push/style/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/style/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "b"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/style/a$b$a;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lcom/salesforce/marketingcloud/push/style/a<",
        "Lcom/salesforce/marketingcloud/push/data/c;",
        ">;"
    }
.end annotation


# instance fields
.field private final d:Landroid/content/Context;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/style/a$b;->d:Landroid/content/Context;

    .line 10
    .line 11
    return-void
.end method

.method private final a(II)D
    .locals 4

    .line 25
    invoke-static {p1}, Ls5/a;->b(I)D

    move-result-wide p0

    .line 26
    invoke-static {p2}, Ls5/a;->b(I)D

    move-result-wide v0

    cmpl-double p2, p0, v0

    const-wide v2, 0x3fa999999999999aL    # 0.05

    if-lez p2, :cond_0

    add-double/2addr p0, v2

    add-double/2addr v0, v2

    div-double/2addr p0, v0

    return-wide p0

    :cond_0
    add-double/2addr v0, v2

    add-double/2addr p0, v2

    div-double/2addr v0, p0

    return-wide v0
.end method

.method private final a()Z
    .locals 1

    .line 24
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/style/a$b;->d:Landroid/content/Context;

    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p0

    invoke-virtual {p0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object p0

    iget p0, p0, Landroid/content/res/Configuration;->uiMode:I

    and-int/lit8 p0, p0, 0x30

    const/16 v0, 0x20

    if-ne p0, v0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;)Lcom/salesforce/marketingcloud/push/data/c;
    .locals 16

    move-object/from16 v0, p0

    const-string v1, "t"

    move-object/from16 v2, p1

    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "defaultStyle"

    move-object/from16 v3, p2

    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v9, Landroid/text/SpannableString;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/push/data/c;->n()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v9, v1}, Landroid/text/SpannableString;-><init>(Ljava/lang/CharSequence;)V

    .line 3
    :try_start_0
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/push/data/c;->m()Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object v1

    const/4 v4, 0x0

    if-eqz v1, :cond_2

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/Style$b;->g()Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_2

    .line 4
    invoke-static {v1}, Landroid/graphics/Color;->parseColor(Ljava/lang/String;)I

    move-result v1

    .line 5
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/style/a$b;->a()Z

    move-result v5

    if-eqz v5, :cond_1

    .line 6
    const-string v5, "#333333"

    invoke-static {v5}, Landroid/graphics/Color;->parseColor(Ljava/lang/String;)I

    move-result v5

    .line 7
    invoke-direct {v0, v1, v5}, Lcom/salesforce/marketingcloud/push/style/a$b;->a(II)D

    move-result-wide v5

    const-wide/high16 v7, 0x4008000000000000L    # 3.0

    cmpl-double v5, v5, v7

    if-lez v5, :cond_0

    .line 8
    new-instance v5, Landroid/text/style/ForegroundColorSpan;

    invoke-direct {v5, v1}, Landroid/text/style/ForegroundColorSpan;-><init>(I)V

    invoke-virtual {v9}, Landroid/text/SpannableString;->length()I

    move-result v1

    invoke-virtual {v9, v5, v4, v1, v4}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    goto :goto_0

    :catch_0
    move-exception v0

    goto/16 :goto_2

    .line 9
    :cond_0
    sget-object v10, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v1, Lcom/salesforce/marketingcloud/push/style/a;->a:Lcom/salesforce/marketingcloud/push/style/a$a;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/style/a$a;->a()Ljava/lang/String;

    move-result-object v11

    sget-object v13, Lcom/salesforce/marketingcloud/push/style/a$b$b;->b:Lcom/salesforce/marketingcloud/push/style/a$b$b;

    const/4 v14, 0x2

    const/4 v15, 0x0

    const/4 v12, 0x0

    invoke-static/range {v10 .. v15}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    goto :goto_0

    .line 10
    :cond_1
    new-instance v5, Landroid/text/style/ForegroundColorSpan;

    invoke-direct {v5, v1}, Landroid/text/style/ForegroundColorSpan;-><init>(I)V

    invoke-virtual {v9}, Landroid/text/SpannableString;->length()I

    move-result v1

    invoke-virtual {v9, v5, v4, v1, v4}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 11
    :cond_2
    :goto_0
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/push/data/c;->m()Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object v1

    if-eqz v1, :cond_3

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/Style$b;->b()Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    move-result-object v1

    if-nez v1, :cond_4

    :cond_3
    move-object v1, v3

    .line 12
    :cond_4
    sget-object v3, Lcom/salesforce/marketingcloud/push/style/a$b$a;->a:[I

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    aget v1, v3, v1

    const/4 v3, 0x1

    const/4 v5, 0x2

    if-eq v1, v3, :cond_6

    if-eq v1, v5, :cond_5

    goto :goto_1

    .line 13
    :cond_5
    new-instance v1, Landroid/text/style/StyleSpan;

    invoke-direct {v1, v5}, Landroid/text/style/StyleSpan;-><init>(I)V

    invoke-virtual {v9}, Landroid/text/SpannableString;->length()I

    move-result v3

    invoke-virtual {v9, v1, v4, v3, v4}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    goto :goto_1

    .line 14
    :cond_6
    new-instance v1, Landroid/text/style/StyleSpan;

    invoke-direct {v1, v3}, Landroid/text/style/StyleSpan;-><init>(I)V

    invoke-virtual {v9}, Landroid/text/SpannableString;->length()I

    move-result v3

    invoke-virtual {v9, v1, v4, v3, v4}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 15
    :goto_1
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/push/data/c;->m()Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object v1

    if-eqz v1, :cond_7

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/Style$b;->c()Lcom/salesforce/marketingcloud/push/data/Style$Size;

    move-result-object v1

    if-eqz v1, :cond_7

    .line 16
    new-instance v3, Landroid/text/style/AbsoluteSizeSpan;

    .line 17
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/Style$Size;->toSP()F

    move-result v1

    iget-object v0, v0, Lcom/salesforce/marketingcloud/push/style/a$b;->d:Landroid/content/Context;

    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v0

    .line 18
    invoke-static {v5, v1, v0}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    move-result v0

    float-to-int v0, v0

    .line 19
    invoke-direct {v3, v0}, Landroid/text/style/AbsoluteSizeSpan;-><init>(I)V

    .line 20
    invoke-virtual {v9}, Landroid/text/SpannableString;->length()I

    move-result v0

    .line 21
    invoke-virtual {v9, v3, v4, v0, v4}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_3

    .line 22
    :goto_2
    sget-object v1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v3, Lcom/salesforce/marketingcloud/push/style/a;->a:Lcom/salesforce/marketingcloud/push/style/a$a;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/push/style/a$a;->a()Ljava/lang/String;

    move-result-object v3

    sget-object v4, Lcom/salesforce/marketingcloud/push/style/a$b$c;->b:Lcom/salesforce/marketingcloud/push/style/a$b$c;

    invoke-virtual {v1, v3, v0, v4}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 23
    :cond_7
    :goto_3
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/push/data/c;->m()Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object v3

    if-eqz v3, :cond_9

    const/16 v10, 0x1f

    const/4 v11, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    invoke-static/range {v3 .. v11}, Lcom/salesforce/marketingcloud/push/data/Style$b;->a(Lcom/salesforce/marketingcloud/push/data/Style$b;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style$Size;Lcom/salesforce/marketingcloud/push/data/Style$Alignment;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;Landroid/text/Spanned;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object v0

    if-nez v0, :cond_8

    goto :goto_4

    :cond_8
    move-object v4, v0

    goto :goto_5

    :cond_9
    :goto_4
    new-instance v3, Lcom/salesforce/marketingcloud/push/data/Style$b;

    const/16 v10, 0x1f

    const/4 v11, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    invoke-direct/range {v3 .. v11}, Lcom/salesforce/marketingcloud/push/data/Style$b;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style$Size;Lcom/salesforce/marketingcloud/push/data/Style$Alignment;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;Landroid/text/Spanned;ILkotlin/jvm/internal/g;)V

    move-object v4, v3

    :goto_5
    const/4 v6, 0x5

    const/4 v7, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    invoke-static/range {v2 .. v7}, Lcom/salesforce/marketingcloud/push/data/c;->a(Lcom/salesforce/marketingcloud/push/data/c;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style$b;Ljava/util/List;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v0

    return-object v0
.end method

.method public bridge synthetic a(Ljava/lang/Object;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lcom/salesforce/marketingcloud/push/data/c;

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/push/style/a$b;->a(Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;)Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object p0

    return-object p0
.end method
