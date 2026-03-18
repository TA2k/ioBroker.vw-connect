.class Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "FontStyle"
.end annotation


# instance fields
.field private textColor:Ljava/lang/Integer;

.field private textSize:Ljava/lang/Float;

.field private textStyle:Ljava/lang/Integer;


# direct methods
.method public constructor <init>(Ljava/lang/Float;Ljava/lang/Integer;Ljava/lang/Integer;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textSize:Ljava/lang/Float;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textColor:Ljava/lang/Integer;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textStyle:Ljava/lang/Integer;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public toCss()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textSize:Ljava/lang/Float;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "font-size: "

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    sget-object v1, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 13
    .line 14
    iget-object v2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textSize:Ljava/lang/Float;

    .line 15
    .line 16
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    const-string v3, "%f"

    .line 21
    .line 22
    invoke-static {v1, v3, v2}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v1, "px!important;\n"

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const-string v0, ""

    .line 40
    .line 41
    :goto_0
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textColor:Ljava/lang/Integer;

    .line 42
    .line 43
    if-eqz v1, :cond_1

    .line 44
    .line 45
    const-string v1, "color: "

    .line 46
    .line 47
    invoke-static {v0, v1}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textColor:Ljava/lang/Integer;

    .line 52
    .line 53
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    invoke-static {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->a(I)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    const-string v2, "!important;\n"

    .line 62
    .line 63
    invoke-static {v0, v1, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    :cond_1
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textStyle:Ljava/lang/Integer;

    .line 68
    .line 69
    if-eqz v1, :cond_3

    .line 70
    .line 71
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    const/4 v2, 0x1

    .line 76
    and-int/2addr v1, v2

    .line 77
    if-ne v1, v2, :cond_2

    .line 78
    .line 79
    const-string v1, "font-weight: bold!important;\n"

    .line 80
    .line 81
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    :cond_2
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textStyle:Ljava/lang/Integer;

    .line 86
    .line 87
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    const/4 v1, 0x2

    .line 92
    and-int/2addr p0, v1

    .line 93
    if-ne p0, v1, :cond_3

    .line 94
    .line 95
    const-string p0, "font-style: italic!important;\n"

    .line 96
    .line 97
    invoke-static {v0, p0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    return-object p0

    .line 102
    :cond_3
    return-object v0
.end method

.method public toJson()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textSize:Ljava/lang/Float;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "\'font-size\': \'"

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    sget-object v1, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 13
    .line 14
    iget-object v2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textSize:Ljava/lang/Float;

    .line 15
    .line 16
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    const-string v3, "%f"

    .line 21
    .line 22
    invoke-static {v1, v3, v2}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v1, "px\',\n"

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const-string v0, ""

    .line 40
    .line 41
    :goto_0
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textColor:Ljava/lang/Integer;

    .line 42
    .line 43
    if-eqz v1, :cond_1

    .line 44
    .line 45
    const-string v1, "\'color\': \'"

    .line 46
    .line 47
    invoke-static {v0, v1}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textColor:Ljava/lang/Integer;

    .line 52
    .line 53
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    invoke-static {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->a(I)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    const-string v2, "\',\n"

    .line 62
    .line 63
    invoke-static {v0, v1, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    :cond_1
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textStyle:Ljava/lang/Integer;

    .line 68
    .line 69
    if-eqz v1, :cond_3

    .line 70
    .line 71
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    const/4 v2, 0x1

    .line 76
    and-int/2addr v1, v2

    .line 77
    if-ne v1, v2, :cond_2

    .line 78
    .line 79
    const-string v1, "\'font-weight\': \'bold\',\n"

    .line 80
    .line 81
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    :cond_2
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->textStyle:Ljava/lang/Integer;

    .line 86
    .line 87
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    const/4 v1, 0x2

    .line 92
    and-int/2addr p0, v1

    .line 93
    if-ne p0, v1, :cond_3

    .line 94
    .line 95
    const-string p0, "\'font-style\': \'italic\',\n"

    .line 96
    .line 97
    invoke-static {v0, p0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    return-object p0

    .line 102
    :cond_3
    return-object v0
.end method
