.class Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "EditTextStyle"
.end annotation


# instance fields
.field editTextBorder:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;

.field editTextFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

.field isPlaceholderVisible:Z


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public toCss(Ljava/lang/String;)Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    const-string v1, ".wpwl-control {\n"

    .line 4
    .line 5
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->editTextFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 14
    .line 15
    invoke-virtual {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->toCss()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const-string v2, "\n"

    .line 20
    .line 21
    invoke-static {v0, v1, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->editTextBorder:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;

    .line 30
    .line 31
    invoke-virtual {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->toCss()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-static {v0, v1, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    const-string v1, "background: transparent;"

    .line 40
    .line 41
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    const-string v1, "margin-top: 4px;"

    .line 46
    .line 47
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    const-string v1, "}\n"

    .line 52
    .line 53
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    const-string v3, ".wpwl-control::-webkit-input-placeholder {\n"

    .line 58
    .line 59
    invoke-static {v0, p1, v3}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    invoke-static {p1}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->editTextFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 68
    .line 69
    invoke-virtual {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->toCss()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    invoke-static {p1, v0, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    const-string v0, "opacity: "

    .line 78
    .line 79
    invoke-static {p1, v0}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    iget-boolean p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->isPlaceholderVisible:Z

    .line 84
    .line 85
    if-eqz p0, :cond_0

    .line 86
    .line 87
    const-string p0, "0.5"

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_0
    const-string p0, "0"

    .line 91
    .line 92
    :goto_0
    const-string v0, ";"

    .line 93
    .line 94
    invoke-static {p1, p0, v0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-static {p0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0
.end method

.method public toCssCyber(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    const-string v1, " {\n"

    .line 4
    .line 5
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-static {p1}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->editTextFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 14
    .line 15
    invoke-virtual {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->toCss()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const-string v1, "\n"

    .line 20
    .line 21
    invoke-static {p1, v0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-static {p1}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->editTextBorder:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;

    .line 30
    .line 31
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->toCss()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-static {p1, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    const-string p1, "background: transparent;"

    .line 40
    .line 41
    invoke-static {p0, p1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    const-string p1, "margin-top: 4px;"

    .line 46
    .line 47
    invoke-static {p0, p1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const-string p1, "}\n"

    .line 52
    .line 53
    invoke-static {p0, p1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0
.end method

.method public toCssPayonPci(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    const-string v1, " {\n"

    .line 4
    .line 5
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-static {p1}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->editTextFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 14
    .line 15
    invoke-virtual {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->toCss()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const-string v1, "\n"

    .line 20
    .line 21
    invoke-static {p1, v0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-static {p1}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->editTextBorder:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;

    .line 30
    .line 31
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->toCss()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-static {p1, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    const-string p1, "background: transparent;"

    .line 40
    .line 41
    invoke-static {p0, p1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    const-string p1, "}\n"

    .line 46
    .line 47
    invoke-static {p0, p1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0
.end method

.method public toJson()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "\'opacity\': "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-boolean v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->isPlaceholderVisible:Z

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    const-string v1, "\'0.5\'"

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const-string v1, "\'0\'"

    .line 16
    .line 17
    :goto_0
    const-string v2, ",\n"

    .line 18
    .line 19
    invoke-static {v0, v1, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->editTextFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 28
    .line 29
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->toJson()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method
