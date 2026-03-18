.class Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "BorderStyle"
.end annotation


# instance fields
.field private bottomBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

.field private leftBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

.field private rightBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

.field private topBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;


# direct methods
.method public constructor <init>(Ljava/lang/Float;Ljava/lang/Integer;Ljava/lang/Float;Ljava/lang/Integer;Ljava/lang/Float;Ljava/lang/Integer;Ljava/lang/Float;Ljava/lang/Integer;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 5
    .line 6
    const-string v1, "left"

    .line 7
    .line 8
    invoke-direct {v0, v1, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;-><init>(Ljava/lang/String;Ljava/lang/Float;Ljava/lang/Integer;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->leftBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 12
    .line 13
    new-instance p1, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 14
    .line 15
    const-string p2, "top"

    .line 16
    .line 17
    invoke-direct {p1, p2, p3, p4}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;-><init>(Ljava/lang/String;Ljava/lang/Float;Ljava/lang/Integer;)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->topBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 21
    .line 22
    new-instance p1, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 23
    .line 24
    const-string p2, "right"

    .line 25
    .line 26
    invoke-direct {p1, p2, p5, p6}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;-><init>(Ljava/lang/String;Ljava/lang/Float;Ljava/lang/Integer;)V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->rightBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 30
    .line 31
    new-instance p1, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 32
    .line 33
    const-string p2, "bottom"

    .line 34
    .line 35
    invoke-direct {p1, p2, p7, p8}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;-><init>(Ljava/lang/String;Ljava/lang/Float;Ljava/lang/Integer;)V

    .line 36
    .line 37
    .line 38
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->bottomBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public toCss()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->leftBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->leftBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 13
    .line 14
    invoke-virtual {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;->toCss()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    :cond_0
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->topBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 26
    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    invoke-static {v1}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->topBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 34
    .line 35
    invoke-virtual {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;->toCss()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    :cond_1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->rightBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 47
    .line 48
    if-eqz v0, :cond_2

    .line 49
    .line 50
    invoke-static {v1}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->rightBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 55
    .line 56
    invoke-virtual {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;->toCss()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    :cond_2
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->bottomBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 68
    .line 69
    if-eqz v0, :cond_3

    .line 70
    .line 71
    invoke-static {v1}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;->bottomBorderStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;

    .line 76
    .line 77
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;->toCss()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    return-object p0

    .line 89
    :cond_3
    return-object v1
.end method
