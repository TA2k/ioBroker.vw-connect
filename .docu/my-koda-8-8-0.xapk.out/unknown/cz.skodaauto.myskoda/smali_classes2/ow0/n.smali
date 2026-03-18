.class public final Low0/n;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Low0/n;->f:I

    .line 2
    .line 3
    const/16 p1, 0xa

    .line 4
    .line 5
    invoke-direct {p0, p1}, Lap0/o;-><init>(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public Y(Ljava/lang/String;)V
    .locals 4

    .line 1
    iget v0, p0, Low0/n;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Lap0/o;->Y(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    const-string p0, "name"

    .line 11
    .line 12
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object p0, Low0/q;->a:Ljava/util/List;

    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    move v0, p0

    .line 19
    :goto_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-ge p0, v1, :cond_1

    .line 24
    .line 25
    invoke-virtual {p1, p0}, Ljava/lang/String;->charAt(I)C

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    add-int/lit8 v2, v0, 0x1

    .line 30
    .line 31
    const/16 v3, 0x20

    .line 32
    .line 33
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->g(II)I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-lez v3, :cond_0

    .line 38
    .line 39
    const-string v3, "\"(),/:;<=>?@[\\]{}"

    .line 40
    .line 41
    invoke-static {v3, v1}, Lly0/p;->B(Ljava/lang/CharSequence;C)Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-nez v1, :cond_0

    .line 46
    .line 47
    add-int/lit8 p0, p0, 0x1

    .line 48
    .line 49
    move v0, v2

    .line 50
    goto :goto_0

    .line 51
    :cond_0
    new-instance p0, Lgz0/a;

    .line 52
    .line 53
    const-string v1, "Header name \'"

    .line 54
    .line 55
    const-string v2, "\' contains illegal character \'"

    .line 56
    .line 57
    invoke-static {v1, p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-virtual {p1, v0}, Ljava/lang/String;->charAt(I)C

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string v2, "\' (code "

    .line 69
    .line 70
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {p1, v0}, Ljava/lang/String;->charAt(I)C

    .line 74
    .line 75
    .line 76
    move-result p1

    .line 77
    and-int/lit16 p1, p1, 0xff

    .line 78
    .line 79
    const/16 v0, 0x29

    .line 80
    .line 81
    invoke-static {v1, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :cond_1
    return-void

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public Z(Ljava/lang/String;)V
    .locals 4

    .line 1
    iget v0, p0, Low0/n;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Lap0/o;->Z(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    const-string p0, "value"

    .line 11
    .line 12
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object p0, Low0/q;->a:Ljava/util/List;

    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    move v0, p0

    .line 19
    :goto_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-ge p0, v1, :cond_2

    .line 24
    .line 25
    invoke-virtual {p1, p0}, Ljava/lang/String;->charAt(I)C

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    add-int/lit8 v2, v0, 0x1

    .line 30
    .line 31
    const/16 v3, 0x20

    .line 32
    .line 33
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->g(II)I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-gez v3, :cond_1

    .line 38
    .line 39
    const/16 v3, 0x9

    .line 40
    .line 41
    if-ne v1, v3, :cond_0

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_0
    new-instance p0, Lgz0/a;

    .line 45
    .line 46
    const-string v1, "Header value \'"

    .line 47
    .line 48
    const-string v2, "\' contains illegal character \'"

    .line 49
    .line 50
    invoke-static {v1, p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    invoke-virtual {p1, v0}, Ljava/lang/String;->charAt(I)C

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v2, "\' (code "

    .line 62
    .line 63
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1, v0}, Ljava/lang/String;->charAt(I)C

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    and-int/lit16 p1, p1, 0xff

    .line 71
    .line 72
    const/16 v0, 0x29

    .line 73
    .line 74
    invoke-static {v1, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    :cond_1
    :goto_1
    add-int/lit8 p0, p0, 0x1

    .line 83
    .line 84
    move v0, v2

    .line 85
    goto :goto_0

    .line 86
    :cond_2
    return-void

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
