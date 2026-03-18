.class public final Lw30/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:I

.field public final j:Lql0/g;


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 13

    and-int/lit8 v0, p1, 0x4

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move v5, v1

    goto :goto_0

    :cond_0
    const/4 v0, 0x1

    move v5, v0

    :goto_0
    and-int/lit8 v0, p1, 0x8

    .line 1
    const-string v2, ""

    if-eqz v0, :cond_1

    move-object v6, v2

    goto :goto_1

    :cond_1
    const-string v0, "I hereby consent to the processing of my identification and contact information and product and service usage data for the purpose of sending me \u0160koda Auto brand product and service offers, including the information about events, competitions and news. The consent is valid for 5 years./n/nMore information about data processing, including your right to withdraw the consent can be found [here](https://www.skoda-auto.com/other/memorandum-marketing-en)."

    move-object v6, v0

    :goto_1
    and-int/lit8 v0, p1, 0x10

    if-eqz v0, :cond_2

    move-object v7, v2

    goto :goto_2

    :cond_2
    const-string v0, "To view and manage all your \u0160koda ID marketing consents, visit the [\u0160KODA ID Portal](https://skodaid.vwgroup.io/account)."

    move-object v7, v0

    :goto_2
    and-int/lit8 v0, p1, 0x20

    if-eqz v0, :cond_3

    move-object v8, v2

    goto :goto_3

    :cond_3
    const-string v0, "Marketing consent for \u0160koda Auto a.s."

    move-object v8, v0

    :goto_3
    and-int/lit8 v0, p1, 0x40

    if-eqz v0, :cond_4

    move-object v9, v2

    goto :goto_4

    :cond_4
    const-string v0, "Germany"

    move-object v9, v0

    :goto_4
    and-int/lit16 v0, p1, 0x80

    if-eqz v0, :cond_5

    :goto_5
    move-object v10, v2

    goto :goto_6

    :cond_5
    const-string v2, "Marketing Consent"

    goto :goto_5

    :goto_6
    and-int/lit16 p1, p1, 0x100

    if-eqz p1, :cond_6

    :goto_7
    move v11, v1

    goto :goto_8

    :cond_6
    const v1, 0x7f120713

    goto :goto_7

    :goto_8
    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v12, 0x0

    move-object v2, p0

    invoke-direct/range {v2 .. v12}, Lw30/a;-><init>(ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILql0/g;)V

    return-void
.end method

.method public constructor <init>(ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILql0/g;)V
    .locals 1

    const-string v0, "body"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "disclaimer"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "header"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "specificCountry"

    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "title"

    invoke-static {p8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Lw30/a;->a:Z

    .line 4
    iput-boolean p2, p0, Lw30/a;->b:Z

    .line 5
    iput-boolean p3, p0, Lw30/a;->c:Z

    .line 6
    iput-object p4, p0, Lw30/a;->d:Ljava/lang/String;

    .line 7
    iput-object p5, p0, Lw30/a;->e:Ljava/lang/String;

    .line 8
    iput-object p6, p0, Lw30/a;->f:Ljava/lang/String;

    .line 9
    iput-object p7, p0, Lw30/a;->g:Ljava/lang/String;

    .line 10
    iput-object p8, p0, Lw30/a;->h:Ljava/lang/String;

    .line 11
    iput p9, p0, Lw30/a;->i:I

    .line 12
    iput-object p10, p0, Lw30/a;->j:Lql0/g;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
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
    instance-of v1, p1, Lw30/a;

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
    check-cast p1, Lw30/a;

    .line 12
    .line 13
    iget-boolean v1, p0, Lw30/a;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lw30/a;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lw30/a;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lw30/a;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lw30/a;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lw30/a;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-object v1, p0, Lw30/a;->d:Ljava/lang/String;

    .line 35
    .line 36
    iget-object v3, p1, Lw30/a;->d:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-nez v1, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-object v1, p0, Lw30/a;->e:Ljava/lang/String;

    .line 46
    .line 47
    iget-object v3, p1, Lw30/a;->e:Ljava/lang/String;

    .line 48
    .line 49
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-nez v1, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-object v1, p0, Lw30/a;->f:Ljava/lang/String;

    .line 57
    .line 58
    iget-object v3, p1, Lw30/a;->f:Ljava/lang/String;

    .line 59
    .line 60
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-nez v1, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-object v1, p0, Lw30/a;->g:Ljava/lang/String;

    .line 68
    .line 69
    iget-object v3, p1, Lw30/a;->g:Ljava/lang/String;

    .line 70
    .line 71
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    if-nez v1, :cond_8

    .line 76
    .line 77
    return v2

    .line 78
    :cond_8
    iget-object v1, p0, Lw30/a;->h:Ljava/lang/String;

    .line 79
    .line 80
    iget-object v3, p1, Lw30/a;->h:Ljava/lang/String;

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
    iget v1, p0, Lw30/a;->i:I

    .line 90
    .line 91
    iget v3, p1, Lw30/a;->i:I

    .line 92
    .line 93
    if-eq v1, v3, :cond_a

    .line 94
    .line 95
    return v2

    .line 96
    :cond_a
    iget-object p0, p0, Lw30/a;->j:Lql0/g;

    .line 97
    .line 98
    iget-object p1, p1, Lw30/a;->j:Lql0/g;

    .line 99
    .line 100
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    if-nez p0, :cond_b

    .line 105
    .line 106
    return v2

    .line 107
    :cond_b
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Lw30/a;->a:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    iget-boolean v2, p0, Lw30/a;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lw30/a;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lw30/a;->d:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lw30/a;->e:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object v2, p0, Lw30/a;->f:Ljava/lang/String;

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-object v2, p0, Lw30/a;->g:Ljava/lang/String;

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object v2, p0, Lw30/a;->h:Ljava/lang/String;

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget v2, p0, Lw30/a;->i:I

    .line 53
    .line 54
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget-object p0, p0, Lw30/a;->j:Lql0/g;

    .line 59
    .line 60
    if-nez p0, :cond_0

    .line 61
    .line 62
    const/4 p0, 0x0

    .line 63
    goto :goto_0

    .line 64
    :cond_0
    invoke-virtual {p0}, Lql0/g;->hashCode()I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    :goto_0
    add-int/2addr v0, p0

    .line 69
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isProcessing="

    .line 2
    .line 3
    const-string v1, ", isConsented="

    .line 4
    .line 5
    const-string v2, "State(isLoading="

    .line 6
    .line 7
    iget-boolean v3, p0, Lw30/a;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lw30/a;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", body="

    .line 16
    .line 17
    const-string v2, ", disclaimer="

    .line 18
    .line 19
    iget-object v3, p0, Lw30/a;->d:Ljava/lang/String;

    .line 20
    .line 21
    iget-boolean v4, p0, Lw30/a;->c:Z

    .line 22
    .line 23
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", header="

    .line 27
    .line 28
    const-string v2, ", specificCountry="

    .line 29
    .line 30
    iget-object v3, p0, Lw30/a;->e:Ljava/lang/String;

    .line 31
    .line 32
    iget-object v4, p0, Lw30/a;->f:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v1, ", title="

    .line 38
    .line 39
    const-string v2, ", switchTitleId="

    .line 40
    .line 41
    iget-object v3, p0, Lw30/a;->g:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v4, p0, Lw30/a;->h:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget v1, p0, Lw30/a;->i:I

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", error="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Lw30/a;->j:Lql0/g;

    .line 59
    .line 60
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string p0, ")"

    .line 64
    .line 65
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0
.end method
