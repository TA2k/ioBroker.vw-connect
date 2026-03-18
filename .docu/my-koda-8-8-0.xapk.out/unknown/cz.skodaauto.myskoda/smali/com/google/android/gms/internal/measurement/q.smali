.class public final Lcom/google/android/gms/internal/measurement/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lcom/google/android/gms/internal/measurement/r;


# direct methods
.method public synthetic constructor <init>(Lcom/google/android/gms/internal/measurement/r;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/android/gms/internal/measurement/q;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/q;->f:Lcom/google/android/gms/internal/measurement/r;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    iput p1, p0, Lcom/google/android/gms/internal/measurement/q;->e:I

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/q;->f:Lcom/google/android/gms/internal/measurement/r;

    .line 7
    .line 8
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 9
    .line 10
    iget p0, p0, Lcom/google/android/gms/internal/measurement/q;->e:I

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-ge p0, v0, :cond_0

    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    :goto_0
    return p0

    .line 22
    :pswitch_0
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/q;->f:Lcom/google/android/gms/internal/measurement/r;

    .line 23
    .line 24
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 25
    .line 26
    iget p0, p0, Lcom/google/android/gms/internal/measurement/q;->e:I

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-ge p0, v0, :cond_1

    .line 33
    .line 34
    const/4 p0, 0x1

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/4 p0, 0x0

    .line 37
    :goto_1
    return p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final synthetic next()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/q;->f:Lcom/google/android/gms/internal/measurement/r;

    .line 7
    .line 8
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 9
    .line 10
    iget v2, p0, Lcom/google/android/gms/internal/measurement/q;->e:I

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-ge v2, v1, :cond_0

    .line 17
    .line 18
    add-int/lit8 v1, v2, 0x1

    .line 19
    .line 20
    new-instance v3, Lcom/google/android/gms/internal/measurement/r;

    .line 21
    .line 22
    iput v1, p0, Lcom/google/android/gms/internal/measurement/q;->e:I

    .line 23
    .line 24
    iget-object p0, v0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    invoke-static {p0}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-direct {v3, p0}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object v3

    .line 38
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 39
    .line 40
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :pswitch_0
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/q;->f:Lcom/google/android/gms/internal/measurement/r;

    .line 45
    .line 46
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 47
    .line 48
    iget v1, p0, Lcom/google/android/gms/internal/measurement/q;->e:I

    .line 49
    .line 50
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-ge v1, v0, :cond_1

    .line 55
    .line 56
    add-int/lit8 v0, v1, 0x1

    .line 57
    .line 58
    new-instance v2, Lcom/google/android/gms/internal/measurement/r;

    .line 59
    .line 60
    iput v0, p0, Lcom/google/android/gms/internal/measurement/q;->e:I

    .line 61
    .line 62
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-direct {v2, p0}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    return-object v2

    .line 70
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 71
    .line 72
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 73
    .line 74
    .line 75
    throw p0

    .line 76
    nop

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
