.class public final Lcom/google/android/gms/internal/measurement/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public f:Ljava/lang/Iterable;


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lcom/google/android/gms/internal/measurement/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/e;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lcom/google/android/gms/internal/measurement/d;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/d;->f:Ljava/lang/Iterable;

    const/4 p1, 0x0

    iput p1, p0, Lcom/google/android/gms/internal/measurement/d;->e:I

    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lcom/google/android/gms/internal/measurement/d;->e:I

    .line 7
    .line 8
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/d;->f:Ljava/lang/Iterable;

    .line 9
    .line 10
    check-cast p0, Ld5/f;

    .line 11
    .line 12
    iget-object p0, p0, Ld5/b;->h:Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-ge v0, p0, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    :goto_0
    return p0

    .line 24
    :pswitch_0
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/d;->f:Ljava/lang/Iterable;

    .line 25
    .line 26
    check-cast v0, Lcom/google/android/gms/internal/measurement/e;

    .line 27
    .line 28
    iget p0, p0, Lcom/google/android/gms/internal/measurement/d;->e:I

    .line 29
    .line 30
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-ge p0, v0, :cond_1

    .line 35
    .line 36
    const/4 p0, 0x1

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/4 p0, 0x0

    .line 39
    :goto_1
    return p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/d;->f:Ljava/lang/Iterable;

    .line 7
    .line 8
    check-cast v0, Ld5/f;

    .line 9
    .line 10
    iget-object v0, v0, Ld5/b;->h:Ljava/util/ArrayList;

    .line 11
    .line 12
    iget v1, p0, Lcom/google/android/gms/internal/measurement/d;->e:I

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    check-cast v0, Ld5/d;

    .line 19
    .line 20
    iget v1, p0, Lcom/google/android/gms/internal/measurement/d;->e:I

    .line 21
    .line 22
    add-int/lit8 v1, v1, 0x1

    .line 23
    .line 24
    iput v1, p0, Lcom/google/android/gms/internal/measurement/d;->e:I

    .line 25
    .line 26
    return-object v0

    .line 27
    :pswitch_0
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/d;->f:Ljava/lang/Iterable;

    .line 28
    .line 29
    check-cast v0, Lcom/google/android/gms/internal/measurement/e;

    .line 30
    .line 31
    iget v1, p0, Lcom/google/android/gms/internal/measurement/d;->e:I

    .line 32
    .line 33
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-ge v1, v2, :cond_0

    .line 38
    .line 39
    iget v1, p0, Lcom/google/android/gms/internal/measurement/d;->e:I

    .line 40
    .line 41
    add-int/lit8 v2, v1, 0x1

    .line 42
    .line 43
    iput v2, p0, Lcom/google/android/gms/internal/measurement/d;->e:I

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0

    .line 50
    :cond_0
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 51
    .line 52
    iget p0, p0, Lcom/google/android/gms/internal/measurement/d;->e:I

    .line 53
    .line 54
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    new-instance v2, Ljava/lang/StringBuilder;

    .line 63
    .line 64
    add-int/lit8 v1, v1, 0x15

    .line 65
    .line 66
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 67
    .line 68
    .line 69
    const-string v1, "Out of bounds index: "

    .line 70
    .line 71
    invoke-static {p0, v1, v2}, Lvj/b;->h(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-direct {v0, p0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw v0

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
