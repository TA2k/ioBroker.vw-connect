.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    if-eqz v0, :cond_1

    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    new-instance v0, Ljava/util/ArrayDeque;

    .line 2
    iget v1, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->j:I

    .line 3
    invoke-direct {v0, v1}, Ljava/util/ArrayDeque;-><init>(I)V

    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->e:Ljava/lang/Object;

    .line 4
    invoke-virtual {v0, p1}, Ljava/util/ArrayDeque;->push(Ljava/lang/Object;)V

    .line 5
    iget-object p1, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 6
    :goto_0
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    if-eqz v0, :cond_0

    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->e:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayDeque;

    .line 7
    invoke-virtual {v0, p1}, Ljava/util/ArrayDeque;->push(Ljava/lang/Object;)V

    .line 8
    iget-object p1, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    goto :goto_0

    .line 9
    :cond_0
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 10
    iput-object p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->f:Ljava/lang/Object;

    goto :goto_1

    :cond_1
    const/4 v0, 0x0

    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->e:Ljava/lang/Object;

    .line 11
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    iput-object p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->f:Ljava/lang/Object;

    :goto_1
    return-void
.end method

.method public constructor <init>(Lj11/s;Lj11/s;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->d:I

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    iput-object p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->e:Ljava/lang/Object;

    .line 14
    iput-object p2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayDeque;

    .line 4
    .line 5
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 8
    .line 9
    if-eqz v1, :cond_4

    .line 10
    .line 11
    :cond_0
    const/4 v2, 0x0

    .line 12
    if-eqz v0, :cond_3

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-eqz v3, :cond_1

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->pop()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    check-cast v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    .line 26
    .line 27
    iget-object v2, v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->h:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 28
    .line 29
    :goto_0
    instance-of v3, v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    .line 30
    .line 31
    if-eqz v3, :cond_2

    .line 32
    .line 33
    check-cast v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    .line 34
    .line 35
    invoke-virtual {v0, v2}, Ljava/util/ArrayDeque;->push(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object v2, v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    check-cast v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 42
    .line 43
    invoke-virtual {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;->i()I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    if-eqz v3, :cond_0

    .line 48
    .line 49
    :cond_3
    :goto_1
    iput-object v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->f:Ljava/lang/Object;

    .line 50
    .line 51
    return-object v1

    .line 52
    :cond_4
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 53
    .line 54
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 55
    .line 56
    .line 57
    throw p0
.end method

.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lj11/s;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lj11/s;

    .line 15
    .line 16
    if-eq v0, p0, :cond_0

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
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 25
    .line 26
    if-eqz p0, :cond_1

    .line 27
    .line 28
    const/4 p0, 0x1

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/4 p0, 0x0

    .line 31
    :goto_1
    return p0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lj11/s;

    .line 9
    .line 10
    iget-object v1, v0, Lj11/s;->e:Lj11/s;

    .line 11
    .line 12
    iput-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->e:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0

    .line 15
    :pswitch_0
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->a()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final remove()V
    .locals 1

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 7
    .line 8
    const-string v0, "remove"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 17
    .line 18
    .line 19
    throw p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
